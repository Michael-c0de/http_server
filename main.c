/*
gcc https.c -lssl -lcrypto   -o https
*/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <sys/select.h>

#define BufSize 1024 * 16

typedef struct
{
    long start;
    long end;
} Range;
SSL_CTX *ctx;

int parse_range(const char *recv_buf, Range *range)
{
    const char *range_header = "Range: ";
    const char *range_start = strstr(recv_buf, range_header);
    range->start = range->end = -1;
    if (!range_start)
    {
        return 0; // 没有找到 Range 头
    }

    range_start += strlen(range_header);

    // 检查是否以 "bytes=" 开头
    if (strncmp(range_start, "bytes=", 6) != 0)
    {
        return 0; // 格式不正确
    }

    range_start += 6; // 跳过 "bytes="

    // 解析范围
    if (sscanf(range_start, "%ld-%ld", &range->start, &range->end) == 2)
    {
        // 正确解析 start 和 end
        return 1;
    }
    else if (sscanf(range_start, "%ld-", &range->start) == 1)
    {
        // 只解析 start，end 留空
        return 1;
    }
    else
    {
        // 处理不完整的范围（例如："-100"）
        sscanf(range_start, "-%ld", &range->end);
        return 1;
    }
    range->start = range->start >= -1 ? range->start : -1;
    range->end = range->end >= -1 ? range->end : -1;
}

int create_socket_listen(int port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    // 设置 SO_REUSEADDR 选项
    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        close(s);
        exit(EXIT_FAILURE);
    }
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }
    if (listen(s, 3) < 0)
    {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

SSL_CTX *initSSL(const char *cert, const char *key)
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_method());
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stdout);
        return NULL;
    }

    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx))
    {
        ERR_print_errors_fp(stdout);
        return NULL;
    }
    assert(ctx != NULL);
    return ctx;
}

// 读取[from，to)范围内的数据写入套接字
size_t range_write(SSL *ssl, FILE *f, long l, long r, char *reply_buf)
{
    long num_bytes = r - l;
    assert(num_bytes >= 0);
    if (fseek(f, l, SEEK_SET) == -1)
        return -1;
    long left_bytes = num_bytes;
    size_t read_size = -1;
    while (left_bytes > 0 && read_size)
    {
        long tmp_size = left_bytes > BufSize ? BufSize : left_bytes;
        read_size = fread(reply_buf, 1, tmp_size, f);
        SSL_write(ssl, reply_buf, read_size);
        left_bytes -= read_size;
    }
    return num_bytes - left_bytes;
}
void serve_file(SSL *ssl, char *filename, Range *r, char *reply_buf)
{

    FILE *f = fopen(filename, "rb");
    if (f == NULL)
    {

        memset(reply_buf, 0, BufSize);
        snprintf(reply_buf, BufSize,
                 "HTTP/1.1 404 Not Found\r\n"
                 "Connection: close\r\n"
                 "\r\n");
        SSL_write(ssl, reply_buf, strlen(reply_buf));
        return;
    }
    // 获取文件大小
    fseek(f, 0, SEEK_END);
    size_t fsize = ftell(f);
    int state = r->start == -1 && r->end == -1 ? 200 : 206;
    r->start = r->start == -1 ? 0 : r->start;
    r->end = r->end == -1 || r->end - 1 > fsize ? fsize - 1 : r->end;
    // 响应头
    memset(reply_buf, 0, BufSize);
    snprintf(reply_buf, BufSize,
             "HTTP/1.1 %d OK\r\n"
             "Content-Type: text/html; charset=UTF-8\r\n"
             "Content-Length: %ld\r\n"
             "Connection: close\r\n"
             "\r\n",
             state, r->end - r->start + 1);
    SSL_write(ssl, reply_buf, strlen(reply_buf));
    // 循环读取和写入
    range_write(ssl, f, r->start, r->end + 1, reply_buf);
    fclose(f);
}

void handle_http(int client)
{
    char buffer[BufSize];
    memset(buffer, 0, BufSize);

    read(client, buffer, BufSize);
    char *filename = strtok(buffer, " ");
    filename = strtok(NULL, " ");

    if (filename && filename[0] == '/')
    {
        filename++;
    }
    char *name = strdup(filename);
    memset(buffer, 0, BufSize);
    snprintf(buffer, BufSize,
             "HTTP/1.1 301 Moved Permanently\r\n"
             "Location: https://10.0.0.1/%s\r\n"
             "Connection: close\r\n"
             "\r\n",
             name);
    free(name);
    write(client, buffer, strlen(buffer));
    close(client);
}
void *handle_https(void *args)
{
    char buffer[BufSize];
    memset(buffer, 0, BufSize);
    int client = *(int *)args;
    free(args);
    SSL *ssl;
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client);
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        goto end;
    }

    SSL_read(ssl, buffer, BufSize);
    Range range;
    parse_range(buffer, &range);

    char *filename = strtok(buffer, " ");
    filename = strtok(NULL, " ");

    if (filename && filename[0] == '/')
    {
        filename++;
    }

    serve_file(ssl, filename, &range, buffer);

end:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
    return NULL;
}

int main(int argc, char **argv)
{

    /* Ignore broken pipe signals */
    signal(SIGPIPE, SIG_IGN);
    ctx = initSSL("./keys/cnlab.cert", "./keys/cnlab.prikey");
    int fd1 = create_socket_listen(80);
    int fd2 = create_socket_listen(443);
    fd_set fds;
    int max_sd = (fd1 > fd2) ? fd1 : fd2;

    /* Handle connections */
    while (1)
    {
        FD_ZERO(&fds);
        FD_SET(fd1, &fds);
        FD_SET(fd2, &fds);
        // 使用 select 等待可读事件
        if (select(max_sd + 1, &fds, NULL, NULL, NULL) < 0)
        {
            perror("Select error");
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(fd1, &fds))
        {
            struct sockaddr_in addr;
            unsigned int len = sizeof(addr);
            int client = accept(fd1, (struct sockaddr *)&addr, &len);
            handle_http(client);
        }
        if (FD_ISSET(fd2, &fds))
        {
            struct sockaddr_in addr;
            unsigned int len = sizeof(addr);
            int *client = malloc(sizeof(int)); // 动态分配内存
            *client = accept(fd2, (struct sockaddr *)&addr, &len);
            if (*client < 0)
            {

                perror("Unable to accept");
                exit(EXIT_FAILURE);
            }
            pthread_t pid;
            if (pthread_create(&pid, NULL, handle_https, client) != 0)
            {
                perror("Faild to create thread");
                close(*client);
                free(client);
            }
            else
            {
                pthread_detach(pid);
            }
        }
    }

    close(fd1);
    close(fd2);
    SSL_CTX_free(ctx);
}