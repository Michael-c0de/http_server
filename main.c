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
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include "thpool.h"
#define BufSize 1024 * 16

typedef struct
{
    long start;
    long end;
    int flag;
} Range;
SSL_CTX *ctx;

int parse_range(const char *recv_buf, Range *range)
{
    const char *range_header = "Range: ";
    const char *range_start = strstr(recv_buf, range_header);
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

        range->end = -1;
        return 1;
    }
    else
    {
        // 处理不完整的范围（例如："-100"）
        sscanf(range_start, "-%ld", &range->end);
        range->start = 0;

        return 1;
    }
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

void get_filetype(char *filename, char *filetype)
{
    if (strstr(filename, ".html") || strstr(filename, ".php"))
        strcpy(filetype, "text/html");
    else if (strstr(filename, ".gif"))
        strcpy(filetype, "image/gif");
    else if (strstr(filename, ".png"))
        strcpy(filetype, "image/png");
    else if (strstr(filename, ".jpg"))
        strcpy(filetype, "image/jpeg");
    else if (strstr(filename, ".mp4"))
        strcpy(filetype, "video/mp4");
    else
        strcpy(filetype, "text/plain");
}

void serve_file(SSL *ssl, char *filename, Range *r, char *reply_buf)
{

    int f = open(filename, O_RDONLY);
    if (f == -1)
    {

        memset(reply_buf, 0, BufSize);
        snprintf(reply_buf, BufSize,
                 "HTTP/1.1 404 Not Found\r\n"
                 "Connection: close\r\n"
                 "\r\n");
        SSL_write(ssl, reply_buf, strlen(reply_buf));
        return;
    }
    struct stat s;
    fstat(f, &s);
    // 获取文件大小
    size_t fsize = s.st_size;
    int state = r->flag == 0 ? 200 : 206;

    r->end = r->end == -1 || r->end - 1 > fsize ? fsize - 1 : r->end;

    // 响应头
    char filetype[0x20];
    memset(filetype, 0, 0x20);
    get_filetype(filename, filetype);
    memset(reply_buf, 0, BufSize);

    char temp[BufSize];
    memset(temp, 0, BufSize);
    snprintf(temp, BufSize,
             "HTTP/1.0 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %ld\r\n",
             state,
             state == 200 ? "OK" : "Partial Content",
             filetype,
             r->end - r->start + 1);
    strcat(reply_buf, temp);

    if (state == 206)
    {
        memset(temp, 0, BufSize);
        snprintf(temp, BufSize,
                 "Accept-Ranges: bytes\r\n"
                 "Content-Range: bytes %ld-%ld/%ld\r\n",
                 r->start, r->end, fsize);
        strcat(reply_buf, temp);
    }

    strcat(reply_buf, "\r\n");
    SSL_write(ssl, reply_buf, strlen(reply_buf));

    void *buffer = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, f, 0);
    size_t wsize = r->end - r->start + 1;
    SSL_write(ssl, buffer + r->start, wsize);
    printf("SSL_write(%ld %ld)\n", r->start, r->end);
    munmap(buffer, fsize);
    close(f);
}

void handle_http(int client)
{
    char buffer[BufSize];
    memset(buffer, 0, BufSize);

    read(client, buffer, BufSize);

    char *filename = strtok(buffer, " ");
    if (filename == NULL)
        goto http_end;
    filename = strtok(NULL, " ");

    if (filename && filename[0] == '/')
    {
        filename++;
    }

    char *name = strdup(filename);
    memset(buffer, 0, BufSize);
    snprintf(buffer, BufSize,
             "HTTP/1.1 301 Moved Permanently\r\n"
             "Location: https://192.168.93.128/%s\r\n"
             "Connection: close\r\n"
             "\r\n",
             name);
    free(name);
    write(client, buffer, strlen(buffer));
http_end:
    close(client);
}
void handle_https(void *args)
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
    memset(&range, 0, sizeof(range));
    range.flag = parse_range(buffer, &range);

    char method[10];
    char path[256];
    char version[10];
    if (sscanf(buffer, "%s %s %s", method, path, version) == 3)
    {
        printf("Method: %s\n", method);
        printf("Path: %s\n", path);
        printf("Version: %s\n", version);
    }
    else
    {
        printf("Failed to parse HTTP request.\n");
    }
    char *filename = &path[1];

    serve_file(ssl, filename, &range, buffer);

end:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client);
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
    threadpool thpool = thpool_init(1000);
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
            handle_https(client);
            thpool_add_work(thpool, handle_https, client);
        }
    }
    thpool_wait(thpool);
    thpool_destroy(thpool);
    close(fd1);
    close(fd2);
    SSL_CTX_free(ctx);
}