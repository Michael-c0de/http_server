import asyncio
import httpx
import threading
import time

client = httpx.AsyncClient(verify=False)

async def async_main(url, sign):
    response = await client.get(url)
    status_code = response.status_code
    print(f'async_main: {threading.current_thread()}: {sign}:{status_code}')


loop = asyncio.get_event_loop()
tasks = [async_main(url='https://127.0.0.1/index.html', sign=i) for i in range(300)]
async_start = time.time()
loop.run_until_complete(asyncio.wait(tasks))
async_end = time.time()
loop.close()
print(async_end - async_start)