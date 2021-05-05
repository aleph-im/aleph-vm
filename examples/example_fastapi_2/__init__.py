import asyncio
import socket
from typing import Optional
import logging
logging.basicConfig(level=logging.DEBUG)

from fastapi import FastAPI

app = FastAPI()

import aiohttp


# async def get_data():
#     conn = aiohttp.TCPConnector(family=socket.AF_VSOCK)
#     async with aiohttp.ClientSession(connector=conn) as session:
#         async with session.get('http://localhost/get') as resp:
#             print(resp.status)
#             print(await resp.text())
#             return await resp.json()


@app.get("/")
async def read_root():
    print('*' * 100)
    # data = await get_data()
    s0 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s0.connect((2, 53))
    s0.send(b"GET / HTTP/1.1\nHost: localhost\n\n")
    d = s0.recv(1000)
    s0.close()

    # await asyncio.sleep(20)

    return {"Foo": "Bar" + d.decode()}


@app.get("/run/{item_id}")
def read_item(item_id: str, q: Optional[str] = None):
    return {"pyz item_id": item_id, "q": q}


@app.post("/run/{item_id}")
def read_item_post(item_id: str, q: Optional[str] = None):
    return {"pyz item_id_post": item_id, "q": q}
