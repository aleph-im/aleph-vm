import asyncio
import socket
from typing import Optional
import logging
logging.basicConfig(level=logging.DEBUG)

from fastapi import FastAPI

app = FastAPI()

import aiohttp


async def get_data():
    # conn = aiohttp.TCPConnector(family=socket.AF_VSOCK)
    conn = aiohttp.UnixConnector(path='/tmp/socat-socket')
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get('http://localhost/get') as resp:
            print(resp.status)
            return await resp.text()


@app.get("/")
async def read_root():
    data = await get_data()
    return {"Foo": "Bar", "data": data}


@app.get("/run/{item_id}")
def read_item(item_id: str, q: Optional[str] = None):
    return {"pyz item_id": item_id, "q": q}


@app.post("/run/{item_id}")
def read_item_post(item_id: str, q: Optional[str] = None):
    return {"pyz item_id_post": item_id, "q": q}
