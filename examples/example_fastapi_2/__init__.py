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
        async with session.get('https://api2.aleph.im/api/v0/messages.json?hashes='
                               '750468b3e4ed31f66630c5dff5081d8e7e071ae669beb3955dec6edb28145787'
                               '&chain=ETH&addresses=0xE255493a528F639b739C9cbA8736f03d7Cbe094c'
                               '&msgType=POST') as resp:
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
