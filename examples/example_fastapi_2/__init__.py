import logging
from typing import Optional
logger = logging.getLogger(__name__)

logger.debug("")

logger.debug("import aleph_client")
from aleph_client.asynchronous import get_messages
logger.debug("import fastapi")
from fastapi import FastAPI
logger.debug("imports done")

app = FastAPI()


async def get_data_http():
    return "Have a look at <b>/messages</b>"


@app.get("/")
async def index():
    data = await get_data_http()
    return {
        "Example": "example_fastapi_2",
        "endpoints": ["/messages", "/run/{item_id}"],
    }


@app.get("/messages")
async def read_aleph_messages():
    data = await get_messages(
        hashes=["f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e"]
    )
    return {"Messages": data}


@app.get("/run/{item_id}")
def read_item(item_id: str, q: Optional[str] = None):
    return {"pyz item_id": item_id, "q": q}


@app.post("/run/{item_id}")
def read_item_post(item_id: str, q: Optional[str] = None):
    return {"pyz item_id_post": item_id, "q": q}
