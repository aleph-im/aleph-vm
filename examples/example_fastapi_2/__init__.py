import logging
logger = logging.getLogger(__name__)

logger.debug("import aiohttp")
import aiohttp


logger.debug("import aleph_client")
from aleph_client.asynchronous import get_messages
logger.debug("import fastapi")
from fastapi import FastAPI
logger.debug("imports done")

app = FastAPI()


@app.get("/")
async def index():
    return {
        "Example": "example_fastapi_2",
        "endpoints": ["/messages", "/internet"],
    }


@app.get("/messages")
async def read_aleph_messages():
    """Read data from Aleph using the Aleph Client library."""
    data = await get_messages(
        hashes=["f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e"]
    )
    return {"Messages": data}


@app.get("/internet")
async def read_internet():
    """Read data from the public Internet using aiohttp."""
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
        async with session.get("https://aleph.im/") as resp:
            resp.raise_for_status()
            return {"result": resp.status, "headers": resp.headers}
