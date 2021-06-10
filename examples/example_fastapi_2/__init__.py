import logging
from datetime import datetime

logger = logging.getLogger(__name__)

logger.debug("import aiohttp")
import aiohttp

logger.debug("import aleph_client")
from aleph_client.asynchronous import get_messages, create_post
from aleph_client.chains.remote import RemoteAccount
from aleph_client.vm.cache import VmCache

logger.debug("import fastapi")
from fastapi import FastAPI
logger.debug("imports done")

app = FastAPI()
cache = VmCache()


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


@app.get("/post_a_message")
async def post_a_message():
    """Post a message on the Aleph network"""

    account = await RemoteAccount.from_crypto_host(
        host="http://localhost", unix_socket="/tmp/socat-socket")

    content = {
        "date": datetime.utcnow().isoformat(),
        "test": True,
        "answer": 42,
        "something": "interesting",
    }
    response = await create_post(
        account=account,
        post_content=content,
        post_type="test",
        ref=None,
        channel="TEST",
        inline=True,
        storage_engine="storage",
    )
    return {
        "response": response,
    }


@app.get("/cache/get/{key}")
async def get_from_cache(key: str):
    """Get data in the VM cache"""
    return await cache.get(key)


@app.get("/cache/set/{key}/{value}")
async def store_in_cache(key: str, value: str):
    """Store data in the VM cache"""
    return await cache.set(key, value)


@app.get("/cache/remove/{key}")
async def remove_from_cache(key: str):
    """Store data in the VM cache"""
    result = await cache.delete(key)
    return result == 1
