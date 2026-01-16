import json
import logging

import aiohttp
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import Response, StreamingResponse
from pydantic import BaseModel

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephHttpClient
from aleph.sdk.types import StorageEnum

from .conf import settings

logger = logging.getLogger(__file__)


app = FastAPI()


@app.get("/")
def read_root():
    return {"Server": "Aleph.im VM Connector"}


async def get_latest_message_amend(ref: str, sender: str) -> dict | None:
    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/messages.json?msgType=STORE&sort_order=-1&refs={ref}&addresses={sender}"
        resp = await session.get(url)
        resp.raise_for_status()
        resp_data = await resp.json()
        if resp_data["messages"]:
            return resp_data["messages"][0]
        else:
            return None


async def get_message(hash_: str) -> dict | None:
    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/messages.json?hashes={hash_}"
        resp = await session.get(url)
        resp.raise_for_status()
        resp_data = await resp.json()
        return resp_data["messages"][0] if resp_data["messages"] else None


async def stream_url_chunks(url):
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        resp.raise_for_status()
        # with open(local_path, 'wb') as cache_file:
        if True:
            while True:
                chunk = await resp.content.read(65536)
                if not chunk:
                    break
                # cache_file.write(chunk)
                yield chunk
        logger.debug("Download complete")


@app.get("/download/message/{ref}")
async def download_message(ref: str) -> dict:
    """
    Fetch on Aleph and return a VM function message, after checking its validity.
    Used by the VM Supervisor run the code.

    :param ref: item_hash of the code file
    :return: a file containing the code file
    """

    msg = await get_message(hash_=ref)

    # TODO: Validate the message (signature, hashes)
    if not msg:
        raise HTTPException(status_code=404, detail="Hash not found")

    return msg


@app.get("/download/code/{ref}")
async def download_code(ref: str):
    """
    Fetch on Aleph and return a VM code file, after checking its validity.
    Used by the VM Supervisor to download function source code.

    :param ref: item_hash of the code file
    :return: a file containing the code file
    """
    return await download_data(ref=ref)


@app.get("/download/data/{ref}")
async def download_data(ref: str):
    """
    Fetch on Aleph and return a VM data file, after checking its validity.
    Used by the VM Supervisor to download state data.

    :param ref: item_hash of the data
    :return: a file containing the data
    """

    # Download message
    msg = await get_message(hash_=ref)
    if not msg:
        return Response(status_code=404, content="Hash not found")

    media_type = msg["content"].get("mime_type", "application/octet-stream")

    data_hash = msg["content"]["item_hash"]
    if msg["content"]["item_type"] == "ipfs":
        url = f"{settings.IPFS_SERVER}/{data_hash}"
    else:
        url = f"{settings.API_SERVER}/api/v0/storage/raw/{data_hash}"

    return StreamingResponse(stream_url_chunks(url), media_type=media_type)


@app.get("/download/runtime/{ref}")
async def download_runtime(ref: str):
    """
    Fetch on Aleph and return a VM runtime, after checking its validity.
    Used by the VM Supervisor to download a runtime.

    :param ref: item_hash of the runtime
    :return: a file containing the runtime
    """
    return await download_data(ref=ref)


@app.get("/compute/latest_amend/{item_hash}")
async def compute_latest_amend(item_hash: str) -> str:
    msg = await get_message(hash_=item_hash)
    if not msg:
        raise HTTPException(status_code=404, detail="Hash not found")
    sender = msg["sender"]
    latest_amend = await get_latest_message_amend(ref=item_hash, sender=sender)
    if latest_amend:
        # Validation
        assert latest_amend["sender"] == sender
        assert latest_amend["content"]["ref"] == item_hash

        return latest_amend["item_hash"]
    else:
        # Original message is the latest
        return item_hash


class PostBody(BaseModel):
    topic: str
    data: str


@app.post("/api/v0/ipfs/pubsub/pub")
@app.post("/api/v0/p2p/pubsub/pub")
async def publish_data(body: PostBody):
    """
    Publish a new POST message on the Aleph Network.
    """
    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    message = json.loads(body.data)
    content = json.loads(message["item_content"])
    content_content = content["content"]

    async with AuthenticatedAlephHttpClient(account=account, api_server=settings.API_SERVER) as client:
        result = await client.create_post(
            post_content=content_content,
            post_type=content["type"],
            address=content["address"],
            ref=None,
            channel=message["channel"],
            inline=True,
            storage_engine=StorageEnum.storage,
        )
    return {"status": "success"}


@app.get("/properties")
async def properties(request: Request):
    """Get signing key properties"""
    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    return {
        "chain": account.CHAIN,
        "curve": account.CURVE,
        "address": account.get_address(),
        "public_key": account.get_public_key(),
    }


@app.post("/sign")
async def sign_message(request: Request):
    """Sign a message"""
    # TODO: Check
    private_key = get_fallback_private_key()
    account: ETHAccount = ETHAccount(private_key=private_key)

    message = await request.json()
    message = await account.sign_message(message)
    return message
