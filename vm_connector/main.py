import json
import logging
import os.path
from typing import Optional, Dict, Union

# from aleph_client.chains.common import get_fallback_private_key
# from aleph_client.asynchronous import get_posts
import aiohttp
from fastapi import FastAPI
from fastapi.responses import StreamingResponse, Response, FileResponse

from .conf import settings

logger = logging.getLogger(__file__)


app = FastAPI()


@app.get("/")
def read_root():
    return {"Hello": "World"}


class Encoding:
    plain = 'plain'
    zip = 'zip'


async def get_message(hash_: str) -> Optional[Dict]:
    async with aiohttp.ClientSession() as session:
        url = f"{settings.ALEPH_SERVER}/api/v0/messages.json?hashes={hash_}"
        resp = await session.get(url)
        resp.raise_for_status()
        resp_data = await resp.json()
        return resp_data['messages'][0] if resp_data['messages'] else None


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
async def download_message(ref: str, last_amend: Optional[bool] = True) -> \
        Union[Dict, Response]:
    """
    Fetch on Aleph and return a VM function message, after checking its validity.
    Used by the VM Supervisor run the code.

    :param ref: item_hash of the code file
    :param last_amend: should the last amend to the code be used
    :return: a file containing the code file
    """

    if settings.OFFLINE_TEST_MODE:
        filepath = os.path.abspath('./tests/test_message.json')
        with open(filepath) as fd:
            return json.load(fd)

    msg = await get_message(hash_=ref)

    # TODO: Validate the validity of the message (signature, hashes)

    return msg or Response(status_code=404, content="Hash not found")


@app.get("/download/code/{ref}")
async def download_code(ref: str, last_amend: Optional[bool] = True
                  ) -> Union[StreamingResponse, Response]:
    """
    Fetch on Aleph and return a VM code file, after checking its validity.
    Used by the VM Supervisor to download function source code.

    :param ref: item_hash of the code file
    :param last_amend: should the last amend to the code be used
    :return: a file containing the code file
    """

    if settings.OFFLINE_TEST_MODE:
        filepath = os.path.abspath('./examples/example_fastapi_2.zip')
        return FileResponse(filepath, filename=f"{ref}")

    msg = await get_message(hash_=ref)
    if not msg:
        return Response(status_code=404, content="Hash not found")

    data_hash = msg['content']['item_hash']
    url = f"{settings.IPFS_SERVER}/{data_hash}"
    return StreamingResponse(stream_url_chunks(url),
                             media_type='application/zip')


@app.get("/download/data/{ref}")
async def download_data(ref: str, last_amend: Optional[bool] = True
                        ) -> Union[StreamingResponse, Response]:
    """
    Fetch on Aleph and return a VM data file, after checking its validity.
    Used by the VM Supervisor to download state data.

    :param ref: item_hash of the data
    :param last_amend: should the last amend to the data be used
    :return: a file containing the data
    """

    if settings.OFFLINE_TEST_MODE:
        filepath = os.path.abspath('./examples/data.tgz')
        return FileResponse(filepath, filename=f"{ref}.tgz")

    # Download message
    msg = await get_message(hash_=ref)
    if not msg:
        return Response(status_code=404, content="Hash not found")

    data_hash = msg['content']['item_hash']
    url = f"{settings.IPFS_SERVER}/{data_hash}"
    return StreamingResponse(stream_url_chunks(url),
                             media_type='application/gzip')


@app.get("/download/runtime/{ref}")
async def download_runtime(ref: str, last_amend: Optional[bool] = True
                     ) -> Union[StreamingResponse, Response]:
    """
    Fetch on Aleph and return a VM runtime, after checking its validity.
    Used by the VM Supervisor to download a runtime.

    :param ref: item_hash of the runtime
    :param last_amend: should the last amend to the runtime be used
    :return: a file containing the runtime
    """

    if settings.OFFLINE_TEST_MODE:
        filepath = os.path.abspath('./runtimes/aleph-alpine-3.13-python/rootfs.ext4')
        return FileResponse(filepath, filename=f"{ref}.ext4")

    # Download message
    msg = await get_message(hash_=ref)
    if not msg:
        return Response(status_code=404, content="Hash not found")

    data_hash = msg['content']['item_hash']
    url = f"{settings.IPFS_SERVER}/{data_hash}"
    return StreamingResponse(stream_url_chunks(url),
                             media_type='application/ext4')


@app.post("/publish/data/")
async def publish_data(encoding: str):
    """
    Publish a new state on the Aleph Network.
    :param encoding:
    :return:
    """
    raise NotImplementedError()
