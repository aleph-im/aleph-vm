"""
This module is in charge of providing the source code corresponding to a 'code id'.

In this prototype, it returns a hardcoded example.
In the future, it should connect to an Aleph node and retrieve the code from there.
"""
import json
import logging
import os
from os.path import isfile, join

import aiohttp

from .conf import settings
from .models import FunctionMessage, FilePath

logger = logging.getLogger(__name__)


async def download_file(url: str, local_path: FilePath) -> None:
    if isfile(local_path):
        logger.debug(f"File already exists: {local_path}")
    else:
        logger.debug(f"Downloading {url} -> {local_path}")
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url)
            resp.raise_for_status()
            try:
                with open(local_path, "wb") as cache_file:
                    while True:
                        chunk = await resp.content.read(65536)
                        if not chunk:
                            break
                        cache_file.write(chunk)
                logger.debug("Download complete")
            except Exception:
                # Ensure no partial file is left
                os.remove(local_path)
                raise


async def get_message(ref) -> FunctionMessage:
    if settings.FAKE_DATA:
        cache_path = os.path.abspath(join(__file__, '../examples/message_from_aleph.json'))
    else:
        cache_path = FilePath(join(settings.MESSAGE_CACHE, ref) + ".json")
        url = f"{settings.CONNECTOR_URL}/download/message/{ref}"
        await download_file(url, cache_path)

    with open(cache_path, "r") as cache_file:
        msg = json.load(cache_file)
        # TODO: Define VM Function type instead of wrapping in 'content' key
        msg_content = msg["content"]
        return FunctionMessage(**msg_content)


async def get_code_path(ref) -> FilePath:
    if settings.FAKE_DATA:
        return FilePath(os.path.abspath(join(__file__,
            '../examples/example_fastapi_2.zip')))

    cache_path = FilePath(join(settings.CODE_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/code/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_data_path(ref) -> FilePath:
    if settings.FAKE_DATA:
        return FilePath(os.path.abspath(join(__file__,
            '../examples/example_fastapi_2.zip')))

    cache_path = FilePath(join(settings.DATA_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_runtime_path(ref) -> FilePath:
    if settings.FAKE_DATA
        return FilePath(os.path.abspath(join(__file__,
            '../runtimes/aleph-alpine-3.13-python/rootfs.ext4')))

    cache_path = FilePath(join(settings.RUNTIME_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/runtime/{ref}"
    await download_file(url, cache_path)
    return cache_path
