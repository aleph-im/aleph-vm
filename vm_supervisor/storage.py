"""
This module is in charge of providing the source code corresponding to a 'code id'.

In this prototype, it returns a hardcoded example.
In the future, it should connect to an Aleph node and retrieve the code from there.
"""
import asyncio
import hashlib
import json
import logging
import os
import re
import sys
from os.path import isfile, join
from pathlib import Path
from shutil import make_archive

import aiohttp
from aleph_message.models import ProgramMessage
from aleph_message.models.program import (
    Encoding,
    ImmutableVolume,
    MachineVolume,
    PersistentVolume,
    VolumePersistence,
)

from .conf import settings

logger = logging.getLogger(__name__)


async def download_file(url: str, local_path: Path) -> None:
    # TODO: Limit max size of download to the message specification
    if isfile(local_path):
        logger.debug(f"File already exists: {local_path}")
    else:
        tmp_path = f"{local_path}.part"
        logger.debug(f"Downloading {url} -> {tmp_path}")
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url)
            resp.raise_for_status()
            try:
                with open(tmp_path, "wb") as cache_file:
                    counter = 0
                    while True:
                        chunk = await resp.content.read(65536)
                        if not chunk:
                            break
                        cache_file.write(chunk)
                        counter += 1
                        if not (counter % 20):
                            sys.stdout.write(".")
                            sys.stdout.flush()

                os.rename(tmp_path, local_path)
                logger.debug(f"Download complete, moved {tmp_path} -> {local_path}")
            except Exception:
                # Ensure no partial file is left
                try:
                    os.remove(tmp_path)
                except FileNotFoundError:
                    pass
                raise


async def get_latest_amend(item_hash: str) -> str:
    if settings.FAKE_DATA_PROGRAM:
        return item_hash
    else:
        url = f"{settings.CONNECTOR_URL}/compute/latest_amend/{item_hash}"
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url)
            resp.raise_for_status()
            result: str = await resp.json()
            assert isinstance(result, str)
            return result or item_hash


async def get_message(ref: str) -> ProgramMessage:
    if settings.FAKE_DATA_PROGRAM:
        cache_path = settings.FAKE_DATA_MESSAGE
    else:
        cache_path = Path(join(settings.MESSAGE_CACHE, ref) + ".json")
        url = f"{settings.CONNECTOR_URL}/download/message/{ref}"
        await download_file(url, cache_path)

    with open(cache_path, "r") as cache_file:
        msg = json.load(cache_file)
        if settings.FAKE_DATA_PROGRAM:
            msg["item_content"] = json.dumps(msg["content"])
            msg["item_hash"] = hashlib.sha256(
                msg["item_content"].encode("utf-8")
            ).hexdigest()
        return ProgramMessage(**msg)


async def get_code_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM:
        archive_path = settings.FAKE_DATA_PROGRAM

        encoding: Encoding = (
            await get_message(ref="fake-message")
        ).content.code.encoding
        if encoding == Encoding.squashfs:
            if os.path.exists(f"{archive_path}.squashfs"):
                os.remove(f"{archive_path}.squashfs")
            os.system(f"mksquashfs {archive_path} {archive_path}.squashfs")
            logger.debug(f"Squashfs generated on {archive_path}.squashfs")
            return Path(f"{archive_path}.squashfs")
        elif encoding == Encoding.zip:
            make_archive(str(archive_path), "zip", root_dir=archive_path)
            logger.debug(f"Zip generated on {archive_path}.zip")
            return Path(f"{archive_path}.zip")
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    cache_path = Path(join(settings.CODE_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/code/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_data_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_DATA:
        data_dir = settings.FAKE_DATA_DATA
        make_archive(str(data_dir), "zip", data_dir)
        return Path(f"{data_dir}.zip")

    cache_path = Path(join(settings.DATA_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_runtime_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM:
        return Path(settings.FAKE_DATA_RUNTIME)

    cache_path = Path(join(settings.RUNTIME_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/runtime/{ref}"
    await download_file(url, cache_path)
    return cache_path


def create_ext4(path: Path, size_mib: int) -> bool:
    if os.path.isfile(path):
        return False
    tmp_path = f"{path}.tmp"
    os.system(f"dd if=/dev/zero of={tmp_path} bs=1M count={size_mib}")
    os.system(f"mkfs.ext4 {tmp_path}")
    if settings.USE_JAILER:
        os.system(f"chown jailman:jailman {tmp_path}")
    os.rename(tmp_path, path)
    return True


async def get_volume_path(volume: MachineVolume, namespace: str) -> Path:
    if isinstance(volume, ImmutableVolume):
        ref = volume.ref
        if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_VOLUME:
            return Path(settings.FAKE_DATA_VOLUME)

        cache_path = Path(join(settings.DATA_CACHE, ref))
        url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
        await download_file(url, cache_path)
        return cache_path
    elif isinstance(volume, PersistentVolume):
        if volume.persistence != VolumePersistence.host:
            raise NotImplementedError("Only 'host' persistence is supported")
        if not re.match(r"^[\w\-_/]+$", volume.name):
            raise ValueError(f"Invalid value for volume name: {volume.name}")
        os.makedirs(join(settings.PERSISTENT_VOLUMES_DIR, namespace), exist_ok=True)
        volume_path = Path(
            join(settings.PERSISTENT_VOLUMES_DIR, namespace, f"{volume.name}.ext4")
        )
        await asyncio.get_event_loop().run_in_executor(
            None, create_ext4, volume_path, volume.size_mib
        )
        return volume_path
    else:
        raise NotImplementedError("Only immutable volumes are supported")
