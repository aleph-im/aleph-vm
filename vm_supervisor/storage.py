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
import subprocess
from os.path import isfile, join
from pathlib import Path
from shutil import make_archive

import aiohttp
from aleph_message.models import ExecutableMessage, InstanceMessage, ProgramMessage, MessageType
from aleph_message.models.execution.volume import (
    MachineVolume,
    ImmutableVolume,
    PersistentVolume,
    VolumePersistence,
)
from aleph_message.models.execution.program import Encoding
from aleph_message.models.execution.instance import RootfsVolume

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


async def get_message(ref: str) -> ExecutableMessage:
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
        if msg["type"] == MessageType.program:
            return ProgramMessage(**msg)
        return InstanceMessage(**msg)


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
    if settings.USE_JAILER:
        os.system(f"chown jailman:jailman {cache_path}")
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


async def create_devmapper(volume: PersistentVolume | RootfsVolume, namespace: str) -> Path:
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    volume_dev_name = f"{namespace}_{volume_name}"
    path_volume_dev_name = Path(f"/dev/mapper/{volume_dev_name}")
    if path_volume_dev_name.is_block_device():
        return path_volume_dev_name
    path = Path(
        join(settings.PERSISTENT_VOLUMES_DIR, namespace, f"{volume_name}.ext4")
    )
    if not os.path.isfile(path):
        logger.debug(f"Creating {volume.size_mib}MB volume")
        os.system(f"dd if=/dev/zero of={path} bs=1M count={volume.size_mib}")
        if settings.USE_JAILER:
            os.system(f"chown jailman:jailman {path}")
    try:
        parent_path = await get_runtime_path(volume.parent.ref)
        loop_base = subprocess.run(
            ["losetup", "--find", "--show", "--read-only", parent_path],
            check=True,
            capture_output=True,
            encoding="UTF-8").stdout.strip()
        root_size = subprocess.run(
            ["blockdev", "--getsz", parent_path],
            check=True,
            capture_output=True,
            encoding="UTF-8").stdout.strip()
        volume_data_size = subprocess.run(
            ["blockdev", "--getsz", path],
            check=True,
            capture_output=True,
            encoding="UTF-8").stdout.strip()
        loop_user_data = subprocess.run(
            ["losetup", "--find", "--show", path],
            check=True,
            capture_output=True,
            encoding="UTF-8").stdout.strip()
        table_command = f"0 {root_size} linear {loop_base} 0\n{root_size} {volume_data_size} zero"
        base_dev_name = f"{namespace}_{volume_name}_base"
        os.system(f" printf \"{table_command}\" | dmsetup create {base_dev_name}")
        path_base_dev_name = f"/dev/mapper/{base_dev_name}"
        table_command = f"0 {volume_data_size} snapshot {path_base_dev_name} {loop_user_data} P 8"
        os.system(f" printf \"{table_command}\" | dmsetup create {volume_dev_name}")
        os.system(f"e2fsck -fy {path_volume_dev_name.__str__()}")
        os.system(f"resize2fs {path_volume_dev_name.__str__()}")
        if settings.USE_JAILER:
            os.system(f"chown jailman:jailman {path_base_dev_name}")
            os.system(f"chown jailman:jailman {path_volume_dev_name}")
        return path_volume_dev_name
    except Exception:
        raise


async def get_existing_file(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_VOLUME:
        return Path(settings.FAKE_DATA_VOLUME)

    cache_path = Path(join(settings.DATA_CACHE, ref))
    url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
    await download_file(url, cache_path)
    if settings.USE_JAILER:
        os.system(f"chown jailman:jailman {cache_path}")
    return cache_path


async def get_volume_path(volume: MachineVolume, namespace: str) -> Path:
    if isinstance(volume, ImmutableVolume):
        ref = volume.ref
        return await get_existing_file(ref)
    elif isinstance(volume, PersistentVolume) | isinstance(volume, RootfsVolume):
        volume_name = volume.name if isinstance(volume, RootfsVolume) else "rootfs"
        if volume.persistence != VolumePersistence.host:
            raise NotImplementedError("Only 'host' persistence is supported")
        if not re.match(r"^[\w\-_/]+$", volume_name):
            raise ValueError(f"Invalid value for volume name: {volume_name}")
        os.makedirs(join(settings.PERSISTENT_VOLUMES_DIR, namespace), exist_ok=True)
        if volume.parent:
            device_path = await asyncio.get_event_loop().run_in_executor(
                None, create_devmapper, volume, namespace
            )
            return device_path
        else:
            volume_path = Path(
                join(settings.PERSISTENT_VOLUMES_DIR, namespace, f"{volume_name}.ext4")
            )
            await asyncio.get_event_loop().run_in_executor(
                None, create_ext4, volume_path, volume.size_mib
            )
            return volume_path
    else:
        raise NotImplementedError("Only immutable volumes are supported")
