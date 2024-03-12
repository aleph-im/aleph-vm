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
import subprocess
import sys
from os.path import isfile, join
from pathlib import Path
from shutil import make_archive
from typing import Union

import aiohttp
from aleph_message.models import (
    ExecutableMessage,
    InstanceMessage,
    MessageType,
    ProgramMessage,
)
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.program import Encoding
from aleph_message.models.execution.volume import (
    ImmutableVolume,
    MachineVolume,
    PersistentVolume,
    VolumePersistence,
)

from .conf import settings

logger = logging.getLogger(__name__)

DEVICE_MAPPER_DIRECTORY = "/dev/mapper"


async def download_file(url: str, local_path: Path) -> None:
    # TODO: Limit max size of download to the message specification
    if isfile(local_path):
        logger.debug(f"File already exists: {local_path}")
        return

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
            return ProgramMessage.parse_obj(msg)
        return InstanceMessage.parse_obj(msg)


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


async def create_volume_file(
    volume: Union[PersistentVolume, RootfsVolume], namespace: str
) -> Path:
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    path = Path(settings.PERSISTENT_VOLUMES_DIR) / namespace / f"{volume_name}.ext4"
    if not path.is_file():
        logger.debug(f"Creating {volume.size_mib}MB volume")
        os.system(f"dd if=/dev/zero of={path} bs=1M count={volume.size_mib}")
        if settings.USE_JAILER:
            os.system(f"chown jailman:jailman {path}")
    return path


async def create_loopback_device(path: Path, read_only: bool = False) -> str:
    command_args = ["losetup", "--find", "--show"]
    if read_only:
        command_args.append("--read-only")
    command_args.append(str(path))
    loop_device = subprocess.run(
        command_args, check=True, capture_output=True, encoding="UTF-8"
    ).stdout.strip()
    return loop_device


def get_block_size(device_path: Path) -> str:
    block_size = subprocess.run(
        ["blockdev", "--getsz", device_path],
        check=True,
        capture_output=True,
        encoding="UTF-8",
    ).stdout.strip()
    return block_size


def create_mapped_device(device_name: str, table_command: str) -> None:
    subprocess.run(
        f"dmsetup create {device_name}",
        input=table_command,
        text=True,
        shell=True,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def e2fs_check_and_resize(device_path: Path) -> None:
    os.system(f"e2fsck -fy {device_path}")
    os.system(f"resize2fs {device_path}")


async def create_devmapper(
    volume: Union[PersistentVolume, RootfsVolume], namespace: str
) -> Path:
    """It creates a /dev/mapper/DEVICE inside the VM, that is an extended mapped device of the volume specified.
    We follow the steps described here: https://community.aleph.im/t/deploying-mutable-vm-instances-on-aleph/56/2"""
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    mapped_volume_name = f"{namespace}_{volume_name}"
    path_mapped_volume_name = Path(DEVICE_MAPPER_DIRECTORY) / mapped_volume_name

    if path_mapped_volume_name.is_block_device():
        return path_mapped_volume_name

    volume_path = await create_volume_file(volume, namespace)
    parent_path = await get_runtime_path(volume.parent.ref)

    base_loop_device = await create_loopback_device(parent_path, read_only=True)
    base_block_size = get_block_size(parent_path)
    extended_loop_device = await create_loopback_device(volume_path)
    extended_block_size = get_block_size(volume_path)

    base_table_command = f"0 {base_block_size} linear {base_loop_device} 0\n{base_block_size} {extended_block_size} zero"
    base_volume_name = volume.parent.ref
    path_base_device_name = Path(DEVICE_MAPPER_DIRECTORY) / base_volume_name
    if not path_base_device_name.is_block_device():
        create_mapped_device(base_volume_name, base_table_command)

    snapshot_table_command = f"0 {extended_block_size} snapshot {path_base_device_name} {extended_loop_device} P 8"
    create_mapped_device(mapped_volume_name, snapshot_table_command)

    e2fs_check_and_resize(path_mapped_volume_name)
    if settings.USE_JAILER:
        os.system(f"chown jailman:jailman {path_base_device_name}")
        os.system(f"chown jailman:jailman {path_mapped_volume_name}")
    return path_mapped_volume_name


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
    elif isinstance(volume, PersistentVolume) or isinstance(volume, RootfsVolume):
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
