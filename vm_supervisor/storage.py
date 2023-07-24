"""
This module is in charge of providing the source code corresponding to a 'code id'.

In this prototype, it returns a hardcoded example.
In the future, it should connect to an Aleph node and retrieve the code from there.
"""
import json
import logging
import re
import sys
from datetime import datetime
from pathlib import Path
from shutil import copy2, disk_usage, make_archive
from typing import Union

import aiohttp
from aleph_message.models import (
    InstanceMessage,
    ItemHash,
    ProgramMessage,
    parse_message,
)
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.program import Encoding
from aleph_message.models.execution.volume import (
    ImmutableVolume,
    MachineVolume,
    PersistentVolume,
    VolumePersistence,
)

from .conf import SnapshotCompressionAlgorithm, settings
from .utils import fix_message_validation, run_in_subprocess

logger = logging.getLogger(__name__)

DEVICE_MAPPER_DIRECTORY = "/dev/mapper"


class NotEnoughDiskSpace(Exception):
    pass


async def chown_to_jailman(path: Path) -> None:
    """Changes ownership of the target when running firecracker inside jailer isolation."""
    if not path.exists():
        raise FileNotFoundError("No such file to change ownership from", path)
    if settings.USE_JAILER:
        await run_in_subprocess(["chown", "jailman:jailman", str(path)])


async def download_file(url: str, local_path: Path) -> None:
    # TODO: Limit max size of download to the message specification
    if local_path.is_file():
        logger.debug(f"File already exists: {local_path}")
        return

    tmp_path = Path(f"{local_path}.part")
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

            sys.stdout.write("\n")
            sys.stdout.flush()

            tmp_path.rename(local_path)
            logger.debug(f"Download complete, moved {tmp_path} -> {local_path}")
        except Exception:
            # Ensure no partial file is left
            tmp_path.unlink(missing_ok=True)
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


async def get_message(ref: str) -> Union[ProgramMessage, InstanceMessage]:
    if ref == settings.FAKE_INSTANCE_ID:
        logger.debug("Using the fake instance message since the ref matches")
        cache_path = settings.FAKE_INSTANCE_MESSAGE
    elif settings.FAKE_DATA_PROGRAM:
        cache_path = settings.FAKE_DATA_MESSAGE
    else:
        cache_path = (Path(settings.MESSAGE_CACHE) / ref).with_suffix(".json")
        url = f"{settings.CONNECTOR_URL}/download/message/{ref}"
        await download_file(url, cache_path)

    with open(cache_path, "r") as cache_file:
        msg = json.load(cache_file)

        if cache_path in (settings.FAKE_DATA_MESSAGE, settings.FAKE_INSTANCE_MESSAGE):
            # Ensure validation passes while tweaking message content
            msg = fix_message_validation(msg)

        result = parse_message(message_dict=msg)
        assert isinstance(result, ProgramMessage) or isinstance(
            result, InstanceMessage
        ), "Parsed message is not executable"
        return result


async def get_code_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM:
        archive_path = Path(settings.FAKE_DATA_PROGRAM)

        encoding: Encoding = (
            await get_message(ref="fake-message")
        ).content.code.encoding
        if encoding == Encoding.squashfs:
            squashfs_path = Path(archive_path.name + ".squashfs")
            squashfs_path.unlink(missing_ok=True)
            await run_in_subprocess(
                ["mksquashfs", str(archive_path), str(squashfs_path)]
            )
            logger.debug(f"Squashfs generated on {squashfs_path}")
            return squashfs_path
        elif encoding == Encoding.zip:
            make_archive(str(archive_path), "zip", root_dir=archive_path)
            zip_path = Path(f"{archive_path}.zip")
            logger.debug(f"Zip generated on {zip_path}")
            return zip_path
        else:
            raise ValueError(f"Unsupported encoding: {encoding}")

    cache_path = Path(settings.CODE_CACHE) / ref
    url = f"{settings.CONNECTOR_URL}/download/code/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_data_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_DATA:
        data_dir = settings.FAKE_DATA_DATA
        make_archive(str(data_dir), "zip", data_dir)
        return Path(f"{data_dir}.zip")

    cache_path = Path(settings.DATA_CACHE) / ref
    url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
    await download_file(url, cache_path)
    return cache_path


async def get_runtime_path(ref: str) -> Path:
    """Obtain the runtime used for the rootfs of a program."""
    if settings.FAKE_DATA_PROGRAM:
        return Path(settings.FAKE_DATA_RUNTIME)

    cache_path = Path(settings.RUNTIME_CACHE) / ref
    url = f"{settings.CONNECTOR_URL}/download/runtime/{ref}"
    await download_file(url, cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def get_rootfs_base_path(ref: ItemHash) -> Path:
    """Obtain the base partition for the rootfs of an instance."""
    if settings.USE_FAKE_INSTANCE_BASE and settings.FAKE_INSTANCE_BASE:
        logger.debug("Using fake instance base")
        return Path(settings.FAKE_INSTANCE_BASE)

    cache_path = Path(settings.RUNTIME_CACHE) / ref
    url = f"{settings.CONNECTOR_URL}/download/runtime/{ref}"
    await download_file(url, cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def create_ext4(path: Path, size_mib: int) -> bool:
    if path.is_file():
        logger.debug(f"File already exists, skipping ext4 creation on {path}")
        return False
    tmp_path = f"{path}.tmp"
    await run_in_subprocess(
        ["dd", "if=/dev/zero", f"of={tmp_path}", "bs=1M", f"count={size_mib}"]
    )
    await run_in_subprocess(["mkfs.ext4", tmp_path])
    await chown_to_jailman(Path(tmp_path))
    Path(tmp_path).rename(path)
    return True


async def create_volume_file(
    volume: Union[PersistentVolume, RootfsVolume], namespace: str
) -> Path:
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    # Assume that the main filesystem format is BTRFS
    path = settings.PERSISTENT_VOLUMES_DIR / namespace / f"{volume_name}.btrfs"
    if not path.is_file():
        logger.debug(f"Creating {volume.size_mib}MB volume")
        # Ensure that the parent directory exists
        path.parent.mkdir(exist_ok=True)
        # Create an empty file the right size
        await run_in_subprocess(
            ["dd", "if=/dev/zero", f"of={path}", "bs=1M", f"count={volume.size_mib}"]
        )
        await chown_to_jailman(path)
    return path


async def create_loopback_device(path: Path, read_only: bool = False) -> str:
    command_args = ["losetup", "--find", "--show"]
    if read_only:
        command_args.append("--read-only")
    command_args.append(str(path))
    stdout = await run_in_subprocess(command_args)
    loop_device = stdout.strip().decode()
    return loop_device


async def get_block_size(device_path: Path) -> int:
    command = ["blockdev", "--getsz", str(device_path)]
    stdout = await run_in_subprocess(command)
    block_size = int(stdout.decode("UTF-8").strip())
    return block_size


async def create_mapped_device(device_name: str, table_command: str) -> None:
    command = ["dmsetup", "create", device_name]
    await run_in_subprocess(command, stdin_input=table_command.encode())


async def resize_and_tune_file_system(device_path: Path, mount_path: Path) -> None:
    # This tune is needed to assign a random fsid to BTRFS device to be able to mount it
    await run_in_subprocess(["btrfstune", "-m", str(device_path)])
    await run_in_subprocess(["mount", str(device_path), str(mount_path)])
    await run_in_subprocess(["btrfs", "filesystem", "resize", "max", str(mount_path)])
    await run_in_subprocess(["umount", str(mount_path)])


async def create_devmapper(
    volume: Union[PersistentVolume, RootfsVolume], namespace: str
) -> Path:
    """It creates a /dev/mapper/DEVICE inside the VM, that is an extended mapped device of the volume specified.
    We follow the steps described here: https://community.aleph.im/t/deploying-mutable-vm-instances-on-aleph/56/2
    """
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    mapped_volume_name = f"{namespace}_{volume_name}"
    path_mapped_volume_name = Path(DEVICE_MAPPER_DIRECTORY) / mapped_volume_name

    # Check if rootfs volume is created
    if path_mapped_volume_name.is_block_device():
        return path_mapped_volume_name

    parent_path = await get_rootfs_base_path(volume.parent.ref)

    image_volume_name = volume.parent.ref
    image_block_size: int = await get_block_size(parent_path)
    path_image_device_name = Path(DEVICE_MAPPER_DIRECTORY) / image_volume_name
    # Checks if parent rootfs image block device is created
    if not path_image_device_name.is_block_device():
        image_loop_device = await create_loopback_device(parent_path, read_only=True)

        # Creates the parent rootfs image block device with the entire image size
        base_table_command = f"0 {image_block_size} linear {image_loop_device} 0"
        await create_mapped_device(image_volume_name, base_table_command)

    volume_path = await create_volume_file(volume, namespace)
    extended_block_size: int = await get_block_size(volume_path)

    mapped_volume_name_base = f"{namespace}_base"
    path_mapped_volume_name_base = (
        Path(DEVICE_MAPPER_DIRECTORY) / mapped_volume_name_base
    )
    if not path_mapped_volume_name_base.is_block_device():
        # Creates the base rootfs block device with the entire rootfs size using the image block device as source
        base_table_command = (
            f"0 {image_block_size} linear {path_image_device_name} 0\n"
            f"{image_block_size} {extended_block_size} zero "
        )
        await create_mapped_device(mapped_volume_name_base, base_table_command)

    extended_loop_device = await create_loopback_device(volume_path)

    # Creates the final rootfs block device that is a snapshot of the base block device
    snapshot_table_command = f"0 {extended_block_size} snapshot {path_mapped_volume_name_base} {extended_loop_device} P 8"
    await create_mapped_device(mapped_volume_name, snapshot_table_command)

    mount_path = Path(f"/mnt/{mapped_volume_name}")
    mount_path.mkdir(parents=True, exist_ok=True)
    await resize_and_tune_file_system(path_mapped_volume_name, mount_path)
    await chown_to_jailman(path_image_device_name)
    await chown_to_jailman(path_mapped_volume_name_base)
    await chown_to_jailman(path_mapped_volume_name)
    return path_mapped_volume_name


async def get_existing_file(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_VOLUME:
        return Path(settings.FAKE_DATA_VOLUME)

    cache_path = Path(settings.DATA_CACHE) / ref
    url = f"{settings.CONNECTOR_URL}/download/data/{ref}"
    await download_file(url, cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def get_volume_path(volume: MachineVolume, namespace: str) -> Path:
    if isinstance(volume, ImmutableVolume):
        ref = volume.ref
        return await get_existing_file(ref)
    elif isinstance(volume, PersistentVolume) or isinstance(volume, RootfsVolume):
        volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
        if volume.persistence != VolumePersistence.host:
            raise NotImplementedError("Only 'host' persistence is supported")
        if not re.match(r"^[\w\-_/]+$", volume_name):
            raise ValueError(f"Invalid value for volume name: {volume_name}")
        (Path(settings.PERSISTENT_VOLUMES_DIR) / namespace).mkdir(exist_ok=True)
        if volume.parent:
            return await create_devmapper(volume, namespace)
        else:
            volume_path = (
                Path(settings.PERSISTENT_VOLUMES_DIR)
                / namespace
                / f"{volume_name}.ext4"
            )
            await create_ext4(volume_path, volume.size_mib)
            return volume_path
    else:
        raise NotImplementedError("Only immutable volumes are supported")


async def create_volume_snapshot(path: Path) -> Path:
    new_path = Path(f"{path}.{datetime.today().strftime('%d%m%Y-%H%M%S')}.bak")
    copy2(path, new_path)
    return new_path


async def compress_volume_snapshot(
    path: Path,
    algorithm: SnapshotCompressionAlgorithm = SnapshotCompressionAlgorithm.gz,
) -> Path:
    if algorithm != SnapshotCompressionAlgorithm.gz:
        raise NotImplementedError

    new_path = Path(f"{path}.gz")

    await run_in_subprocess(
        [
            "gzip",
            str(path),
        ]
    )

    return new_path


def check_disk_space(bytes_to_use: int) -> bool:
    host_disk_usage = disk_usage("/")
    return host_disk_usage.free >= bytes_to_use
