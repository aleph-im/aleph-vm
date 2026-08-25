"""
This module is in charge of providing the source code corresponding to a 'code id'.

In this prototype, it returns a hardcoded example.
In the future, it should connect to an Aleph node and retrieve the code from there.
"""

import asyncio
import json
import logging
import re
import sys
from pathlib import Path
from shutil import make_archive
from subprocess import CalledProcessError

import aiohttp
from aleph_message.models import (
    InstanceMessage,
    ItemHash,
    ProgramMessage,
    VerifiableProgramMessage,
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

from aleph.vm.conf import settings
from aleph.vm.storage_pools import find_existing_volume, volume_path_for
from aleph.vm.utils import fix_message_validation, run_in_subprocess

logger = logging.getLogger(__name__)
DEVICE_MAPPER_DIRECTORY = "/dev/mapper"
# Where create_devmapper mounts a volume to resize its filesystem.
MOUNT_ROOT = Path("/mnt")
# What may be composed into a dmsetup device name. create_devmapper builds
# names out of a VM hash and a volume name straight from the message, so a
# name outside this set is one dmsetup would have refused to create.
DEVICE_NAME_PATTERN = re.compile(r"^[\w\-]+$")

# Runtimes and base images can be several hundred MiB and are sometimes served by slow
# gateways (e.g. IPFS). We must not cap the *total* transfer time, or large-but-steady
# downloads get killed mid-stream; instead guard against genuine stalls with sock timeouts.
DOWNLOAD_SOCKET_CONNECT_TIMEOUT_SECONDS = 30
DOWNLOAD_SOCKET_READ_TIMEOUT_SECONDS = 120


class CorruptedFilesystemError(Exception):
    """Raised when a file containing a filesystem is corrupted."""


async def chown_to_jailman(path: Path) -> None:
    """Changes ownership of the target when running firecracker inside jailer isolation."""
    if not path.exists():
        msg = "No such file to change ownership from"
        raise FileNotFoundError(msg, path)
    if settings.USE_JAILER:
        await run_in_subprocess(["chown", "jailman:jailman", str(path)])


async def file_downloaded_by_another_task(final_path: Path) -> None:
    """Wait for a file to be downloaded by another task in parallel."""
    part_path = Path(f"{final_path}.part")
    while not final_path.is_file():
        # If the .part file is gone and the final file still doesn't
        # exist, the other task failed — stop waiting so we can retry.
        if not part_path.exists():
            return
        await asyncio.sleep(0.1)


async def download_file_in_chunks(url: str, tmp_path: Path) -> None:
    # No total timeout: a 500+ MiB image over a slow gateway is a legitimate multi-minute
    # download. sock_read makes the request fail fast only if the transfer truly stalls.
    timeout = aiohttp.ClientTimeout(
        total=None,
        sock_connect=DOWNLOAD_SOCKET_CONNECT_TIMEOUT_SECONDS,
        sock_read=DOWNLOAD_SOCKET_READ_TIMEOUT_SECONDS,
    )
    async with aiohttp.ClientSession(timeout=timeout) as session:
        resp = await session.get(url)
        resp.raise_for_status()

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


async def download_file(url: str, local_path: Path) -> None:
    # TODO: Limit max size of download to the message specification
    if local_path.is_file():
        logger.debug(f"File already exists: {local_path}")
        return

    # Avoid partial downloads and incomplete files by only moving the file when it's complete.
    tmp_path = Path(f"{local_path}.part")

    logger.debug(f"Downloading {url} -> {tmp_path}")
    download_attempts = 10
    for attempt in range(download_attempts):
        logger.debug(f"Download attempt {attempt + 1}/{download_attempts}...")
        owns_tmp = False
        try:
            # Ensure the file is not being downloaded by another task in parallel.
            tmp_path.touch(exist_ok=False)
            owns_tmp = True

            await download_file_in_chunks(url, tmp_path)
            tmp_path.rename(local_path)
            logger.debug(f"Download complete, moved {tmp_path} -> {local_path}")
            return
        except FileExistsError as file_exists_error:
            # Another task is already downloading the file.
            logger.debug(f"File already being downloaded by another task: {local_path}")
            try:
                await asyncio.wait_for(file_downloaded_by_another_task(local_path), timeout=30)
                if local_path.is_file():
                    return
            except TimeoutError as error:
                if attempt < (download_attempts - 1):
                    logger.warning(
                        f"Download failed (waiting for another task), retrying attempt {attempt + 1}/{download_attempts}..."
                    )
                    continue
                else:
                    logger.warning(f"Download of {url} failed (waiting for another task), aborting...")
                    raise error from file_exists_error
        except (
            aiohttp.ClientConnectionError,
            aiohttp.ClientResponseError,
            aiohttp.ClientPayloadError,
            # A stalled transfer raises asyncio.TimeoutError (sock_read); retry it too.
            asyncio.TimeoutError,
        ) as error:
            if attempt < (download_attempts - 1):
                logger.warning(f"Download failed, retrying attempt {attempt + 1}/{download_attempts}...")
            else:
                logger.warning(f"Download of {url} failed, aborting...")
                raise error
        finally:
            # Only clean up the .part file if this task created it
            if owns_tmp:
                tmp_path.unlink(missing_ok=True)


async def _fetch_aleph_message(ref: str) -> dict | None:
    """Fetch a message from the Aleph API by item_hash."""
    url = f"{settings.API_SERVER}/api/v0/messages.json?hashes={ref}"
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        resp.raise_for_status()
        data = await resp.json()
        messages = data.get("messages", [])
        return messages[0] if messages else None


async def _get_content_url(ref: str) -> str:
    """Resolve a STORE message ref to its raw content download URL."""
    msg = await _fetch_aleph_message(ref)
    if not msg:
        raise FileNotFoundError(f"Aleph message not found: {ref}")
    content = msg.get("content")
    if not content or "item_hash" not in content:
        raise ValueError(f"Malformed Aleph message {ref}: missing content.item_hash")
    data_hash = content["item_hash"]
    if content.get("item_type") == "ipfs":
        return f"{settings.IPFS_GATEWAY}/{data_hash}"
    return f"{settings.API_SERVER}/api/v0/storage/raw/{data_hash}"


async def get_latest_amend(item_hash: str) -> str:
    if settings.FAKE_DATA_PROGRAM:
        return item_hash

    msg = await _fetch_aleph_message(item_hash)
    if not msg:
        return item_hash
    # Match amends by owner (`content.address`), not signer (`sender`), so
    # delegated publishers (sender ≠ content.address, authorised via the
    # owner's security aggregate) can still update the original.
    owner = msg["content"]["address"]
    url = f"{settings.API_SERVER}/api/v0/messages.json?msgType=STORE&sort_order=-1&refs={item_hash}&owners={owner}"
    async with aiohttp.ClientSession() as session:
        resp = await session.get(url)
        resp.raise_for_status()
        data = await resp.json()
        messages = data.get("messages", [])
        if messages:
            latest = messages[0]
            latest_content = latest.get("content", {})
            if latest_content.get("address") == owner and latest_content.get("ref") == item_hash:
                return latest["item_hash"]
    return item_hash


async def get_message(ref: str) -> ProgramMessage | InstanceMessage | VerifiableProgramMessage:
    if ref == settings.FAKE_INSTANCE_ID:
        logger.debug("Using the fake instance message since the ref matches")
        cache_path = settings.FAKE_INSTANCE_MESSAGE
    elif settings.FAKE_DATA_PROGRAM:
        cache_path = settings.FAKE_DATA_MESSAGE
        logger.debug("Using the fake data message")
    else:
        cache_path = (Path(settings.MESSAGE_CACHE) / ref).with_suffix(".json")
        if not cache_path.is_file():
            msg_data = await _fetch_aleph_message(ref)
            if not msg_data:
                raise FileNotFoundError(f"Aleph message not found: {ref}")
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = cache_path.with_suffix(".json.tmp")
            tmp_path.write_text(json.dumps(msg_data))
            tmp_path.rename(cache_path)

    with open(cache_path) as cache_file:
        msg = json.load(cache_file)

        if cache_path in (settings.FAKE_DATA_MESSAGE, settings.FAKE_INSTANCE_MESSAGE):
            # Ensure validation passes while tweaking message content
            msg = fix_message_validation(msg)

        result = parse_message(message_dict=msg)
        assert isinstance(
            result, InstanceMessage | ProgramMessage | VerifiableProgramMessage
        ), "Parsed message is not executable"
        return result


async def get_code_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM:
        archive_path = Path(settings.FAKE_DATA_PROGRAM)

        fake_message = await get_message(ref="fake-message")
        assert isinstance(fake_message, ProgramMessage), "The fake data message must be a program"
        encoding: Encoding = fake_message.content.code.encoding
        if encoding == Encoding.squashfs:
            squashfs_path = Path(archive_path.name + ".squashfs")
            squashfs_path.unlink(missing_ok=True)
            await run_in_subprocess(["mksquashfs", str(archive_path), str(squashfs_path)])
            logger.debug(f"Squashfs generated on {squashfs_path}")
            return squashfs_path
        elif encoding == Encoding.zip:
            make_archive(str(archive_path), "zip", root_dir=archive_path)
            zip_path = Path(f"{archive_path}.zip")
            logger.debug(f"Zip generated on {zip_path}")
            return zip_path
        else:
            msg = f"Unsupported encoding: {encoding}"
            raise ValueError(msg)

    cache_path = Path(settings.CODE_CACHE) / ref
    url = await _get_content_url(ref)
    await download_file(url, cache_path)
    return cache_path


async def get_data_path(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_DATA:
        data_dir = settings.FAKE_DATA_DATA
        make_archive(str(data_dir), "zip", data_dir)
        return Path(f"{data_dir}.zip")

    cache_path = Path(settings.DATA_CACHE) / ref
    url = await _get_content_url(ref)
    await download_file(url, cache_path)
    return cache_path


async def check_squashfs_integrity(path: Path) -> None:
    """Check that the squashfs file is not corrupted."""
    try:
        await run_in_subprocess(["unsquashfs", "-stat", "-no-progress", str(path)], check=True)
    except CalledProcessError as error:
        msg = f"Corrupted squashfs file: {path}"
        raise CorruptedFilesystemError(msg) from error


async def get_runtime_path(ref: str) -> Path:
    """Obtain the runtime used for the rootfs of a program."""
    if settings.FAKE_DATA_PROGRAM:
        await check_squashfs_integrity(Path(settings.FAKE_DATA_RUNTIME))
        return Path(settings.FAKE_DATA_RUNTIME)

    cache_path = Path(settings.RUNTIME_CACHE) / ref

    if not cache_path.is_file():
        url = await _get_content_url(ref)
        await download_file(url, cache_path)

    await check_squashfs_integrity(cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def get_rootfs_base_path(ref: ItemHash) -> Path:
    """Obtain the base partition for the rootfs of an instance."""
    if settings.USE_FAKE_INSTANCE_BASE and settings.FAKE_INSTANCE_BASE:
        logger.debug("Using fake instance base")
        return Path(settings.FAKE_INSTANCE_BASE)

    cache_path = Path(settings.RUNTIME_CACHE) / ref
    if not cache_path.is_file():
        url = await _get_content_url(ref)
        await download_file(url, cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def create_ext4(path: Path, size_mib: int) -> bool:
    if path.is_file():
        logger.debug(f"File already exists, skipping ext4 creation on {path}")
        return False
    tmp_path = f"{path}.tmp"
    await run_in_subprocess(["fallocate", "-l", f"{size_mib}M", str(tmp_path)])
    await run_in_subprocess(["mkfs.ext4", tmp_path])
    await chown_to_jailman(Path(tmp_path))
    Path(tmp_path).rename(path)
    return True


async def create_volume_file(
    volume: PersistentVolume | RootfsVolume, namespace: str, *, pool0_only: bool = False
) -> Path:
    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"
    # Assume that the main filesystem format is BTRFS
    # Off the loop: placement reads every pool's free space and can call the
    # reclaimer's evictor (storage_pools.set_room_maker), which walks pools and
    # removes directories.
    path = await asyncio.to_thread(
        volume_path_for, namespace, f"{volume_name}.btrfs", volume.size_mib, pool0_only=pool0_only
    )
    if not path.is_file():
        logger.debug(f"Creating {volume.size_mib}MB volume")
        # Create an empty file the right size
        await run_in_subprocess(["fallocate", "-l", f"{volume.size_mib}M", str(path)])
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


_BTRFS_CORRUPTION_MARKERS = ("open ctree failed", "parent transid verify failed")


async def _tune_with_recovery(device_path: Path) -> None:
    """Assign a random fsid and, on log-tree corruption, self-heal.

    Unclean stops of a running instance (SIGKILL before BTRFS could flush
    its write cache) leave the guest's rootfs with a log tree that points
    at blocks with older transids. ``btrfstune -m`` refuses to touch the
    volume and the VM becomes permanently unstartable. Zero the log tree
    (losing at most the last few seconds of guest writes, which for a
    rootfs is acceptable) and retry once.
    """
    try:
        await run_in_subprocess(["btrfstune", "-m", str(device_path)])
    except CalledProcessError as error:
        # run_in_subprocess stashes stderr in `.output` (not `.stderr`).
        message = error.output or ""
        if not any(marker in message for marker in _BTRFS_CORRUPTION_MARKERS):
            raise
        logger.warning(
            "BTRFS corruption on %s (%s); running `btrfs rescue zero-log` and retrying",
            device_path,
            message.strip(),
        )
        await run_in_subprocess(["btrfs", "rescue", "zero-log", str(device_path)])
        await run_in_subprocess(["btrfstune", "-m", str(device_path)])


async def resize_and_tune_file_system(device_path: Path, mount_path: Path) -> None:
    # This tune is needed to assign a random fsid to BTRFS device to be able to mount it
    await _tune_with_recovery(device_path)
    await run_in_subprocess(["mount", str(device_path), str(mount_path)])
    await run_in_subprocess(["btrfs", "filesystem", "resize", "max", str(mount_path)])
    await run_in_subprocess(["umount", str(mount_path)])


async def create_devmapper(
    volume: PersistentVolume | RootfsVolume, namespace: str, *, pool0_only: bool = False
) -> Path:
    """It creates a /dev/mapper/DEVICE inside the VM, that is an extended mapped device of the volume specified.
    We follow the steps described here: https://community.aleph.im/t/deploying-mutable-vm-instances-on-aleph/56/2

    ``pool0_only`` pins the backing volume file's placement to pool 0 (see
    volume_path_for): the Firecracker jailer hardlink-copies drive files
    across filesystems, silently losing guest writes. Devmapper volumes are
    only used by QEMU instances today, but the flag is threaded through so
    that assumption never has to hold silently.
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

    volume_path = await create_volume_file(volume, namespace, pool0_only=pool0_only)
    extended_block_size: int = await get_block_size(volume_path)

    mapped_volume_name_base = f"{namespace}_base"
    path_mapped_volume_name_base = Path(DEVICE_MAPPER_DIRECTORY) / mapped_volume_name_base
    if not path_mapped_volume_name_base.is_block_device():
        # Creates the base rootfs block device with the entire rootfs size using the image block device as source
        base_table_command = (
            f"0 {image_block_size} linear {path_image_device_name} 0\n"
            f"{image_block_size} {extended_block_size} zero "
        )
        await create_mapped_device(mapped_volume_name_base, base_table_command)

    extended_loop_device = await create_loopback_device(volume_path)

    # Creates the final rootfs block device that is a snapshot of the base block device
    snapshot_table_command = (
        f"0 {extended_block_size} snapshot {path_mapped_volume_name_base} {extended_loop_device} P 8"
    )
    await create_mapped_device(mapped_volume_name, snapshot_table_command)

    mount_path = MOUNT_ROOT / mapped_volume_name
    mount_path.mkdir(parents=True, exist_ok=True)
    await resize_and_tune_file_system(path_mapped_volume_name, mount_path)
    await chown_to_jailman(path_image_device_name)
    await chown_to_jailman(path_mapped_volume_name_base)
    await chown_to_jailman(path_mapped_volume_name)
    return path_mapped_volume_name


async def detach_loop_devices(backing_file: Path) -> list[str]:
    """Detach every loop device backed by ``backing_file``.

    ``losetup -j`` lines look like ``/dev/loop3: [2049]:12 (/path/to/file)``.
    A file can be attached more than once (a create that was interrupted
    between the loop setup and the dmsetup create leaves one behind), so
    every match is detached, not just the first.
    """
    stdout = await run_in_subprocess(["losetup", "-j", str(backing_file)])
    detached: list[str] = []
    for line in stdout.decode().splitlines():
        device = line.split(":", 1)[0].strip()
        if not device.startswith("/dev/loop"):
            continue
        await run_in_subprocess(["losetup", "-d", device])
        logger.info("Detached loop device %s of %s", device, backing_file)
        detached.append(device)
    return detached


async def remove_devmapper(namespace: str, volume_name: str) -> None:
    """The inverse of ``create_devmapper`` for one volume.

    Removes the snapshot device, detaches the loop devices of its backing
    file, drops the resize mount point, and removes the per-VM base device
    once no snapshot of this VM is left. The parent image's device and its
    read-only loop are shared across VMs and are removed by the cache pass
    when the image is evicted, never here.

    Until this runs, the volume file is pinned by its loop device: unlinking
    it would free no space and would not reset the volume either, since
    ``create_devmapper`` returns early while the dm device exists (which is
    what ``purge._held_by_device_mapper`` guards against).
    """
    mapped_name = f"{namespace}_{volume_name}"
    if not DEVICE_NAME_PATTERN.match(namespace) or not DEVICE_NAME_PATTERN.match(volume_name):
        logger.error("Refusing to remove an implausible device-mapper name: %r", mapped_name)
        return

    mapper = Path(DEVICE_MAPPER_DIRECTORY)
    if (mapper / mapped_name).is_block_device():
        await run_in_subprocess(["dmsetup", "remove", mapped_name])
        logger.info("Removed device-mapper target %s", mapped_name)

    backing_file = find_existing_volume(namespace, f"{volume_name}.btrfs")
    if backing_file is not None:
        await detach_loop_devices(backing_file)

    mount_path = MOUNT_ROOT / mapped_name
    if mount_path.is_dir() and not mount_path.is_mount():
        try:
            mount_path.rmdir()
        except OSError:
            logger.warning("Could not remove %s", mount_path, exc_info=True)

    # The base device is per VM but shared by all of its parent-backed
    # volumes (create_devmapper builds it once, from the first one), so it
    # only goes once the last snapshot of this VM is gone.
    base_name = f"{namespace}_base"
    siblings = [path for path in mapper.glob(f"{namespace}_*") if path.name != base_name and path.is_block_device()]
    if not siblings and (mapper / base_name).is_block_device():
        await run_in_subprocess(["dmsetup", "remove", base_name])
        logger.info("Removed device-mapper base %s", base_name)


async def get_existing_file(ref: str) -> Path:
    if settings.FAKE_DATA_PROGRAM and settings.FAKE_DATA_VOLUME:
        return Path(settings.FAKE_DATA_VOLUME)

    cache_path = Path(settings.DATA_CACHE) / ref
    url = await _get_content_url(ref)
    await download_file(url, cache_path)
    await chown_to_jailman(cache_path)
    return cache_path


async def get_volume_path(volume: MachineVolume, namespace: str, *, pool0_only: bool = False) -> Path:
    if isinstance(volume, ImmutableVolume):
        ref = volume.ref
        return await get_existing_file(ref)
    elif isinstance(volume, PersistentVolume | RootfsVolume):
        volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"

        if volume.persistence != VolumePersistence.host:
            msg = "Only 'host' persistence is supported"
            raise NotImplementedError(msg)
        if not re.match(r"^[\w\-_/]+$", volume_name):
            # Sanitize volume names
            logger.debug(f"Invalid values for volume name: {volume_name!r} detected, sanitizing")
            volume_name = re.sub(r"[^\w\-_]", "_", volume_name)
        if volume.parent:
            # create_devmapper resolves its volume file through
            # create_volume_file, which is pool-aware; pool0_only rides along
            # so a hypothetical Firecracker parent volume could never land off
            # pool 0 (jailer hardlink-copy would lose guest writes).
            return await create_devmapper(volume, namespace, pool0_only=pool0_only)
        else:
            # Off the loop, same reason as create_volume_file above.
            volume_path = await asyncio.to_thread(
                volume_path_for, namespace, f"{volume_name}.ext4", volume.size_mib, pool0_only=pool0_only
            )
            await create_ext4(volume_path, volume.size_mib)
            return volume_path
    else:
        msg = "Only immutable volumes are supported"
        raise NotImplementedError(msg)
