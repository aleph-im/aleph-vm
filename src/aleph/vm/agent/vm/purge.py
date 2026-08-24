"""Agent-side deallocation of a VM's on-host storage.

The deallocation counterpart of ``downloader.py``. The agent resolves a
message into on-host paths and creates the volume files (``qemu-img create``,
``fallocate``, ``mkfs.ext4``), placing them through ``storage_pools``; so the
agent is also the side that deletes them.

The supervisor cannot do this job. It is handed resolved absolute paths on a
``CreateVmSpec`` and never allocates a byte (``VmExecution.prepare``: "No
download (paths are resolved)"), which leaves it unable to tell a per-VM
volume apart from a shared cache entry: a program's ``rootfs_path`` *is*
``RUNTIME_CACHE/<runtime_ref>``, shared by every program running that
runtime. Deleting storage from that side either misses files it never saw
(the namespace directory itself, volumes on other pools, the staging dirs)
or destroys files it does not own.

Whoever allocates, deallocates. Everything here is keyed by ``vm_hash`` and
scoped to directories the agent itself created, so a shared cache entry is
not merely spared by a check -- it is unreachable from this code.
"""

from __future__ import annotations

import logging
import re
import shutil
from collections.abc import Iterator
from pathlib import Path

from aleph_message.models import ItemHash

from aleph.vm.agent.snp_instance_launch import remove_snp_instance_staging
from aleph.vm.agent.vprogram_launch import remove_vprogram_staging
from aleph.vm.conf import settings
from aleph.vm.storage_pools import iter_namespace_dirs

logger = logging.getLogger(__name__)

# Volume files are named after the volume they back: "rootfs.qcow2",
# "rootfs.btrfs" for the boot disk, "<volume name>.ext4" / ".btrfs" /
# ".qcow2" for the extra persistent volumes (see storage.get_volume_path and
# downloader._make_writable_volume).
ROOTFS_STEM = "rootfs"

# A namespace is an item hash. Anything else must never reach a path join in
# a delete path: defence in depth behind ItemHash's own validation, since the
# cost of being wrong here is deleting an unrelated directory tree.
_ITEM_HASH_PATTERN = re.compile(r"^[0-9a-zA-Z]{16,128}$")


def _checked_namespace(vm_hash: ItemHash | str) -> str:
    namespace = str(vm_hash)
    if not _ITEM_HASH_PATTERN.match(namespace):
        msg = f"Refusing to purge storage for an implausible VM hash: {namespace!r}"
        raise ValueError(msg)
    return namespace


def iter_volume_files(
    vm_hash: ItemHash | str,
    *,
    include_rootfs: bool = True,
    include_data_volumes: bool = True,
) -> Iterator[Path]:
    """The VM's volume files, across every storage pool.

    Only regular files directly inside ``{pool}/{vm_hash}/`` are yielded, so
    this can never reach a cache entry or another VM's volume.
    """
    namespace = _checked_namespace(vm_hash)
    for volumes_dir in iter_namespace_dirs(namespace):
        try:
            entries = sorted(volumes_dir.iterdir())
        except OSError:
            logger.warning("Volume directory %s not readable, skipping", volumes_dir)
            continue
        for entry in entries:
            if not entry.is_file():
                continue
            is_rootfs = entry.stem == ROOTFS_STEM
            if is_rootfs and not include_rootfs:
                continue
            if not is_rootfs and not include_data_volumes:
                continue
            yield entry


def purge_vm_volumes(
    vm_hash: ItemHash | str,
    *,
    include_rootfs: bool = True,
    include_data_volumes: bool = True,
) -> int:
    """Delete a VM's volume files, leaving the namespace directories in place.

    Used by the reinstall path, which deletes the volumes and then re-runs
    the downloader to recreate them. Returns the number of files deleted.
    """
    deleted = 0
    for volume in iter_volume_files(
        vm_hash,
        include_rootfs=include_rootfs,
        include_data_volumes=include_data_volumes,
    ):
        try:
            volume.unlink()
        except OSError:
            logger.warning("Failed to delete volume %s", volume, exc_info=True)
            continue
        logger.info("Deleted volume %s", volume)
        deleted += 1
    return deleted


def purge_vm_staging(vm_hash: ItemHash | str) -> None:
    """Delete the extracted runtime bundles staged for this VM.

    Covers both the V-PROGRAM and the confidential-instance staging
    directories; each is a no-op for a VM of the other type.
    """
    namespace = _checked_namespace(vm_hash)
    item_hash = vm_hash if isinstance(vm_hash, ItemHash) else ItemHash(namespace)
    remove_vprogram_staging(item_hash)
    remove_snp_instance_staging(item_hash)


def purge_vm_storage(vm_hash: ItemHash | str) -> int:
    """Delete everything this VM owns on disk, for a VM that is gone for good.

    Covers the per-VM volume directories on every pool, the confidential
    session directory, and the SEV-SNP / V-PROGRAM staging directories that
    each teardown path used to clean up with its own call. The VM must
    already be stopped: the supervisor releases its handles on the disks
    (device-mapper targets, jailer chroot, sockets) during DeleteVm, and this
    runs after that returns.

    Returns the number of volume files deleted. Idempotent: purging a VM with
    nothing on disk is a no-op.
    """
    namespace = _checked_namespace(vm_hash)
    deleted = purge_vm_volumes(namespace)

    for volumes_dir in list(iter_namespace_dirs(namespace)):
        try:
            shutil.rmtree(volumes_dir)
            logger.info("Removed volume directory %s", volumes_dir)
        except OSError:
            logger.warning("Failed to remove volume directory %s", volumes_dir, exc_info=True)

    if settings.CONFIDENTIAL_SESSION_DIRECTORY:
        session_dir = Path(settings.CONFIDENTIAL_SESSION_DIRECTORY) / namespace
        if session_dir.exists():
            try:
                shutil.rmtree(session_dir)
                logger.info("Removed confidential session directory %s", session_dir)
            except OSError:
                logger.warning("Failed to remove session directory %s", session_dir, exc_info=True)

    purge_vm_staging(namespace)

    return deleted
