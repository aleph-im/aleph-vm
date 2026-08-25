"""Agent-side VM disk backups and restores.

The agent allocates a VM's disks (``downloader.py``), deletes them
(``purge.py``) and, here, copies and restores them. The supervisor's only
part is quiescence: the agent cannot freeze the guest's filesystems from
outside the VM, so it asks the supervisor to ``freeze_guest`` around its
copy and to ``thaw_guest`` afterwards, and it drives ``stop_vm`` /
``start_vm`` around a restore, the same shape as ``operate_reinstall``.

A backup is a ``qemu-img convert -c`` compressed, standalone copy of the
rootfs (plus the VM's writable persistent volumes when ``include_volumes``
is set) archived into a tar next to a ``.tar.sha256`` checksum and a
``.tar.meta.json`` sidecar (``aleph.vm.backup.archive``). The archive on
disk is the record; only in-flight and failed runs live in memory.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import subprocess
import tarfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from aleph.vm.agent.vm.purge import ROOTFS_STEM, iter_volume_files
from aleph.vm.backup.archive import (
    backup_metadata,
    check_disk_space_for_multiple,
    cleanup_expired_backups,
    create_backup_archive,
    create_qemu_disk_backup,
    find_existing_backup,
    get_backup_directory,
    get_qemu_disk_virtual_size,
    restore_rootfs,
    verify_qemu_disk,
)
from aleph.vm.backup.types import (
    BackupId,
    BackupInfo,
    BackupInProgressError,
    BackupNotFoundError,
    BackupNotSupportedError,
    BackupStatus,
    InvalidRestoreImageError,
)
from aleph.vm.storage import DEVICE_MAPPER_DIRECTORY
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import SupervisorError
from aleph.vm.supervisor_interface.types import VmId, VmStatus

logger = logging.getLogger(__name__)

# The rootfs archive member, always present in a backup. With include_volumes
# the VM's writable persistent volumes are added alongside it (named by their
# on-disk basename stem). restore_backup replaces only the rootfs member; the
# extra volumes are carried for the owner's own use (download).
BACKUP_ROOTFS_MEMBER = "rootfs.qcow2"
DOWNLOAD_CHUNK_BYTES = 1024 * 1024


def validate_backup_id(vm_hash: str, backup_id: str) -> None:
    """Reject ids that are not of this VM or that could escape the backup
    directory (the id becomes a file name)."""
    malformed = not backup_id or "/" in backup_id or "\\" in backup_id or ".." in backup_id
    if malformed or not backup_id.startswith(f"{vm_hash}-"):
        raise BackupNotFoundError(backup_id)


@dataclass(frozen=True)
class VmDisks:
    """The on-host disks of a VM, as the backup sees them."""

    rootfs: Path
    # Archive member name -> path to read. A device-mapper-backed volume is
    # read through its /dev/mapper device (the backing file alone is the
    # snapshot's copy-on-write store, not the volume's content).
    members: dict[str, Path]


def vm_disks(vm_hash: str, *, include_volumes: bool) -> VmDisks:
    """Resolve the VM's disks from its namespace directories.

    The rootfs of a QEMU instance is the ``rootfs.qcow2`` the downloader
    created; a program has none (it boots the shared runtime cache file) and
    is refused with ``BackupNotSupportedError``.
    """
    rootfs: Path | None = None
    volumes: dict[str, Path] = {}
    for volume in iter_volume_files(vm_hash):
        if volume.stem == ROOTFS_STEM:
            if volume.suffix == ".qcow2":
                rootfs = volume
            continue
        if volume.suffix == ".btrfs":
            mapped = Path(DEVICE_MAPPER_DIRECTORY) / f"{vm_hash}_{volume.stem}"
            volumes[f"{volume.stem}.qcow2"] = mapped if mapped.is_block_device() else volume
        else:
            volumes[f"{volume.stem}.qcow2"] = volume
    if rootfs is None:
        msg = "Backups operate on the rootfs disk image; only QEMU instances have one"
        raise BackupNotSupportedError(msg)
    members = {BACKUP_ROOTFS_MEMBER: rootfs}
    if include_volumes:
        members.update(sorted(volumes.items()))
    return VmDisks(rootfs=rootfs, members=members)


def _info_from_tar(tar_path: Path, vm_hash: str) -> BackupInfo:
    stat = tar_path.stat()
    try:
        # checksum/source_sizes come from the sidecars; volumes is read from
        # the archive index. A corrupt or non-tar file (e.g. a partial write)
        # still yields a usable BackupInfo, just without the archive metadata.
        meta = backup_metadata(tar_path)
    except (tarfile.TarError, OSError):
        logger.warning("Could not read backup metadata for %s", tar_path.name)
        meta = {}
    return BackupInfo(
        vm_hash=vm_hash,
        backup_id=BackupId(tar_path.stem),
        status=BackupStatus.COMPLETE,
        size_bytes=stat.st_size,
        created_at_unix_secs=int(stat.st_mtime),
        error_message="",
        checksum=meta.get("checksum", ""),
        volumes=list(meta.get("volumes", [])),
        source_sizes=dict(meta.get("source_sizes", {})),
    )


def _extract_rootfs_member(tar_path: Path, destination: Path) -> None:
    """Stream the rootfs member of a backup archive to *destination*.

    Member-streamed on purpose (no extractall): archive member names never
    touch the filesystem, so a crafted archive cannot escape the backup
    directory.
    """
    with tarfile.open(tar_path, "r") as tar:
        try:
            member = tar.getmember(BACKUP_ROOTFS_MEMBER)
        except KeyError:
            msg = f"Backup archive {tar_path.name} has no {BACKUP_ROOTFS_MEMBER} member"
            raise InvalidRestoreImageError(msg) from None
        source = tar.extractfile(member)
        if source is None:
            msg = f"Backup member {BACKUP_ROOTFS_MEMBER} in {tar_path.name} is not a regular file"
            raise InvalidRestoreImageError(msg)
        with source, destination.open("wb") as dst:
            shutil.copyfileobj(source, dst)


class BackupManager:
    """The archive registry and the backup/restore operations of one agent.

    Completed archives live on disk (the source of truth); ``_jobs`` only
    holds in-flight and failed runs. Backup and restore are serialized per VM:
    neither may touch the disks while the other converts or swaps them.
    """

    def __init__(self, supervisor: Supervisor):
        self._supervisor = supervisor
        self._jobs: dict[BackupId, BackupInfo] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        # Serializes start_backup's check-and-register: the disk-space check
        # awaits, and two callers racing past the running-task check would
        # otherwise both spawn a run.
        self._admission = asyncio.Lock()

    def _lock(self, vm_hash: str) -> asyncio.Lock:
        return self._locks.setdefault(vm_hash, asyncio.Lock())

    # ── Backup ──
    async def start_backup(
        self, vm_hash: str, *, quiesce_guest: bool = True, include_volumes: bool = False
    ) -> BackupInfo:
        """Start (or return) a backup of the VM's rootfs. Idempotent: a run
        already in progress, or a non-expired archive, is the answer."""
        async with self._admission:
            return await self._admit_backup(vm_hash, quiesce_guest=quiesce_guest, include_volumes=include_volumes)

    async def _admit_backup(self, vm_hash: str, *, quiesce_guest: bool, include_volumes: bool) -> BackupInfo:
        disks = vm_disks(vm_hash, include_volumes=include_volumes)
        backup_dir = get_backup_directory()
        cleanup_expired_backups(backup_dir)

        running_task = self._tasks.get(vm_hash)
        if running_task is not None and not running_task.done():
            for job in self._jobs.values():
                if job.vm_hash == vm_hash and job.status is BackupStatus.RUNNING:
                    return job

        # Expiry (24h TTL) defines backup freshness.
        existing = find_existing_backup(backup_dir, vm_hash)
        if existing is not None:
            return _info_from_tar(existing, vm_hash)

        await check_disk_space_for_multiple(list(disks.members.values()), backup_dir)

        # Microsecond precision: a retry right after a failed run must get a
        # fresh id (the id is also the tar stem, which keeps the format
        # dash-free for list_backups' rsplit).
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        backup_id = BackupId(f"{vm_hash}-{timestamp}")
        job = BackupInfo(
            vm_hash=vm_hash,
            backup_id=backup_id,
            status=BackupStatus.RUNNING,
            size_bytes=0,
            created_at_unix_secs=int(time.time()),
            error_message="",
        )
        # This run supersedes earlier failed attempts for the VM.
        for old_id, old_job in list(self._jobs.items()):
            if old_job.vm_hash == vm_hash and old_job.status is BackupStatus.FAILED:
                del self._jobs[old_id]
        self._jobs[backup_id] = job
        self._tasks[vm_hash] = asyncio.create_task(
            self._run_backup(vm_hash, backup_id, timestamp, disks.members, backup_dir, quiesce_guest)
        )
        return job

    async def _run_backup(
        self,
        vm_hash: str,
        backup_id: BackupId,
        timestamp: str,
        disk_paths: dict[str, Path],
        backup_dir: Path,
        quiesce_guest: bool,
    ) -> None:
        disk_backups: list[Path] = []
        try:
            async with self._lock(vm_hash):
                frozen = await self._freeze(vm_hash) if quiesce_guest else False
                backup_files: dict[str, Path] = {}
                try:
                    for member_name, source_path in disk_paths.items():
                        disk_backup = await create_qemu_disk_backup(vm_hash, source_path, backup_dir)
                        disk_backups.append(disk_backup)
                        backup_files[member_name] = disk_backup
                finally:
                    if frozen:
                        await self._thaw(vm_hash)
                for disk_backup in disk_backups:
                    await verify_qemu_disk(disk_backup)
                await create_backup_archive(
                    vm_hash=vm_hash,
                    backup_files=backup_files,
                    destination_dir=backup_dir,
                    source_sizes={name: src.stat().st_size for name, src in disk_paths.items()},
                    timestamp=timestamp,
                )
                # The archive on disk is now the record; drop the live job.
                self._jobs.pop(backup_id, None)
        except Exception as exc:
            logger.exception("Backup %s failed", backup_id)
            self._jobs[backup_id] = BackupInfo(
                vm_hash=vm_hash,
                backup_id=backup_id,
                status=BackupStatus.FAILED,
                size_bytes=0,
                created_at_unix_secs=int(time.time()),
                error_message=str(exc),
            )
        finally:
            for disk_backup in disk_backups:
                disk_backup.unlink(missing_ok=True)
            self._tasks.pop(vm_hash, None)

    async def _freeze(self, vm_hash: str) -> bool:
        """Best-effort quiescence: the copy proceeds crash-consistent when the
        supervisor cannot freeze the guest (no guest agent, VM not running,
        VM unknown to the supervisor)."""
        try:
            frozen = await self._supervisor.freeze_guest(VmId(vm_hash))
        except SupervisorError as exc:
            logger.warning("fsfreeze unavailable for %s, proceeding without: %s", vm_hash, exc)
            return False
        if not frozen:
            logger.info("Guest %s not frozen for its backup (no guest agent or not running)", vm_hash)
        return frozen

    async def _thaw(self, vm_hash: str) -> None:
        try:
            await self._supervisor.thaw_guest(VmId(vm_hash))
        except SupervisorError:
            logger.exception("Failed to thaw filesystems for %s", vm_hash)

    # ── Archive registry ──
    def get_backup_status(self, vm_hash: str, backup_id: BackupId) -> BackupInfo:
        validate_backup_id(vm_hash, backup_id)
        tar_path = get_backup_directory() / f"{backup_id}.tar"
        if tar_path.exists():
            return _info_from_tar(tar_path, vm_hash)
        job = self._jobs.get(backup_id)
        if job is not None:
            return job
        raise BackupNotFoundError(backup_id)

    def list_backups(self, vm_hash: str | None = None) -> list[BackupInfo]:
        backup_dir = get_backup_directory()
        pattern = f"{vm_hash}-*.tar" if vm_hash else "*.tar"
        # The archive stem is "<vm_hash>-<timestamp>"; neither part contains
        # a dash (hex item hash, %Y%m%dT%H%M%SZ), so rsplit is exact.
        infos = [
            _info_from_tar(tar_path, tar_path.stem.rsplit("-", 1)[0]) for tar_path in sorted(backup_dir.glob(pattern))
        ]
        infos += [job for job in self._jobs.values() if vm_hash is None or job.vm_hash == vm_hash]
        return infos

    async def download_backup(self, vm_hash: str, backup_id: BackupId) -> AsyncIterator[bytes]:
        """Open the archive and return its chunk stream. The lookup happens
        here, at call time, so a missing archive raises before the caller
        has committed a response; the generator only reads."""
        validate_backup_id(vm_hash, backup_id)
        tar_path = get_backup_directory() / f"{backup_id}.tar"
        try:
            tar_file = tar_path.open("rb")
        except FileNotFoundError:
            raise BackupNotFoundError(backup_id) from None
        return _stream_file(tar_file)

    def delete_backup(self, vm_hash: str, backup_id: BackupId) -> None:
        validate_backup_id(vm_hash, backup_id)
        job = self._jobs.get(backup_id)
        if job is not None and job.status is BackupStatus.RUNNING:
            msg = f"Backup {backup_id} is still running"
            raise BackupInProgressError(msg)
        tar_path = get_backup_directory() / f"{backup_id}.tar"
        existed = tar_path.exists()
        tar_path.unlink(missing_ok=True)
        tar_path.with_suffix(".tar.sha256").unlink(missing_ok=True)
        tar_path.with_suffix(".tar.meta.json").unlink(missing_ok=True)
        # Deleting a FAILED record is also a valid delete.
        if self._jobs.pop(backup_id, None) is None and not existed:
            raise BackupNotFoundError(backup_id)

    def forget(self, vm_hash: str) -> None:
        """Drop the in-memory state of a VM that is gone (its archives on
        disk stay until they expire)."""
        for backup_id, job in list(self._jobs.items()):
            if job.vm_hash == vm_hash:
                del self._jobs[backup_id]
        self._locks.pop(vm_hash, None)

    # ── Restore ──
    async def restore_backup(self, vm_hash: str, backup_id: BackupId) -> None:
        """Swap the VM's rootfs for the archived one, stopping and restarting
        the VM around the swap."""
        disks = vm_disks(vm_hash, include_volumes=False)
        validate_backup_id(vm_hash, backup_id)
        backup_dir = get_backup_directory()
        tar_path = backup_dir / f"{backup_id}.tar"
        if not tar_path.exists():
            raise BackupNotFoundError(backup_id)
        async with self._lock(vm_hash):
            staging = backup_dir / f"{backup_id}.restore.qcow2"
            try:
                await asyncio.to_thread(_extract_rootfs_member, tar_path, staging)
                try:
                    await verify_qemu_disk(staging)
                except subprocess.CalledProcessError as exc:
                    msg = f"Backup {backup_id} holds a corrupt rootfs image"
                    raise InvalidRestoreImageError(msg) from exc
                await self._swap_rootfs(vm_hash, staging, disks.rootfs)
            finally:
                staging.unlink(missing_ok=True)

    async def restore_from_image(self, vm_hash: str, image: Path, *, max_virtual_size_bytes: int = 0) -> None:
        """Swap the VM's rootfs for a QCOW2 image already staged on a host
        path (an upload or a downloaded volume). Rejects an image that is not
        a valid QCOW2 or whose virtual size exceeds ``max_virtual_size_bytes``
        (0 = no cap): a restore must not grow the disk."""
        disks = vm_disks(vm_hash, include_volumes=False)
        if not image.exists():
            msg = f"staged restore image {image} does not exist"
            raise FileNotFoundError(msg)
        try:
            await verify_qemu_disk(image)
        except subprocess.CalledProcessError as exc:
            msg = f"Restore image {image.name} is not a valid QCOW2 disk"
            raise InvalidRestoreImageError(msg) from exc
        if max_virtual_size_bytes:
            new_size = await get_qemu_disk_virtual_size(image)
            if new_size > max_virtual_size_bytes:
                msg = (
                    f"New rootfs virtual size ({new_size} bytes) exceeds the declared rootfs size "
                    f"({max_virtual_size_bytes} bytes). Restore cannot increase disk size."
                )
                raise InvalidRestoreImageError(msg)
        async with self._lock(vm_hash):
            await self._swap_rootfs(vm_hash, image, disks.rootfs)

    async def _swap_rootfs(self, vm_hash: str, new_rootfs: Path, current_rootfs: Path) -> None:
        """Stop the VM if it runs, swap the rootfs file, start it again. The
        supervisor holds the VM's handles on the disk; only a stopped VM can
        have its rootfs replaced under it."""
        vm_id = VmId(vm_hash)
        info = await self._supervisor.get_vm(vm_id)
        if info.status is not VmStatus.STOPPED:
            await self._supervisor.stop_vm(vm_id)
        await restore_rootfs(new_rootfs, current_rootfs)
        await self._supervisor.start_vm(vm_id)


async def _stream_file(tar_file: BinaryIO) -> AsyncIterator[bytes]:
    with tar_file:
        while True:
            data = await asyncio.to_thread(tar_file.read, DOWNLOAD_CHUNK_BYTES)
            if not data:
                return
            yield data
