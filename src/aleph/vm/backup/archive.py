"""The backup archive format and the ``qemu-img`` seam.

Pure disk and archive work: a ``qemu-img convert -c`` compressed copy per
disk, an uncompressed tar of those copies next to a ``.tar.sha256`` checksum
sidecar and a ``.tar.meta.json`` sidecar, the TTL cleanup and the rootfs
swap. Driven by the agent's ``BackupManager``; the supervisor never touches an
archive.
"""

import asyncio
import hashlib
import json
import logging
import shutil
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

# The staging helpers are re-exported for the callers (and tests) that
# import the whole archive vocabulary from this module.
from aleph.vm.backup.staging import (  # noqa: F401
    download_volume_by_ref,
    get_backup_directory,
)
from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)

BACKUP_TTL_HOURS = 24


class InsufficientDiskSpaceError(Exception):
    """Raised when there is not enough free disk space for a backup."""


def _require_qemu_img() -> str:
    """Return the path to ``qemu-img`` or raise ``FileNotFoundError``."""
    path = shutil.which("qemu-img")
    if not path:
        msg = "qemu-img not found in PATH"
        raise FileNotFoundError(msg)
    return path


async def check_disk_space_for_multiple(
    disk_paths: list[Path],
    destination_dir: Path,
) -> None:
    """Check whether there is enough free space to back up multiple disks.

    Uses the virtual size of each QCOW2 image as an upper-bound estimate,
    since ``qemu-img convert`` may expand thin-provisioned images.

    Raises:
        InsufficientDiskSpaceError: If free space is less than needed.
    """
    # Best-effort check; concurrent operations may change available space.
    needed = 0
    for p in disk_paths:
        needed += await get_qemu_disk_virtual_size(p)
    free = shutil.disk_usage(destination_dir).free
    if free < needed:
        msg = (
            f"Insufficient disk space: {free} bytes available, "
            f"{needed} bytes required for {len(disk_paths)} disk(s)"
        )
        raise InsufficientDiskSpaceError(msg)


async def create_qemu_disk_backup(
    vm_hash: str,
    source_disk_path: Path,
    destination_dir: Path,
) -> Path:
    """Create a compressed QCOW2 backup of a VM disk.

    Uses ``qemu-img convert`` to produce a standalone copy with no
    backing-file dependency.
    """
    qemu_img = _require_qemu_img()

    # The source stem keeps the copies of one include_volumes run apart:
    # two disks converted within the same second must not share a path.
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = destination_dir / f"{vm_hash}-{source_disk_path.stem}-{timestamp}.qcow2"

    logger.info("Creating backup %s from %s", dest, source_disk_path)

    await run_in_subprocess(
        [
            qemu_img,
            "convert",
            "-U",
            "-O",
            "qcow2",
            "-c",
            str(source_disk_path),
            str(dest),
        ]
    )

    return dest


async def verify_qemu_disk(disk_path: Path) -> None:
    """Verify a QCOW2 disk image using ``qemu-img check``.

    Raises ``subprocess.CalledProcessError`` if the check fails.
    """
    qemu_img = _require_qemu_img()
    await run_in_subprocess([qemu_img, "check", str(disk_path)])


async def get_qemu_disk_virtual_size(disk_path: Path) -> int:
    """Return the virtual size in bytes of a QCOW2 disk image."""
    qemu_img = _require_qemu_img()
    out = await run_in_subprocess([qemu_img, "info", "--force-share", "--output=json", str(disk_path)])
    info = json.loads(out)
    return info["virtual-size"]


def _sha256_file(path: Path, chunk_size: int = 65536) -> str:
    """Compute the SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _create_tar_and_checksum(
    tar_path: Path,
    backup_files: dict[str, Path],
    vm_hash: str,
    timestamp: str,
    source_sizes: dict[str, int] | None,
) -> None:
    """Synchronous tar + sha256 + metadata creation (run via to_thread).

    The tar is written to a .tar.partial staging name and renamed into
    place last: the .tar appearing on disk is what marks a backup
    complete everywhere (status, listing, download, find_existing_backup),
    so the final path must never hold a half-written archive.
    """
    staging = tar_path.with_suffix(".tar.partial")
    try:
        with tarfile.open(staging, "w") as tar:
            for member_name, file_path in backup_files.items():
                tar.add(str(file_path), arcname=member_name)

        checksum = _sha256_file(staging)
        sidecar = tar_path.with_suffix(".tar.sha256")
        sidecar.write_text(f"{checksum}  {tar_path.name}\n")

        meta: dict = {"vm_hash": vm_hash, "created_at": timestamp}
        if source_sizes:
            meta["source_sizes"] = source_sizes
        meta_path = tar_path.with_suffix(".tar.meta.json")
        meta_path.write_text(json.dumps(meta))

        staging.rename(tar_path)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise


async def create_backup_archive(
    vm_hash: str,
    backup_files: dict[str, Path],
    destination_dir: Path,
    source_sizes: dict[str, int] | None = None,
    timestamp: str | None = None,
) -> Path:
    """Create a tar archive containing all backup QCOW2 files.

    Args:
        vm_hash: The VM identifier.
        backup_files: Mapping of archive member name to file path on disk.
        destination_dir: Where to write the tar and its .sha256 sidecar.
        source_sizes: Optional mapping of volume name to original disk
            size in bytes (before backup compression).
        timestamp: Archive timestamp (UTC, ``%Y%m%dT%H%M%SZ``). Defaults to
            now; callers that issued a backup id upfront pass it so the tar
            stem matches the id.

    Returns:
        Path to the created tar archive.
    """
    timestamp = timestamp or datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tar_path = destination_dir / f"{vm_hash}-{timestamp}.tar"

    await asyncio.to_thread(
        _create_tar_and_checksum,
        tar_path,
        backup_files,
        vm_hash,
        timestamp,
        source_sizes,
    )

    return tar_path


def cleanup_expired_backups(
    backup_dir: Path,
    ttl_hours: int = BACKUP_TTL_HOURS,
    *,
    now: float | None = None,
) -> int:
    """Remove backup archives older than ``ttl_hours``.

    Also removes the companion .sha256 and .tar.meta.json sidecar files.

    ``now`` is the timestamp the TTL is evaluated against, defaulting to the
    wall clock. The reconciler passes the one ``now`` it threads through a
    whole pass, so a run is deterministic and does not drift between the
    archives it looks at.

    Every file is handled on its own: another sweep, or ``purge_vm_backups``
    for a VM being retired, can remove an archive between the listing and the
    unlink. Losing that race is normal, and it must not abort the rest of the
    pass.

    Returns:
        Number of expired archives deleted.
    """
    cutoff = (now if now is not None else time.time()) - (ttl_hours * 3600)
    deleted = 0

    # A .tar.partial older than the TTL is an archive whose writer died
    # mid-backup (live ones are renamed to .tar within minutes).
    for partial in backup_dir.glob("*.tar.partial"):
        try:
            if partial.stat().st_mtime < cutoff:
                partial.unlink()
                logger.info("Deleted stale partial backup %s", partial.name)
        except OSError:
            logger.debug("Skipping %s: it went away or is not readable", partial, exc_info=True)

    for tar_file in backup_dir.glob("*.tar"):
        try:
            if tar_file.stat().st_mtime >= cutoff:
                continue
            tar_file.unlink()
            tar_file.with_suffix(".tar.sha256").unlink(missing_ok=True)
            tar_file.with_suffix(".tar.meta.json").unlink(missing_ok=True)
        except OSError:
            logger.debug("Skipping %s: it went away or is not readable", tar_file, exc_info=True)
            continue
        logger.info("Deleted expired backup %s", tar_file.name)
        deleted += 1

    return deleted


def find_existing_backup(
    backup_dir: Path,
    vm_hash: str,
    ttl_hours: int = BACKUP_TTL_HOURS,
) -> Path | None:
    """Find a non-expired tar backup for a VM, if one exists."""
    cutoff = time.time() - (ttl_hours * 3600)

    for tar_file in sorted(backup_dir.glob(f"{vm_hash}-*.tar"), reverse=True):
        if tar_file.stat().st_mtime >= cutoff:
            return tar_file

    return None


def backup_metadata(tar_path: Path) -> dict:
    """Build metadata dict for a backup tar archive."""
    sidecar = tar_path.with_suffix(".tar.sha256")
    checksum = ""
    if sidecar.exists():
        checksum = sidecar.read_text().split()[0]

    with tarfile.open(tar_path, "r") as tar:
        volumes = [m.name for m in tar.getmembers()]

    expires_at = datetime.fromtimestamp(
        tar_path.stat().st_mtime + BACKUP_TTL_HOURS * 3600,
        tz=timezone.utc,
    )

    meta: dict = {
        "backup_id": tar_path.stem,
        "size": tar_path.stat().st_size,
        "volumes": volumes,
        "expires_at": expires_at.isoformat(),
    }

    if checksum:
        meta["checksum"] = f"sha256:{checksum}"

    meta_file = tar_path.with_suffix(".tar.meta.json")
    if meta_file.exists():
        stored = json.loads(meta_file.read_text())
        if "source_sizes" in stored:
            meta["source_sizes"] = stored["source_sizes"]

    return meta


def _restore_rootfs_sync(new_rootfs: Path, current_rootfs: Path) -> Path:
    """Synchronous rootfs replacement (run via to_thread).

    Copies new image to a temp file first, then atomically renames it
    over the current rootfs. The old rootfs is preserved as a backup.
    """
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    old_backup = current_rootfs.with_suffix(f".pre-restore-{timestamp}.qcow2")
    # Copy to a temp file in the same directory for atomic rename
    staging = current_rootfs.with_suffix(".restore-staging.qcow2")
    try:
        shutil.copy2(str(new_rootfs), str(staging))
        # Preserve the old rootfs
        current_rootfs.rename(old_backup)
        # Atomic rename on the same filesystem
        staging.rename(current_rootfs)
    except BaseException:
        # Rollback: if old rootfs was moved but staging rename failed,
        # restore from backup
        if not current_rootfs.exists() and old_backup.exists():
            old_backup.rename(current_rootfs)
        staging.unlink(missing_ok=True)
        raise

    logger.info(
        "Restored rootfs: %s -> %s (old saved as %s)",
        new_rootfs.name,
        current_rootfs,
        old_backup,
    )
    return old_backup


async def restore_rootfs(
    new_rootfs: Path,
    current_rootfs: Path,
) -> Path:
    """Replace the current rootfs with a verified QCOW2 backup.

    Creates a timestamped backup of the current rootfs before replacing
    it, so the operation can be manually reversed if needed.

    The replacement is atomic: the new image is copied to a staging file
    first, then renamed into place.

    Args:
        new_rootfs: Path to the new QCOW2 file (already verified).
        current_rootfs: Path to the current rootfs to replace.

    Returns:
        Path to the old rootfs backup.
    """
    return await asyncio.to_thread(_restore_rootfs_sync, new_rootfs, current_rootfs)
