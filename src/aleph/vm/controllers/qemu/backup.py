import hashlib
import logging
import shutil
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path

from aleph.vm.conf import settings
from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)

BACKUP_TTL_HOURS = 24


def get_backup_directory() -> Path:
    """Return the directory used to store VM disk backups."""
    path = settings.BACKUP_DIRECTORY or (settings.EXECUTION_ROOT / "backups")
    path.mkdir(parents=True, exist_ok=True)
    return path


def check_disk_space_for_backup(
    source_disk_path: Path,
    destination_dir: Path,
) -> tuple[bool, str]:
    """Check whether there is enough free space to back up a disk.

    Returns (True, "") on success, or (False, reason) on failure.
    """
    needed = source_disk_path.stat().st_size
    free = shutil.disk_usage(destination_dir).free
    if free >= needed:
        return True, ""
    return (
        False,
        f"Insufficient disk space: {free} bytes available, " f"{needed} bytes required",
    )


def check_disk_space_for_multiple(
    disk_paths: list[Path],
    destination_dir: Path,
) -> tuple[bool, str]:
    """Check whether there is enough free space to back up multiple disks.

    Returns (True, "") on success, or (False, reason) on failure.
    """
    needed = sum(p.stat().st_size for p in disk_paths)
    free = shutil.disk_usage(destination_dir).free
    if free >= needed:
        return True, ""
    return (
        False,
        f"Insufficient disk space: {free} bytes available, " f"{needed} bytes required for {len(disk_paths)} disk(s)",
    )


async def create_qemu_disk_backup(
    vm_hash: str,
    source_disk_path: Path,
    destination_dir: Path,
) -> Path:
    """Create a compressed QCOW2 backup of a VM disk.

    Uses ``qemu-img convert`` to produce a standalone copy with no
    backing-file dependency.
    """
    qemu_img_path = shutil.which("qemu-img")
    if not qemu_img_path:
        msg = "qemu-img not found in PATH"
        raise FileNotFoundError(msg)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = destination_dir / f"{vm_hash}-{timestamp}.qcow2"

    logger.info("Creating backup %s from %s", dest, source_disk_path)

    await run_in_subprocess(
        [
            qemu_img_path,
            "convert",
            "-f",
            "qcow2",
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
    qemu_img_path = shutil.which("qemu-img")
    if not qemu_img_path:
        msg = "qemu-img not found in PATH"
        raise FileNotFoundError(msg)

    await run_in_subprocess([qemu_img_path, "check", str(disk_path)])


def _sha256_file(path: Path) -> str:
    """Compute the SHA256 hex digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


async def create_backup_archive(
    vm_hash: str,
    backup_files: dict[str, Path],
    destination_dir: Path,
) -> Path:
    """Create a tar archive containing all backup QCOW2 files.

    Args:
        vm_hash: The VM identifier.
        backup_files: Mapping of archive member name to file path on disk.
        destination_dir: Where to write the tar and its .sha256 sidecar.

    Returns:
        Path to the created tar archive.
    """
    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    tar_name = f"{vm_hash}-{timestamp}.tar"
    tar_path = destination_dir / tar_name

    with tarfile.open(tar_path, "w") as tar:
        for member_name, file_path in backup_files.items():
            tar.add(str(file_path), arcname=member_name)

    checksum = _sha256_file(tar_path)
    sidecar = tar_path.with_suffix(".tar.sha256")
    sidecar.write_text(f"{checksum}  {tar_name}\n")

    return tar_path


def cleanup_expired_backups(
    backup_dir: Path,
    ttl_hours: int = BACKUP_TTL_HOURS,
) -> int:
    """Remove backup archives older than ``ttl_hours``.

    Also removes the companion .sha256 sidecar files.

    Returns:
        Number of expired archives deleted.
    """
    cutoff = time.time() - (ttl_hours * 3600)
    deleted = 0

    for tar_file in backup_dir.glob("*.tar"):
        if tar_file.stat().st_mtime < cutoff:
            tar_file.unlink()
            sidecar = tar_file.with_suffix(".tar.sha256")
            sidecar.unlink(missing_ok=True)
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

    return {
        "backup_id": tar_path.stem,
        "size": tar_path.stat().st_size,
        "checksum": f"sha256:{checksum}",
        "volumes": volumes,
        "expires_at": expires_at.isoformat(),
    }
