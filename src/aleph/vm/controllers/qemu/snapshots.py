import logging
import shutil
from datetime import datetime, timezone
from pathlib import Path

from aleph.vm.conf import settings
from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)


def get_snapshots_directory() -> Path:
    """Return the directory used to store VM snapshots."""
    path = settings.EXECUTION_ROOT / "snapshots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def check_disk_space_for_snapshot(
    source_disk_path: Path,
    destination_dir: Path,
) -> tuple[bool, str]:
    """Check whether there is enough free space to snapshot a disk.

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


async def create_qemu_disk_snapshot(
    vm_hash: str,
    source_disk_path: Path,
    destination_dir: Path,
) -> Path:
    """Create a compressed QCOW2 snapshot of a VM disk.

    Uses ``qemu-img convert`` to produce a standalone copy with no
    backing-file dependency.
    """
    qemu_img_path = shutil.which("qemu-img")
    if not qemu_img_path:
        msg = "qemu-img not found in PATH"
        raise FileNotFoundError(msg)

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = destination_dir / f"{vm_hash}-{timestamp}.qcow2"

    logger.info("Creating snapshot %s from %s", dest, source_disk_path)

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
