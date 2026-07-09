"""Agent-side storage pools: multiple fast disks for VM volumes.

A pool is a directory (typically the mountpoint of one dedicated SSD/NVMe
filesystem) holding persistent volumes and instance rootfs overlays under
``{pool}/{namespace}/``. Pool 0 is always ``settings.PERSISTENT_VOLUMES_DIR``;
extra pools come from ``settings.VOLUME_POOLS``. Placement picks the eligible
pool with the most free bytes; lookup scans pools in index order. HDD pools
are never eligible for VM volumes (rotational storage is for caches and
backups: point CACHE_ROOT / BACKUP_DIRECTORY at it instead).

The supervisor/controller side is path-agnostic (DiskConfig carries resolved
absolute paths), so everything here is agent policy.
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class MediaClass(str, Enum):
    NVME = "nvme"
    SSD = "ssd"
    HDD = "hdd"

    @property
    def slowness(self) -> int:
        return _SLOWNESS[self]

    @property
    def vm_eligible(self) -> bool:
        return self is not MediaClass.HDD


_SLOWNESS = {MediaClass.NVME: 0, MediaClass.SSD: 1, MediaClass.HDD: 2}


def _read_rotational(disk_node: Path) -> bool | None:
    try:
        return (disk_node / "queue" / "rotational").read_text().strip() == "1"
    except OSError:
        return None


def _device_media_class(device_name: str, sys_root: Path) -> MediaClass | None:
    """Media class of one block device, walking dm/md stacks to the slowest member."""
    node = sys_root / "class" / "block" / device_name
    if not node.exists():
        return None
    slaves_dir = node / "slaves"
    if slaves_dir.is_dir():
        slave_classes = [_device_media_class(entry.name, sys_root) for entry in slaves_dir.iterdir()]
        if slave_classes:
            if any(slave_class is None for slave_class in slave_classes):
                return None
            return max(slave_classes, key=lambda slave_class: slave_class.slowness)
    # A partition node has no queue/; its resolved parent (the whole disk) does.
    disk_node = node.resolve()
    if not (disk_node / "queue").is_dir():
        disk_node = disk_node.parent
    is_rotational = _read_rotational(disk_node)
    if is_rotational is None:
        return None
    if is_rotational:
        return MediaClass.HDD
    return MediaClass.NVME if disk_node.name.startswith("nvme") else MediaClass.SSD


def detect_media_class(path: Path, sys_root: Path = Path("/sys")) -> MediaClass | None:
    """Media class of the filesystem holding ``path``, None when undetectable
    (tmpfs/overlay/network filesystems, exotic devices, missing sysfs)."""
    try:
        stat = os.stat(path)
    except OSError:
        return None
    major, minor = os.major(stat.st_dev), os.minor(stat.st_dev)
    if major == 0:
        # Unnamed devices: tmpfs, overlayfs, NFS... no backing block device.
        return None
    dev_node = sys_root / "dev" / "block" / f"{major}:{minor}"
    try:
        device_name = dev_node.resolve(strict=True).name
    except OSError:
        return None
    return _device_media_class(device_name, sys_root)
