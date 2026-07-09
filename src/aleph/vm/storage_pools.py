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

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aleph.vm.conf import settings

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


POOL_MARKER_NAME = ".aleph-vm-pool"
POOL_MARKER_VERSION = 1


@dataclass(frozen=True)
class StoragePool:
    path: Path
    media_class: MediaClass
    index: int

    @property
    def vm_eligible(self) -> bool:
        # Pool 0 (PERSISTENT_VOLUMES_DIR) is always eligible, even on HDD:
        # existing nodes must not break. setup_pools() warns instead.
        return self.index == 0 or self.media_class.vm_eligible


class StoragePoolConfigError(ValueError):
    """A configured volume pool cannot be used; startup must abort."""


_pools: list[StoragePool] | None = None


def _parse_pool_entry(entry: str) -> tuple[Path, MediaClass | None]:
    path_part, separator, class_part = entry.partition("=")
    override: MediaClass | None = None
    if separator:
        try:
            override = MediaClass(class_part.strip())
        except ValueError as error:
            msg = (
                f"Unknown media class {class_part.strip()!r} in VOLUME_POOLS entry {entry!r} "
                "(expected nvme, ssd or hdd)"
            )
            raise StoragePoolConfigError(msg) from error
    return Path(path_part.strip()), override


def _adoption_registry_path() -> Path:
    return Path(settings.EXECUTION_ROOT) / "volume-pools.json"


def _load_adopted() -> set[str]:
    try:
        return set(json.loads(_adoption_registry_path().read_text()))
    except (OSError, ValueError):
        return set()


def _record_adopted(path: Path) -> None:
    adopted = _load_adopted()
    adopted.add(str(path))
    _adoption_registry_path().write_text(json.dumps(sorted(adopted)) + "\n")


def _adopt_pool(path: Path, media_class: MediaClass) -> None:
    """Write the in-pool marker on first use; refuse a pool whose marker
    vanished after adoption (the disk is very likely not mounted and writes
    would silently land on the filesystem below the mountpoint)."""
    marker = path / POOL_MARKER_NAME
    if marker.is_file():
        _record_adopted(path)  # heal the registry after e.g. a restore
        return
    if str(path) in _load_adopted():
        msg = (
            f"Volume pool {path} was adopted before but its {POOL_MARKER_NAME} marker is gone. "
            "Most likely the disk is not mounted; refusing to write to whatever is at that path."
        )
        raise StoragePoolConfigError(msg)
    marker.write_text(json.dumps({"version": POOL_MARKER_VERSION, "media_class": media_class.value}) + "\n")
    _record_adopted(path)
    logger.info("Adopted %s as a %s volume pool", path, media_class.value)


def setup_pools(sys_root: Path = Path("/sys")) -> list[StoragePool]:
    """Validate, classify and adopt the configured pools.

    Call once at agent startup, after ``settings.setup()``. Raises
    StoragePoolConfigError on any misconfiguration: never degrade silently.
    """
    global _pools  # noqa: PLW0603
    pools: list[StoragePool] = []

    default_dir = Path(settings.PERSISTENT_VOLUMES_DIR)
    default_class = detect_media_class(default_dir, sys_root)
    if default_class is MediaClass.HDD:
        logger.warning(
            "PERSISTENT_VOLUMES_DIR %s is on rotational storage; VM volumes will be slow",
            default_dir,
        )
    # Record the honest media class (SSD only as the undetectable fallback);
    # pool 0 stays VM-eligible regardless, see StoragePool.vm_eligible.
    pools.append(StoragePool(path=default_dir, media_class=default_class or MediaClass.SSD, index=0))

    for position, entry in enumerate(settings.VOLUME_POOLS, start=1):
        path, override = _parse_pool_entry(entry)
        if not path.is_dir():
            msg = f"Volume pool {path} does not exist (is the disk mounted?)"
            raise StoragePoolConfigError(msg)
        media_class = override or detect_media_class(path, sys_root)
        if media_class is None:
            msg = f"Cannot detect the media class of {path}; add an explicit override, e.g. {path}=ssd"
            raise StoragePoolConfigError(msg)
        if media_class is MediaClass.HDD:
            msg = (
                f"Volume pool {path} is rotational storage (HDD); VM volumes require ssd/nvme. "
                "Point CACHE_ROOT or BACKUP_DIRECTORY at it instead."
            )
            raise StoragePoolConfigError(msg)
        _adopt_pool(path, media_class)
        pools.append(StoragePool(path=path, media_class=media_class, index=position))

    _pools = pools
    return pools


def get_pools() -> list[StoragePool]:
    """The active pools. Falls back to pool 0 alone when setup_pools() has
    not run (library/test callers); the agent CLI always runs it."""
    if _pools is None:
        return [StoragePool(path=Path(settings.PERSISTENT_VOLUMES_DIR), media_class=MediaClass.SSD, index=0)]
    return _pools


def reset_pools() -> None:
    """Drop the setup_pools() result (tests)."""
    global _pools  # noqa: PLW0603
    _pools = None
