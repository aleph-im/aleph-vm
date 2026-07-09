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
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError

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
            resolved_slave_classes = [slave_class for slave_class in slave_classes if slave_class is not None]
            if len(resolved_slave_classes) != len(slave_classes):
                return None
            return max(resolved_slave_classes, key=lambda slave_class: slave_class.slowness)
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


def _pool_free_bytes(pool: StoragePool) -> int | None:
    try:
        return shutil.disk_usage(str(pool.path)).free
    except OSError:
        logger.error("Volume pool %s not accessible, skipping", pool.path)
        return None


def select_pool(size_mib: int) -> StoragePool:
    """The eligible pool with the most free bytes that fits ``size_mib``.

    Ties break on the lowest pool index (dict iteration is stable and pools
    are scanned in index order, so the first max wins). Unreachable pools are
    skipped: a dead disk stops receiving placements without failing the agent.
    """
    required_bytes = size_mib * 1024 * 1024
    best: StoragePool | None = None
    best_free = -1
    for pool in get_pools():
        if not pool.vm_eligible:
            continue
        free = _pool_free_bytes(pool)
        if free is None:
            continue
        if free > best_free:
            best, best_free = pool, free
    if best is None or best_free < required_bytes:
        msg = f"No volume pool has {size_mib} MiB free"
        raise InsufficientResourcesError(
            msg,
            required={"disk_mib": size_mib},
            available={"disk_mib": max(best_free, 0) // (1024 * 1024)},
        )
    return best


def find_existing_volume(namespace: str, filename: str) -> Path | None:
    """The first ``{pool}/{namespace}/{filename}`` that exists, in pool order."""
    matches = [pool.path / namespace / filename for pool in get_pools() if (pool.path / namespace / filename).is_file()]
    if not matches:
        return None
    if len(matches) > 1:
        logger.warning("Volume %s/%s found in %d pools; using %s", namespace, filename, len(matches), matches[0])
    return matches[0]


def volume_path_for(namespace: str, filename: str, size_mib: int) -> Path:
    """The host path for a volume: its existing file when one pool already
    holds it (sticky), else a fresh placement on the best pool. The namespace
    directory is created; the volume file itself is not."""
    existing = find_existing_volume(namespace, filename)
    if existing is not None:
        return existing
    pool = select_pool(size_mib)
    parent = pool.path / namespace
    parent.mkdir(parents=True, exist_ok=True)
    return parent / filename


def iter_namespace_dirs(namespace: str | None = None) -> Iterator[Path]:
    """Existing per-namespace dirs across pools: ``{pool}/{namespace}``, or
    every namespace dir in every pool when ``namespace`` is None."""
    for pool in get_pools():
        if namespace is not None:
            candidate = pool.path / namespace
            if candidate.is_dir():
                yield candidate
            continue
        try:
            entries = sorted(pool.path.iterdir())
        except OSError:
            logger.error("Volume pool %s not accessible, skipping", pool.path)
            continue
        for entry in entries:
            if entry.is_dir():
                yield entry


def pools_disk_usage() -> tuple[int, int]:
    """(total, free) bytes across pools, filesystems deduplicated by st_dev
    so two pool directories on one filesystem count once."""
    seen_devices: set[int] = set()
    total = free = 0
    for pool in get_pools():
        try:
            st_dev = os.stat(pool.path).st_dev
            usage = shutil.disk_usage(str(pool.path))
        except OSError:
            logger.warning("Volume pool %s not accessible, ignoring in accounting", pool.path)
            continue
        if st_dev in seen_devices:
            continue
        seen_devices.add(st_dev)
        total += usage.total
        free += usage.free
    return total, free


def roomiest_pool_free_bytes() -> int:
    """Free bytes on the emptiest eligible pool (the largest single volume
    that could still be placed); 0 when no pool is reachable."""
    frees = [free for pool in get_pools() if pool.vm_eligible and (free := _pool_free_bytes(pool)) is not None]
    return max(frees, default=0)
