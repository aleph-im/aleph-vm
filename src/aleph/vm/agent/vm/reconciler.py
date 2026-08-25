"""Storage reconciler: the filesystem is the truth, the registry says who is alive.

Runs at startup, every VOLUME_RECONCILE_INTERVAL, after every GONE retire,
and on admission pressure (make_room). Each pass walks the pools and the
per-VM side directories and applies VOLUME_RETENTION to anything no live VM
owns. It only ever touches directories the agent created, keyed by a
plausible item hash; a create in flight (``creating``) or younger than
VOLUME_CREATE_GUARD is left alone.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from aiohttp import web

from aleph.vm.agent.vm.backup import sweep_expired_backups
from aleph.vm.agent.vm.purge import _ITEM_HASH_PATTERN, purge_vm_storage
from aleph.vm.agent.vm.reclaimable import (
    ReclaimableMarker,
    adopt,
    clear_marker,
    directory_size_bytes,
    iter_reclaimable,
    mark_reclaimable,
    read_marker,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import StoragePool, get_pools, iter_namespace_dirs
from aleph.vm.utils import create_task_log_exceptions

logger = logging.getLogger(__name__)

# Where create_devmapper mounts a volume while resizing it (storage.py mounts
# /mnt/{namespace}_{volume name}).
MOUNT_ROOT = Path("/mnt")
STAGING_KINDS = ("vprogram", "snp-instance")

_creating: set[str] = set()


@dataclass
class ReconcileReport:
    purged_orphans: list[str] = field(default_factory=list)
    marked_orphans: list[str] = field(default_factory=list)
    evicted: list[str] = field(default_factory=list)
    parts_removed: int = 0
    side_dirs_removed: int = 0
    backups_removed: int = 0
    bytes_freed: int = 0

    def summary(self) -> str:
        return (
            f"orphans purged={len(self.purged_orphans)} marked={len(self.marked_orphans)}, "
            f"evicted={len(self.evicted)}, parts={self.parts_removed}, side dirs={self.side_dirs_removed}, "
            f"backups={self.backups_removed}, freed={self.bytes_freed} bytes"
        )


@contextmanager
def creating(namespace: str) -> Iterator[None]:
    """Mark a create as in flight; adopt retained directories on entry."""
    adopt(namespace)
    _creating.add(namespace)
    try:
        yield
    finally:
        _creating.discard(namespace)


def is_creating(namespace: str) -> bool:
    return namespace in _creating


def _plausible(name: str) -> bool:
    return bool(_ITEM_HASH_PATTERN.match(name))


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _dir_bytes(namespace: str) -> int:
    """Allocated bytes of a VM's volumes, on every pool it spans."""
    return sum(directory_size_bytes(directory) for directory in iter_namespace_dirs(namespace))


def reconcile_storage(
    registry: AgentVmRegistry,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
) -> ReconcileReport:
    """One reconciliation pass: namespaces, .part files, side directories,
    the retention budget, then the backups."""
    now = now or datetime.now(tz=timezone.utc)
    guard = timedelta(seconds=settings.VOLUME_CREATE_GUARD)
    live = {str(vm_hash) for vm_hash, _ in registry.items()}
    report = ReconcileReport()
    _reconcile_namespaces(live, now, guard, report, dry_run=dry_run)
    _sweep_parts(now, guard, report, dry_run=dry_run)
    _sweep_side_dirs(live, report, dry_run=dry_run)
    _enforce_retention_budget(report, dry_run=dry_run)
    if not dry_run:
        report.backups_removed = sweep_expired_backups(now)
    logger.info("Storage reconcile%s: %s", " (dry run)" if dry_run else "", report.summary())
    return report


def _is_orphan(directory: Path, live: set[str], now: datetime, guard: timedelta, *, dry_run: bool) -> bool:
    """True when nothing owns ``directory`` and the reconciler may act on it.

    A live VM's directory is owned; a stale marker on one (a VM re-created
    without going through ``creating()``) is cleared here so the budget pass
    cannot evict a running VM's disks. A directory that already carries a
    marker is reclaimable, not an orphan: the budget pass owns it. What is
    left is unowned, unless it is young enough to be a create in flight.
    """
    namespace = directory.name
    if namespace in live or is_creating(namespace):
        if read_marker(directory) is not None and not dry_run:
            clear_marker(directory)
        return False
    if read_marker(directory) is not None:
        return False
    try:
        return now - _mtime(directory) >= guard
    except OSError:
        return False


def _reconcile_namespaces(
    live: set[str],
    now: datetime,
    guard: timedelta,
    report: ReconcileReport,
    *,
    dry_run: bool,
) -> None:
    seen: set[str] = set()
    for directory in list(iter_namespace_dirs()):
        namespace = directory.name
        if not _plausible(namespace):
            # A pool is usually a mountpoint, so lost+found is expected here:
            # debug, not a warning repeated every VOLUME_RECONCILE_INTERVAL.
            logger.debug("Ignoring %s: not a VM directory", directory)
            continue
        # A VM spanning two pools is handled once: purging or marking covers
        # every pool it is on.
        if namespace in seen or not _is_orphan(directory, live, now, guard, dry_run=dry_run):
            continue
        seen.add(namespace)
        if settings.VOLUME_RETENTION == "keep":
            report.marked_orphans.append(namespace)
            if not dry_run:
                mark_reclaimable(namespace, "orphan", now=now)
        else:
            report.purged_orphans.append(namespace)
            report.bytes_freed += _dir_bytes(namespace)
            if not dry_run:
                purge_vm_storage(namespace)


def _part_roots() -> Iterator[Path]:
    """Where a half-downloaded file can sit: the four caches, and every
    per-VM volume directory (the downloader streams volumes in place)."""
    for cache in (settings.RUNTIME_CACHE, settings.CODE_CACHE, settings.DATA_CACHE, settings.MESSAGE_CACHE):
        if cache:
            yield Path(cache)
    yield from iter_namespace_dirs()


def _sweep_parts(now: datetime, guard: timedelta, report: ReconcileReport, *, dry_run: bool) -> None:
    for root in _part_roots():
        try:
            parts = list(root.glob("*.part"))
        except OSError:
            continue
        for part in parts:
            try:
                stat = part.stat()
                if now - datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc) < guard:
                    continue
                if not dry_run:
                    part.unlink()
                    logger.info("Removed stale partial download %s", part)
                report.parts_removed += 1
                report.bytes_freed += stat.st_blocks * 512
            except OSError:
                logger.warning("Failed to remove %s", part, exc_info=True)


def _side_dir_roots() -> Iterator[tuple[Path, str]]:
    """(root, how the hash is derived from the child name)."""
    if settings.CONFIDENTIAL_SESSION_DIRECTORY:
        yield Path(settings.CONFIDENTIAL_SESSION_DIRECTORY), "exact"
    for kind in STAGING_KINDS:
        yield Path(settings.EXECUTION_ROOT) / kind, "exact"
    yield MOUNT_ROOT, "prefix"  # /mnt/{namespace}_{volume name}


def _sweep_side_dirs(live: set[str], report: ReconcileReport, *, dry_run: bool) -> None:
    for root, mode in _side_dir_roots():
        if not root.is_dir():
            continue
        for child in list(root.iterdir()):
            if not child.is_dir():
                continue
            namespace = child.name if mode == "exact" else child.name.split("_", 1)[0]
            if not _plausible(namespace) or namespace in live or is_creating(namespace):
                continue
            if os.path.ismount(child):
                logger.warning("Not removing %s: it is a mount point", child)
                continue
            if not dry_run:
                try:
                    shutil.rmtree(child)
                except OSError:
                    logger.warning("Failed to remove %s", child, exc_info=True)
                    continue
                logger.info("Removed the stale side directory %s", child)
            report.side_dirs_removed += 1


def _pool_total(pool: StoragePool) -> int:
    try:
        return shutil.disk_usage(str(pool.path)).total
    except OSError:
        return 0


def _reclaimable_on(pool: StoragePool) -> list[tuple[Path, ReclaimableMarker]]:
    """The pool's reclaimable directories, oldest marker first.

    Implausibly named directories are dropped here rather than left to fail
    the ``_checked_namespace`` guard mid-pass: a hand-made marker under a
    directory nobody named after a VM must not abort a reconcile.
    """
    entries = [
        (directory, marker)
        for directory, marker in iter_reclaimable()
        if directory.parent == pool.path and _plausible(directory.name)
    ]
    entries.sort(key=lambda item: item[1].reclaimable_since)
    return entries


def _evict(namespace: str, report: ReconcileReport, *, dry_run: bool) -> int:
    size = _dir_bytes(namespace)
    report.evicted.append(namespace)
    report.bytes_freed += size
    if not dry_run:
        purge_vm_storage(namespace)
    return size


def _enforce_retention_budget(report: ReconcileReport, *, dry_run: bool) -> None:
    reap = settings.VOLUME_RETENTION == "reap"
    for pool in get_pools():
        entries = _reclaimable_on(pool)
        if not entries:
            continue
        # Under reap nothing is retained: a node switched from keep to reap
        # gives back everything marked, whatever the budget says.
        budget = 0 if reap else parse_budget(settings.VOLUME_RETENTION_BUDGET, _pool_total(pool))
        total = sum(marker.size_bytes for _, marker in entries)
        for directory, marker in entries:
            if not reap and total <= budget:
                break
            total -= marker.size_bytes
            if directory.name in report.evicted:
                # A VM spanning two pools is purged whole on the first one.
                continue
            _evict(directory.name, report, dry_run=dry_run)


def make_room(pool: StoragePool, needed_bytes: int) -> int:
    """Evict reclaimable directories on ``pool``, oldest first, until
    ``needed_bytes`` have been freed or nothing reclaimable is left. Returns
    the bytes freed."""
    freed = 0
    report = ReconcileReport()
    for directory, _marker in _reclaimable_on(pool):
        if freed >= needed_bytes:
            break
        freed += _evict(directory.name, report, dry_run=False)
    if freed:
        logger.info("Made room on %s: evicted %s (%d bytes)", pool.path, ", ".join(report.evicted), freed)
    return freed


async def reconcile_now(app: web.Application) -> ReconcileReport:
    return await asyncio.to_thread(reconcile_storage, app["vm_registry"])


async def reconcile_at_startup(app: web.Application) -> None:
    """on_startup hook: one pass, preceded by a summary of what the pass will
    remove, so an operator reading the log knows why free space jumped after
    an upgrade."""
    registry = app["vm_registry"]
    preview = await asyncio.to_thread(reconcile_storage, registry, dry_run=True)
    if preview.purged_orphans or preview.marked_orphans or preview.evicted:
        logger.warning(
            "Startup storage reconcile will purge %d orphan(s), mark %d, evict %d, freeing about %d bytes "
            "(VOLUME_RETENTION=%s)",
            len(preview.purged_orphans),
            len(preview.marked_orphans),
            len(preview.evicted),
            preview.bytes_freed,
            settings.VOLUME_RETENTION,
        )
    await reconcile_now(app)


async def periodic_reconcile(app: web.Application) -> None:
    interval = settings.VOLUME_RECONCILE_INTERVAL
    # Jitter, not cryptography: spread the passes of a fleet of nodes.
    await asyncio.sleep(random.uniform(0, interval))  # noqa: S311
    while True:
        try:
            await reconcile_now(app)
        except Exception as error:
            if isinstance(error, RuntimeError) and "Event loop is closed" in str(error):
                return
            logger.warning("Storage reconcile failed: %s", error, exc_info=True)
        await asyncio.sleep(interval * random.uniform(0.85, 1.15))  # noqa: S311


async def start_storage_reconcile_task(app: web.Application) -> None:
    app["storage_reconcile"] = create_task_log_exceptions(periodic_reconcile(app), name="storage_reconcile")


async def stop_storage_reconcile_task(app: web.Application) -> None:
    task = app.get("storage_reconcile")
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        logger.debug("Task storage_reconcile is cancelled now")
