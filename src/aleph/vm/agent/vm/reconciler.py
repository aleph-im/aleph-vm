"""Storage reconciler: the filesystem is the truth, the registry says who is alive.

Runs at startup, every VOLUME_RECONCILE_INTERVAL, after every GONE retire,
and on admission pressure (make_room). Each pass walks the pools and the
per-VM side directories and applies VOLUME_RETENTION to anything no live VM
owns. It only ever touches directories the agent created, keyed by a
plausible item hash.

Nothing a create is still building is touched: every pass (namespaces and
side directories alike) skips a hash registered through ``creating`` and
anything whose mtime is younger than VOLUME_CREATE_GUARD. The two are
belt and braces, and both matter: a create that outlives the guard is only
protected by ``creating``, which is why wrapping every create path in it is
mandatory, and a create that somehow escaped ``creating`` still has the
guard.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
import shutil
from collections.abc import Collection, Iterator
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
    """Mark a create as in flight; adopt retained directories on entry.

    Every create path must be wrapped in this: it is the only thing that
    keeps a reconcile pass off a half-built VM once the create outlives
    VOLUME_CREATE_GUARD, and the only place a retained directory is adopted
    (spec section 3). A create that stages files, allocates volumes or
    writes a session directory outside this context can have them removed
    from under it by the next pass.
    """
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


def _still_on_disk(namespace: str) -> bool:
    """False when the namespace's directories vanished between being listed
    and being acted on.

    Passes can overlap (a GONE fires one while the periodic pass runs, and
    ``make_room`` evicts from the create path), so losing a race is normal.
    It is not an error, and it is not space this pass may claim to have
    freed.
    """
    return any(True for _ in iter_namespace_dirs(namespace))


def live_hashes(registry: AgentVmRegistry) -> set[str]:
    """Snapshot of the VMs the registry knows are alive.

    A pass runs in a worker thread while the event loop keeps creating and
    retiring VMs, so the set is taken once, on the loop, and handed over;
    iterating the registry from the thread would read it mid-mutation.
    ``list()`` first, so the snapshot itself is one atomic step.
    """
    return {str(vm_hash) for vm_hash, _ in list(registry.items())}


def reconcile_storage(
    registry: AgentVmRegistry,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
    live: Collection[str] | None = None,
) -> ReconcileReport:
    """One reconciliation pass: namespaces, .part files, side directories,
    the retention budget, then the backups.

    ``live`` is the set of hashes a live VM owns. Pass it when the caller
    runs this off the event loop (see ``live_hashes``); it defaults to
    reading ``registry`` directly, which is only safe on the loop itself.
    """
    now = now or datetime.now(tz=timezone.utc)
    guard = timedelta(seconds=settings.VOLUME_CREATE_GUARD)
    live = set(live) if live is not None else live_hashes(registry)
    report = ReconcileReport()
    _reconcile_namespaces(live, now, guard, report, dry_run=dry_run)
    _sweep_parts(now, guard, report, dry_run=dry_run)
    _sweep_side_dirs(live, now, guard, report, dry_run=dry_run)
    _enforce_retention_budget(report, dry_run=dry_run)
    if not dry_run:
        report.backups_removed = sweep_expired_backups(now)
    logger.info("Storage reconcile%s: %s", " (dry run)" if dry_run else "", report.summary())
    return report


def _is_orphan(directory: Path, live: Collection[str], now: datetime, guard: timedelta, *, dry_run: bool) -> bool:
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
    live: Collection[str],
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
        if not dry_run and not _still_on_disk(namespace):
            logger.debug("Skipping %s: another pass got there first", namespace)
            continue
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
    per-VM volume directory (the downloader streams volumes in place).

    A namespace a create holds is skipped whole: a migration import streams
    multi-GB disks into it for far longer than VOLUME_CREATE_GUARD, and its
    ``.part`` files belong to that transfer however old they look.
    """
    for cache in (settings.RUNTIME_CACHE, settings.CODE_CACHE, settings.DATA_CACHE, settings.MESSAGE_CACHE):
        if cache:
            yield Path(cache)
    for directory in iter_namespace_dirs():
        if not is_creating(directory.name):
            yield directory


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


def _is_stale_side_dir(child: Path, mode: str, live: Collection[str], now: datetime, guard: timedelta) -> bool:
    """True when this side directory belongs to a VM that is not here any more.

    Same three questions as the namespace pass, in the same order: is the
    name a VM hash at all, does a live VM (or a create in flight) own it,
    and is it old enough that no create can still be building it. A mount
    point is left alone: unmounting is not this pass's job.
    """
    if not child.is_dir():
        return False
    namespace = child.name if mode == "exact" else child.name.split("_", 1)[0]
    if not _plausible(namespace) or namespace in live or is_creating(namespace):
        return False
    try:
        if now - _mtime(child) < guard:
            return False
    except OSError:
        return False
    return _side_dir_is_removable(child, mode)


def _side_dir_is_removable(child: Path, mode: str) -> bool:
    """The last two questions, about the directory rather than its owner."""
    if os.path.ismount(child):
        logger.warning("Not removing %s: it is a mount point", child)
        return False
    if mode == "prefix" and not _is_empty(child):
        # /mnt belongs to the operator, not to the agent: the only thing the
        # agent puts there is a mount point (storage.create_devmapper mkdirs
        # it and unmounts after the resize), which is empty by construction
        # once unmounted. A name that merely looks like one but holds data
        # (/mnt/externalstoragedisk_1) is the operator's, and an rmtree of it
        # would be a disaster.
        logger.debug("Not removing %s: it is not an empty mount point", child)
        return False
    return True


def _is_empty(directory: Path) -> bool:
    try:
        return not any(directory.iterdir())
    except OSError:
        return False


def _sweep_side_dirs(
    live: Collection[str],
    now: datetime,
    guard: timedelta,
    report: ReconcileReport,
    *,
    dry_run: bool,
) -> None:
    for root, mode in _side_dir_roots():
        if not root.is_dir():
            continue
        for child in list(root.iterdir()):
            if not _is_stale_side_dir(child, mode, live, now, guard):
                continue
            if not dry_run:
                try:
                    if mode == "exact":
                        shutil.rmtree(child)
                    else:
                        # Never an rmtree here: see _is_stale_side_dir.
                        os.rmdir(child)
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


def _pool_free(pool: StoragePool) -> int:
    try:
        return shutil.disk_usage(str(pool.path)).free
    except OSError:
        # Unknown free space: report none, so make_room falls back to its
        # "stop once needed_bytes have been freed" bound instead of looping.
        logger.warning("Volume pool %s not accessible; freeing on the evicted bytes alone", pool.path)
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
    if not _still_on_disk(namespace):
        logger.debug("Not evicting %s: its directories are already gone", namespace)
        return 0
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


def make_room(pool: StoragePool, needed_bytes: int, *, live: Collection[str] | None = None) -> int:
    """Evict reclaimable directories on ``pool``, oldest first, until a
    ``needed_bytes`` create fits on it. Returns the bytes freed on ``pool``.

    Admission pressure, not a quota: the pool's own free space is what has
    to reach ``needed_bytes``, so a pool that already fits the create loses
    nothing. The second bound (``freed >= needed_bytes``) only exists so an
    unreadable or lying filesystem cannot turn this into a loop over every
    retained VM on the pool.

    A marker on a directory a live VM owns is a bug (``_is_orphan`` clears
    those on every pass), but this runs on its own, off the create path, so
    callers should pass ``live`` (see ``live_hashes``) or have reconciled
    first; a hash in ``live`` is never evicted.

    Synchronous, and called from placement: its callers wrap it in
    ``asyncio.to_thread`` so the walk and the removals stay off the event
    loop. It can therefore overlap a pass running in another thread, which is
    why every removal here tolerates a directory that vanished first.
    """
    protected = set(live or ())
    freed = 0
    report = ReconcileReport()
    for directory, _marker in _reclaimable_on(pool):
        if _pool_free(pool) >= needed_bytes or freed >= needed_bytes:
            break
        if directory.name in protected:
            logger.warning("Not evicting %s: a live VM owns it despite its reclaimable marker", directory)
            continue
        if not directory.is_dir():
            # A concurrent pass took it between the listing and now.
            continue
        # Only what this pool gets back: _evict purges the VM on every pool
        # it spans, and the other pools' bytes do not help this create.
        on_this_pool = directory_size_bytes(directory)
        _evict(directory.name, report, dry_run=False)
        freed += on_this_pool
    if freed:
        logger.info("Made room on %s: evicted %s (%d bytes)", pool.path, ", ".join(report.evicted), freed)
    return freed


def _pass_lock(app: web.Application) -> asyncio.Lock:
    """The lock that serializes loop-triggered passes, one per event loop.

    Stored on the app rather than at module level: the app outlives (and in
    the tests, precedes) the loop, and an asyncio.Lock binds to the first
    loop that awaits it.
    """
    loop = asyncio.get_running_loop()
    cached = app.get("storage_reconcile_lock")
    if cached is None or cached[0] is not loop:
        cached = (loop, asyncio.Lock())
        app["storage_reconcile_lock"] = cached
    return cached[1]


async def reconcile_now(app: web.Application, *, dry_run: bool = False) -> ReconcileReport:
    """One pass, off the event loop, serialized against the other passes.

    A GONE fires a pass while the periodic one may still be running: two
    threads walking the same pools would evict the same directories twice,
    double-counting the bytes freed and logging each removal twice. The
    waiting pass is not redundant, it re-reads the filesystem when it starts.
    """
    registry = app["vm_registry"]
    async with _pass_lock(app):
        live = live_hashes(registry)
        return await asyncio.to_thread(reconcile_storage, registry, dry_run=dry_run, live=live)


def _log_startup_preview(preview: ReconcileReport) -> None:
    """Announce what the first pass is about to remove, per pool.

    On an upgraded node the first pass finds every directory leaked by the
    bugs this work fixes, which under ``reap`` is a one-shot cleanup of
    potentially a lot of data (spec section 6). The per-pool breakdown is
    what lets an operator match the log against the disk whose free space
    jumped.
    """
    namespaces = [*preview.purged_orphans, *preview.marked_orphans, *preview.evicted]
    if not namespaces:
        return
    logger.warning(
        "Startup storage reconcile will purge %d orphan(s), mark %d, evict %d, freeing about %d bytes "
        "(VOLUME_RETENTION=%s)",
        len(preview.purged_orphans),
        len(preview.marked_orphans),
        len(preview.evicted),
        preview.bytes_freed,
        settings.VOLUME_RETENTION,
    )
    for pool in get_pools():
        on_pool = [pool.path / namespace for namespace in namespaces if (pool.path / namespace).is_dir()]
        if not on_pool:
            continue
        logger.warning(
            "Startup storage reconcile: pool %d (%s) gives back %d directory(ies), %d bytes",
            pool.index,
            pool.path,
            len(on_pool),
            sum(directory_size_bytes(directory) for directory in on_pool),
        )


async def reconcile_at_startup(app: web.Application) -> None:
    """on_startup hook: one pass, preceded by a summary of what the pass will
    remove, so an operator reading the log knows why free space jumped after
    an upgrade."""
    preview = await reconcile_now(app, dry_run=True)
    _log_startup_preview(preview)
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
