"""Bounded download caches: a budget per cache root, LRU eviction of the
entries no live VM and no retained disk still needs.

The four caches (runtime, code, data, message) are flat directories keyed by
item hash, shared by every VM that names the same hash. Nothing used to
remove anything from them: a node accumulated every runtime, every program
archive and every parent image it had ever been asked for until the disk was
full. Each root now gets ``CACHE_BUDGET`` and the reconciler evicts what is
over it, least recently used first (the downloader touches an entry's mtime
on every cache hit, so "recently used" is a real signal and not just
"recently downloaded").

Two things are never evicted. An entry a live VM names is off limits, since
its VM is running on it right now; if live references alone exceed the
budget, this logs and stops, because that is a capacity problem admission
should have refused, not something eviction can fix. An entry a
``.reclaimable`` marker names in ``depends_on`` is a parent image a retained
overlay is built on: reclaiming the overlay comes first, and only then does
its parent become evictable (spec section 4).

A parent image also has a shared read-only loop device and a
``/dev/mapper/<ref>`` device on top of it, built once by
``storage.create_devmapper`` for every VM using that image. Unlinking the
file while those exist frees nothing (the loop pins the inode), so the
device teardown belongs here, with the eviction (spec section 5), and an
image whose device still has holders is not evicted at all.

Residual race, accepted: a create that has downloaded a cache entry but has
not recorded its VM yet holds no reference this module can see. The mtime
touch makes such an entry the most recently used one, so LRU reaches it
last, and the next create simply re-downloads what was taken.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from collections.abc import Callable, Collection, Iterable
from dataclasses import dataclass
from pathlib import Path

from aleph.vm.agent.vm.purge import _ITEM_HASH_PATTERN, purge_vm_storage
from aleph.vm.agent.vm.reclaimable import (
    MANIFEST_REF_KINDS,
    ReclaimableMarker,
    file_size_bytes,
    iter_content_refs,
    iter_reclaimable,
    refs_from_content,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.storage import (
    DEVICE_MAPPER_DIRECTORY,
    DEVICE_NAME_MAX_BYTES,
    reserve_download,
    reserved_downloads,
)
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import iter_namespace_dirs
from aleph.vm.utils import create_task_log_exceptions, run_in_subprocess

logger = logging.getLogger(__name__)

MIB = 1024 * 1024
# A runtime manifest is a few kilobytes of JSON; anything larger in the data
# cache is a payload, not a manifest, and is not read.
MANIFEST_MAX_BYTES = 64 * 1024
# Where the kernel lists the loop devices and what backs them. Read rather
# than `losetup -j` when the backing file is already unlinked: sysfs keeps
# the path (with a " (deleted)" suffix), losetup cannot stat it any more.
SYS_BLOCK = Path("/sys/block")
SYS_DEV_BLOCK = Path("/sys/dev/block")
DELETED_SUFFIX = " (deleted)"
# Suffixes of files that are not cache entries: a download in flight
# (download_file) and a message being written (storage.get_message).
IN_FLIGHT_SUFFIXES = (".part", ".tmp")


# The reconciler's most recent live set. The admission hook runs on the create
# path, off any pass, and cannot ask the supervisor what it is running; the
# pass can, so it leaves its answer here. Session state, deliberately: an
# agent that has not reconciled yet has no live set, and admission treats
# that as "do not evict" rather than as "nothing is live".
_live_snapshot: frozenset[str] | None = None


def record_live_snapshot(live: Collection[str]) -> None:
    """Publish the live set a pass established, for the admission hook."""
    global _live_snapshot  # noqa: PLW0603
    _live_snapshot = frozenset(str(namespace) for namespace in live)


def live_snapshot() -> frozenset[str] | None:
    return _live_snapshot


@dataclass(frozen=True)
class CacheEntry:
    path: Path
    size_bytes: int
    mtime: float


def cache_roots() -> list[Path]:
    """The download caches that exist, deduplicated."""
    roots: list[Path] = []
    for setting in (settings.RUNTIME_CACHE, settings.CODE_CACHE, settings.DATA_CACHE, settings.MESSAGE_CACHE):
        if not setting:
            continue
        root = Path(setting)
        if root.is_dir() and root not in roots:
            roots.append(root)
    return roots


def _runtime_cache() -> Path | None:
    return Path(settings.RUNTIME_CACHE) if settings.RUNTIME_CACHE else None


def cache_entries(root: Path) -> list[CacheEntry]:
    """The regular files directly inside ``root``, oldest mtime first.

    Sizes come from ``file_size_bytes`` (allocated blocks), the same
    definition the volume budgets use, and a symlink is not an entry: what it
    points at is not this cache's space.
    """
    entries: list[CacheEntry] = []
    try:
        children = list(root.iterdir())
    except OSError:
        logger.warning("Cache directory %s is not readable", root, exc_info=True)
        return entries
    for path in children:
        if path.suffix in IN_FLIGHT_SUFFIXES:
            continue
        size = file_size_bytes(path)  # 0 for a symlink, a directory or a vanished file
        if not path.is_file() or path.is_symlink():
            continue
        try:
            mtime = path.lstat().st_mtime
        except OSError:
            continue
        entries.append(CacheEntry(path=path, size_bytes=size, mtime=mtime))
    entries.sort(key=lambda entry: entry.mtime)
    return entries


def in_flight_bytes(root: Path) -> int:
    """What ``root`` owes to downloads that have not finished.

    Two overlapping things, counted once. A ``.part`` or ``.tmp`` file holds
    real blocks the moment it is written, and it is not a cache entry, so
    ``cache_entries`` skips it and nothing else would charge for it. And a
    download admission has already approved holds room that does not exist on
    disk yet: without it two creates arriving together are both told there is
    space only one of them can have. For a reservation still being written the
    bigger of the two is the honest figure, never their sum.
    """
    reserved = reserved_downloads()
    total = 0
    counted: set[Path] = set()
    for path, size_bytes in reserved.items():
        if path.parent != root:
            continue
        total += max(size_bytes, file_size_bytes(path))
        counted.add(path)
    try:
        children = list(root.iterdir())
    except OSError:
        return total
    for path in children:
        if path.suffix not in IN_FLIGHT_SUFFIXES or path in counted:
            continue
        total += file_size_bytes(path)
    return total


def _root_usage(root: Path, entries: list[CacheEntry]) -> int:
    return sum(entry.size_bytes for entry in entries) + in_flight_bytes(root)


def _entry_refs(path: Path) -> set[str]:
    """The item hashes an entry's file name can stand for.

    The three binary caches key an entry by the hash itself; the message
    cache appends ``.json`` to it (``storage.get_message``).
    """
    return {path.name, path.stem}


def _manifest_bundle_ref(ref: str) -> str | None:
    """The bundle tarball a locally cached runtime manifest names, or None.

    A V-PROGRAM and a confidential instance pin their runtime by the hash of
    a small JSON manifest, and the tarball it points at is a ref no message
    carries: it is knowable only from the manifest. So it is protected when
    the manifest is here to read, and treated as a re-downloadable artifact
    when it is not (nothing runs off the tarball itself, which is verified
    and extracted into the VM's staging directory at create time).

    Bounded on purpose: only DATA_CACHE (where both manifests are fetched to)
    and only a small file, so this never reads a runtime image looking for
    JSON.
    """
    if not settings.DATA_CACHE or not _safe_ref(ref):
        return None
    path = Path(settings.DATA_CACHE) / ref
    try:
        if not path.is_file() or path.stat().st_size > MANIFEST_MAX_BYTES:
            return None
        manifest = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    bundle = manifest.get("bundle") if isinstance(manifest, dict) else None
    bundle_ref = bundle.get("ref") if isinstance(bundle, dict) else None
    return str(bundle_ref) if bundle_ref else None


def _record_refs(content, vm_hash: object) -> set[str]:
    """Every cache entry one live record names.

    ``reclaimable.iter_content_refs`` is the enumeration; this adds what only
    the filesystem knows, the bundle tarball named by a cached manifest.
    """
    refs = refs_from_content(content, vm_hash=str(vm_hash) if vm_hash else None)
    for kind, ref in iter_content_refs(content):
        if kind not in MANIFEST_REF_KINDS:
            continue
        bundle_ref = _manifest_bundle_ref(ref)
        if bundle_ref:
            refs.add(bundle_ref)
    return refs


def live_refs(registry: AgentVmRegistry) -> set[str]:
    """The refs live records name: never evictable, whatever the budget."""
    refs: set[str] = set()
    for vm_hash, record in list(registry.items()):
        refs |= _record_refs(record.message, vm_hash)
    return refs


def _is_creating(namespace: str) -> bool:
    """Whether a create currently holds this namespace.

    Imported late on purpose: the reconciler imports this module, so this
    module cannot import it back at load time. The set is asked at call time
    anyway, which is the only moment its answer is worth anything.
    """
    from aleph.vm.agent.vm.reconciler import is_creating

    return is_creating(namespace)


def _markers() -> list[tuple[Path, ReclaimableMarker]]:
    """The reclaimable directories, oldest marker first, implausibly named
    ones dropped (they can never be handed to ``purge_vm_storage``)."""
    entries = [(directory, marker) for directory, marker in iter_reclaimable() if _plausible(directory.name)]
    entries.sort(key=lambda item: item[1].reclaimable_since)
    return entries


def _plausible(name: str) -> bool:
    return bool(_ITEM_HASH_PATTERN.match(name))


def _marker_refs(markers: Iterable[tuple[Path, ReclaimableMarker]]) -> set[str]:
    return {ref for _directory, marker in markers for ref in marker.depends_on}


def referenced_hashes(registry: AgentVmRegistry) -> set[str]:
    """Live refs plus what the ``.reclaimable`` markers pin."""
    return live_refs(registry) | _marker_refs(_markers())


def cache_budget_bytes(root: Path) -> int:
    return parse_budget(settings.CACHE_BUDGET, shutil.disk_usage(str(root)).total)


def _safe_ref(ref: str) -> bool:
    """Whether ``ref`` can be handed to dmsetup as a device name.

    A cache entry's name is a path component, so it can hold no ``/`` and be
    neither ``.`` nor ``..``; this says so anyway, and refuses a name that a
    subprocess would read as an option.
    """
    if not ref or ref in (".", "..") or "/" in ref or ref.startswith("-"):
        return False
    return len(ref.encode()) <= DEVICE_NAME_MAX_BYTES


def _is_block_device(path: Path) -> bool:
    try:
        return path.is_block_device()
    except OSError:
        return False


def parent_device_is_free(ref: str) -> bool:
    """Whether the parent image's shared device can go with the image.

    ``create_devmapper`` stacks one ``<namespace>_base`` device per VM on top
    of ``/dev/mapper/<ref>``; the kernel lists those in the device's
    ``holders`` directory. Fail closed: an unanswerable question (no sysfs
    entry, an unreadable directory) counts as held, because evicting an image
    a running VM's snapshot is built on takes that VM's disk with it.
    """
    if not _safe_ref(ref):
        return False
    device = Path(DEVICE_MAPPER_DIRECTORY) / ref
    if not _is_block_device(device):
        return True
    try:
        rdev = device.stat().st_rdev
        holders = [path.name for path in (SYS_DEV_BLOCK / f"{os.major(rdev)}:{os.minor(rdev)}" / "holders").iterdir()]
    except OSError:
        logger.warning("Cannot tell whether the parent device %s is still in use; keeping it", ref, exc_info=True)
        return False
    if holders:
        logger.info("Parent device %s is still held by %s", ref, ", ".join(sorted(holders)))
        return False
    return True


def parent_refs_of(evicted: list[Path]) -> list[str]:
    """The runtime-cache refs among ``evicted``: the images whose shared
    device and loop device the caller has to remove."""
    runtime = _runtime_cache()
    if runtime is None:
        return []
    return [path.name for path in evicted if path.parent == runtime]


def _loop_devices_backing(path: Path) -> list[str]:
    """The loop devices backed by ``path``, found through sysfs.

    ``storage.detach_loop_devices`` asks ``losetup -j``, which has to stat
    the backing file; an evicted cache entry is already unlinked, and the
    loop that still pins its blocks is exactly the one that has to go. sysfs
    keeps the path, marked " (deleted)".
    """
    devices: list[str] = []
    try:
        backing_files = sorted(SYS_BLOCK.glob("loop*/loop/backing_file"))
    except OSError:
        return devices
    for backing_file in backing_files:
        try:
            backing = backing_file.read_text().strip()
        except OSError:
            continue
        if backing.removesuffix(DELETED_SUFFIX) == str(path):
            devices.append(f"/dev/{backing_file.parent.parent.name}")
    return devices


async def remove_parent_device(ref: str) -> None:
    """Remove the shared read-only device of an evicted parent image.

    The inverse of what ``create_devmapper`` builds once per image rather
    than once per VM: the ``/dev/mapper/<ref>`` linear target and the
    read-only loop device under it. ``remove_devmapper`` deliberately leaves
    both alone, because they are shared; the cache pass owns them, and calls
    this only for an image it has just evicted (so no ``<ns>_base`` device
    was stacked on it, see ``parent_device_is_free``).
    """
    if not _safe_ref(ref):
        logger.error("Refusing to remove an implausible parent device name: %r", ref)
        return
    runtime = _runtime_cache()
    cache_path = runtime / ref if runtime is not None else None
    if cache_path is not None and cache_path.exists():
        # A create downloaded the image again between the eviction and this
        # teardown: the devices are that create's now, and removing them
        # would break the VM it is building.
        logger.info("Not removing the devices of %s: the image is back in the cache", ref)
        return
    device = Path(DEVICE_MAPPER_DIRECTORY) / ref
    if _is_block_device(device):
        await run_in_subprocess(["dmsetup", "remove", "--retry", ref])
        logger.info("Removed the shared device of the evicted parent image %s", ref)
    if cache_path is None:
        return
    for loop_device in _loop_devices_backing(cache_path):
        await run_in_subprocess(["losetup", "-d", loop_device])
        logger.info("Detached loop device %s of the evicted parent image %s", loop_device, ref)


async def remove_parent_devices(refs: list[str]) -> None:
    """``remove_parent_device`` for each ref, one failure never stopping the
    others: a device left behind costs disk, not correctness."""
    for ref in refs:
        try:
            await remove_parent_device(ref)
        except Exception:
            logger.exception("Removing the device of the evicted parent image %s failed", ref)


def release_parent_devices(evicted: list[Path]) -> None:
    """Schedule the device teardown of the parent images among ``evicted``.

    For the synchronous callers that run on the event loop (the download
    admission hook): the teardown is a subprocess away and cannot be awaited
    from here. Nothing else picks these up later, since the entry itself is
    already gone by the time the next pass walks the cache.
    """
    refs = parent_refs_of(evicted)
    if not refs:
        return
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        logger.warning("No event loop to remove the devices of %s on", ", ".join(refs))
        return
    create_task_log_exceptions(remove_parent_devices(refs), name="remove parent devices")


def _may_evict(entry: CacheEntry) -> bool:
    """Whether this entry's file can be unlinked right now.

    Only parent images have devices on top of them, and only they can be
    refused here.
    """
    runtime = _runtime_cache()
    if runtime is None or entry.path.parent != runtime:
        return True
    if parent_device_is_free(entry.path.name):
        return True
    logger.warning("Not evicting %s: its device-mapper device is still held", entry.path)
    return False


def _evict_entry(entry: CacheEntry, evicted: list[Path], *, dry_run: bool) -> bool:
    if dry_run:
        evicted.append(entry.path)
        return True
    try:
        entry.path.unlink()
    except FileNotFoundError:
        logger.debug("Cache entry %s was already gone", entry.path)
        return False
    except OSError:
        logger.warning("Failed to evict %s", entry.path, exc_info=True)
        return False
    logger.info("Evicted cache entry %s (%d bytes)", entry.path, entry.size_bytes)
    evicted.append(entry.path)
    return True


@dataclass
class _RootBudget:
    """One cache root's arithmetic, carried through the two eviction phases."""

    root: Path
    budget: int
    usage: int
    evicted: list[Path]
    live_only: set[str]
    is_live: Callable[[str], bool]
    dry_run: bool

    @property
    def over_budget(self) -> bool:
        return self.usage > self.budget

    def take(self, entry: CacheEntry) -> bool:
        """Evict one entry and discount what it was holding."""
        if not _evict_entry(entry, self.evicted, dry_run=self.dry_run):
            return False
        self.usage -= entry.size_bytes
        return True


def evict_caches(
    registry: AgentVmRegistry,
    *,
    needed: dict[Path, int] | None = None,
    dry_run: bool = False,
    is_live: Callable[[str], bool] | None = None,
    reclaim_retained: bool = True,
) -> list[Path]:
    """Bring every cache root under ``CACHE_BUDGET``; return what was evicted.

    ``needed`` is what a download about to start would add to a root, so
    admission asks the same question a pass does, one download ahead of it.

    ``is_live`` decides whether a reclaimable directory may be reclaimed to
    free its parent image; it defaults to the registry alone, which is what a
    caller holding no supervisor handle can offer.

    ``reclaim_retained`` is the second phase, purging retained VM directories
    to free the parent images they pin. Admission turns it off: it runs on the
    event loop inside a download, where an rmtree of a retained VM's disks
    does not belong. What it cannot free there, the next pass frees.
    """
    needed = needed or {}
    evicted: list[Path] = []
    is_live = is_live or (lambda namespace: namespace in registry)
    live_only = live_refs(registry)
    for root in cache_roots():
        try:
            budget = cache_budget_bytes(root)
        except OSError:
            logger.warning("Cache directory %s is not accessible; not applying its budget", root, exc_info=True)
            continue
        entries = cache_entries(root)
        state = _RootBudget(
            root=root,
            budget=budget,
            usage=_root_usage(root, entries) + needed.get(root, 0),
            evicted=evicted,
            live_only=live_only,
            is_live=is_live,
            dry_run=dry_run,
        )
        if not state.over_budget:
            continue
        # Re-read the markers per root: what was reclaimed for the previous
        # root changes what this one is allowed to touch.
        markers = _markers()
        _evict_unreferenced(state, entries, state.live_only | _marker_refs(markers))
        if state.over_budget and reclaim_retained:
            _reclaim_pinning_dirs(state, entries, markers)
        if not state.over_budget:
            continue
        if reclaim_retained:
            logger.error(
                "Cache %s is %d bytes over its %d byte budget but only live references remain; "
                "admission should have refused this load",
                root,
                state.usage - budget,
                budget,
            )
        else:
            logger.info(
                "Cache %s is %d bytes over its %d byte budget; what is left is pinned, leaving it to the pass",
                root,
                state.usage - budget,
                budget,
            )
    return evicted


def _evict_unreferenced(state: _RootBudget, entries: list[CacheEntry], referenced: set[str]) -> None:
    """Least recently used first, skipping anything anyone still names."""
    for entry in entries:
        if not state.over_budget:
            return
        if _entry_refs(entry.path) & referenced:
            continue
        if _may_evict(entry):
            state.take(entry)


def _reclaim_pinning_dirs(
    state: _RootBudget,
    entries: list[CacheEntry],
    markers: list[tuple[Path, ReclaimableMarker]],
) -> None:
    """Give back retained disks so their parent images become evictable.

    Only the entries a ``.reclaimable`` marker pins are reachable here: a live
    VM's entries were skipped above and stay skipped. The directories go
    oldest marker first, the same order the retention budget uses, and a
    parent image is evicted only once every retained VM that named it is gone.
    """
    pinned = _pinned_entries(state, entries)
    reclaimed: set[str] = set()
    for directory, marker in markers:
        if not state.over_budget:
            return
        if not _reclaim_for_parents(state, directory, marker, pinned, reclaimed):
            continue
        _evict_freed_parents(state, marker, markers, pinned, reclaimed)


def _pinned_entries(state: _RootBudget, entries: list[CacheEntry]) -> dict[str, CacheEntry]:
    """The still-present entries by every ref they answer to, live ones left
    out: those are never evictable, so nothing is reclaimed to free them."""
    gone = set(state.evicted)
    pinned: dict[str, CacheEntry] = {}
    for entry in entries:
        if entry.path in gone:
            continue
        for ref in _entry_refs(entry.path) - state.live_only:
            pinned.setdefault(ref, entry)
    return pinned


def _reclaim_for_parents(
    state: _RootBudget,
    directory: Path,
    marker: ReclaimableMarker,
    pinned: dict[str, CacheEntry],
    reclaimed: set[str],
) -> bool:
    """Purge one retained VM because it pins a parent image; False if it does
    not pin one, must not be touched, or kept its disks."""
    namespace = directory.name
    if namespace in reclaimed:
        # A VM spanning two pools is purged whole on the first marker.
        return False
    if not any(ref in pinned for ref in marker.depends_on):
        return False
    if state.is_live(namespace):
        logger.warning("Not reclaiming %s for its parent images: a live VM owns it", namespace)
        return False
    if _is_creating(namespace):
        # A re-create adopted the directory after the markers were listed:
        # ``creating`` clears the marker, but this list is older than that,
        # and the VM has no registry record yet for ``is_live`` to find.
        logger.warning("Not reclaiming %s for its parent images: a create is using it", namespace)
        return False
    if not state.dry_run:
        purge_vm_storage(namespace)
        if any(True for _ in iter_namespace_dirs(namespace)):
            # purge_vm_storage refuses a directory a device-mapper target
            # still holds: those volumes still need their parent image, so
            # the parent stays too.
            logger.warning("Not evicting the parent images of %s: its purge left directories behind", namespace)
            return False
    reclaimed.add(namespace)
    logger.info("Reclaimed the retained volumes of %s to free its parent images", namespace)
    return True


def _evict_freed_parents(
    state: _RootBudget,
    marker: ReclaimableMarker,
    markers: list[tuple[Path, ReclaimableMarker]],
    pinned: dict[str, CacheEntry],
    reclaimed: set[str],
) -> None:
    """Evict the parent images the VM just reclaimed was the last to need."""
    for ref in marker.depends_on:
        entry = pinned.get(ref)
        if entry is None:
            continue
        if _still_pinned(ref, markers, reclaimed):
            logger.debug("Keeping the parent image %s: another retained VM still depends on it", ref)
            continue
        if not _may_evict(entry) or not state.take(entry):
            continue
        for name in [name for name, pinned_entry in pinned.items() if pinned_entry is entry]:
            pinned.pop(name)


def _still_pinned(ref: str, markers: list[tuple[Path, ReclaimableMarker]], reclaimed: set[str]) -> bool:
    """Whether a retained VM other than the ones just reclaimed needs ``ref``."""
    return any(ref in marker.depends_on and directory.name not in reclaimed for directory, marker in markers)


def _may_evict_for_admission(registry: AgentVmRegistry) -> bool:
    """Whether admission is allowed to evict anything at all.

    The same precondition the pass applies (``reconciler._enforce_cache_budget``):
    what a cache holds for a live VM is read from that VM's message, so a live
    VM without a registry record makes the referenced set incomplete, and
    evicting on an incomplete set unlinks a running VM's disk. Admission is
    the riskier of the two, since it runs on the create path with no
    supervisor answer of its own, so it refuses on the same doubt and on one
    more: no pass has run yet, so there is no live set to check against.
    """
    snapshot = live_snapshot()
    if snapshot is None:
        logger.warning("No storage reconcile has run yet; admitting downloads without evicting")
        return False
    unknown = sorted(namespace for namespace in snapshot if namespace not in registry)
    if unknown:
        logger.error(
            "Not evicting for a download: %d live VM(s) have no registry record (%s), so what they reference is "
            "unknown and the caches stay unbounded until this is resolved",
            len(unknown),
            ", ".join(unknown[:3]),
        )
        return False
    return True


def admit_download(
    registry: AgentVmRegistry,
    tmp_path: Path,
    content_length: int | None,
    max_bytes: int | None = None,
) -> None:
    """Refuse, before a byte is written, a download the cache cannot hold.

    Registered on ``storage.set_cache_admission`` so it runs inside
    ``download_file_in_chunks`` as soon as the response headers are in.
    Evicting first is the point: the budget is a cap on what is kept, not on
    what may be fetched, and only a load that stays over the budget with
    nothing safely evictable left is refused (spec section 4).

    An admitted download is then charged to its ``.part`` path until
    ``download_file`` releases it, so the next admission sees the room this
    one was promised and not just the bytes it has managed to write.

    ``content_length`` is None when the server sent none (a chunked-encoding
    response), and that is a different question, answered by
    ``_admit_unknown_length``: ``max_bytes`` is then all that bounds the body,
    and it is a ceiling on every download of that kind rather than a
    measurement of this one.

    Two things it deliberately does not do. It does not reclaim retained VM
    directories (``reclaim_retained=False``): that is an rmtree, and this runs
    on the event loop inside a download. And it does not evict at all when the
    live set cannot be trusted; the download is then admitted or refused on
    the budget as it stands.

    A directory that is not a cache root is not this budget's business: the
    downloader also streams per-VM volumes in place, and those are admitted by
    the capacity checks and the pool budget.
    """
    tmp_path = Path(tmp_path)
    root = tmp_path.parent
    if root not in cache_roots():
        logger.debug("Not a download cache, so not subject to CACHE_BUDGET: %s", root)
        return
    try:
        budget = cache_budget_bytes(root)
    except OSError:
        logger.warning("Cache directory %s is not accessible; admitting the download", root, exc_info=True)
        if content_length is not None:
            reserve_download(tmp_path, content_length)
        return
    if content_length is None:
        _admit_unknown_length(tmp_path, root, budget, max_bytes)
        return
    if _may_evict_for_admission(registry):
        release_parent_devices(
            evict_caches(registry, needed={root: content_length}, reclaim_retained=False),
        )
    usage = _root_usage(root, cache_entries(root)) + content_length
    if usage <= budget:
        reserve_download(tmp_path, content_length)
        return
    free = max(budget - (usage - content_length), 0)
    msg = f"Cache {root} cannot hold a {content_length} byte download within CACHE_BUDGET"
    raise InsufficientResourcesError(
        msg,
        required={"disk_mib": content_length // MIB},
        available={"disk_mib": free // MIB},
    )


def _admit_unknown_length(tmp_path: Path, root: Path, budget: int, max_bytes: int | None) -> None:
    """Admit a download whose size the server did not state.

    All that is known is the cap the caller is downloading under, and a cap is
    not a measurement: ``MAX_RUNTIME_ARCHIVE_SIZE`` is 100 GiB, which is the
    ceiling for a runtime image and equally the ceiling for the few kilobytes
    of a manifest. Treating it as a size made every chunked-encoding response
    ask for 100 GiB of room, which on any cache disk under half a terabyte
    meant evicting the entire unreferenced cache and then refusing the
    download anyway.

    So: never evict for a figure that is only a ceiling, and refuse only what
    a root that is already over its budget cannot start at all. What is
    charged is ``min(cap, budget)``, enough that a handful of concurrent
    unknown-length downloads still run the root over its budget and the next
    one is refused, and never more than the budget itself.
    """
    usage = _root_usage(root, cache_entries(root))
    if usage > budget:
        msg = f"Cache {root} is already over CACHE_BUDGET; not starting a download of unknown length"
        raise InsufficientResourcesError(
            msg,
            required={"disk_mib": (usage - budget) // MIB},
            available={"disk_mib": 0},
        )
    charge = min(max_bytes, budget) if max_bytes is not None else budget
    reserve_download(tmp_path, charge)


def _deleted_cache_backings() -> list[tuple[str, Path]]:
    """``(loop device, cache entry)`` for every loop device still backed by a
    cache entry that is already unlinked."""
    roots = cache_roots()
    leaked: list[tuple[str, Path]] = []
    try:
        backing_files = sorted(SYS_BLOCK.glob("loop*/loop/backing_file"))
    except OSError:
        return leaked
    for backing_file in backing_files:
        try:
            backing = backing_file.read_text().strip()
        except OSError:
            continue
        if not backing.endswith(DELETED_SUFFIX):
            continue
        path = Path(backing.removesuffix(DELETED_SUFFIX))
        if path.parent in roots:
            leaked.append((f"/dev/{backing_file.parent.parent.name}", path))
    return leaked


async def sweep_leaked_cache_loops() -> list[str]:
    """Detach the loop devices of cache entries that are already gone.

    The recovery path for a teardown that never happened or failed: the
    eviction unlinks the entry and only then removes its devices, so a crash,
    a restart or a failing ``dmsetup`` in between leaves a loop device holding
    the inode of a file nobody can name any more. Its blocks are not free, and
    no later pass would find it, because the entry it belonged to is no longer
    in the cache. The kernel still knows, so ask it.

    Fail closed the same way the eviction does: a leaked loop whose
    ``/dev/mapper/<ref>`` target still has holders is in use after all and is
    left alone.
    """
    detached: list[str] = []
    for loop_device, path in _deleted_cache_backings():
        ref = path.name
        device = Path(DEVICE_MAPPER_DIRECTORY) / ref
        if _is_block_device(device):
            if not parent_device_is_free(ref):
                continue
            await run_in_subprocess(["dmsetup", "remove", "--retry", ref])
            logger.info("Removed the leaked device of the evicted cache entry %s", ref)
        await run_in_subprocess(["losetup", "-d", loop_device])
        logger.info("Detached the leaked loop device %s of the evicted cache entry %s", loop_device, path)
        detached.append(loop_device)
    return detached
