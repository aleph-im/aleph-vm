"""The ``.reclaimable`` marker: a VM directory nobody owns any more.

A ``{pool}/{vm_hash}/`` directory without a marker belongs to a live VM. When
the registry record drops at GONE under VOLUME_RETENTION=keep, the marker
records what the registry no longer will: that the directory is unowned (so
the reconciler may evict it and does not mistake it for a crashed create),
since when (eviction order), how big it is (budget), and which cache entries
its volumes depend on (so the cache pass does not evict a parent image from
under a retained disk). The filesystem is the source of truth: there is no
ledger, and restoring is deleting the marker.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, get_args

from aleph_message.models import ExecutableContent

from aleph.vm.agent.vm.purge import _checked_namespace
from aleph.vm.storage_pools import get_pools, iter_namespace_dirs

logger = logging.getLogger(__name__)

MARKER_NAME = ".reclaimable"
MARKER_VERSION = 1

ReclaimReason = Literal["gone", "orphan"]
RECLAIM_REASONS: frozenset[str] = frozenset(get_args(ReclaimReason))


class UnsupportedMarkerVersion(ValueError):
    """A marker written to a schema this agent does not know.

    Distinct from a corrupt marker: the file is intact, a newer agent wrote
    it, and the fields it holds may not mean what this version thinks they
    do. The reader keeps such a file rather than removing it.
    """


@dataclass(frozen=True)
class ReclaimableMarker:
    reclaimable_since: datetime
    reason: ReclaimReason
    size_bytes: int
    depends_on: tuple[str, ...] = ()
    # The owner address from the VM's message, copied here because the marker
    # outlives every other record of it: GONE forgets the registry record and
    # deletes the DB rows. It is the only thing that lets the node answer
    # "these are your disks" for a retained VM (see views.operator.operate_erase).
    # Optional: markers written before this field, and orphan markers for a VM
    # whose message the node never held, have no owner.
    owner: str | None = None
    version: int = MARKER_VERSION

    def to_json(self) -> str:
        data = asdict(self)
        data["reclaimable_since"] = self.reclaimable_since.isoformat()
        data["depends_on"] = list(self.depends_on)
        return json.dumps(data, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> ReclaimableMarker:
        """Parse a marker, refusing anything this agent did not write.

        The reason and the version are checked rather than taken on trust:
        both decide what happens to the directory (an orphan marker is
        claimed exclusively and carries no owner, a gone one authorizes the
        owner's erase), and a value from outside the set this agent knows
        would be carried into those decisions unread.
        """
        data = json.loads(text)
        if not isinstance(data, dict):
            msg = f"marker is not a JSON object: {type(data).__name__}"
            raise ValueError(msg)
        version = int(data.get("version", MARKER_VERSION))
        if version != MARKER_VERSION:
            msg = f"marker version {version} is not the version {MARKER_VERSION} this agent writes"
            raise UnsupportedMarkerVersion(msg)
        reason = data["reason"]
        if reason not in RECLAIM_REASONS:
            msg = f"marker reason {reason!r} is not one of {', '.join(sorted(RECLAIM_REASONS))}"
            raise ValueError(msg)
        owner = data.get("owner")
        since = datetime.fromisoformat(data["reclaimable_since"])
        if since.tzinfo is None:
            # Everything this node writes carries an offset, but a marker an
            # operator restored or edited by hand may not. Parsed naive it
            # cannot be compared with the aware clock the rest of the agent
            # uses: every subtraction raises TypeError, and one such marker
            # would abort a whole listing or eviction pass. The writers all
            # use UTC, so that is what a bare timestamp means.
            since = since.replace(tzinfo=timezone.utc)
        return cls(
            reclaimable_since=since,
            reason=reason,
            size_bytes=int(data["size_bytes"]),
            depends_on=tuple(data.get("depends_on", ())),
            owner=str(owner) if owner else None,
            version=version,
        )


def file_size_bytes(path: Path) -> int:
    """Allocated bytes of one regular file, 0 for anything else.

    Uses st_blocks so a sparse qcow2 counts what it really occupies rather
    than its virtual size. A symlink counts 0: what it points at is not this
    directory's space, and counting it would let a link inflate any figure
    derived from here (a reclaim estimate, an admission discount).

    The single definition of "how much disk does this file actually hold" for
    the agent: everything that measures a VM's storage goes through here or
    through ``directory_size_bytes``."""
    try:
        st = path.lstat()
    except OSError:
        return 0
    if path.is_symlink() or not path.is_file():
        return 0
    return st.st_blocks * 512


def directory_size_bytes(directory: Path) -> int:
    """Allocated bytes of the regular files directly inside ``directory``.

    The marker itself is excluded, so the recorded size_bytes does not shift
    depending on whether the marker already exists when this runs."""
    try:
        entries = list(directory.iterdir())
    except OSError:
        return 0
    return sum(file_size_bytes(entry) for entry in entries if entry.name != MARKER_NAME)


def read_marker(namespace_dir: Path, *, repair: bool = True) -> ReclaimableMarker | None:
    """The directory's marker, or None when it has none.

    A marker that does not parse is removed, not just ignored: writes are
    atomic, so a corrupt marker is never a write in progress, and left in
    place it would wedge the directory (the exclusive orphan write backs off
    from any existing file, so nothing could ever re-mark or evict it). Gone,
    the directory re-enters the orphan flow on the next pass.

    That removal is a write, and not every reader is allowed to make one:
    ``repair=False`` reads the same marker without touching the file, for
    the commands that only report on a node (they may be run by a user who
    cannot unlink it at all, and an operator inspecting a node has not asked
    for anything on disk to change). The reconciler keeps the repair, since
    it is the pass that has to be able to move the directory on.

    A marker whose schema version this agent does not know is the exception:
    it is intact, a newer agent wrote it, and removing it would hand a
    retained directory to the orphan flow, which re-marks it without the
    owner and the parent-image pins it was carrying. It is kept and reported
    instead, and the operator is told which agent has to look at it.
    """
    path = namespace_dir / MARKER_NAME
    if not path.is_file():
        return None
    try:
        return ReclaimableMarker.from_json(path.read_text())
    except OSError:
        logger.warning("Unreadable reclaimable marker at %s, ignoring it", path)
        return None
    except UnsupportedMarkerVersion as error:
        logger.error("Reclaimable marker at %s is in a schema this agent does not know (%s); keeping it", path, error)
        return None
    except (ValueError, KeyError, TypeError, AttributeError):
        if not repair:
            logger.warning("Corrupt reclaimable marker at %s, ignoring it", path)
            return None
        logger.warning("Corrupt reclaimable marker at %s, removing it", path)
        invalidate_reclaimable_cache()
        try:
            path.unlink(missing_ok=True)
        except OSError:
            # Best effort: a read-only filesystem or a marker this user does
            # not own must not raise out of a caller that was only reading.
            logger.warning("Could not remove the corrupt marker at %s", path, exc_info=True)
        return None


def write_marker(namespace_dir: Path, marker: ReclaimableMarker, *, exclusive: bool = False) -> bool:
    """Publish the marker atomically (a reader sees the whole file or none).

    With ``exclusive`` the write claims the directory only if no marker
    exists yet, and reports whether it did: os.link publishes the finished
    temp file if and only if nothing sits at the path. The two modes use
    distinct temp names so an exclusive writer can never hand its content to
    a concurrent replacing writer.
    """
    path = namespace_dir / MARKER_NAME
    tmp = path.with_name(MARKER_NAME + (".x.tmp" if exclusive else ".tmp"))
    # Invalidated on both sides of the publish: a reader between the two
    # would otherwise cache the pre-change sum, and a marker write does not
    # touch the pool directory's mtime, so the fingerprint would not notice.
    invalidate_reclaimable_cache()
    try:
        tmp.write_text(marker.to_json())
        if exclusive:
            os.link(tmp, path)
        else:
            os.replace(tmp, path)
    except FileExistsError:
        # Exclusive only: another writer claimed the directory first.
        return False
    except OSError:
        # No space, no permission, no hardlinks on this filesystem: the
        # directory simply stays unmarked and the next pass tries again.
        # Raising would abort the whole reconcile pass for one directory,
        # and at startup the agent's boot, on a full pool: the one condition
        # the reconciler exists to relieve.
        logger.warning("Could not write the reclaimable marker at %s", path, exc_info=True)
        return False
    finally:
        # On success the publish consumed the temp file; on any failure
        # (ENOSPC, EACCES, a failed write) nothing else would ever collect it.
        tmp.unlink(missing_ok=True)
        invalidate_reclaimable_cache()
    return True


def clear_marker(namespace_dir: Path) -> bool:
    """Remove the marker; whether there was one. A marker another adopter or
    pass removed first is not an error, like every removal in the reclaimer."""
    path = namespace_dir / MARKER_NAME
    invalidate_reclaimable_cache()
    try:
        path.unlink()
    except FileNotFoundError:
        return False
    finally:
        invalidate_reclaimable_cache()
    return True


# The kinds ``iter_content_refs`` labels a parent image with: what a per-VM
# volume is built on, and so what a retained volume keeps needing.
PARENT_REF_KINDS = frozenset({"rootfs_parent", "volume_parent"})
# The kinds that name a runtime manifest, whose bundle tarball is a ref only
# the manifest itself knows (see agent.vm.cache).
MANIFEST_REF_KINDS = frozenset({"runtime", "tee_runtime"})


def _ref_of(obj: object) -> str | None:
    ref = getattr(obj, "ref", None) if obj is not None else None
    return str(ref) if ref else None


def _iter_volume_refs(content: ExecutableContent) -> Iterator[tuple[str, str]]:
    """The rootfs parent image, and each volume's parent image or own ref."""
    rootfs = getattr(content, "rootfs", None)
    ref = _ref_of(getattr(rootfs, "parent", None)) if rootfs is not None else None
    if ref:
        yield "rootfs_parent", ref
    for volume in getattr(content, "volumes", None) or []:
        parent_ref = _ref_of(getattr(volume, "parent", None))
        if parent_ref:
            yield "volume_parent", parent_ref
        volume_ref = _ref_of(volume)
        if volume_ref:
            yield "volume", volume_ref


def _iter_measured_refs(content: ExecutableContent) -> Iterator[tuple[str, str]]:
    """What the confidential content types name: a V-PROGRAM's workload image
    and hash tree (both attached as disks), and a TEE instance's firmware and
    runtime manifest."""
    workload = getattr(content, "workload", None)
    if workload is not None:
        ref = _ref_of(workload)
        if ref:
            yield "workload", ref
        hash_tree = getattr(workload, "hash_tree", None)
        if hash_tree:
            yield "workload_hash_tree", str(hash_tree)
    environment = getattr(content, "environment", None)
    trusted_execution = getattr(environment, "trusted_execution", None) if environment is not None else None
    if trusted_execution is None:
        return
    for kind, attribute in (("tee_firmware", "firmware"), ("tee_runtime", "runtime")):
        value = getattr(trusted_execution, attribute, None)
        if value:
            yield kind, str(value)


def iter_content_refs(content: ExecutableContent) -> Iterator[tuple[str, str]]:
    """Every item hash a message names, as ``(kind, ref)`` pairs.

    The single enumeration of what a VM needs out of the download caches, so
    the two questions asked of it cannot drift apart: what a retained volume
    depends on (``depends_on_from_content``, the parent images) and what may
    never be evicted while the VM is alive (``refs_from_content``, all of it).
    Getting the second one short is how a running VM's disk gets unlinked:
    a V-PROGRAM's workload image and its hash tree are attached straight out
    of DATA_CACHE, and so are a confidential instance's firmware and runtime
    manifest.

    Read with ``getattr``: one enumeration covers program, instance,
    V-PROGRAM and confidential content, and a field a content type does not
    have is simply not there.
    """
    for kind in ("runtime", "code", "data"):
        ref = _ref_of(getattr(content, kind, None))
        if ref:
            yield kind, ref
    yield from _iter_volume_refs(content)
    yield from _iter_measured_refs(content)


def refs_from_content(content: ExecutableContent, *, vm_hash: str | None = None) -> set[str]:
    """Every cache entry a message names, the VM's own message included.

    ``vm_hash`` is the VM's item hash: the message cache holds it as
    ``<vm_hash>.json`` and a live VM's message is not a spare copy.
    """
    refs = {ref for _kind, ref in iter_content_refs(content)}
    if vm_hash:
        refs.add(str(vm_hash))
    return refs


def depends_on_from_content(content: ExecutableContent) -> tuple[str, ...]:
    """The cache entries (parent images) a VM's per-VM volumes are built on."""
    return tuple(dict.fromkeys(ref for kind, ref in iter_content_refs(content) if kind in PARENT_REF_KINDS))


def mark_reclaimable(
    namespace: str,
    reason: ReclaimReason,
    depends_on: tuple[str, ...] = (),
    *,
    now: datetime | None = None,
    owner: str | None = None,
) -> list[Path]:
    """Write one marker per namespace directory (one per pool the VM spans)."""
    namespace = _checked_namespace(namespace)
    since = now or datetime.now(tz=timezone.utc)
    written: list[Path] = []
    for directory in iter_namespace_dirs(namespace):
        marker = ReclaimableMarker(
            reclaimable_since=since,
            reason=reason,
            size_bytes=directory_size_bytes(directory),
            depends_on=depends_on,
            owner=owner,
        )
        # An orphan marker only ever claims an unmarked directory: the
        # periodic pass can decide "orphan" in the window where a GONE
        # retire is writing the real marker, and replacing that marker
        # would drop the owner (erase authorization) and the parent-image
        # pins it carries.
        if not write_marker(directory, marker, exclusive=reason == "orphan"):
            logger.info("Not marking %s: another marker landed first", directory)
            continue
        written.append(directory / MARKER_NAME)
        logger.info("Marked %s reclaimable (%s, %d bytes)", directory, reason, marker.size_bytes)
    return written


def adopt(namespace: str) -> dict[Path, ReclaimableMarker]:
    """A create for this hash takes its retained directories back.

    Returns the markers it removed, keyed by directory, so a create that
    does not commit can put them back (``restore_markers``). A directory
    whose marker was unreadable or corrupt is adopted like any other and
    simply has nothing to give back.
    """
    namespace = _checked_namespace(namespace)
    adopted: dict[Path, ReclaimableMarker] = {}
    for directory in iter_namespace_dirs(namespace):
        marker = read_marker(directory)
        if clear_marker(directory):
            logger.info("Adopted retained volumes in %s", directory)
            if marker is not None:
                adopted[directory] = marker
    return adopted


def restore_markers(adopted: Mapping[Path, ReclaimableMarker]) -> int:
    """Put back the markers an adopt cleared, for a create that then failed.

    Adoption happens before the create is known to succeed, and a failed
    create must leave the directory as it found it. Left unmarked it is only
    an orphan to the next pass, which re-marks it with no owner (so the
    owner can no longer have their own retained data erased) and no
    depends_on (so the cache may evict the parent image the retained volumes
    are built on), and with a fresh timestamp that moves it to the back of
    the eviction queue on every retry.

    Restored exclusively: a marker written while the create ran is a newer
    record of the same directory (a retire of this very hash) and stays. A
    directory the failed create's own teardown purged is skipped rather than
    recreated.
    """
    restored = 0
    for directory, marker in adopted.items():
        if not directory.is_dir():
            continue
        # size_bytes is a measurement of what the directory holds, and a
        # create that failed part way may have left more or less than it
        # found. The rest of the marker (since when, whose, what it is built
        # on) is the record that has to survive unchanged.
        current = replace(marker, size_bytes=directory_size_bytes(directory))
        if write_marker(directory, current, exclusive=True):
            logger.info("Restored the reclaimable marker in %s after a create that did not commit", directory)
            restored += 1
    return restored


def retained_marker(namespace: str) -> ReclaimableMarker | None:
    """The marker of a retained VM, from the first of its directories that
    carries one, or None.

    The only record a retained VM has left: its registry record and its DB
    rows were dropped at GONE, so this is how a caller asks whether the node
    still holds anything for a hash it otherwise knows nothing about, and
    who it belongs to.
    """
    namespace = _checked_namespace(namespace)
    for directory in iter_namespace_dirs(namespace):
        marker = read_marker(directory)
        if marker is not None:
            return marker
    return None


def iter_reclaimable(*, repair: bool = True) -> Iterator[tuple[Path, ReclaimableMarker]]:
    """Every marked directory and its marker. ``repair=False`` leaves a
    corrupt marker where it is, for a read-only caller."""
    for directory in iter_namespace_dirs():
        marker = read_marker(directory, repair=repair)
        if marker is not None:
            yield directory, marker


# reclaimable_bytes runs on every admission check and every capacity report,
# and adds the markers up by walking every namespace directory. The sum is
# cached, keyed on the pools' own directory mtimes (a namespace directory
# appearing or going changes them) and dropped whenever this process writes
# or removes a marker, so the common case costs one stat per pool and an
# in-process change is never stale. A marker written by another process (the
# storage CLI) shows up within the TTL; until then the figure errs towards
# counting space as reclaimable, which placement's own free-space check then
# corrects.
_RECLAIMABLE_CACHE_TTL = 5.0
_reclaimable_cache: dict[Path | None, tuple[float, tuple, int]] = {}


def invalidate_reclaimable_cache() -> None:
    _reclaimable_cache.clear()


def _pools_fingerprint() -> tuple:
    stamps = []
    for pool in get_pools():
        try:
            stamps.append((str(pool.path), pool.path.stat().st_mtime_ns))
        except OSError:
            stamps.append((str(pool.path), None))
    return tuple(stamps)


def reclaimable_bytes(pool_path: Path | None = None, *, repair: bool = True) -> int:
    """Sum of marker size_bytes, across every pool or for one pool.

    ``repair=False`` is for a caller that may not write: the walk then reads
    a corrupt marker without removing it."""
    now = time.monotonic()
    fingerprint = _pools_fingerprint()
    cached = _reclaimable_cache.get(pool_path)
    if cached is not None and cached[1] == fingerprint and now - cached[0] < _RECLAIMABLE_CACHE_TTL:
        return cached[2]
    total = sum(
        marker.size_bytes
        for directory, marker in iter_reclaimable(repair=repair)
        if pool_path is None or directory.parent == pool_path
    )
    _reclaimable_cache[pool_path] = (now, fingerprint, total)
    return total
