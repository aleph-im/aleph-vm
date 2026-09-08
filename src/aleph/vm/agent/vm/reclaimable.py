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
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from aleph_message.models import ExecutableContent, InstanceContent

from aleph.vm.agent.vm.purge import _checked_namespace
from aleph.vm.storage_pools import get_pools, iter_namespace_dirs

logger = logging.getLogger(__name__)

MARKER_NAME = ".reclaimable"
MARKER_VERSION = 1

ReclaimReason = Literal["gone", "orphan"]


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
        data = json.loads(text)
        if not isinstance(data, dict):
            msg = f"marker is not a JSON object: {type(data).__name__}"
            raise ValueError(msg)
        owner = data.get("owner")
        return cls(
            reclaimable_since=datetime.fromisoformat(data["reclaimable_since"]),
            reason=data["reason"],
            size_bytes=int(data["size_bytes"]),
            depends_on=tuple(data.get("depends_on", ())),
            owner=str(owner) if owner else None,
            version=int(data.get("version", MARKER_VERSION)),
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


def read_marker(namespace_dir: Path) -> ReclaimableMarker | None:
    """The directory's marker, or None when it has none.

    A marker that does not parse is removed, not just ignored: writes are
    atomic, so a corrupt marker is never a write in progress, and left in
    place it would wedge the directory (the exclusive orphan write backs off
    from any existing file, so nothing could ever re-mark or evict it). Gone,
    the directory re-enters the orphan flow on the next pass.
    """
    path = namespace_dir / MARKER_NAME
    if not path.is_file():
        return None
    try:
        return ReclaimableMarker.from_json(path.read_text())
    except OSError:
        logger.warning("Unreadable reclaimable marker at %s, ignoring it", path)
        return None
    except (ValueError, KeyError, TypeError, AttributeError):
        logger.warning("Corrupt reclaimable marker at %s, removing it", path)
        invalidate_reclaimable_cache()
        path.unlink(missing_ok=True)
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


def depends_on_from_content(content: ExecutableContent) -> tuple[str, ...]:
    """The cache entries (parent images) a VM's per-VM volumes are built on."""
    refs: list[str] = []
    if isinstance(content, InstanceContent) and content.rootfs and content.rootfs.parent:
        refs.append(str(content.rootfs.parent.ref))
    for vol in content.volumes or []:
        parent = getattr(vol, "parent", None)
        if parent is not None:
            refs.append(str(parent.ref))
    return tuple(dict.fromkeys(refs))


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


def adopt(namespace: str) -> int:
    """A create for this hash takes its retained directories back."""
    namespace = _checked_namespace(namespace)
    cleared = 0
    for directory in iter_namespace_dirs(namespace):
        if clear_marker(directory):
            logger.info("Adopted retained volumes in %s", directory)
            cleared += 1
    return cleared


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


def iter_reclaimable() -> Iterator[tuple[Path, ReclaimableMarker]]:
    for directory in iter_namespace_dirs():
        marker = read_marker(directory)
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


def reclaimable_bytes(pool_path: Path | None = None) -> int:
    """Sum of marker size_bytes, across every pool or for one pool."""
    now = time.monotonic()
    fingerprint = _pools_fingerprint()
    cached = _reclaimable_cache.get(pool_path)
    if cached is not None and cached[1] == fingerprint and now - cached[0] < _RECLAIMABLE_CACHE_TTL:
        return cached[2]
    total = sum(
        marker.size_bytes
        for directory, marker in iter_reclaimable()
        if pool_path is None or directory.parent == pool_path
    )
    _reclaimable_cache[pool_path] = (now, fingerprint, total)
    return total
