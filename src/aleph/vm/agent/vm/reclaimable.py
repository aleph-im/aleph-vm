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
from collections.abc import Iterator
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from aleph_message.models import ExecutableContent, InstanceContent

from aleph.vm.agent.vm.purge import _checked_namespace
from aleph.vm.storage_pools import iter_namespace_dirs

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
    version: int = MARKER_VERSION

    def to_json(self) -> str:
        data = asdict(self)
        data["reclaimable_since"] = self.reclaimable_since.isoformat()
        data["depends_on"] = list(self.depends_on)
        return json.dumps(data, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> ReclaimableMarker:
        data = json.loads(text)
        return cls(
            reclaimable_since=datetime.fromisoformat(data["reclaimable_since"]),
            reason=data["reason"],
            size_bytes=int(data["size_bytes"]),
            depends_on=tuple(data.get("depends_on", ())),
            version=int(data.get("version", MARKER_VERSION)),
        )


def directory_size_bytes(directory: Path) -> int:
    """Allocated bytes of the regular files directly inside ``directory``.

    Uses st_blocks so a sparse qcow2 counts what it really occupies. The
    marker itself is excluded, so the recorded size_bytes does not shift
    depending on whether the marker already exists when this runs."""
    total = 0
    try:
        entries = list(directory.iterdir())
    except OSError:
        return 0
    for entry in entries:
        if entry.name == MARKER_NAME:
            continue
        try:
            st = entry.lstat()
        except OSError:
            continue
        if not entry.is_file() or entry.is_symlink():
            continue
        total += st.st_blocks * 512
    return total


def read_marker(namespace_dir: Path) -> ReclaimableMarker | None:
    path = namespace_dir / MARKER_NAME
    if not path.is_file():
        return None
    try:
        return ReclaimableMarker.from_json(path.read_text())
    except (OSError, ValueError, KeyError, TypeError):
        logger.warning("Corrupt reclaimable marker at %s, ignoring it", path)
        return None


def write_marker(namespace_dir: Path, marker: ReclaimableMarker) -> None:
    path = namespace_dir / MARKER_NAME
    tmp = path.with_name(MARKER_NAME + ".tmp")
    tmp.write_text(marker.to_json())
    os.replace(tmp, path)


def clear_marker(namespace_dir: Path) -> bool:
    path = namespace_dir / MARKER_NAME
    if not path.exists():
        return False
    path.unlink()
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
        )
        write_marker(directory, marker)
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


def iter_reclaimable() -> Iterator[tuple[Path, ReclaimableMarker]]:
    for directory in iter_namespace_dirs():
        marker = read_marker(directory)
        if marker is not None:
            yield directory, marker


def reclaimable_bytes(pool_path: Path | None = None) -> int:
    """Sum of marker size_bytes, across every pool or for one pool."""
    return sum(
        marker.size_bytes
        for directory, marker in iter_reclaimable()
        if pool_path is None or directory.parent == pool_path
    )
