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

from aleph_message.models import ExecutableContent

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


def reclaimable_bytes(pool_path: Path | None = None) -> int:
    """Sum of marker size_bytes, across every pool or for one pool."""
    return sum(
        marker.size_bytes
        for directory, marker in iter_reclaimable()
        if pool_path is None or directory.parent == pool_path
    )
