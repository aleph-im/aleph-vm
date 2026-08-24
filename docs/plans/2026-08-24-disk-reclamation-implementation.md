# Disk Reclamation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every path that ends a VM reclaims its on-host storage or retains it under a budgeted node-wide policy; creates are transactional; caches and downloads are bounded; an operator CLI shows and drives reclamation.

**Architecture:** One agent-side deletion function, `retire_vm(vm_hash, reason)`, replaces every ad-hoc `supervisor.delete_vm` + cleanup sequence. Under `VOLUME_RETENTION=keep`, a `.reclaimable` JSON marker written in place inside `{pool}/{vm_hash}/` records that the directory is unowned; a reconciler (startup, periodic, after every `GONE`, on admission pressure) purges orphans, sweeps side directories and `.part` files, and enforces per-pool retention and cache budgets. The supervisor is never involved: it only quiesces (`DeleteVm`/`StopVm`).

**Tech Stack:** Python 3.12, aiohttp agent, pydantic settings (`aleph.vm.conf.settings`), pytest + pytest-asyncio + pytest-mock, `qemu-img`/`dmsetup`/`losetup` behind `aleph.vm.utils.run_in_subprocess`.

**Spec:** `docs/plans/2026-08-24-disk-reclamation-design.md`

## Global Constraints

- Python 3.12+; settings are pydantic `Field`s on `Settings` in `src/aleph/vm/conf.py`; derived defaults are filled in `Settings.setup()` (the `if not self.X:` block around line 675).
- Style: `ruff format` and `isort --profile black` (hatch `linting` env: `hatch run linting:style`). Run `./venv/bin/ruff format <files>` and `./venv/bin/isort --profile black <files>` before every commit.
- No em-dashes anywhere: code, comments, docstrings, commit messages. Use commas, colons, parentheses.
- Commit messages carry no `Co-Authored-By` trailer. One commit per task.
- Names from the spec are binding: settings `VOLUME_RETENTION`, `VOLUME_RETENTION_BUDGET`, `VOLUME_RECONCILE_INTERVAL`, `VOLUME_CREATE_GUARD`, `CACHE_BUDGET`; marker file `.reclaimable` with fields `version`, `reclaimable_since`, `reason`, `size_bytes`, `depends_on`; `RetireReason` with `RECREATE`, `GONE`, `ERASE`, `FAILED_CREATE`; `retire_vm(vm_hash, reason, ...)`; `reconcile_storage()`; `remove_devmapper(namespace, volume_name)`; CLI `aleph-vm storage status|list|reclaim|reconcile`.
- Test command (from the repo root, `TMPDIR` is any scratch directory):
  ```bash
  export PYTHONPATH=$PWD/src:$PWD/.dev-stubs ALEPH_VM_CACHE_ROOT=$TMPDIR/cache ALEPH_VM_EXECUTION_ROOT=$TMPDIR/exec
  ./venv/bin/python -m pytest <path> -q -p no:cacheprovider
  ```
  The full suite (`tests/supervisor`, with `--ignore=tests/supervisor/test_snp_instance_launch.py --ignore=tests/supervisor/test_snp_instance_run.py`) has 46 pre-existing environment failures on `dev`; no new failures are allowed.
- Every delete path must go through `retire_vm`. After PR A no file under `src/aleph/vm/agent/` except `retire.py` may call `supervisor.delete_vm` (a test pins this).
- Deleting only ever happens under directories the agent created and keyed by a hash validated by `aleph.vm.agent.vm.purge._checked_namespace`.

## Prerequisite: the backup move

Sequencing step 1 of the spec is the backup move (branch `od/backups-agent-side`, PR to `dev`): the supervisor loses its backup RPCs and the agent gains `src/aleph/vm/agent/vm/backup.py`. Task 3 (`retire_vm`) and Task 8 (the reconciler's backup pass) call into that module. **Rebase this work onto `od/backups-agent-side` (or onto `dev` once it is merged) before starting Task 3.** If `backup.py` does not yet expose a per-VM purge, add it there as part of Task 3:

```python
def purge_vm_backups(vm_hash: ItemHash | str) -> int:
    """Delete every backup archive of a VM (the .tar and its sidecars)."""
    backup_dir = Path(settings.BACKUP_DIRECTORY)
    removed = 0
    for archive in backup_dir.glob(f"{vm_hash}-*.tar"):
        for path in (archive, Path(f"{archive}.sha256"), Path(f"{archive}.meta.json")):
            if path.exists():
                path.unlink()
        removed += 1
    return removed
```

and `sweep_expired_backups(now: datetime) -> int` applying the existing TTL (`cleanup_expired_backups`) to every archive.

## File Structure

| File | Responsibility |
|------|----------------|
| `src/aleph/vm/conf.py` (modify) | The five new settings plus `MAX_RUNTIME_ARCHIVE_SIZE`. |
| `src/aleph/vm/storage_budget.py` (create) | `parse_budget("10%" or "50G" or bytes, total) -> int`. Shared by pools and caches. |
| `src/aleph/vm/agent/vm/reclaimable.py` (create) | The `.reclaimable` marker: dataclass, read/write/clear, `mark_reclaimable`, `adopt`, `reclaimable_bytes`, `depends_on_from_content`. |
| `src/aleph/vm/agent/vm/retire.py` (create) | `RetireReason`, `retire_vm`. The only agent caller of `supervisor.delete_vm`. |
| `src/aleph/vm/agent/vm/purge.py` (modify) | Add `purge_vm_side_dirs` (session + staging), used by both purge and keep paths. |
| `src/aleph/vm/agent/vm/reconciler.py` (create) | `reconcile_storage`, `creating()` guard, `make_room`, the periodic task and startup hook. |
| `src/aleph/vm/agent/vm/cache.py` (create) | Referenced set, cache entries, LRU eviction, parent device removal. |
| `src/aleph/vm/storage_pools.py` (modify) | `set_room_maker` hook consulted by `_select_from` when no pool fits. |
| `src/aleph/vm/storage.py` (modify) | In-stream size cap in `download_file_in_chunks`, mtime touch on cache hit, `remove_devmapper`, `detach_loop_devices`. |
| `src/aleph/vm/agent/capacity.py` (modify) | `check_message` (admission from the message, before allocation); reclaimable bytes count as free. |
| `src/aleph/vm/agent/run.py`, `tasks.py`, `expiry.py`, `update_watcher.py`, `views/__init__.py`, `views/operator.py`, `views/migration.py` (modify) | Call-site conversion to `retire_vm`. |
| `src/aleph/vm/agent/supervisor.py` (modify) | Register the reconciler startup hook, periodic task, and the room maker. |
| `src/aleph/vm/agent/storage_cli.py` (create), `src/aleph/vm/agent/cli.py` (modify) | `aleph-vm storage ...`. |
| `tests/supervisor/test_storage_budget.py`, `test_reclaimable.py`, `test_retire.py`, `test_reconciler.py`, `test_cache_eviction.py`, `test_storage_download_cap.py`, `test_devmapper_teardown.py`, `test_storage_cli.py`, `test_agent_no_direct_delete.py` (create) | Tier 1 tests, temp directories, subprocess seams mocked. |
| `docs/architecture/storage.md`, `docs/architecture/vm-lifecycle.md` (modify) | Reclamation and retire reasons. |

The `pools` fixture from `tests/supervisor/test_vm_purge.py` (two pools, a session dir, a runtime cache, `storage_pools_module._pools` monkeypatched, `reset_pools()` on teardown) is the model for every new test file. Copy it into a shared `tests/supervisor/reclaim_fixtures.py` in Task 2 and import it from there afterwards.

---

# PR A: `retire_vm`, `.reclaimable`, reconciler (spec sections 1, 3, 6)

Branch: `od/disk-reclaim-retire` off `dev` (rebased onto the backup move, see above).

### Task 1: Settings and budget parsing

**Files:**
- Modify: `src/aleph/vm/conf.py` (after `MAX_DATA_ARCHIVE_SIZE`, line 283)
- Create: `src/aleph/vm/storage_budget.py`
- Test: `tests/supervisor/test_storage_budget.py`

**Interfaces:**
- Produces: `settings.VOLUME_RETENTION: Literal["reap", "keep"]`, `settings.VOLUME_RETENTION_BUDGET: str`, `settings.VOLUME_RECONCILE_INTERVAL: int` (seconds), `settings.VOLUME_CREATE_GUARD: int` (seconds), `settings.CACHE_BUDGET: str`, `settings.MAX_RUNTIME_ARCHIVE_SIZE: int`; `parse_budget(value: str | int, total_bytes: int) -> int`.

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_storage_budget.py
import pytest

from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget


@pytest.mark.parametrize(
    ("value", "total", "expected"),
    [
        ("10%", 1000, 100),
        ("0%", 1000, 0),
        ("100%", 1000, 1000),
        ("512M", 0, 512 * 1024 * 1024),
        ("50G", 0, 50 * 1024**3),
        ("2T", 0, 2 * 1024**4),
        ("4096", 0, 4096),
        (4096, 0, 4096),
    ],
)
def test_parse_budget(value, total, expected):
    assert parse_budget(value, total) == expected


@pytest.mark.parametrize("value", ["", "ten percent", "-5%", "150%", "10X", "-1"])
def test_parse_budget_rejects_garbage(value):
    with pytest.raises(ValueError):
        parse_budget(value, 1000)


def test_settings_defaults():
    assert settings.VOLUME_RETENTION == "reap"
    assert settings.VOLUME_RETENTION_BUDGET == "10%"
    assert settings.VOLUME_RECONCILE_INTERVAL == 3600
    assert settings.VOLUME_CREATE_GUARD == 600
    assert settings.CACHE_BUDGET == "20%"
    assert settings.MAX_RUNTIME_ARCHIVE_SIZE == 100 * 1024**3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_budget.py -q -p no:cacheprovider`
Expected: FAIL with `ModuleNotFoundError: aleph.vm.storage_budget`

- [ ] **Step 3: Write the implementation**

```python
# src/aleph/vm/storage_budget.py
"""Budget strings for on-disk classes ("10%" of a filesystem, or "50G")."""

from __future__ import annotations

import re

_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_ABSOLUTE = re.compile(r"^(\d+)\s*([KMGT]?)$")
_PERCENT = re.compile(r"^(\d+(?:\.\d+)?)\s*%$")


def parse_budget(value: str | int, total_bytes: int) -> int:
    """A budget as bytes: a percentage of ``total_bytes`` or an absolute size.

    Accepts "10%", "512M", "50G", "2T", or a plain byte count (str or int).
    """
    if isinstance(value, int):
        if value < 0:
            raise ValueError(f"Negative budget: {value}")
        return value
    text = value.strip().upper()
    if match := _PERCENT.match(text):
        percent = float(match.group(1))
        if percent > 100:
            raise ValueError(f"Budget above 100%: {value!r}")
        return int(total_bytes * percent / 100)
    if match := _ABSOLUTE.match(text):
        return int(match.group(1)) * _UNITS[match.group(2)]
    raise ValueError(f"Unparseable budget: {value!r} (expected e.g. '10%', '50G' or a byte count)")
```

In `src/aleph/vm/conf.py`, after `MAX_DATA_ARCHIVE_SIZE`:

```python
    MAX_RUNTIME_ARCHIVE_SIZE: int = Field(
        default=100 * 1024**3,
        description="Maximum size in bytes of a runtime or instance base image download (default 100 GiB)",
    )

    VOLUME_RETENTION: Literal["reap", "keep"] = Field(
        default="reap",
        description="What happens to a VM's volumes when the VM is gone for good: "
        "'reap' deletes them immediately, 'keep' retains them (within VOLUME_RETENTION_BUDGET, "
        "oldest evicted first) so the same VM can be re-created with its data.",
    )
    VOLUME_RETENTION_BUDGET: str = Field(
        default="10%",
        description="Cap on retained (reclaimable) bytes per volume pool: a percentage of the pool "
        "or an absolute size such as '50G'.",
    )
    VOLUME_RECONCILE_INTERVAL: int = Field(default=3600, description="Seconds between storage reconciler passes.")
    VOLUME_CREATE_GUARD: int = Field(
        default=600,
        description="Seconds a directory or .part file is considered part of an in-flight create "
        "and left alone by the reconciler.",
    )
    CACHE_BUDGET: str = Field(
        default="20%",
        description="Cap on each download cache (runtime, code, data, message): a percentage of the "
        "filesystem the cache sits on or an absolute size.",
    )
```

Add to `Settings.check()` (next to the existing checks) a validation that both budgets parse: `parse_budget(self.VOLUME_RETENTION_BUDGET, 0)` and `parse_budget(self.CACHE_BUDGET, 0)`, wrapped to raise a `ValueError` naming the setting.

- [ ] **Step 4: Run tests to verify they pass**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_budget.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/storage_budget.py src/aleph/vm/conf.py tests/supervisor/test_storage_budget.py
git commit -m "feat(conf): retention, reconcile and cache budget settings"
```

### Task 2: The `.reclaimable` marker

**Files:**
- Create: `src/aleph/vm/agent/vm/reclaimable.py`
- Create: `tests/supervisor/reclaim_fixtures.py`
- Test: `tests/supervisor/test_reclaimable.py`

**Interfaces:**
- Consumes: `storage_pools.iter_namespace_dirs(namespace)`, `storage_pools.get_pools()`, `purge._checked_namespace`.
- Produces:
  - `MARKER_NAME = ".reclaimable"`
  - `@dataclass(frozen=True) ReclaimableMarker(reclaimable_since: datetime, reason: Literal["gone", "orphan"], size_bytes: int, depends_on: tuple[str, ...] = (), version: int = 1)` with `to_json() -> str` and `ReclaimableMarker.from_json(text) -> ReclaimableMarker`
  - `read_marker(namespace_dir: Path) -> ReclaimableMarker | None`
  - `write_marker(namespace_dir: Path, marker: ReclaimableMarker) -> None`
  - `clear_marker(namespace_dir: Path) -> bool`
  - `directory_size_bytes(directory: Path) -> int` (allocated blocks of regular files directly inside, sparse-aware)
  - `depends_on_from_content(content: ExecutableContent) -> tuple[str, ...]`
  - `mark_reclaimable(namespace: str, reason, depends_on=(), *, now: datetime | None = None) -> list[Path]`
  - `adopt(namespace: str) -> int` (markers cleared)
  - `iter_reclaimable() -> Iterator[tuple[Path, ReclaimableMarker]]` (every marked namespace dir across pools)
  - `reclaimable_bytes(pool_path: Path | None = None) -> int`

- [ ] **Step 1: Write the shared fixture and the failing tests**

```python
# tests/supervisor/reclaim_fixtures.py
"""Shared temp-directory fixture for the reclamation tests: two volume pools,
a session directory, and the four download caches."""

from __future__ import annotations

from pathlib import Path

import pytest

import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.conf import settings
from aleph.vm.storage_pools import MediaClass, StoragePool, reset_pools

VM_HASH = "cafe" * 16
OTHER_HASH = "beef" * 16


@pytest.fixture
def pools(tmp_path, monkeypatch):
    execution_root = tmp_path / "execution"
    pool0 = execution_root / "volumes" / "persistent"
    pool1 = tmp_path / "mnt" / "nvme1"
    sessions = execution_root / "sessions"
    caches = {name: tmp_path / "cache" / name for name in ("runtime", "code", "data", "message")}
    for directory in (pool0, pool1, sessions, *caches.values()):
        directory.mkdir(parents=True)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", pool0)
    monkeypatch.setattr(settings, "CONFIDENTIAL_SESSION_DIRECTORY", sessions)
    monkeypatch.setattr(settings, "RUNTIME_CACHE", caches["runtime"])
    monkeypatch.setattr(settings, "CODE_CACHE", caches["code"])
    monkeypatch.setattr(settings, "DATA_CACHE", caches["data"])
    monkeypatch.setattr(settings, "MESSAGE_CACHE", caches["message"])
    monkeypatch.setattr(settings, "BACKUP_DIRECTORY", execution_root / "backups")
    (execution_root / "backups").mkdir()
    monkeypatch.setattr(
        storage_pools_module,
        "_pools",
        [
            StoragePool(path=pool0, media_class=MediaClass.SSD, index=0),
            StoragePool(path=pool1, media_class=MediaClass.NVME, index=1),
        ],
    )
    yield {"pool0": pool0, "pool1": pool1, "sessions": sessions, "execution_root": execution_root, **caches}
    reset_pools()


def volume(pool: Path, namespace: str, filename: str, size: int = 1) -> Path:
    directory = pool / namespace
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_bytes(b"x" * size)
    return path
```

```python
# tests/supervisor/test_reclaimable.py
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from aleph_message.models import InstanceContent, ProgramContent

from aleph.vm.agent.vm.reclaimable import (
    MARKER_NAME,
    ReclaimableMarker,
    adopt,
    clear_marker,
    depends_on_from_content,
    directory_size_bytes,
    iter_reclaimable,
    mark_reclaimable,
    read_marker,
    reclaimable_bytes,
    write_marker,
)
from aleph.vm.storage import get_message

from .reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def test_marker_round_trips_through_json():
    marker = ReclaimableMarker(reclaimable_since=NOW, reason="gone", size_bytes=42, depends_on=("abc", "def"))
    text = marker.to_json()
    assert json.loads(text) == {
        "version": 1,
        "reclaimable_since": "2026-08-24T12:00:00+00:00",
        "reason": "gone",
        "size_bytes": 42,
        "depends_on": ["abc", "def"],
    }
    assert ReclaimableMarker.from_json(text) == marker


def test_read_marker_is_none_without_file(pools):
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    assert read_marker(directory) is None


def test_read_marker_tolerates_a_corrupt_file(pools, caplog):
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    (directory / MARKER_NAME).write_text("{not json")
    assert read_marker(directory) is None
    assert "corrupt" in caplog.text.lower()


def test_write_and_clear_marker(pools):
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    write_marker(directory, ReclaimableMarker(reclaimable_since=NOW, reason="orphan", size_bytes=0))
    assert read_marker(directory).reason == "orphan"
    assert clear_marker(directory) is True
    assert clear_marker(directory) is False
    assert read_marker(directory) is None


def test_mark_reclaimable_writes_one_marker_per_pool_dir(pools):
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], VM_HASH, "data.ext4", size=8192)

    written = mark_reclaimable(VM_HASH, "gone", ("parent-ref",), now=NOW)

    assert sorted(written) == sorted([pools["pool0"] / VM_HASH / MARKER_NAME, pools["pool1"] / VM_HASH / MARKER_NAME])
    marker0 = read_marker(pools["pool0"] / VM_HASH)
    marker1 = read_marker(pools["pool1"] / VM_HASH)
    assert marker0.reclaimable_since == NOW
    assert marker0.depends_on == ("parent-ref",)
    # size_bytes is per directory, so each pool's budget is local
    assert marker0.size_bytes == directory_size_bytes(pools["pool0"] / VM_HASH)
    assert marker1.size_bytes == directory_size_bytes(pools["pool1"] / VM_HASH)
    assert marker1.size_bytes >= 8192


def test_mark_reclaimable_refuses_an_implausible_namespace(pools):
    with pytest.raises(ValueError):
        mark_reclaimable("../etc", "gone")


def test_directory_size_counts_only_regular_files_directly_inside(pools):
    directory = pools["pool0"] / VM_HASH
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    (directory / "sub").mkdir()
    (directory / "sub" / "big").write_bytes(b"x" * 100_000)
    assert 4096 <= directory_size_bytes(directory) < 100_000


def test_adopt_clears_every_marker_of_the_namespace(pools):
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "data.ext4")
    volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    mark_reclaimable(OTHER_HASH, "gone", now=NOW)

    assert adopt(VM_HASH) == 2

    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert read_marker(pools["pool1"] / VM_HASH) is None
    assert read_marker(pools["pool0"] / OTHER_HASH) is not None
    assert adopt(VM_HASH) == 0


def test_iter_reclaimable_and_reclaimable_bytes(pools):
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], OTHER_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], "dead" * 16, "rootfs.qcow2")  # live, unmarked
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    mark_reclaimable(OTHER_HASH, "orphan", now=NOW + timedelta(hours=1))

    found = {path.name: marker for path, marker in iter_reclaimable()}
    assert set(found) == {VM_HASH, OTHER_HASH}
    assert reclaimable_bytes() == found[VM_HASH].size_bytes + found[OTHER_HASH].size_bytes
    assert reclaimable_bytes(pools["pool0"]) == found[VM_HASH].size_bytes


@pytest.mark.asyncio
async def test_depends_on_from_instance_content_lists_parent_refs():
    from aleph.vm.conf import settings

    message = await get_message(ref=settings.FAKE_INSTANCE_ID)
    content = message.content
    assert isinstance(content, InstanceContent)
    depends = depends_on_from_content(content)
    assert content.rootfs.parent.ref in depends
    for vol in content.volumes:
        parent = getattr(vol, "parent", None)
        if parent is not None:
            assert parent.ref in depends


def test_depends_on_from_program_content_has_no_parents(mocker):
    """A program's rootfs is the shared runtime cache entry, not a per-VM
    volume, so nothing here depends on a parent image."""
    content = mocker.MagicMock(spec=ProgramContent)
    content.volumes = [mocker.MagicMock(parent=None), mocker.MagicMock(spec=[])]
    assert depends_on_from_content(content) == ()


def test_depends_on_deduplicates_parent_refs(mocker):
    content = mocker.MagicMock(spec=InstanceContent)
    content.rootfs = mocker.MagicMock(parent=mocker.MagicMock(ref="same"))
    content.volumes = [mocker.MagicMock(parent=mocker.MagicMock(ref="same")), mocker.MagicMock(parent=mocker.MagicMock(ref="other"))]
    assert depends_on_from_content(content) == ("same", "other")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_reclaimable.py -q -p no:cacheprovider`
Expected: FAIL with `ModuleNotFoundError: aleph.vm.agent.vm.reclaimable`

- [ ] **Step 3: Write the implementation**

```python
# src/aleph/vm/agent/vm/reclaimable.py
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

    Uses st_blocks so a sparse qcow2 counts what it really occupies."""
    total = 0
    try:
        entries = list(directory.iterdir())
    except OSError:
        return 0
    for entry in entries:
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./venv/bin/python -m pytest tests/supervisor/test_reclaimable.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/vm/reclaimable.py tests/supervisor/reclaim_fixtures.py tests/supervisor/test_reclaimable.py
git commit -m "feat(agent): the .reclaimable marker for unowned VM directories"
```

### Task 3: `retire_vm`

**Files:**
- Create: `src/aleph/vm/agent/vm/retire.py`
- Modify: `src/aleph/vm/agent/vm/purge.py` (split `purge_vm_side_dirs` out of `purge_vm_storage`, lines 187-196)
- Modify: `src/aleph/vm/agent/vm/backup.py` (add `purge_vm_backups` if absent; see Prerequisite)
- Test: `tests/supervisor/test_retire.py`

**Interfaces:**
- Consumes: `purge.purge_vm_storage`, `purge.purge_vm_side_dirs`, `reclaimable.mark_reclaimable`, `reclaimable.depends_on_from_content`, `metrics.delete_records_for_vm`, `backup.purge_vm_backups`, `AgentVmRegistry.get/forget`.
- Produces:
  - `class RetireReason(Enum): RECREATE = "recreate"; GONE = "gone"; ERASE = "erase"; FAILED_CREATE = "failed_create"`
  - `async def retire_vm(vm_hash: ItemHash | str, reason: RetireReason, *, supervisor: Supervisor, registry: AgentVmRegistry | None = None) -> None`
  - `def purge_vm_side_dirs(vm_hash: ItemHash | str) -> None` (in `purge.py`)

Behaviour table (from the spec):

| Reason | `delete_vm(keep_port_mappings=)` | Registry + DB records | Volumes | Session, staging | Backups |
|---|---|---|---|---|---|
| RECREATE | True | kept | untouched | untouched | untouched |
| GONE, `reap` | False | dropped | purged | removed | purged |
| GONE, `keep` | False | dropped | marked `gone` | removed | purged |
| ERASE | False | dropped | purged | removed | purged |
| FAILED_CREATE | False | dropped | purged | removed | purged |

`VmNotFoundError` from `delete_vm` is swallowed for every reason: a VM the supervisor never created (a create that failed before `CreateVm`) still has staging to purge, and a double retire is a no-op. Storage work runs in `asyncio.to_thread`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_retire.py
"""retire_vm: the one agent-side deletion function and its reasons."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

import aleph.vm.agent.vm.retire as retire_module
from aleph.vm.agent.vm.reclaimable import read_marker
from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId

from .reclaim_fixtures import VM_HASH, pools, volume  # noqa: F401


@pytest.fixture
def env(pools, mocker):
    """A registry with one recorded VM, its files on disk, and every side
    effect that leaves the filesystem mocked."""
    registry = AgentVmRegistry()
    content = MagicMock(volumes=[], rootfs=MagicMock(parent=MagicMock(ref="parent-ref")))
    registry.record(ItemHash(VM_HASH), message=content, original=content, persistent=True)
    rootfs = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    data = volume(pools["pool1"], VM_HASH, "data.ext4", size=4096)
    session = pools["sessions"] / VM_HASH
    session.mkdir()
    (session / "vm_session.b64").write_bytes(b"s")
    staging = pools["execution_root"] / "vprogram" / VM_HASH
    staging.mkdir(parents=True)
    (staging / "bundle").write_bytes(b"b")
    delete_records = mocker.patch.object(retire_module, "delete_records_for_vm", new_callable=AsyncMock)
    purge_backups = mocker.patch.object(retire_module, "purge_vm_backups")
    supervisor = MagicMock(delete_vm=AsyncMock())
    return {
        "registry": registry,
        "supervisor": supervisor,
        "rootfs": rootfs,
        "data": data,
        "session": session,
        "staging": staging,
        "delete_records": delete_records,
        "purge_backups": purge_backups,
    }


def _all_present(env) -> bool:
    return all(env[k].exists() for k in ("rootfs", "data", "session", "staging"))


@pytest.mark.asyncio
async def test_recreate_only_quiesces(env):
    await retire_vm(VM_HASH, RetireReason.RECREATE, supervisor=env["supervisor"])

    env["supervisor"].delete_vm.assert_awaited_once_with(VmId(VM_HASH), keep_port_mappings=True)
    assert _all_present(env)
    assert ItemHash(VM_HASH) in env["registry"]
    env["delete_records"].assert_not_awaited()
    env["purge_backups"].assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [RetireReason.GONE, RetireReason.ERASE, RetireReason.FAILED_CREATE])
async def test_purging_reasons_under_reap(env, monkeypatch, reason):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")

    await retire_vm(VM_HASH, reason, supervisor=env["supervisor"], registry=env["registry"])

    env["supervisor"].delete_vm.assert_awaited_once_with(VmId(VM_HASH), keep_port_mappings=False)
    assert not env["rootfs"].exists()
    assert not env["data"].exists()
    assert not env["session"].exists()
    assert not env["staging"].exists()
    assert ItemHash(VM_HASH) not in env["registry"]
    env["delete_records"].assert_awaited_once_with(VM_HASH)
    env["purge_backups"].assert_called_once_with(VM_HASH)


@pytest.mark.asyncio
async def test_gone_under_keep_marks_volumes_and_removes_the_rest(env, monkeypatch, pools):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")

    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    assert env["rootfs"].exists()
    assert env["data"].exists()
    marker = read_marker(pools["pool0"] / VM_HASH)
    assert marker is not None and marker.reason == "gone"
    assert marker.depends_on == ("parent-ref",)
    assert read_marker(pools["pool1"] / VM_HASH) is not None
    assert not env["session"].exists()
    assert not env["staging"].exists()
    assert ItemHash(VM_HASH) not in env["registry"]
    env["purge_backups"].assert_called_once_with(VM_HASH)


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [RetireReason.ERASE, RetireReason.FAILED_CREATE])
async def test_erase_and_failed_create_ignore_keep(env, monkeypatch, reason):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")

    await retire_vm(VM_HASH, reason, supervisor=env["supervisor"], registry=env["registry"])

    assert not env["rootfs"].exists()
    assert not env["data"].exists()


@pytest.mark.asyncio
async def test_vm_unknown_to_the_supervisor_is_still_retired(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    env["supervisor"].delete_vm.side_effect = VmNotFoundError(VM_HASH)

    await retire_vm(VM_HASH, RetireReason.FAILED_CREATE, supervisor=env["supervisor"], registry=env["registry"])

    assert not env["rootfs"].exists()
    assert not env["staging"].exists()


@pytest.mark.asyncio
async def test_non_recreate_requires_a_registry(env):
    with pytest.raises(ValueError):
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"])


@pytest.mark.asyncio
async def test_retire_is_idempotent(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    assert env["supervisor"].delete_vm.await_count == 2
```

Add to `tests/supervisor/test_vm_purge.py`:

```python
def test_purge_side_dirs_leaves_the_volumes(pools):
    from aleph.vm.agent.vm.purge import purge_vm_side_dirs

    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    session_dir = pools["sessions"] / VM_HASH
    session_dir.mkdir(parents=True)

    purge_vm_side_dirs(VM_HASH)

    assert rootfs.exists()
    assert not session_dir.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_retire.py tests/supervisor/test_vm_purge.py -q -p no:cacheprovider`
Expected: FAIL with `ModuleNotFoundError: aleph.vm.agent.vm.retire` and `ImportError: purge_vm_side_dirs`

- [ ] **Step 3: Write the implementation**

In `purge.py`, replace lines 187-196 of `purge_vm_storage` (the session directory block and the `purge_vm_staging` call) with `purge_vm_side_dirs(namespace)` and add:

```python
def purge_vm_side_dirs(vm_hash: ItemHash | str) -> None:
    """Delete the per-VM directories that are not volumes: the confidential
    session directory and the staging directories. Rebuilt by the next
    create, so a retained (reclaimable) VM keeps only its volumes."""
    namespace = _checked_namespace(vm_hash)
    if settings.CONFIDENTIAL_SESSION_DIRECTORY:
        session_dir = Path(settings.CONFIDENTIAL_SESSION_DIRECTORY) / namespace
        if session_dir.exists():
            try:
                shutil.rmtree(session_dir)
                logger.info("Removed the confidential session directory of %s", namespace)
            except OSError:
                logger.warning("Failed to remove the session directory of %s", namespace, exc_info=True)
    purge_vm_staging(namespace)
```

```python
# src/aleph/vm/agent/vm/retire.py
"""The one way the agent ends a VM.

Every path that used to call ``supervisor.delete_vm`` and then some subset
of ``registry.forget``, ``delete_records_for_vm`` and ``remove_*_staging``
goes through ``retire_vm`` with a reason. The reason has no default: a call
site must say what it means, which is what was missing when disks leaked
(spec S1). The supervisor's DeleteVm is quiescence only; storage policy is
decided here, agent-side, and never crosses the wire.
"""

from __future__ import annotations

import asyncio
import logging
from enum import Enum

from aleph_message.models import ItemHash

from aleph.vm.agent.metrics import delete_records_for_vm
from aleph.vm.agent.vm.backup import purge_vm_backups
from aleph.vm.agent.vm.purge import purge_vm_side_dirs, purge_vm_storage
from aleph.vm.agent.vm.reclaimable import depends_on_from_content, mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId

logger = logging.getLogger(__name__)


class RetireReason(Enum):
    RECREATE = "recreate"  # the same VM comes back immediately: amend, crash recovery, idle reap, reboot
    GONE = "gone"  # positive knowledge it will not return: forgotten, unpaid, deallocated, migrated away
    ERASE = "erase"  # the owner asked for a wipe
    FAILED_CREATE = "failed_create"  # a create that never committed


async def retire_vm(
    vm_hash: ItemHash | str,
    reason: RetireReason,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry | None = None,
) -> None:
    """Quiesce the VM through the supervisor, then apply ``reason`` to
    everything the agent holds for it: registry record, DB records, volumes,
    session and staging directories, backups.

    RECREATE stops after the quiesce (port mappings kept, storage untouched).
    Every other reason drops the records and the side directories; GONE
    applies VOLUME_RETENTION to the volumes, ERASE and FAILED_CREATE purge
    them regardless (retention protects against administrative deletion,
    not against the owner's own request, and a VM that never ran has nothing
    worth keeping).
    """
    vm_id = VmId(str(vm_hash))
    try:
        await supervisor.delete_vm(vm_id, keep_port_mappings=reason is RetireReason.RECREATE)
    except VmNotFoundError:
        logger.debug("Retire %s (%s): the supervisor does not know it", vm_hash, reason.value)
    if reason is RetireReason.RECREATE:
        return
    if registry is None:
        msg = f"retire_vm({reason.value}) needs the registry to drop the VM's record"
        raise ValueError(msg)

    item_hash = vm_hash if isinstance(vm_hash, ItemHash) else ItemHash(str(vm_hash))
    record = registry.get(item_hash)
    registry.forget(item_hash)
    await delete_records_for_vm(str(vm_hash))
    await asyncio.to_thread(_release_storage, str(vm_hash), reason, record)
    await asyncio.to_thread(purge_vm_backups, str(vm_hash))
    logger.info("Retired %s (%s)", vm_hash, reason.value)


def _release_storage(namespace: str, reason: RetireReason, record: AgentVmRecord | None) -> None:
    if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep":
        depends_on = depends_on_from_content(record.message) if record is not None else ()
        mark_reclaimable(namespace, "gone", depends_on)
        purge_vm_side_dirs(namespace)
        return
    purge_vm_storage(namespace)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./venv/bin/python -m pytest tests/supervisor/test_retire.py tests/supervisor/test_vm_purge.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/vm/retire.py src/aleph/vm/agent/vm/purge.py src/aleph/vm/agent/vm/backup.py tests/supervisor/test_retire.py tests/supervisor/test_vm_purge.py
git commit -m "feat(agent): retire_vm, the one deletion function with a mandatory reason"
```

### Task 4: Convert `tasks.py` (terminal status and payment stops)

**Files:**
- Modify: `src/aleph/vm/agent/tasks.py:30-39` (imports), `:404-408`, `:429`, `:456`, `:517`
- Test: `tests/supervisor/test_checkpayment.py` (extend)

**Interfaces:**
- Consumes: `retire_vm`, `RetireReason.GONE`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/supervisor/test_checkpayment.py` (reuse that file's `fake_instance_content` fixture and the mocking pattern of `test_not_enough_flow`):

```python
@pytest.mark.asyncio
async def test_terminal_status_retires_as_gone(mocker, fake_instance_content):
    from aleph.vm.agent import tasks
    from aleph.vm.agent.vm.retire import RetireReason

    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.FORGOTTEN)
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    # The payment loops still run over the same snapshot: keep them satisfied
    # so only the terminal-status branch retires anything.
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=10_000, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=0)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    tasks._terminal_strike_count.clear()
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=fake_instance_content, original=fake_instance_content, persistent=True)
    supervisor = MagicMock(list_vms=AsyncMock(return_value=[_info(vm_hash)]), delete_vm=AsyncMock())

    for _ in range(tasks.STOP_AFTER_CONFIRMATIONS):
        await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_awaited_once_with(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_insufficient_stream_retires_as_gone(mocker, fake_instance_content):
    from aleph.vm.agent.vm.retire import RetireReason

    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=2, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=fake_instance_content, original=fake_instance_content, persistent=True)
    supervisor = MagicMock(list_vms=AsyncMock(return_value=[_info(vm_hash)]), delete_vm=AsyncMock())

    await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_awaited_once_with(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
```

`_info(vm_hash)` is the `VmInfo` builder already used in `tests/supervisor/test_tasks_registry_reads.py`; copy it into `test_checkpayment.py` if it is not there. `fake_instance_content` must carry a superfluid payment for the second test; check how `test_not_enough_flow` builds it and reuse that.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_checkpayment.py -q -p no:cacheprovider -k retires`
Expected: FAIL with `AttributeError: module 'aleph.vm.agent.tasks' has no attribute 'retire_vm'`

- [ ] **Step 3: Convert the call sites**

In `tasks.py`: add `from aleph.vm.agent.vm.retire import RetireReason, retire_vm`; remove the now-unused imports of `delete_records_for_vm`, `remove_snp_instance_staging`, `remove_vprogram_staging` (lines 30, 32, 39; confirm with `grep -n` that nothing else in the file uses them).

Lines 404-408 become:

```python
            await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
```

Each of the three payment sites (lines 427-431, 454-458, 515-519) becomes:

```python
                await retire_vm(ItemHash(last_info.vm_id), RetireReason.GONE, supervisor=supervisor, registry=registry)
```

(drop the `try/except VmNotFoundError`; `retire_vm` swallows it). Update the docstring of `check_payment`: "Stopping a VM here means retiring it as GONE: the record is dropped and the disks follow VOLUME_RETENTION."

- [ ] **Step 4: Run the file's tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_checkpayment.py tests/supervisor/test_tasks_registry_reads.py -q -p no:cacheprovider`
Expected: PASS (existing tests that asserted `delete_vm` on payment stops must be updated to assert `retire_vm`; do that in the same step)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/tasks.py tests/supervisor/test_checkpayment.py
git commit -m "refactor(agent): terminal-status and payment stops retire VMs as GONE"
```

### Task 5: Convert the allocation view and migration cleanup

**Files:**
- Modify: `src/aleph/vm/agent/views/__init__.py:29,45,66` (imports), `:604-612`
- Modify: `src/aleph/vm/agent/views/migration.py:385-395`
- Test: `tests/supervisor/test_views.py` (extend), `tests/supervisor/views/test_migration.py:651-676`

- [ ] **Step 1: Write the failing tests**

In `tests/supervisor/views/test_migration.py::TestMigrationCleanup::test_cleanup_success`, replace the final assertion block with:

```python
        # Cleanup retires the migrated-away source as GONE: the destination
        # owns the data now, so under VOLUME_RETENTION=reap the disks go.
        retire.assert_awaited_once()
        args, kwargs = retire.await_args
        assert args[0] == mock_vm_hash
        assert args[1] is RetireReason.GONE
        assert kwargs["supervisor"] is supervisor
```

adding at the top of the test `retire = mocker.patch("aleph.vm.agent.views.migration.retire_vm", new_callable=AsyncMock)` and the import `from aleph.vm.agent.vm.retire import RetireReason`.

In `tests/supervisor/test_vprogram.py`, rewrite `test_update_allocations_stops_descheduled_vprogram` (line 157) so the assertions target `retire_vm`:

```python
@pytest.mark.asyncio
async def test_update_allocations_stops_descheduled_vprogram(aiohttp_client, mocker, scheduler_auth):
    """The scheduler is the single source of truth for v-programs: absence from
    the allocation retires them as GONE, despite being credit-paid and
    confidential (both of which spare other VM types)."""
    from aleph.vm.agent.vm.retire import RetireReason

    message = load_vprogram_message()
    vm_hash = str(message.item_hash)

    app = setup_webapp(supervisor=LocalSupervisor(None))
    app["pubsub"] = None
    app["vm_registry"].record(ItemHash(vm_hash), message=message.content, original=message.content, persistent=True)

    fake_supervisor = MagicMock(delete_vm=AsyncMock(), list_vms=AsyncMock(return_value=[_running_vm_info(vm_hash)]))
    app["supervisor"] = fake_supervisor

    retire = mocker.patch("aleph.vm.agent.views.retire_vm", new_callable=AsyncMock)
    client = await aiohttp_client(app)

    body, headers = scheduler_auth({"persistent_vms": []})
    response = await client.post("/control/allocations", data=body, headers=headers)
    assert response.status == 200
    assert vm_hash in (await response.json())["stopped"]
    retire.assert_awaited_once_with(
        ItemHash(vm_hash), RetireReason.GONE, supervisor=fake_supervisor, registry=app["vm_registry"]
    )
    fake_supervisor.delete_vm.assert_not_awaited()
```

(The registry-forget and `delete_records_for_vm` assertions move to `test_retire.py`, which already covers them.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/views/test_migration.py tests/supervisor/test_vprogram.py -q -p no:cacheprovider -k "cleanup_success or stops_descheduled"`
Expected: FAIL (`retire_vm` not an attribute of the module)

- [ ] **Step 3: Convert the call sites**

`views/__init__.py` lines 604-612 become:

```python
                await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
                stopped_vms.append(vm_hash)
```

Add `from aleph.vm.agent.vm.retire import RetireReason, retire_vm`; drop the imports of `delete_records_for_vm`, `remove_snp_instance_staging`, `remove_vprogram_staging` if nothing else in the file uses them (`get_execution_records` stays).

`views/migration.py` lines 386-395 become:

```python
        # The source VM has migrated away: the destination owns the data now.
        # Retire it as GONE: the supervisor stops it and forgets the
        # definition, the agent drops the record and applies
        # VOLUME_RETENTION to the disks it left behind.
        await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=request.app["vm_registry"])
```

with the import added.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/views/test_migration.py tests/supervisor/test_vprogram.py tests/supervisor/test_views.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/views/__init__.py src/aleph/vm/agent/views/migration.py tests/supervisor/views/test_migration.py tests/supervisor/test_vprogram.py
git commit -m "refactor(agent): allocation removal and migration cleanup retire VMs as GONE"
```

### Task 6: Convert `run.py`

**Files:**
- Modify: `src/aleph/vm/agent/run.py:31,39` (imports), `:376-383`, `:440-448`, `:474-483`, `:511-517`, `:530-538`, `:685-690`, `:707-714`, `:822-824`, `:846-849`, `:925-928`, `:972-975`
- Test: `tests/supervisor/test_run.py`, `tests/supervisor/test_run_idle_teardown.py`, `tests/supervisor/test_run_program_path.py` (extend/update)

Reasons per site:

| Lines | Today | Reason |
|---|---|---|
| 376-383 program readiness failure | `registry.forget` + `delete_vm` | `FAILED_CREATE` |
| 440-448 instance build/create failure | `registry.forget` + `remove_snp_instance_staging` | `FAILED_CREATE` |
| 474-483 instance readiness failure | forget + delete + staging | `FAILED_CREATE` |
| 511-517 vprogram build failure | forget + staging | `FAILED_CREATE` |
| 530-538 vprogram readiness failure | forget + delete + staging | `FAILED_CREATE` |
| 685-690 `_ensure_program_vm` unconfigured recreate | `delete_vm` | `RECREATE` |
| 707-714 `_ensure_program_vm` setup failure | forget + delete | `FAILED_CREATE` |
| 822-824 empty result teardown | `delete_vm` | `RECREATE` |
| 846-849, 925-928 `REUSE_TIMEOUT == 0` teardown | `delete_vm` | `RECREATE` |
| 972-975 FAILED persistent VM | `delete_vm(keep_port_mappings=True)` | `RECREATE` |

- [ ] **Step 1: Write the failing tests**

In `tests/supervisor/test_supervisor_run_routing.py`, rewrite `test_eligible_instance_timeout_tears_down` (line 187) and `test_eligible_instance_port_forward_failure_tears_down` (line 211) to assert the retire call; the first becomes:

```python
@pytest.mark.asyncio
async def test_eligible_instance_timeout_retires_as_failed_create(monkeypatch):
    from aleph.vm.agent.vm.retire import RetireReason

    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_START_POLL_TIMEOUT_SECONDS", 0)
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    supervisor = _fake_supervisor(get_status=VmStatus.BOOTING)  # never RUNNING
    registry = AgentVmRegistry()

    with pytest.raises(run_module.VmStartupError):
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    retire.assert_awaited_once_with(_HASH, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()
```

and the second the same with `supervisor.add_port_forward = AsyncMock(side_effect=RuntimeError("nftables boom"))` and `pytest.raises(RuntimeError, match="nftables boom")`. In the same file, `test_start_persistent_recreates_after_failed` (line 630) asserts `retire.assert_awaited_once_with(_HASH, RetireReason.RECREATE, supervisor=supervisor)` instead of `delete_vm(..., keep_port_mappings=True)`.

In `tests/supervisor/test_vprogram.py`, `test_create_vm_execution_vprogram_build_failure_forgets_record` (line 307) and `test_create_vm_execution_vprogram_wait_failure_tears_down` (line 271) gain `retire = mocker.patch("aleph.vm.agent.run.retire_vm", new_callable=AsyncMock)` and assert `retire.assert_awaited_once_with(message.item_hash, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)`; drop their `assert message.item_hash not in registry` line (the forget now lives inside the mocked `retire_vm`).

In `tests/supervisor/test_run_idle_teardown.py`, the tests asserting `supervisor.delete_vm` for the `REUSE_TIMEOUT == 0` path change to `mocker.patch("aleph.vm.agent.run.retire_vm", new_callable=AsyncMock)` and assert `RetireReason.RECREATE` with `supervisor=` only.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_vprogram.py tests/supervisor/test_run_idle_teardown.py -q -p no:cacheprovider`
Expected: FAIL (`retire_vm` missing on `aleph.vm.agent.run`)

- [ ] **Step 3: Convert the call sites**

Import `from aleph.vm.agent.vm.retire import RetireReason, retire_vm`; remove the `remove_snp_instance_staging` / `remove_vprogram_staging` imports if unused.

Every `FAILED_CREATE` site collapses to the same shape; for 474-483:

```python
        except Exception:
            # Readiness or port-forward setup failed: retire the half-started
            # VM (records, staging and volumes go: nothing worth keeping from a
            # VM that never ran), but never let a teardown error mask the
            # original failure.
            try:
                await retire_vm(vm_hash, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
            except Exception:
                logger.exception("Teardown of half-started VM %s failed", vm_hash)
            raise
```

The sites where no VM was created yet (440-448, 511-517) use the same call: `retire_vm` swallows the supervisor's `VmNotFoundError`.

`RECREATE` sites, for 685-690:

```python
            logger.info("Program VM %s is %s/unconfigured; recreating", vm_hash, info.status.value)
            await program_client.forget(vm_id)
            await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)
            await _wait_until_gone(supervisor, vm_id)
```

and 972-975:

```python
            # Crash recovery is a delete+recreate cycle, not a dealloc:
            # RECREATE keeps the persisted host-port forwards and the disks.
            await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)
            info = None
```

Keep the surrounding `program_client.forget`, `update_watcher.cancel` calls as they are.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_run_idle_teardown.py tests/supervisor/test_run_program_path.py tests/supervisor/test_spec_program.py tests/supervisor/test_vprogram.py tests/supervisor/test_vprogram_port_map.py -q -p no:cacheprovider`
Expected: PASS (update any test that patched `supervisor.delete_vm` on a converted site to patch `aleph.vm.agent.run.retire_vm` instead)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/run.py tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_vprogram.py tests/supervisor/test_run_idle_teardown.py tests/supervisor/test_run_program_path.py
git commit -m "refactor(agent): create failures retire as FAILED_CREATE, recreates as RECREATE"
```

### Task 7: Convert expiry, update watcher and the operator views

**Files:**
- Modify: `src/aleph/vm/agent/expiry.py:52`, `src/aleph/vm/agent/update_watcher.py:93`, `src/aleph/vm/agent/views/operator.py:509,539,663-674,755`
- Create: `tests/supervisor/test_agent_no_direct_delete.py`
- Test: `tests/supervisor/test_expiry.py`, `tests/supervisor/test_update_watcher.py`, `tests/supervisor/views/test_operator.py`

- [ ] **Step 1: Write the failing tests**

The guard test, modelled on `tests/supervisor/test_agent_pool_free.py`:

```python
# tests/supervisor/test_agent_no_direct_delete.py
"""Every agent delete goes through retire_vm.

A call site that reaches supervisor.delete_vm directly has no reason, and a
delete without a reason is how disks leaked (spec S1). retire.py is the one
allowed caller."""

from __future__ import annotations

from pathlib import Path

import pytest

import aleph.vm.agent as agent_package

AGENT_ROOT = Path(agent_package.__file__).parent
ALLOWED = {AGENT_ROOT / "vm" / "retire.py"}


@pytest.mark.parametrize(
    "path",
    sorted(p for p in AGENT_ROOT.rglob("*.py") if p not in ALLOWED and "migrations" not in p.parts),
    ids=lambda p: str(p.relative_to(AGENT_ROOT)),
)
def test_agent_module_never_calls_delete_vm_directly(path):
    source = path.read_text()
    assert ".delete_vm(" not in source, f"{path.relative_to(AGENT_ROOT)} must retire VMs through retire_vm"
```

`tests/supervisor/test_expiry.py`: `FakeSupervisor.delete_vm` records `(vm_id, keep_port_mappings)`; change the expectation in `test_schedule_reaps_after_timeout` to `[("vm-a", True)]` (RECREATE keeps port mappings). The ids stay as they are: `retire_vm` builds `VmId(str(vm_hash))` and the RECREATE path never validates the hash. Same in `tests/supervisor/test_update_watcher.py::test_watch_reaps_on_update`.

`tests/supervisor/views/test_operator.py::test_operator_erase_with_delegation` (line 908): replace the `mock_purge` patch and its assertion with

```python
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)
    # (the delegation, session and app setup lines of the test stay unchanged)
    response = await client.post(f"/control/machine/{vm_hash}/erase")

    assert response.status == 200
    retire.assert_awaited_once_with(vm_hash, RetireReason.ERASE, supervisor=fake_sup, registry=app["vm_registry"])
    fake_sup.get_vm.assert_awaited()  # the 404 precheck
    fake_sup.delete_vm.assert_not_awaited()
```

and drop the registry/`delete_records` assertions (they now belong to `test_retire.py`). `test_operator_erase_unknown_vm_404` stays as is. The ephemeral stop and reboot tests assert `RECREATE` the same way.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_agent_no_direct_delete.py tests/supervisor/test_expiry.py tests/supervisor/test_update_watcher.py tests/supervisor/views/test_operator.py -q -p no:cacheprovider`
Expected: FAIL (guard test lists the remaining direct callers; operator tests miss `retire_vm`)

- [ ] **Step 3: Convert the call sites**

`expiry.py:52`: `await retire_vm(str(vm_id), RetireReason.RECREATE, supervisor=self.supervisor)` (an idle on-demand program is recreated on the next request; its volumes stay).
`update_watcher.py:93`: `await retire_vm(str(vm_id), RetireReason.RECREATE, supervisor=self.supervisor)`.
`operator.py:509` and `:539` (ephemeral stop and reboot): `await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)`.
`operator.py:755` (rebuild from scratch): `await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)` followed by the existing `purge_vm_volumes` and `purge_vm_staging` calls (a reinstall is a deliberate partial purge with the record kept).
`operate_erase` (lines 661-675) becomes:

```python
        logger.info(f"Erasing {vm_hash}")
        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        request.app["expiry"].cancel(vm_id)
        request.app["update_watcher"].cancel(vm_id)
        # The owner asked for a wipe: ERASE purges regardless of VOLUME_RETENTION.
        await retire_vm(vm_hash, RetireReason.ERASE, supervisor=supervisor, registry=request.app["vm_registry"])
        return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
```

Drop the now-unused `purge_vm_storage` and `metrics` imports from `operator.py`.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_agent_no_direct_delete.py tests/supervisor/test_expiry.py tests/supervisor/test_update_watcher.py tests/supervisor/views/test_operator.py -q -p no:cacheprovider`
Expected: PASS, including the guard: no agent module but `retire.py` contains `.delete_vm(`

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/expiry.py src/aleph/vm/agent/update_watcher.py src/aleph/vm/agent/views/operator.py tests/supervisor/test_agent_no_direct_delete.py tests/supervisor/test_expiry.py tests/supervisor/test_update_watcher.py tests/supervisor/views/test_operator.py
git commit -m "refactor(agent): expiry, update watcher and operator views retire through retire_vm"
```

### Task 8: The reconciler

**Files:**
- Create: `src/aleph/vm/agent/vm/reconciler.py`
- Test: `tests/supervisor/test_reconciler.py`

**Interfaces:**
- Consumes: `reclaimable.*`, `purge.purge_vm_storage`, `purge._ITEM_HASH_PATTERN`, `storage_pools.get_pools/iter_namespace_dirs`, `backup.sweep_expired_backups`, `AgentVmRegistry.items()`.
- Produces:
  - `@dataclass ReconcileReport(purged_orphans: list[str], marked_orphans: list[str], evicted: list[str], parts_removed: int, side_dirs_removed: int, backups_removed: int, bytes_freed: int)`
  - `creating(namespace: str)` context manager (registers the in-flight create, adopts retained dirs on enter)
  - `is_creating(namespace: str) -> bool`
  - `reconcile_storage(registry: AgentVmRegistry, *, now: datetime | None = None, dry_run: bool = False) -> ReconcileReport`
  - `make_room(pool: StoragePool, needed_bytes: int) -> int` (bytes freed by evicting reclaimable dirs on that pool, oldest first)

Pass order per call: namespaces, `.part` files, side directories, retention budget, backups (the cache pass is added in Task 13).

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_reconciler.py
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash

import aleph.vm.agent.vm.reconciler as reconciler_module
from aleph.vm.agent.vm.reclaimable import mark_reclaimable, read_marker
from aleph.vm.agent.vm.reconciler import creating, is_creating, make_room, reconcile_storage
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage_pools import get_pools

from .reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def _age(path, seconds: int) -> None:
    stamp = time.time() - seconds
    os.utime(path, (stamp, stamp))


@pytest.fixture
def registry():
    reg = AgentVmRegistry()
    content = MagicMock(volumes=[], rootfs=None)
    reg.record(ItemHash(LIVE), message=content, original=content, persistent=True)
    return reg


@pytest.fixture(autouse=True)
def _no_backups(mocker):
    mocker.patch.object(reconciler_module, "sweep_expired_backups", return_value=0)


def test_live_dirs_are_left_alone(pools, registry):
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    _age(live.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert live.exists()
    assert report.purged_orphans == [] and report.marked_orphans == []


def test_young_orphan_is_inside_the_create_guard(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    young = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")

    reconcile_storage(registry, now=NOW)

    assert young.exists()


def test_in_flight_create_is_never_an_orphan(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    with creating(VM_HASH):
        assert is_creating(VM_HASH)
        reconcile_storage(registry, now=NOW)
        assert old.exists()
    assert not is_creating(VM_HASH)


def test_creating_adopts_retained_dirs(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    with creating(VM_HASH):
        assert read_marker(pools["pool0"] / VM_HASH) is None


def test_old_orphan_is_purged_under_reap(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert not old.parent.exists()
    assert report.purged_orphans == [VM_HASH]


def test_old_orphan_is_marked_under_keep(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert old.exists()
    assert read_marker(old.parent).reason == "orphan"
    assert report.marked_orphans == [VM_HASH]


def test_marked_dir_whose_vm_is_live_again_is_adopted(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], LIVE, "rootfs.qcow2")
    mark_reclaimable(LIVE, "gone", now=NOW)

    reconcile_storage(registry, now=NOW)

    assert read_marker(pools["pool0"] / LIVE) is None


def test_implausible_dir_names_are_skipped(pools, registry, monkeypatch, caplog):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    weird = pools["pool0"] / "lost+found"
    weird.mkdir()
    _age(weird, 10_000)

    reconcile_storage(registry, now=NOW)

    assert weird.exists()


def test_dry_run_changes_nothing(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW, dry_run=True)

    assert old.exists()
    assert report.purged_orphans == [VM_HASH]


def test_old_part_files_are_removed_young_ones_kept(pools, registry):
    old_part = pools["runtime"] / "abc.part"
    old_part.write_bytes(b"x")
    _age(old_part, 10_000)
    young_part = pools["code"] / "def.part"
    young_part.write_bytes(b"x")
    pool_part = volume(pools["pool0"], LIVE, "rootfs.qcow2.part")
    _age(pool_part, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert not old_part.exists()
    assert young_part.exists()
    assert not pool_part.exists()
    assert report.parts_removed == 2


def test_side_dirs_of_unknown_hashes_are_removed(pools, registry):
    stale_session = pools["sessions"] / VM_HASH
    stale_session.mkdir()
    live_session = pools["sessions"] / LIVE
    live_session.mkdir()
    stale_staging = pools["execution_root"] / "snp-instance" / VM_HASH
    stale_staging.mkdir(parents=True)
    stale_mount = pools["execution_root"] / "mnt" / f"{VM_HASH}_data"
    stale_mount.mkdir(parents=True)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconciler_module, "MOUNT_ROOT", pools["execution_root"] / "mnt")
        report = reconcile_storage(registry, now=NOW)

    assert not stale_session.exists()
    assert live_session.exists()
    assert not stale_staging.exists()
    assert not stale_mount.exists()
    assert report.side_dirs_removed == 3


def test_budget_evicts_oldest_first(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    monkeypatch.setattr(settings, "VOLUME_RETENTION_BUDGET", "8192")
    oldest = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    newest = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    mark_reclaimable(OTHER_HASH, "gone", now=NOW - timedelta(days=1))

    report = reconcile_storage(registry, now=NOW)

    assert not oldest.exists()
    assert newest.exists()
    assert report.evicted == [VM_HASH]


def test_switching_to_reap_evicts_everything_marked(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    kept = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    reconcile_storage(registry, now=NOW)

    assert not kept.exists()


def test_make_room_frees_only_what_is_needed(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    oldest = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    newest = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    mark_reclaimable(OTHER_HASH, "gone", now=NOW - timedelta(days=1))

    freed = make_room(get_pools()[0], needed_bytes=4096)

    assert freed >= 4096
    assert not oldest.exists()
    assert newest.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_reconciler.py -q -p no:cacheprovider`
Expected: FAIL with `ModuleNotFoundError: aleph.vm.agent.vm.reconciler`

- [ ] **Step 3: Write the implementation**

```python
# src/aleph/vm/agent/vm/reconciler.py
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

# Where create_devmapper mounts a volume while resizing it (storage.py).
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
    from aleph.vm.agent.vm.reclaimable import directory_size_bytes

    return sum(directory_size_bytes(d) for d in iter_namespace_dirs(namespace))


def reconcile_storage(
    registry: AgentVmRegistry,
    *,
    now: datetime | None = None,
    dry_run: bool = False,
) -> ReconcileReport:
    now = now or datetime.now(tz=timezone.utc)
    guard = timedelta(seconds=settings.VOLUME_CREATE_GUARD)
    live = {str(vm_hash) for vm_hash, _ in registry.items()}
    report = ReconcileReport()
    _reconcile_namespaces(live, now, guard, dry_run, report)
    _sweep_parts(now, guard, dry_run, report)
    _sweep_side_dirs(live, dry_run, report)
    _enforce_retention_budget(dry_run, report)
    if not dry_run:
        report.backups_removed = sweep_expired_backups(now)
    logger.info("Storage reconcile%s: %s", " (dry run)" if dry_run else "", report.summary())
    return report


def _reconcile_namespaces(live: set[str], now: datetime, guard: timedelta, dry_run: bool, report: ReconcileReport) -> None:
    seen: set[str] = set()
    for directory in list(iter_namespace_dirs()):
        namespace = directory.name
        if not _plausible(namespace):
            logger.warning("Ignoring %s: not a VM directory", directory)
            continue
        if namespace in live or is_creating(namespace):
            # A live VM owns it; a stale marker (re-created without going
            # through creating()) is cleared so the budget pass cannot evict it.
            if read_marker(directory) is not None and not dry_run:
                clear_marker(directory)
            continue
        if read_marker(directory) is not None or namespace in seen:
            continue
        try:
            if now - _mtime(directory) < guard:
                continue
        except OSError:
            continue
        seen.add(namespace)
        if settings.VOLUME_RETENTION == "keep":
            report.marked_orphans.append(namespace)
            if not dry_run:
                mark_reclaimable(namespace, "orphan", now=now)
        else:
            report.purged_orphans.append(namespace)
            if not dry_run:
                report.bytes_freed += _dir_bytes(namespace)
                purge_vm_storage(namespace)


def _part_roots() -> Iterator[Path]:
    for cache in (settings.RUNTIME_CACHE, settings.CODE_CACHE, settings.DATA_CACHE, settings.MESSAGE_CACHE):
        if cache:
            yield Path(cache)
    yield from iter_namespace_dirs()


def _sweep_parts(now: datetime, guard: timedelta, dry_run: bool, report: ReconcileReport) -> None:
    for root in _part_roots():
        try:
            parts = list(root.glob("*.part"))
        except OSError:
            continue
        for part in parts:
            try:
                if now - _mtime(part) < guard:
                    continue
                size = part.stat().st_size
                if not dry_run:
                    part.unlink()
                report.parts_removed += 1
                report.bytes_freed += size
            except OSError:
                logger.warning("Failed to remove %s", part, exc_info=True)


def _side_dir_roots() -> Iterator[tuple[Path, str]]:
    """(root, how the hash is derived from the child name)."""
    if settings.CONFIDENTIAL_SESSION_DIRECTORY:
        yield Path(settings.CONFIDENTIAL_SESSION_DIRECTORY), "exact"
    for kind in STAGING_KINDS:
        yield Path(settings.EXECUTION_ROOT) / kind, "exact"
    yield MOUNT_ROOT, "prefix"  # /mnt/{ns}_{vol}


def _sweep_side_dirs(live: set[str], dry_run: bool, report: ReconcileReport) -> None:
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
            report.side_dirs_removed += 1


def _pool_total(pool: StoragePool) -> int:
    try:
        return shutil.disk_usage(str(pool.path)).total
    except OSError:
        return 0


def _reclaimable_on(pool: StoragePool) -> list[tuple[Path, ReclaimableMarker]]:
    entries = [(d, m) for d, m in iter_reclaimable() if d.parent == pool.path]
    entries.sort(key=lambda item: item[1].reclaimable_since)
    return entries


def _evict(namespace: str, dry_run: bool, report: ReconcileReport) -> int:
    size = _dir_bytes(namespace)
    report.evicted.append(namespace)
    if not dry_run:
        purge_vm_storage(namespace)
        report.bytes_freed += size
    return size


def _enforce_retention_budget(dry_run: bool, report: ReconcileReport) -> None:
    for pool in get_pools():
        entries = _reclaimable_on(pool)
        if not entries:
            continue
        budget = 0 if settings.VOLUME_RETENTION == "reap" else parse_budget(settings.VOLUME_RETENTION_BUDGET, _pool_total(pool))
        total = sum(marker.size_bytes for _, marker in entries)
        for directory, marker in entries:
            if total <= budget:
                break
            if directory.name in report.evicted:
                continue
            _evict(directory.name, dry_run, report)
            total -= marker.size_bytes


def make_room(pool: StoragePool, needed_bytes: int) -> int:
    """Evict reclaimable directories on ``pool``, oldest first, until
    ``needed_bytes`` are free or nothing reclaimable is left. Returns the
    bytes freed."""
    freed = 0
    report = ReconcileReport()
    for directory, _marker in _reclaimable_on(pool):
        try:
            if shutil.disk_usage(str(pool.path)).free >= needed_bytes:
                break
        except OSError:
            break
        freed += _evict(directory.name, False, report)
    if freed:
        logger.info("Made room on %s: evicted %s (%d bytes)", pool.path, ", ".join(report.evicted), freed)
    return freed


async def reconcile_now(app: web.Application) -> ReconcileReport:
    return await asyncio.to_thread(reconcile_storage, app["vm_registry"])


async def reconcile_at_startup(app: web.Application) -> None:
    """on_startup hook: one pass, preceded by a per-pool summary of what the
    pass will remove, so an operator reading the log knows why free space
    jumped after an upgrade."""
    registry = app["vm_registry"]
    preview = await asyncio.to_thread(reconcile_storage, registry, dry_run=True)
    if preview.purged_orphans or preview.marked_orphans or preview.evicted:
        logger.warning(
            "Startup storage reconcile will purge %d orphan(s), mark %d, evict %d (VOLUME_RETENTION=%s)",
            len(preview.purged_orphans),
            len(preview.marked_orphans),
            len(preview.evicted),
            settings.VOLUME_RETENTION,
        )
    await reconcile_now(app)


async def periodic_reconcile(app: web.Application) -> None:
    interval = settings.VOLUME_RECONCILE_INTERVAL
    await asyncio.sleep(random.uniform(0, interval))
    while True:
        try:
            await reconcile_now(app)
        except Exception as error:
            if isinstance(error, RuntimeError) and "Event loop is closed" in str(error):
                return
            logger.warning("Storage reconcile failed: %s", error, exc_info=True)
        await asyncio.sleep(interval * random.uniform(0.85, 1.15))


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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `./venv/bin/python -m pytest tests/supervisor/test_reconciler.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/vm/reconciler.py tests/supervisor/test_reconciler.py
git commit -m "feat(agent): storage reconciler (orphans, .part files, side dirs, retention budget)"
```

### Task 9: Wire the reconciler in, count reclaimable space as free, and document

**Files:**
- Modify: `src/aleph/vm/agent/supervisor.py:462-491` (hooks), `src/aleph/vm/agent/run.py` (wrap the three create paths in `creating()`), `src/aleph/vm/agent/vm/retire.py` (reconcile after GONE), `src/aleph/vm/agent/capacity.py:246-255`, `src/aleph/vm/storage_pools.py:289-320`
- Modify: `docs/architecture/storage.md`, `docs/architecture/vm-lifecycle.md`
- Test: `tests/supervisor/test_reconciler.py`, `tests/supervisor/test_agent_capacity.py`, `tests/supervisor/test_storage_pools.py`, `tests/supervisor/test_retire.py`

**Interfaces:**
- Produces: `storage_pools.set_room_maker(fn: Callable[[StoragePool, int], int] | None) -> None`; `_select_from` calls it once for the roomiest eligible pool before raising `InsufficientResourcesError`; `CapacityManager._available_disk_bytes()` returns free plus `reclaimable_bytes()`; `retire_vm(GONE)` schedules `reconcile_storage` when `settings.VOLUME_RETENTION == "keep"` via an optional `on_gone: Callable[[], Awaitable[None]] | None` module-level hook set by the app (`retire.set_after_gone_hook`).

- [ ] **Step 1: Write the failing tests**

`tests/supervisor/test_storage_pools.py`, append (use that file's own pool fixture, named `pools` below; add `import aleph.vm.storage_pools as storage_pools_module` if the file does not have it):

```python
def test_select_pool_asks_the_room_maker_before_refusing(pools, monkeypatch):
    from aleph.vm.storage_pools import InsufficientResourcesError, select_pool, set_room_maker

    calls = []
    monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: 0)
    set_room_maker(lambda pool, needed: calls.append((pool.index, needed)) or 0)
    try:
        with pytest.raises(InsufficientResourcesError):
            select_pool(1)
    finally:
        set_room_maker(None)
    assert calls and calls[0][1] == 1024 * 1024


def test_select_pool_succeeds_when_the_room_maker_frees_enough(pools, monkeypatch):
    from aleph.vm.storage_pools import select_pool, set_room_maker

    frees = iter([0, 4 * 1024 * 1024])
    monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: next(frees, 4 * 1024 * 1024))
    set_room_maker(lambda pool, needed: 4 * 1024 * 1024)
    try:
        assert select_pool(1).index in (0, 1)
    finally:
        set_room_maker(None)
```

`tests/supervisor/test_agent_capacity.py`, append:

```python
def test_available_disk_counts_reclaimable_bytes_as_free(mocker):
    from aleph.vm.agent.capacity import CapacityManager

    mocker.patch("aleph.vm.agent.capacity.storage_pools.pools_disk_usage", return_value=(100, 10))
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=5)
    assert CapacityManager._available_disk_bytes() == 15
```

`tests/supervisor/test_reconciler.py`, append:

```python
@pytest.mark.asyncio
async def test_startup_hook_logs_a_preview_then_reconciles(pools, registry, monkeypatch, caplog):
    from aleph.vm.agent.vm.reconciler import reconcile_at_startup

    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    await reconcile_at_startup({"vm_registry": registry})

    assert "will purge 1 orphan" in caplog.text
    assert not old.parent.exists()
```

`tests/supervisor/test_retire.py`, append:

```python
@pytest.mark.asyncio
async def test_gone_under_keep_runs_the_after_gone_hook(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    hook = AsyncMock()
    retire_module.set_after_gone_hook(hook)
    try:
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    finally:
        retire_module.set_after_gone_hook(None)
    hook.assert_awaited_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_pools.py tests/supervisor/test_agent_capacity.py tests/supervisor/test_reconciler.py tests/supervisor/test_retire.py -q -p no:cacheprovider`
Expected: FAIL (`set_room_maker`, `reclaimable_bytes` patch target, `set_after_gone_hook` missing)

- [ ] **Step 3: Implement the wiring**

`storage_pools.py`: add near `_select_from`

```python
RoomMaker = Callable[["StoragePool", int], int]
_room_maker: RoomMaker | None = None


def set_room_maker(fn: RoomMaker | None) -> None:
    """Register the agent's evictor: called with (pool, needed_bytes) when no
    pool fits a placement, before the placement is refused."""
    global _room_maker
    _room_maker = fn
```

and in `_select_from`, replace the final `if best is None or best_free < required_bytes: raise ...` with:

```python
    if (best is None or best_free < required_bytes) and _room_maker is not None:
        target = best or next((p for p in candidates if p.vm_eligible), None)
        if target is not None and _room_maker(target, required_bytes) > 0:
            free = _pool_free_bytes(target)
            if free is not None and free >= required_bytes:
                return target
    if best is None or best_free < required_bytes:
        msg = f"No volume pool has {size_mib} MiB free"
        raise InsufficientResourcesError(...)  # unchanged
```

`capacity.py`: `from aleph.vm.agent.vm.reclaimable import reclaimable_bytes` and `_available_disk_bytes` returns `max(storage_pools.pools_disk_usage()[1], 0) + reclaimable_bytes()`; extend its docstring: "Reclaimable (retained) bytes count as free: the reconciler evicts them on demand when a placement needs the room."

`retire.py`: add

```python
AfterGoneHook = Callable[[], Awaitable[None]]
_after_gone: AfterGoneHook | None = None


def set_after_gone_hook(hook: AfterGoneHook | None) -> None:
    """The app registers a reconcile pass here; it runs after every GONE
    under VOLUME_RETENTION=keep so the budget is enforced right away."""
    global _after_gone
    _after_gone = hook
```

and at the end of `retire_vm`, after the backups purge: `if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep" and _after_gone is not None: await _after_gone()`.

`run.py`: wrap each of the three create bodies (program spec path from `spec, _resources = await build_program_create_vm_spec(...)` to `persist_record`; instance path from `snp_instance = ...` to `persist_record`; vprogram path likewise; and the `try:` in `_ensure_program_vm` that builds the spec) in `with creating(str(vm_hash)):`. Import `from aleph.vm.agent.vm.reconciler import creating`.

`agent/supervisor.py`, in `run()` after `app.on_startup.append(_rehydrate_vm_registry)`:

```python
    app.on_startup.append(reconcile_at_startup)
    app.on_startup.append(start_storage_reconcile_task)
    app.on_cleanup.append(stop_storage_reconcile_task)
    storage_pools.set_room_maker(make_room)
    set_after_gone_hook(lambda: reconcile_now(app))
```

(`reconcile_at_startup` must run after `_rehydrate_vm_registry`, which fills the live set; `on_startup` hooks run in append order.)

Docs: in `docs/architecture/storage.md` add a "Reclamation" section (retire reasons table, the `.reclaimable` marker fields, the reconciler's passes and triggers, the settings table from spec section 6, the startup migration behaviour). In `docs/architecture/vm-lifecycle.md`, "Storage ownership": replace the per-path description with "every delete goes through `retire_vm` with a reason" and the reason table.

- [ ] **Step 4: Run the tests and the full suite**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_pools.py tests/supervisor/test_agent_capacity.py tests/supervisor/test_reconciler.py tests/supervisor/test_retire.py tests/supervisor/test_run.py -q -p no:cacheprovider`
Expected: PASS

Run the full suite (see Global Constraints): no new failures beyond the 46 environment ones.

- [ ] **Step 5: Lint and commit**

```bash
./venv/bin/ruff format src/aleph/vm tests/supervisor && ./venv/bin/isort --profile black src/aleph/vm tests/supervisor
git add src/aleph/vm/agent/supervisor.py src/aleph/vm/agent/run.py src/aleph/vm/agent/vm/retire.py src/aleph/vm/agent/capacity.py src/aleph/vm/storage_pools.py docs/architecture/storage.md docs/architecture/vm-lifecycle.md tests/supervisor/
git commit -m "feat(agent): run the reconciler at startup, periodically, after GONE and on placement pressure"
```

Open PR A against `dev`.

---

# PR B: Transactional create (spec section 2)

Branch: `od/disk-reclaim-admission` off PR A.

### Task 10: Admission before allocation

**Files:**
- Modify: `src/aleph/vm/agent/capacity.py` (add `check_message`)
- Modify: `src/aleph/vm/agent/run.py:364-370`, `:453-459`, `:504-510`, `:691-697` (move admission ahead of the downloader)
- Test: `tests/supervisor/test_agent_capacity.py`, `tests/supervisor/test_run.py`

**Interfaces:**
- Produces: `CapacityManager.check_message(content: ExecutableContent, *, exclude_vm_hash: ItemHash | None = None) -> None`: builds `requirements_from_message(content)`, subtracts the bytes already allocated under `{pool}/{exclude_vm_hash}/` (a RECREATE of a VM whose disks exist must not be refused for space it already holds), and calls `check_capacity` with the real `disk_mib` and `max_volume_mib`.

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/supervisor/test_agent_capacity.py
def test_check_message_admits_disk_from_the_message(mocker):
    from aleph.vm.agent.capacity import CapacityManager

    manager = CapacityManager(supervisor=MagicMock(), registry=AgentVmRegistry())
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=0)
    content = MagicMock(spec=InstanceContent)
    content.resources = MagicMock(vcpus=2, memory=2048)
    content.rootfs = MagicMock(size_mib=20_000)
    content.volumes = [MagicMock(size_mib=5_000)]
    content.requirements = None

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    kwargs = check.call_args.kwargs
    assert kwargs["disk_mib"] == 25_000
    assert kwargs["max_volume_mib"] == 20_000
    assert kwargs["is_instance"] is True


def test_check_message_discounts_bytes_the_vm_already_holds(mocker):
    from aleph.vm.agent.capacity import CapacityManager

    manager = CapacityManager(supervisor=MagicMock(), registry=AgentVmRegistry())
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=20_000 * 1024 * 1024)
    content = MagicMock(spec=InstanceContent)
    content.resources = MagicMock(vcpus=2, memory=2048)
    content.rootfs = MagicMock(size_mib=20_000)
    content.volumes = []
    content.requirements = None

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    assert check.call_args.kwargs["disk_mib"] == 0
```

In `tests/supervisor/test_vprogram.py`, rewrite `test_create_vm_execution_vprogram_capacity_failure_forgets_record` (line 336): admission now runs before the bundle is staged.

```python
@pytest.mark.asyncio
async def test_create_vm_execution_vprogram_capacity_failure_refuses_before_staging(mocker):
    """Admission runs from the message, before build_vprogram_spec stages a
    byte: an InsufficientResourcesError never reaches the downloader."""
    from aleph.vm.agent.vm.retire import RetireReason

    message = load_vprogram_message()
    mocker.patch("aleph.vm.agent.run.load_updated_message", new_callable=AsyncMock, return_value=(message, message))
    build = mocker.patch("aleph.vm.agent.run.build_vprogram_spec", new_callable=AsyncMock)
    retire = mocker.patch("aleph.vm.agent.run.retire_vm", new_callable=AsyncMock)

    capacity = MagicMock()
    capacity.check_message.side_effect = InsufficientResourcesError("no room", required={}, available={})
    supervisor = MagicMock(create_vm=AsyncMock())
    registry = AgentVmRegistry()

    with pytest.raises(InsufficientResourcesError):
        await create_vm_execution(
            message.item_hash,
            supervisor=supervisor,
            registry=registry,
            capacity=capacity,
            persistent=True,
        )

    build.assert_not_awaited()
    supervisor.create_vm.assert_not_awaited()
    capacity.check_message.assert_called_once_with(message.content, exclude_vm_hash=message.item_hash)
    retire.assert_awaited_once_with(message.item_hash, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
```

Apply the same change to `test_owner_record_recorded_before_resource_download` in `tests/supervisor/test_supervisor_run_routing.py` (line 146) if it asserts on `check_capacity`: `_fake_capacity()` there gains a `check_message = MagicMock()` attribute.

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_agent_capacity.py tests/supervisor/test_vprogram.py -q -p no:cacheprovider -k "check_message or refuses_before"`
Expected: FAIL (`check_message` missing)

- [ ] **Step 3: Implement**

`capacity.py`:

```python
from aleph.vm.agent.vm.reclaimable import directory_size_bytes
from aleph.vm.storage_pools import iter_namespace_dirs


def allocated_bytes_for(vm_hash: ItemHash | str) -> int:
    """Bytes already sitting under this VM's directories on every pool."""
    return sum(directory_size_bytes(d) for d in iter_namespace_dirs(str(vm_hash)))
```

and on `CapacityManager`:

```python
    def check_message(self, content: ExecutableContent, *, exclude_vm_hash: ItemHash | None = None) -> None:
        """Admission from the message alone, before a byte is allocated.

        The sizes come from the message (rootfs and volume size_mib); what
        the VM already holds on disk (a RECREATE, an adoption) is subtracted
        so an existing VM is never refused for space it already occupies.
        """
        requirements = requirements_from_message(content)
        held_mib = allocated_bytes_for(exclude_vm_hash) // (1024 * 1024) if exclude_vm_hash is not None else 0
        self.check_capacity(
            memory_mib=requirements.memory_mib,
            vcpus=requirements.vcpus,
            disk_mib=max(requirements.disk_mib - held_mib, 0),
            max_volume_mib=requirements.max_volume_mib,
            is_instance=requirements.is_instance,
            exclude_vm_hash=exclude_vm_hash,
        )
```

`run.py`: in each create path, call `capacity.check_message(content, exclude_vm_hash=vm_hash)` as the first statement inside `with creating(...)` (before `build_*_spec`), and delete the post-download `capacity.check_capacity(... disk_mib=0 ...)` block. The GPU resolution (`capacity.resolve_gpus`) stays where it is, after the spec is built. Update the comments that said "after the download so a failed download never consumes a GPU hold": GPU holds are still taken after the download; disk, memory and vCPU admission now precede it.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_agent_capacity.py tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_spec_program.py tests/supervisor/test_vprogram.py tests/supervisor/test_supervisor_spec_admission.py tests/supervisor/test_supervisor_spec_create_admission.py -q -p no:cacheprovider`
Expected: PASS (tests that asserted `check_capacity` called with `disk_mib=0` after the build change to assert `check_message` called before it)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/capacity.py src/aleph/vm/agent/run.py tests/supervisor/test_agent_capacity.py tests/supervisor/test_vprogram.py tests/supervisor/test_supervisor_run_routing.py
git commit -m "feat(agent): admit disk, memory and vCPUs from the message before allocating"
```

Open PR B against `dev` (stacked on A). The single failure path (`FAILED_CREATE`) and the `.part` sweep already landed in PR A; this PR completes spec section 2.

---

# PR C: Device-mapper teardown (spec section 5, S9)

Branch: `od/disk-reclaim-devmapper` off PR B.

### Task 11: `remove_devmapper` and the retire/reinstall hooks

**Files:**
- Modify: `src/aleph/vm/storage.py` (after `create_devmapper`, line 464)
- Modify: `src/aleph/vm/agent/vm/retire.py` (call `teardown_vm_devices` for non-RECREATE reasons)
- Modify: `src/aleph/vm/agent/views/operator.py` (in-place reinstall calls it after `stop_vm`)
- Test: `tests/supervisor/test_devmapper_teardown.py`, `tests/supervisor/test_retire.py`

**Interfaces:**
- Produces (in `storage.py`):
  - `async def detach_loop_devices(backing_file: Path) -> list[str]`: `losetup -j <file>` lines are `"/dev/loopN: [...]: (<file>)"`; each is detached with `losetup -d /dev/loopN`; returns the detached device names.
  - `async def remove_devmapper(namespace: str, volume_name: str) -> None`: `dmsetup remove {ns}_{vol}` if that block device exists, then detach the loop devices of `{pool}/{ns}/{vol}.btrfs` (via `storage_pools.find_existing_volume`), `rmdir /mnt/{ns}_{vol}` if it is an empty non-mount directory, and finally `dmsetup remove {ns}_base` when no other `/dev/mapper/{ns}_*` snapshot remains. The parent image's device (`/dev/mapper/{parent_ref}`) and its read-only loop are shared across VMs and are never touched here (Task 13 removes them on cache eviction).
- Produces (in `retire.py`): `async def teardown_vm_devices(namespace: str, record: AgentVmRecord | None) -> None`: for every `PersistentVolume` with a `parent` in `record.message.volumes`, `await remove_devmapper(namespace, volume.name)`; errors are logged, never raised.

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_devmapper_teardown.py
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import aleph.vm.storage as storage_module
from aleph.vm.storage import detach_loop_devices, remove_devmapper

from .reclaim_fixtures import VM_HASH, pools, volume  # noqa: F401

real_glob = Path.glob


@pytest.fixture
def commands(mocker):
    """Record every subprocess call; losetup -j answers with two loop devices."""
    calls: list[list[str]] = []

    async def fake_run(command, check=True, stdin_input=None):
        calls.append([str(c) for c in command])
        if command[:2] == ["losetup", "-j"]:
            return b"/dev/loop7: []: (/some/file)\n/dev/loop9: []: (/some/file)\n"
        return b""

    mocker.patch.object(storage_module, "run_in_subprocess", side_effect=fake_run)
    return calls


@pytest.mark.asyncio
async def test_detach_loop_devices_detaches_every_loop_of_the_file(commands):
    detached = await detach_loop_devices(Path("/some/file"))
    assert detached == ["/dev/loop7", "/dev/loop9"]
    assert ["losetup", "-d", "/dev/loop7"] in commands
    assert ["losetup", "-d", "/dev/loop9"] in commands


@pytest.mark.asyncio
async def test_remove_devmapper_tears_down_in_order(pools, commands, monkeypatch, tmp_path):
    backing = volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    base = Path("/dev/mapper") / f"{VM_HASH}_base"
    present = {mapped, base}
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self in present or real_is_block_device(self))
    monkeypatch.setattr(Path, "glob", lambda self, pattern: iter([]) if str(self) == "/dev/mapper" else real_glob(self, pattern))
    mount_root = tmp_path / "mnt"
    (mount_root / f"{VM_HASH}_data").mkdir(parents=True)
    monkeypatch.setattr(storage_module, "MOUNT_ROOT", mount_root)

    await remove_devmapper(VM_HASH, "data")

    dm_removes = [c for c in commands if c[:2] == ["dmsetup", "remove"]]
    assert dm_removes == [["dmsetup", "remove", f"{VM_HASH}_data"], ["dmsetup", "remove", f"{VM_HASH}_base"]]
    assert ["losetup", "-j", str(backing)] in commands
    assert not (mount_root / f"{VM_HASH}_data").exists()


@pytest.mark.asyncio
async def test_remove_devmapper_keeps_base_while_a_sibling_snapshot_exists(pools, commands, monkeypatch):
    volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    sibling = Path("/dev/mapper") / f"{VM_HASH}_other"
    base = Path("/dev/mapper") / f"{VM_HASH}_base"
    present = {mapped, sibling, base}
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self in present or real_is_block_device(self))
    monkeypatch.setattr(Path, "glob", lambda self, pattern: iter([sibling]) if str(self) == "/dev/mapper" else real_glob(self, pattern))

    await remove_devmapper(VM_HASH, "data")

    dm_removes = [c for c in commands if c[:2] == ["dmsetup", "remove"]]
    assert dm_removes == [["dmsetup", "remove", f"{VM_HASH}_data"]]


@pytest.mark.asyncio
async def test_remove_devmapper_is_a_no_op_without_devices(pools, commands):
    await remove_devmapper(VM_HASH, "data")
    assert [c for c in commands if c[0] == "dmsetup"] == []
```

`tests/supervisor/test_retire.py`, append:

```python
@pytest.mark.asyncio
async def test_gone_tears_down_parent_backed_volume_devices(env, monkeypatch, mocker):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    remove = mocker.patch.object(retire_module, "remove_devmapper", new_callable=AsyncMock)
    record = env["registry"].get(ItemHash(VM_HASH))
    record.message.volumes = [MagicMock(name="data", parent=MagicMock(ref="p")), MagicMock(name="plain", parent=None)]
    record.message.volumes[0].name = "data"

    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    remove.assert_awaited_once_with(VM_HASH, "data")


@pytest.mark.asyncio
async def test_recreate_leaves_devices_in_place(env, mocker):
    remove = mocker.patch.object(retire_module, "remove_devmapper", new_callable=AsyncMock)
    await retire_vm(VM_HASH, RetireReason.RECREATE, supervisor=env["supervisor"])
    remove.assert_not_awaited()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_devmapper_teardown.py tests/supervisor/test_retire.py -q -p no:cacheprovider`
Expected: FAIL (`ImportError: detach_loop_devices`)

- [ ] **Step 3: Implement**

`storage.py`, after `create_devmapper`:

```python
MOUNT_ROOT = Path("/mnt")


async def detach_loop_devices(backing_file: Path) -> list[str]:
    """Detach every loop device backed by ``backing_file``."""
    stdout = await run_in_subprocess(["losetup", "-j", str(backing_file)])
    detached: list[str] = []
    for line in stdout.decode().splitlines():
        device = line.split(":", 1)[0].strip()
        if not device.startswith("/dev/loop"):
            continue
        await run_in_subprocess(["losetup", "-d", device])
        detached.append(device)
    return detached


async def remove_devmapper(namespace: str, volume_name: str) -> None:
    """The inverse of ``create_devmapper`` for one volume.

    Removes the snapshot device, detaches the loop device of its backing
    file, drops the resize mount point, and removes the per-VM base device
    once no snapshot of this VM is left. The parent image's device and
    read-only loop are shared across VMs and are removed by the cache pass
    when the image is evicted, never here.
    """
    mapper = Path(DEVICE_MAPPER_DIRECTORY)
    mapped_name = f"{namespace}_{volume_name}"
    if (mapper / mapped_name).is_block_device():
        await run_in_subprocess(["dmsetup", "remove", mapped_name])
        logger.info("Removed device-mapper target %s", mapped_name)
    backing = find_existing_volume(namespace, f"{volume_name}.btrfs")
    if backing is not None:
        await detach_loop_devices(backing)
    mount_path = MOUNT_ROOT / mapped_name
    if mount_path.is_dir() and not os.path.ismount(mount_path):
        try:
            mount_path.rmdir()
        except OSError:
            logger.warning("Could not remove %s", mount_path, exc_info=True)
    base_name = f"{namespace}_base"
    siblings = [p for p in mapper.glob(f"{namespace}_*") if p.name != base_name and p.is_block_device()]
    if not siblings and (mapper / base_name).is_block_device():
        await run_in_subprocess(["dmsetup", "remove", base_name])
        logger.info("Removed device-mapper base %s", base_name)
```

(import `find_existing_volume` from `storage_pools`, `os` if missing.)

`retire.py`:

```python
async def teardown_vm_devices(namespace: str, record: AgentVmRecord | None) -> None:
    """Remove the device-mapper snapshots and loop devices of a VM's
    parent-backed volumes. Best effort: a failure is logged and the
    reconciler's dm guard leaves the volume file for the next pass."""
    if record is None:
        return
    for vol in record.message.volumes or []:
        if getattr(vol, "parent", None) is None or not getattr(vol, "name", None):
            continue
        try:
            await remove_devmapper(namespace, vol.name)
        except Exception:
            logger.exception("Device teardown of %s/%s failed", namespace, vol.name)
```

called in `retire_vm` right after `delete_vm` returns and before `_release_storage`, for every reason but `RECREATE`.

`operator.py` in-place reinstall: after `await supervisor.stop_vm(vm_id)` and before the purge, `await teardown_vm_devices(str(vm_hash), record)`.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_devmapper_teardown.py tests/supervisor/test_retire.py tests/supervisor/views/test_operator.py tests/supervisor/test_storage.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/storage.py src/aleph/vm/agent/vm/retire.py src/aleph/vm/agent/views/operator.py tests/supervisor/test_devmapper_teardown.py tests/supervisor/test_retire.py
git commit -m "feat(storage): tear down device-mapper snapshots and loop devices on retire and reinstall"
```

Open PR C against `dev` (stacked).

---

# PR D: Caches (spec section 4)

Branch: `od/disk-reclaim-caches` off PR C.

### Task 12: In-stream download size cap

**Files:**
- Modify: `src/aleph/vm/storage.py:72-155` (`download_file_in_chunks`, `download_file`), `:239-317` (the four cache getters)
- Test: `tests/supervisor/test_storage_download_cap.py`

**Interfaces:**
- Produces: `download_file_in_chunks(url, tmp_path, *, max_bytes: int | None = None)` raising `FileTooLargeError` before writing when `Content-Length > max_bytes`, and mid-stream when the byte count passes `max_bytes`; `download_file(url, local_path, *, max_bytes: int | None = None)` passes it through, does not retry on `FileTooLargeError`, and touches the mtime of an existing file (cache hit, used by Task 13's LRU). Callers: `get_code_path` passes `settings.MAX_PROGRAM_ARCHIVE_SIZE`, `get_data_path` `settings.MAX_DATA_ARCHIVE_SIZE`, `get_runtime_path` and `get_rootfs_base_path` `settings.MAX_RUNTIME_ARCHIVE_SIZE`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_storage_download_cap.py
from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.storage import download_file, download_file_in_chunks
from aleph.vm.supervisor_interface.errors import FileTooLargeError


def _session(chunks: list[bytes], content_length: int | None):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.content_length = content_length
    reads = iter(chunks + [b""])
    resp.content.read = AsyncMock(side_effect=lambda n: next(reads))
    session = MagicMock()
    session.get = AsyncMock(return_value=resp)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session, resp


@pytest.mark.asyncio
async def test_content_length_above_the_cap_is_refused_before_writing(tmp_path):
    session, resp = _session([b"x" * 10], content_length=10)
    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        with pytest.raises(FileTooLargeError):
            await download_file_in_chunks("http://x/f", tmp_path / "f.part", max_bytes=5)
    resp.content.read.assert_not_called()


@pytest.mark.asyncio
async def test_stream_past_the_cap_is_aborted(tmp_path):
    session, _ = _session([b"x" * 4, b"x" * 4], content_length=None)
    part = tmp_path / "f.part"
    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        with pytest.raises(FileTooLargeError):
            await download_file_in_chunks("http://x/f", part, max_bytes=5)


@pytest.mark.asyncio
async def test_download_file_unlinks_the_part_and_does_not_retry(tmp_path):
    attempts = []

    async def too_large(url, tmp_path_, max_bytes=None):
        attempts.append(1)
        tmp_path_.write_bytes(b"partial")
        raise FileTooLargeError("too big")

    with patch("aleph.vm.storage.download_file_in_chunks", side_effect=too_large):
        with pytest.raises(FileTooLargeError):
            await download_file("http://x/f", tmp_path / "f", max_bytes=5)
    assert attempts == [1]
    assert not (tmp_path / "f.part").exists()
    assert not (tmp_path / "f").exists()


@pytest.mark.asyncio
async def test_existing_file_is_touched_on_hit(tmp_path):
    target = tmp_path / "f"
    target.write_bytes(b"cached")
    old = time.time() - 100_000
    os.utime(target, (old, old))

    await download_file("http://x/f", target)

    assert target.stat().st_mtime > old + 50_000


@pytest.mark.asyncio
async def test_getters_pass_their_caps(mocker, tmp_path):
    import aleph.vm.storage as storage_module
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "CODE_CACHE", tmp_path / "code")
    mocker.patch.object(settings, "DATA_CACHE", tmp_path / "data")
    mocker.patch.object(settings, "RUNTIME_CACHE", tmp_path / "runtime")
    mocker.patch.object(settings, "FAKE_DATA_PROGRAM", None)
    mocker.patch.object(storage_module, "_get_content_url", AsyncMock(return_value="http://x/f"))
    mocker.patch.object(storage_module, "check_squashfs_integrity", AsyncMock())
    mocker.patch.object(storage_module, "chown_to_jailman", AsyncMock())
    download = mocker.patch.object(storage_module, "download_file", AsyncMock())

    await storage_module.get_code_path("ref")
    await storage_module.get_data_path("ref")
    await storage_module.get_runtime_path("ref")
    await storage_module.get_rootfs_base_path("ref")

    caps = [call.kwargs["max_bytes"] for call in download.await_args_list]
    assert caps == [
        settings.MAX_PROGRAM_ARCHIVE_SIZE,
        settings.MAX_DATA_ARCHIVE_SIZE,
        settings.MAX_RUNTIME_ARCHIVE_SIZE,
        settings.MAX_RUNTIME_ARCHIVE_SIZE,
    ]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_download_cap.py -q -p no:cacheprovider`
Expected: FAIL (`max_bytes` unexpected keyword)

- [ ] **Step 3: Implement**

`download_file_in_chunks`:

```python
async def download_file_in_chunks(url: str, tmp_path: Path, *, max_bytes: int | None = None) -> None:
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=..., sock_read=...)  # unchanged
    async with aiohttp.ClientSession(timeout=timeout) as session:
        resp = await session.get(url)
        resp.raise_for_status()
        if max_bytes is not None and resp.content_length is not None and resp.content_length > max_bytes:
            msg = f"{url} is {resp.content_length} bytes, above the {max_bytes} byte limit"
            raise FileTooLargeError(msg)
        written = 0
        with open(tmp_path, "wb") as cache_file:
            counter = 0
            while True:
                chunk = await resp.content.read(65536)
                if not chunk:
                    break
                written += len(chunk)
                if max_bytes is not None and written > max_bytes:
                    msg = f"{url} exceeded the {max_bytes} byte limit while downloading"
                    raise FileTooLargeError(msg)
                cache_file.write(chunk)
                ...  # progress dots unchanged
```

`download_file(url, local_path, *, max_bytes=None)`: on the existing-file early return, `os.utime(local_path, None)` first; pass `max_bytes=max_bytes` to `download_file_in_chunks`; `FileTooLargeError` is not in the retried exception tuple, so it propagates and the `finally` unlinks the owned `.part`. Import `FileTooLargeError` from `aleph.vm.supervisor_interface.errors` (check for an import cycle: `errors.py` must not import `storage`; it does not today).

The four getters pass their caps as listed in Interfaces. Remove the `# TODO: Limit max size of download` comment.

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_download_cap.py tests/supervisor/test_storage.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/storage.py tests/supervisor/test_storage_download_cap.py
git commit -m "feat(storage): enforce download size limits in the stream, touch cache hits"
```

### Task 13: Cache budget, LRU eviction, parent device removal, docs

**Files:**
- Create: `src/aleph/vm/agent/vm/cache.py`
- Modify: `src/aleph/vm/agent/vm/reconciler.py` (cache pass after the retention budget), `src/aleph/vm/storage.py` (pre-write budget check hook), `src/aleph/vm/agent/supervisor.py` (register the evictor)
- Modify: `docs/architecture/storage.md` (cache section)
- Test: `tests/supervisor/test_cache_eviction.py`, `tests/supervisor/test_reconciler.py`

**Interfaces:**
- Produces (in `cache.py`):
  - `@dataclass(frozen=True) CacheEntry(path: Path, size_bytes: int, mtime: float)`
  - `def cache_roots() -> list[Path]` (runtime, code, data, message; existing dirs only)
  - `def cache_entries(root: Path) -> list[CacheEntry]` (regular files, `.part` excluded, oldest mtime first)
  - `def referenced_hashes(registry: AgentVmRegistry) -> set[str]`: every `runtime.ref`, `code.ref`, `data.ref`, `rootfs.parent.ref`, `volumes[*].parent.ref`, `volumes[*].ref` (immutable volumes) of a live record, plus every `depends_on` entry of every `.reclaimable` marker
  - `def cache_budget_bytes(root: Path) -> int` = `parse_budget(settings.CACHE_BUDGET, shutil.disk_usage(root).total)`
  - `def evict_caches(registry, *, needed: dict[Path, int] | None = None, dry_run: bool = False) -> list[Path]`: per root, while usage (plus `needed[root]` if given) exceeds the budget: evict unreferenced entries LRU; then, if still over, reclaim `.reclaimable` dirs oldest-first whose `depends_on` names a remaining entry (via `purge_vm_storage`) and evict those entries; entries referenced by live VMs are never evicted (log at ERROR and stop). Evicting a runtime entry also calls `remove_parent_device(ref)`.
  - `async def remove_parent_device(ref: str) -> None`: `dmsetup remove <ref>` if `/dev/mapper/<ref>` is a block device, then `detach_loop_devices(RUNTIME_CACHE/<ref>)`. Called synchronously from the eviction via `asyncio.run` is wrong inside the loop: the eviction is sync (runs in a thread), so it collects the refs to remove and `evict_caches` returns them in the result; the async caller (`reconcile_now`, and the download hook) awaits `remove_parent_device` for each evicted runtime ref. Expose `def parent_refs_of(evicted: list[Path]) -> list[str]` (basenames of evicted files under `RUNTIME_CACHE`).
- Produces (in `storage.py`): `set_cache_admission(fn: Callable[[Path, int], None] | None)`; `download_file_in_chunks` calls it with `(tmp_path.parent, content_length)` when `Content-Length` is known, before opening the file. The agent registers a function that calls `evict_caches(registry, needed={root: content_length})` and raises `InsufficientResourcesError` if usage plus `content_length` still exceeds the budget.
- Reconciler: `reconcile_storage` gains a cache pass (`report.cache_evicted: list[Path]`) after the retention budget; `reconcile_now` awaits `remove_parent_device` for `parent_refs_of(report.cache_evicted)`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_cache_eviction.py
from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.vm.cache import (
    cache_entries,
    evict_caches,
    parent_refs_of,
    referenced_hashes,
)
from aleph.vm.agent.vm.reclaimable import mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings

from .reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


def _entry(root, name, size=4096, age=0):
    path = root / name
    path.write_bytes(b"x" * size)
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


def _program_record(registry, vm_hash, *, runtime="rt", code="code", data=None):
    content = MagicMock()
    content.runtime = MagicMock(ref=runtime)
    content.code = MagicMock(ref=code)
    content.data = MagicMock(ref=data) if data else None
    content.rootfs = None
    content.volumes = []
    registry.record(ItemHash(vm_hash), message=content, original=content)
    return content


def test_referenced_hashes_cover_records_and_markers(pools):
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="rt1", code="c1", data="d1")
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent1",), now=NOW)

    assert referenced_hashes(registry) == {"rt1", "c1", "d1", "parent1"}


def test_cache_entries_skip_parts_and_sort_oldest_first(pools):
    new = _entry(pools["runtime"], "new", age=10)
    old = _entry(pools["runtime"], "old", age=1000)
    _entry(pools["runtime"], "x.part")

    assert [e.path for e in cache_entries(pools["runtime"])] == [old, new]


def test_evicts_unreferenced_lru_until_under_budget(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="live")
    live = _entry(pools["runtime"], "live", age=5000)
    oldest = _entry(pools["runtime"], "oldest", age=3000)
    newer = _entry(pools["runtime"], "newer", age=100)

    evicted = evict_caches(registry)

    assert evicted == [oldest]
    assert live.exists() and newer.exists()


def test_never_evicts_a_live_reference_even_over_budget(pools, monkeypatch, caplog):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="live")
    live = _entry(pools["runtime"], "live", size=4096)

    assert evict_caches(registry) == []
    assert live.exists()
    assert "live references" in caplog.text


def test_reclaimable_dependents_go_before_their_parent(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)

    evicted = evict_caches(registry)

    assert evicted == [parent]
    assert not retained.exists()
    assert parent_refs_of(evicted) == ["parent"]


def test_needed_bytes_are_counted_against_the_budget(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    a = _entry(pools["code"], "a", size=4096, age=100)

    assert evict_caches(registry, needed={pools["code"]: 8000}) == [a]


def test_dry_run_reports_without_deleting(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    a = _entry(pools["data"], "a", size=4096)

    assert evict_caches(registry, dry_run=True) == [a]
    assert a.exists()
```

Append to `tests/supervisor/test_reconciler.py`:

```python
def test_reconcile_runs_the_cache_pass(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)

    report = reconcile_storage(registry, now=NOW)

    assert report.cache_evicted == [stale]
    assert not stale.exists()
```

Append to `tests/supervisor/test_storage_download_cap.py`:

```python
@pytest.mark.asyncio
async def test_cache_admission_hook_runs_before_writing(tmp_path):
    import aleph.vm.storage as storage_module

    seen = []
    storage_module.set_cache_admission(lambda root, size: seen.append((root, size)))
    session, _ = _session([b"x" * 4], content_length=4)
    try:
        with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
            await download_file_in_chunks("http://x/f", tmp_path / "f.part")
    finally:
        storage_module.set_cache_admission(None)
    assert seen == [(tmp_path, 4)]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_cache_eviction.py tests/supervisor/test_reconciler.py tests/supervisor/test_storage_download_cap.py -q -p no:cacheprovider`
Expected: FAIL (`ModuleNotFoundError: aleph.vm.agent.vm.cache`, `set_cache_admission` missing)

- [ ] **Step 3: Implement**

```python
# src/aleph/vm/agent/vm/cache.py
"""Bounded download caches: a budget per cache root, LRU eviction of
entries no live VM and no retained disk references."""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass
from pathlib import Path

from aleph_message.models import InstanceContent

from aleph.vm.agent.vm.purge import purge_vm_storage
from aleph.vm.agent.vm.reclaimable import iter_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage import DEVICE_MAPPER_DIRECTORY, detach_loop_devices, run_in_subprocess
from aleph.vm.storage_budget import parse_budget

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CacheEntry:
    path: Path
    size_bytes: int
    mtime: float


def cache_roots() -> list[Path]:
    roots = []
    for setting in (settings.RUNTIME_CACHE, settings.CODE_CACHE, settings.DATA_CACHE, settings.MESSAGE_CACHE):
        if setting and Path(setting).is_dir():
            roots.append(Path(setting))
    return roots


def cache_entries(root: Path) -> list[CacheEntry]:
    entries = []
    for path in root.iterdir():
        if not path.is_file() or path.suffix == ".part":
            continue
        st = path.stat()
        entries.append(CacheEntry(path=path, size_bytes=st.st_blocks * 512, mtime=st.st_mtime))
    entries.sort(key=lambda e: e.mtime)
    return entries


def _record_refs(content) -> set[str]:
    """Every cache entry one message names: runtime, code, data, the rootfs
    parent, volume parents and immutable volume refs."""
    refs: set[str] = set()
    for attr in ("runtime", "code", "data"):
        obj = getattr(content, attr, None)
        if obj is not None and getattr(obj, "ref", None):
            refs.add(str(obj.ref))
    rootfs = getattr(content, "rootfs", None)
    if rootfs is not None and getattr(rootfs, "parent", None):
        refs.add(str(rootfs.parent.ref))
    for vol in getattr(content, "volumes", None) or []:
        parent = getattr(vol, "parent", None)
        if parent is not None:
            refs.add(str(parent.ref))
        if getattr(vol, "ref", None):
            refs.add(str(vol.ref))
    return refs


def _live_only_refs(registry: AgentVmRegistry) -> set[str]:
    """Refs held by live records: never evictable."""
    refs: set[str] = set()
    for _vm_hash, record in registry.items():
        refs |= _record_refs(record.message)
    return refs


def referenced_hashes(registry: AgentVmRegistry) -> set[str]:
    """Live refs plus what the .reclaimable markers pin."""
    refs = _live_only_refs(registry)
    for _directory, marker in iter_reclaimable():
        refs.update(marker.depends_on)
    return refs


def cache_budget_bytes(root: Path) -> int:
    return parse_budget(settings.CACHE_BUDGET, shutil.disk_usage(str(root)).total)


def evict_caches(
    registry: AgentVmRegistry,
    *,
    needed: dict[Path, int] | None = None,
    dry_run: bool = False,
) -> list[Path]:
    needed = needed or {}
    evicted: list[Path] = []
    for root in cache_roots():
        budget = cache_budget_bytes(root)
        entries = cache_entries(root)
        usage = sum(e.size_bytes for e in entries) + needed.get(root, 0)
        if usage <= budget:
            continue
        referenced = referenced_hashes(registry)
        for entry in entries:
            if usage <= budget:
                break
            if entry.path.name in referenced:
                continue
            _evict_entry(entry, dry_run, evicted)
            usage -= entry.size_bytes
        if usage <= budget:
            continue
        # Only referenced entries are left. Reclaimable dirs pinning them go
        # first (oldest first), then the entries they pinned.
        pinned = sorted(iter_reclaimable(), key=lambda item: item[1].reclaimable_since)
        remaining = {e.path.name: e for e in entries if e.path.name in referenced and e.path not in evicted}
        live_only = _live_only_refs(registry)
        for directory, marker in pinned:
            if usage <= budget:
                break
            deps = [d for d in marker.depends_on if d in remaining and d not in live_only]
            if not deps:
                continue
            if not dry_run:
                purge_vm_storage(directory.name)
            for dep in deps:
                entry = remaining.pop(dep)
                _evict_entry(entry, dry_run, evicted)
                usage -= entry.size_bytes
        if usage > budget:
            logger.error(
                "Cache %s is %d bytes over its budget but only live references remain; admission should have refused",
                root,
                usage - budget,
            )
    return evicted


def _evict_entry(entry: CacheEntry, dry_run: bool, evicted: list[Path]) -> None:
    evicted.append(entry.path)
    if dry_run:
        return
    try:
        entry.path.unlink()
        logger.info("Evicted cache entry %s (%d bytes)", entry.path, entry.size_bytes)
    except OSError:
        logger.warning("Failed to evict %s", entry.path, exc_info=True)


def parent_refs_of(evicted: list[Path]) -> list[str]:
    runtime = Path(settings.RUNTIME_CACHE) if settings.RUNTIME_CACHE else None
    return [p.name for p in evicted if runtime is not None and p.parent == runtime]


async def remove_parent_device(ref: str) -> None:
    """Remove the shared read-only device of an evicted parent image."""
    device = Path(DEVICE_MAPPER_DIRECTORY) / ref
    if device.is_block_device():
        await run_in_subprocess(["dmsetup", "remove", ref])
    if settings.RUNTIME_CACHE:
        await detach_loop_devices(Path(settings.RUNTIME_CACHE) / ref)
```

(The `InstanceContent` import in the listing is unused once `_record_refs` reads attributes generically; drop it.)

`storage.py`:

```python
CacheAdmission = Callable[[Path, int], None]
_cache_admission: CacheAdmission | None = None


def set_cache_admission(fn: CacheAdmission | None) -> None:
    global _cache_admission
    _cache_admission = fn
```

and in `download_file_in_chunks`, after the `Content-Length` cap check and before `open(tmp_path, "wb")`: `if _cache_admission is not None and resp.content_length is not None: _cache_admission(tmp_path.parent, resp.content_length)`.

`reconciler.py`: `ReconcileReport.cache_evicted: list[Path]`; after `_enforce_retention_budget`, `report.cache_evicted = evict_caches(registry, dry_run=dry_run)`; `reconcile_now` becomes:

```python
async def reconcile_now(app: web.Application) -> ReconcileReport:
    report = await asyncio.to_thread(reconcile_storage, app["vm_registry"])
    for ref in parent_refs_of(report.cache_evicted):
        try:
            await remove_parent_device(ref)
        except Exception:
            logger.exception("Removing the parent device of %s failed", ref)
    return report
```

`agent/supervisor.py` `run()`: register the admission hook:

```python
    def _admit_download(root: Path, size: int) -> None:
        evict_caches(app["vm_registry"], needed={root: size})
        usage = sum(e.size_bytes for e in cache_entries(root)) + size
        if usage > cache_budget_bytes(root):
            raise InsufficientResourcesError(
                f"Cache {root} cannot hold a {size} byte download within CACHE_BUDGET",
                required={"disk_mib": size // (1024 * 1024)},
                available={"disk_mib": max(cache_budget_bytes(root) - usage + size, 0) // (1024 * 1024)},
            )

    storage.set_cache_admission(_admit_download)
```

(`InsufficientResourcesError` from `aleph.vm.resources`; the create path already maps it to 503.)

Docs: `docs/architecture/storage.md`, cache section: budgets, in-stream caps, the referenced set, eviction order, the parent device removal.

- [ ] **Step 4: Run the tests and the full suite**

Run: `./venv/bin/python -m pytest tests/supervisor/test_cache_eviction.py tests/supervisor/test_reconciler.py tests/supervisor/test_storage_download_cap.py -q -p no:cacheprovider`
Expected: PASS. Then the full suite: no new failures.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/vm/cache.py src/aleph/vm/agent/vm/reconciler.py src/aleph/vm/storage.py src/aleph/vm/agent/supervisor.py docs/architecture/storage.md tests/supervisor/test_cache_eviction.py tests/supervisor/test_reconciler.py tests/supervisor/test_storage_download_cap.py
git commit -m "feat(agent): bounded download caches with LRU eviction and pre-write admission"
```

Open PR D against `dev` (stacked).

---

# PR E: Operator CLI (spec section 6)

Branch: `od/disk-reclaim-cli` off PR D.

### Task 14: `aleph-vm storage status|list|reclaim|reconcile`

**Files:**
- Create: `src/aleph/vm/agent/storage_cli.py`
- Modify: `src/aleph/vm/agent/cli.py:177` (dispatch before `parse_args`)
- Test: `tests/supervisor/test_storage_cli.py`

**Interfaces:**
- Produces: `storage_cli.main(argv: list[str]) -> int`; `storage_cli.run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO) -> int` (the testable core, no settings setup, no DB); `cli.main()` dispatches `aleph-vm storage ...` to `storage_cli.main(sys.argv[2:])` before its own `parse_args`.
- Consumes: `reconcile_storage`, `iter_reclaimable`, `iter_namespace_dirs`, `directory_size_bytes`, `cache_entries`, `cache_budget_bytes`, `reclaimable_bytes`, `purge_vm_storage`, `rehydrate_registry`, `metrics.setup_engine`.

Output formats (plain text, one row per line, tab separated after a header line):

```
$ aleph-vm storage status
POOL                         LIVE        RECLAIMABLE  BUDGET       FREE
/var/lib/aleph/vm/volumes/…  123.4 GiB   2.0 GiB      50.0 GiB     310.2 GiB
CACHE                        USED        BUDGET
/var/cache/aleph/vm/runtime  40.1 GiB    100.0 GiB
...
$ aleph-vm storage list --reclaimable
HASH    POOL    SIZE    REASON  AGE
<hash>  <pool>  1.2 GiB gone    3d 4h
$ aleph-vm storage reclaim <hash>
Purged <hash>: 2 volume file(s)
$ aleph-vm storage reconcile --dry-run
Dry run: orphans purged=1 marked=0, evicted=0, parts=2, side dirs=1, backups=0, freed=0 bytes
```

- [ ] **Step 1: Write the failing tests**

```python
# tests/supervisor/test_storage_cli.py
from __future__ import annotations

import argparse
import io
import os
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash

import aleph.vm.agent.storage_cli as cli
from aleph.vm.agent.vm.reclaimable import mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings

from .reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


@pytest.fixture
def registry():
    reg = AgentVmRegistry()
    content = MagicMock(volumes=[], rootfs=None)
    reg.record(ItemHash(LIVE), message=content, original=content, persistent=True)
    return reg


@pytest.fixture(autouse=True)
def _no_backups(mocker):
    mocker.patch("aleph.vm.agent.vm.reconciler.sweep_expired_backups", return_value=0)


def _run(argv: list[str], registry) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.run(cli.parse_args(argv), registry, out)
    return code, out.getvalue()


def test_status_lists_pools_and_caches(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], LIVE, "rootfs.qcow2", size=4096)
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out = _run(["status"], registry)

    assert code == 0
    assert "POOL" in out and str(pools["pool0"]) in out and str(pools["pool1"]) in out
    assert "CACHE" in out and str(pools["runtime"]) in out


def test_list_shows_every_vm_dir_and_reclaimable_filters(pools, registry):
    volume(pools["pool0"], LIVE, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "orphan", now=NOW - timedelta(days=3))

    code, out = _run(["list"], registry)
    assert code == 0
    assert LIVE in out and VM_HASH in out

    code, out = _run(["list", "--reclaimable"], registry)
    assert LIVE not in out and VM_HASH in out and "orphan" in out


def test_reclaim_purges_a_reclaimable_dir_only(pools, registry):
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out = _run(["reclaim", VM_HASH], registry)
    assert code == 0 and "Purged" in out
    assert not gone.exists()

    code, out = _run(["reclaim", LIVE], registry)
    assert code == 1 and "not reclaimable" in out
    assert live.exists()


def test_reconcile_dry_run_reports_without_changing(pools, registry, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))

    code, out = _run(["reconcile", "--dry-run"], registry)

    assert code == 0 and "Dry run" in out and "purged=1" in out
    assert orphan.exists()

    code, out = _run(["reconcile"], registry)
    assert code == 0 and not orphan.exists()


def test_cli_main_dispatches_storage_subcommand(mocker):
    from aleph.vm.agent import cli as agent_cli

    storage_main = mocker.patch("aleph.vm.agent.storage_cli.main", return_value=7)
    mocker.patch("sys.argv", ["aleph-vm", "storage", "status"])
    with pytest.raises(SystemExit) as exit_info:
        agent_cli.main()
    assert exit_info.value.code == 7
    storage_main.assert_called_once_with(["status"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_cli.py -q -p no:cacheprovider`
Expected: FAIL with `ModuleNotFoundError: aleph.vm.agent.storage_cli`

- [ ] **Step 3: Implement**

```python
# src/aleph/vm/agent/storage_cli.py
"""``aleph-vm storage``: show and drive reclamation from the node shell.

Storage is agent-side and, by design, readable from the filesystem plus the
agent DB, so these commands need no running daemon. They run the same code
the reconciler runs.
"""

from __future__ import annotations

import argparse
import asyncio
import shutil
import sys
from datetime import datetime, timezone
from typing import TextIO

from aleph.vm import storage_pools
from aleph.vm.agent import metrics
from aleph.vm.agent.vm.cache import cache_budget_bytes, cache_entries, cache_roots
from aleph.vm.agent.vm.purge import purge_vm_storage
from aleph.vm.agent.vm.reclaimable import directory_size_bytes, iter_reclaimable, read_marker, reclaimable_bytes
from aleph.vm.agent.vm.reconciler import reconcile_storage
from aleph.vm.agent.vm_registry import AgentVmRegistry, rehydrate_registry
from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import iter_namespace_dirs


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aleph-vm storage", description="VM storage reclamation")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="per-pool and per-cache usage against the budgets")
    list_parser = sub.add_parser("list", help="VM directories on every pool")
    list_parser.add_argument("--reclaimable", action="store_true", help="only directories no VM owns")
    reclaim_parser = sub.add_parser("reclaim", help="purge one reclaimable VM directory now")
    reclaim_parser.add_argument("vm_hash")
    reconcile_parser = sub.add_parser("reconcile", help="run one reconciler pass")
    reconcile_parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args(argv)


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{value:.1f} TiB"


def _age(since: datetime) -> str:
    delta = datetime.now(tz=timezone.utc) - since
    days, rem = divmod(int(delta.total_seconds()), 86400)
    hours = rem // 3600
    return f"{days}d {hours}h"


def _status(registry: AgentVmRegistry, out: TextIO) -> int:
    live = {str(h) for h, _ in registry.items()}
    out.write("POOL\tLIVE\tRECLAIMABLE\tBUDGET\tFREE\n")
    for pool in storage_pools.get_pools():
        live_bytes = sum(directory_size_bytes(d) for d in iter_namespace_dirs() if d.parent == pool.path and d.name in live)
        try:
            usage = shutil.disk_usage(str(pool.path))
            total, free = usage.total, usage.free
        except OSError:
            total = free = 0
        budget = 0 if settings.VOLUME_RETENTION == "reap" else parse_budget(settings.VOLUME_RETENTION_BUDGET, total)
        out.write(
            f"{pool.path}\t{_human(live_bytes)}\t{_human(reclaimable_bytes(pool.path))}\t{_human(budget)}\t{_human(free)}\n"
        )
    out.write("CACHE\tUSED\tBUDGET\n")
    for root in cache_roots():
        used = sum(e.size_bytes for e in cache_entries(root))
        out.write(f"{root}\t{_human(used)}\t{_human(cache_budget_bytes(root))}\n")
    return 0


def _list(registry: AgentVmRegistry, out: TextIO, *, reclaimable_only: bool) -> int:
    out.write("HASH\tPOOL\tSIZE\tREASON\tAGE\n")
    for directory in iter_namespace_dirs():
        marker = read_marker(directory)
        if reclaimable_only and marker is None:
            continue
        reason = marker.reason if marker else "live"
        age = _age(marker.reclaimable_since) if marker else "-"
        out.write(f"{directory.name}\t{directory.parent}\t{_human(directory_size_bytes(directory))}\t{reason}\t{age}\n")
    return 0


def _reclaim(vm_hash: str, out: TextIO) -> int:
    marked = [d for d, _ in iter_reclaimable() if d.name == vm_hash]
    if not marked:
        out.write(f"{vm_hash} is not reclaimable (no .reclaimable marker); refusing to purge a directory a VM may own\n")
        return 1
    deleted = purge_vm_storage(vm_hash)
    out.write(f"Purged {vm_hash}: {deleted} volume file(s)\n")
    return 0


def _reconcile(registry: AgentVmRegistry, out: TextIO, *, dry_run: bool) -> int:
    report = reconcile_storage(registry, dry_run=dry_run)
    prefix = "Dry run: " if dry_run else "Reconciled: "
    out.write(prefix + report.summary() + "\n")
    for name in report.purged_orphans + report.evicted:
        out.write(f"  {'would purge' if dry_run else 'purged'} {name}\n")
    for name in report.marked_orphans:
        out.write(f"  {'would mark' if dry_run else 'marked'} {name}\n")
    return 0


def run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO) -> int:
    if args.command == "status":
        return _status(registry, out)
    if args.command == "list":
        return _list(registry, out, reclaimable_only=args.reclaimable)
    if args.command == "reclaim":
        return _reclaim(args.vm_hash, out)
    if args.command == "reconcile":
        return _reconcile(registry, out, dry_run=args.dry_run)
    return 2


async def _load_registry() -> AgentVmRegistry:
    metrics.setup_engine()
    registry = AgentVmRegistry()
    await rehydrate_registry(registry)
    return registry


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    settings.setup()
    storage_pools.setup_pools()
    registry = asyncio.run(_load_registry())
    return run(args, registry, sys.stdout)
```

`cli.py` `main()`, first lines:

```python
def main():
    if len(sys.argv) > 1 and sys.argv[1] == "storage":
        from aleph.vm.agent import storage_cli

        sys.exit(storage_cli.main(sys.argv[2:]))
    args = parse_args(sys.argv[1:])
```

- [ ] **Step 4: Run the tests**

Run: `./venv/bin/python -m pytest tests/supervisor/test_storage_cli.py -q -p no:cacheprovider`
Expected: PASS

- [ ] **Step 5: Docs and commit**

Add the four commands to the "Reclamation" section of `docs/architecture/storage.md` (one line each, with the note that `reclaim` refuses an unmarked directory).

```bash
git add src/aleph/vm/agent/storage_cli.py src/aleph/vm/agent/cli.py docs/architecture/storage.md tests/supervisor/test_storage_cli.py
git commit -m "feat(cli): aleph-vm storage status, list, reclaim and reconcile"
```

Open PR E against `dev` (stacked).

---

## Spec coverage

| Spec section | Tasks |
|---|---|
| 1 Retention model: settings, `retire_vm` reasons, positive knowledge, budgeted retention | 1, 3, 4-7, 8 (budget), 9 (free counts reclaimable, room maker) |
| 2 Transactional create: admission first, one failure path, `.part`, crash gap | 10, 6 (`FAILED_CREATE`), 8 (`.part` sweep, orphan rule) |
| 3 Marker and reconciler: fields, passes, adoption | 2, 8, 9 (`creating()` in the create paths) |
| 4 Caches: in-stream cap, budget, referenced set, LRU, parent device removal, admission | 12, 13 |
| 5 dm teardown agent-side; backups as a reclaimable class | 11; 3 (`purge_vm_backups`), 8 (`sweep_expired_backups`) |
| 6 CLI, settings table, migration log line | 14, 1, 8 (`reconcile_at_startup`) |
| 7 Testing | every task's Step 1; the full-suite gate in Tasks 9 and 13 |

Deliberate narrowing, recorded here so nobody mistakes it for an oversight:

- Spec section 3 lists "per-VM execution log directories" among the side directories. `EXECUTION_LOG_DIRECTORY` holds supervisor-written, opt-in (`EXECUTION_LOG_ENABLED`) JSON dumps keyed by execution UUID (`models.py:652`), not by VM hash, so the reconciler cannot attribute them to a VM and does not sweep them. If they ever need bounding, a plain age-based sweep is a two-line addition to `_sweep_parts`.
- Spec section 4 says admission counts the cache download "from the message or from `Content-Length` before writing". Runtime, code and data refs carry no size in the message, so the check happens at `Content-Length` time inside `download_file_in_chunks` (Task 13's `set_cache_admission` hook), still before a byte is written. No extra HEAD request.
- `start_backup` counting the projected archive against the pool budget (spec section 5) belongs to the backup module and is left to the backup-move branch; note it in that PR's follow-up list if it is not already there.
