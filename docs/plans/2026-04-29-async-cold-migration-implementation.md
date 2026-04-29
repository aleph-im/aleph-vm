# Async Cold Migration — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the current synchronous cold-migration HTTP API
with an asynchronous job-and-poll API on both source and destination
CRNs, eliminating scheduler-side HTTP timeouts and the data-loss
ambiguity they cause.

**Architecture:** Long-running work moves into background
`asyncio.Task`s. POST handlers return `202 Accepted` immediately
with a status URL; new `GET …/status` endpoints expose live job
state. State for in-flight work lives in two module-level dicts
(`_export_jobs` on source, `_import_jobs` on destination) typed by
new `ExportJob` / `ImportJob` dataclasses. A single
`asyncio.Semaphore` (capacity from a new
`MAX_CONCURRENT_MIGRATIONS` setting, default `1`) caps host-wide
parallel migration work. A startup reaper deletes orphan export and
partial-import files. See
`docs/plans/2026-04-29-async-cold-migration-design.md` for full
design.

**Tech Stack:** Python 3.11, `aiohttp`, `pydantic`, `pytest` +
`pytest-asyncio` + `pytest-mock`. Existing `qemu-img` /
`SystemDManager` / `VmPool` integrations unchanged.

---

## File Map

**New files:**

| Path | Responsibility |
|------|----------------|
| `src/aleph/vm/migration/__init__.py` | Package init |
| `src/aleph/vm/migration/jobs.py` | `ExportJob`, `ImportJob` dataclasses, registries (`_export_jobs`, `_import_jobs`), `get_migration_semaphore()` factory |
| `src/aleph/vm/migration/runner.py` | `_run_export(job)`, `_run_import(job)` background coroutines |
| `src/aleph/vm/migration/helpers.py` | qemu-img / aiohttp helpers (`_compress_disk`, `_graceful_shutdown`, `_download_disk_from_source`, `_rebase_overlay`, `_detect_parent_format`) — moved out of `views/migration.py` |
| `src/aleph/vm/migration/reaper.py` | `reap_orphan_migration_files(pool)` — startup cleanup |
| `tests/migration/__init__.py` | Test package init |
| `tests/migration/test_jobs.py` | Unit tests for `ExportJob`/`ImportJob` state transitions |
| `tests/migration/test_reaper.py` | Tests for startup reaper |

**Modified files:**

| Path | Change |
|------|--------|
| `src/aleph/vm/conf.py` | Add `MAX_CONCURRENT_MIGRATIONS: int = 1` setting |
| `src/aleph/vm/models.py` | Replace `MigrationState` enum values; remove `migration_state` and `export_token` fields from `VmExecution` |
| `src/aleph/vm/orchestrator/views/migration.py` | Become a thin HTTP layer: spawn jobs, register status endpoints, idempotency + cleanup guards. All long-running logic moves to `aleph.vm.migration` package |
| `src/aleph/vm/orchestrator/supervisor.py` | Register two new `GET …/status` routes; wire `reap_orphan_migration_files` into `app.on_startup` |
| `tests/supervisor/views/test_migration.py` | Update tests to reflect new 202 + polling pattern; add idempotency, status, and cleanup-guard tests |

---

## Phase 1 — Foundation: settings and state types

### Task 1: Add `MAX_CONCURRENT_MIGRATIONS` setting

**Files:**
- Modify: `src/aleph/vm/conf.py`

- [ ] **Step 1: Add the setting field**

In `src/aleph/vm/conf.py`, find the `Settings` class and add this near the other top-level int settings (e.g. just below `PREALLOC_VM_COUNT: int = 0`):

```python
    MAX_CONCURRENT_MIGRATIONS: int = Field(
        default=1,
        description="Maximum number of cold migration jobs (export+import combined) that may run concurrently on this CRN. Default 1 matches today's serial behaviour; bump for hosts with spare disk/network capacity.",
    )
```

- [ ] **Step 2: Verify config still loads**

Run: `python -c "from aleph.vm.conf import settings; print(settings.MAX_CONCURRENT_MIGRATIONS)"`
Expected: `1`

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/conf.py
git commit -m "conf: add MAX_CONCURRENT_MIGRATIONS setting"
```

---

### Task 2: Update `MigrationState` enum

**Files:**
- Modify: `src/aleph/vm/models.py:71-79`

- [ ] **Step 1: Replace enum values**

In `src/aleph/vm/models.py`, replace the existing `MigrationState` class:

```python
class MigrationState(str, Enum):
    """State of VM migration process. Source-side states begin with EXPORT_, destination-side with IMPORT_."""

    NONE = "none"
    EXPORTING = "exporting"
    EXPORTED = "exported"
    EXPORT_FAILED = "export_failed"
    IMPORTING = "importing"
    IMPORTED = "imported"
    IMPORT_FAILED = "import_failed"
```

- [ ] **Step 2: Commit (test updates come with later tasks)**

```bash
git add src/aleph/vm/models.py
git commit -m "models: split MigrationState into export/import-specific values"
```

Note: this temporarily breaks `views/migration.py` (which still references `MigrationState.FAILED`/`COMPLETED`). That file is fully rewritten in Tasks 9–13; the broken state lives only between commits within this plan.

---

### Task 3: Remove `migration_state` and `export_token` from `VmExecution`

**Files:**
- Modify: `src/aleph/vm/models.py:132-134`

- [ ] **Step 1: Remove the two fields**

In `src/aleph/vm/models.py`, delete these lines from `VmExecution`:

```python
    # Migration state tracking
    migration_state: MigrationState = MigrationState.NONE
    export_token: str | None = None
```

- [ ] **Step 2: Verify nothing in production code outside the migration view references them**

Run: `grep -rn "migration_state\|export_token" src/aleph/vm/ --include='*.py'`
Expected: only matches in `src/aleph/vm/orchestrator/views/migration.py` (which gets rewritten in Phase 3).

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/models.py
git commit -m "models: remove migration_state and export_token from VmExecution"
```

---

### Task 4: Create `aleph.vm.migration` package skeleton

**Files:**
- Create: `src/aleph/vm/migration/__init__.py`
- Create: `tests/migration/__init__.py`

- [ ] **Step 1: Create empty package init files**

Both files contain a single line:

```python
"""Cold migration runtime: jobs, runners, helpers, and startup reaper."""
```

- [ ] **Step 2: Commit**

```bash
git add src/aleph/vm/migration/__init__.py tests/migration/__init__.py
git commit -m "migration: create package skeleton"
```

---

### Task 5: Define `ExportJob` and `ImportJob` dataclasses

**Files:**
- Create: `src/aleph/vm/migration/jobs.py`
- Create: `tests/migration/test_jobs.py`

- [ ] **Step 1: Write failing test for `ExportJob` initial state**

In `tests/migration/test_jobs.py`:

```python
"""Unit tests for ExportJob and ImportJob dataclasses."""

from datetime import datetime, timezone
from pathlib import Path

from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.migration.jobs import ExportJob, ImportJob
from aleph.vm.models import MigrationState


def test_export_job_starts_in_exporting_state():
    job = ExportJob(
        vm_hash=ItemHash(settings.FAKE_INSTANCE_ID),
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    assert job.state == MigrationState.EXPORTING
    assert job.finished_at is None
    assert job.token is None
    assert job.disk_files is None
    assert job.export_paths == []
    assert job.error is None


def test_import_job_starts_in_importing_state():
    job = ImportJob(
        vm_hash=ItemHash(settings.FAKE_INSTANCE_ID),
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="example.com",
        source_port=443,
    )
    assert job.state == MigrationState.IMPORTING
    assert job.bytes_downloaded == 0
    assert job.total_bytes_expected is None
    assert job.current_step is None
    assert job.downloaded_files == []
```

- [ ] **Step 2: Run test, confirm it fails on import**

Run: `pytest tests/migration/test_jobs.py -v`
Expected: `ModuleNotFoundError: No module named 'aleph.vm.migration.jobs'`

- [ ] **Step 3: Implement `jobs.py`**

In `src/aleph/vm/migration/jobs.py`:

```python
"""Migration job dataclasses and module-level registries."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aleph_message.models import ItemHash
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.models import MigrationState


class DiskFileInfo(BaseModel):
    """Information about an exported disk file. Returned in the export status payload and consumed by the import request."""

    name: str
    size_bytes: int
    download_path: str


@dataclass
class ExportJob:
    vm_hash: ItemHash
    state: MigrationState
    started_at: datetime
    finished_at: datetime | None = None
    token: str | None = None
    disk_files: list[DiskFileInfo] | None = None
    export_paths: list[Path] = field(default_factory=list)
    volumes_dir: Path | None = None
    error: str | None = None
    task: asyncio.Task | None = None
    ttl_task: asyncio.Task | None = None


@dataclass
class ImportJob:
    vm_hash: ItemHash
    state: MigrationState
    started_at: datetime
    source_host: str
    source_port: int
    finished_at: datetime | None = None
    bytes_downloaded: int = 0
    total_bytes_expected: int | None = None
    current_step: str | None = None
    transfer_time_ms: int | None = None
    error: str | None = None
    dest_dir: Path | None = None
    downloaded_files: list[Path] = field(default_factory=list)
    task: asyncio.Task | None = None
    ttl_task: asyncio.Task | None = None


# Module-level registries. Reset to empty on supervisor restart.
_export_jobs: dict[ItemHash, ExportJob] = {}
_import_jobs: dict[ItemHash, ImportJob] = {}

# Lazy-initialised global semaphore. Constructed on first call so the loop
# is running and the settings module is fully loaded.
_migration_semaphore: asyncio.Semaphore | None = None


def get_migration_semaphore() -> asyncio.Semaphore:
    """Return the host-wide migration semaphore, creating it on first call.

    Capacity comes from settings.MAX_CONCURRENT_MIGRATIONS at first-call time.
    """
    global _migration_semaphore
    if _migration_semaphore is None:
        _migration_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_MIGRATIONS)
    return _migration_semaphore


def _reset_migration_semaphore_for_tests() -> None:
    """Clear the cached semaphore so tests can change MAX_CONCURRENT_MIGRATIONS between cases."""
    global _migration_semaphore
    _migration_semaphore = None
```

- [ ] **Step 4: Run test, confirm pass**

Run: `pytest tests/migration/test_jobs.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/migration/jobs.py tests/migration/test_jobs.py
git commit -m "migration: add ExportJob and ImportJob dataclasses"
```

---

### Task 6: Test semaphore lazy-init and capacity from settings

**Files:**
- Modify: `tests/migration/test_jobs.py`

- [ ] **Step 1: Add failing tests for the semaphore**

Append to `tests/migration/test_jobs.py`:

```python
import asyncio

import pytest

from aleph.vm.migration.jobs import (
    _reset_migration_semaphore_for_tests,
    get_migration_semaphore,
)


@pytest.mark.asyncio
async def test_migration_semaphore_uses_settings_capacity(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_MIGRATIONS", 3)
    _reset_migration_semaphore_for_tests()

    sem = get_migration_semaphore()
    assert isinstance(sem, asyncio.Semaphore)
    # Acquire all three permits without blocking.
    await asyncio.wait_for(
        asyncio.gather(sem.acquire(), sem.acquire(), sem.acquire()),
        timeout=0.1,
    )
    # Fourth acquire should block — confirm via timeout.
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(sem.acquire(), timeout=0.05)
    sem.release()
    sem.release()
    sem.release()


@pytest.mark.asyncio
async def test_migration_semaphore_is_singleton():
    _reset_migration_semaphore_for_tests()
    a = get_migration_semaphore()
    b = get_migration_semaphore()
    assert a is b
```

- [ ] **Step 2: Run, confirm pass**

Run: `pytest tests/migration/test_jobs.py -v`
Expected: 4 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/migration/test_jobs.py
git commit -m "migration: cover semaphore lazy-init and capacity"
```

---

## Phase 2 — Extract helpers

### Task 7: Move qemu-img / download helpers into `migration.helpers`

**Files:**
- Create: `src/aleph/vm/migration/helpers.py`
- Modify: `src/aleph/vm/orchestrator/views/migration.py`

- [ ] **Step 1: Create `helpers.py` with the existing helpers verbatim**

Copy these functions from `src/aleph/vm/orchestrator/views/migration.py` into `src/aleph/vm/migration/helpers.py`, plus the constants and required imports:

```python
"""qemu-img and aiohttp helpers used by the migration runners."""

import asyncio
import logging
import shutil
import time
from pathlib import Path

import aiohttp

from aleph.vm.models import VmExecution

logger = logging.getLogger(__name__)

GRACEFUL_SHUTDOWN_TIMEOUT = 30


async def graceful_shutdown(execution: VmExecution, timeout: int = GRACEFUL_SHUTDOWN_TIMEOUT) -> None:
    """Gracefully shut down a QEMU VM via QMP system_powerdown, with fallback to systemd stop."""
    from aleph.vm.controllers.qemu.client import QemuVmClient

    vm = execution.vm
    if not vm:
        msg = "VM not initialized"
        raise RuntimeError(msg)

    try:
        client = QemuVmClient(vm)
        client.system_powerdown()
        client.close()
    except Exception as e:
        logger.warning("Failed to send system_powerdown for %s: %s", execution.vm_hash, e)

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if execution.systemd_manager and not execution.systemd_manager.is_service_active(execution.controller_service):
            logger.info("VM %s shut down gracefully", execution.vm_hash)
            return
        await asyncio.sleep(1)

    logger.warning("VM %s did not shut down within %ds, forcing stop", execution.vm_hash, timeout)
    if execution.systemd_manager:
        execution.systemd_manager.stop_and_disable(execution.controller_service)


async def compress_disk(source_path: Path, dest_path: Path) -> None:
    """Compress a QCOW2 disk using qemu-img convert."""
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img, "convert", "-c", "-O", "qcow2",
        str(source_path), str(dest_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img convert failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def rebase_overlay(overlay_path: Path, parent_path: Path, parent_format: str) -> None:
    """Rebase a QCOW2 overlay to point to a local backing file."""
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img, "rebase", "-u",
        "-b", str(parent_path),
        "-F", parent_format,
        str(overlay_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img rebase failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def detect_parent_format(parent_path: Path) -> str:
    """Detect the format of a parent image using qemu-img info."""
    import json as _json

    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img, "info", str(parent_path), "--output=json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img info failed: {stderr.decode()}"
        raise RuntimeError(msg)

    info = _json.loads(stdout)
    fmt = info.get("format")
    if not fmt:
        msg = f"Could not detect format for {parent_path}"
        raise RuntimeError(msg)
    return fmt


async def download_disk_from_source(
    session: aiohttp.ClientSession,
    url: str,
    dest_path: Path,
    token: str,
    on_chunk=None,
) -> int:
    """Download a disk file from the source CRN.

    on_chunk: optional callback(bytes_downloaded_so_far) for progress reporting.
    """
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")
    part_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    async with session.get(url, params={"token": token}) as resp:
        if resp.status != 200:
            body = await resp.text()
            msg = f"Failed to download {url}: HTTP {resp.status} - {body}"
            raise RuntimeError(msg)
        with open(part_path, "wb") as f:
            async for chunk in resp.content.iter_chunked(1024 * 1024):
                f.write(chunk)
                total_bytes += len(chunk)
                if on_chunk is not None:
                    on_chunk(total_bytes)

    part_path.rename(dest_path)
    return total_bytes
```

The function names lose their leading underscore — they're now part of the migration package's API surface. The `download_disk_from_source` helper gains an optional `on_chunk` callback for progress reporting (used by the import runner in Task 16).

- [ ] **Step 2: Delete the same functions from `views/migration.py`**

Remove the originals (the leading-underscore versions of `_graceful_shutdown`, `_compress_disk`, `_rebase_overlay`, `_detect_parent_format`, `_download_disk_from_source`, and the `GRACEFUL_SHUTDOWN_TIMEOUT` constant) from `src/aleph/vm/orchestrator/views/migration.py`. Don't worry about temporarily breaking the rest of that file — it gets fully rewritten in Phase 3.

- [ ] **Step 3: Run existing test suite to confirm helpers still work where consumed**

Run: `pytest tests/supervisor/test_qemu_client.py -v`
Expected: all pass (this file tests the QemuVmClient helper indirectly, not affected by the move).

The `views/test_migration.py` will fail because the views file is now incomplete. That's expected; tests get updated in Phase 3.

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/migration/helpers.py src/aleph/vm/orchestrator/views/migration.py
git commit -m "migration: extract qemu-img and download helpers to dedicated module"
```

---

## Phase 3 — Export side: async runner and HTTP layer

### Task 8: Implement `_run_export` background coroutine

**Files:**
- Modify: `src/aleph/vm/migration/runner.py` (create)
- Create: `tests/migration/test_runner.py`

- [ ] **Step 1: Write failing test for the happy-path runner**

In `tests/migration/test_runner.py`:

```python
"""Tests for the export and import background runners."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.migration.jobs import (
    ExportJob,
    _reset_migration_semaphore_for_tests,
)
from aleph.vm.migration.runner import _run_export
from aleph.vm.models import MigrationState


@pytest.fixture(autouse=True)
def _reset_semaphore():
    _reset_migration_semaphore_for_tests()
    yield
    _reset_migration_semaphore_for_tests()


@pytest.mark.asyncio
async def test_run_export_success(tmp_path, monkeypatch):
    """Happy path: graceful shutdown succeeds, two qcow2 disks compress, state ends in EXPORTED."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    volumes_dir = tmp_path / str(vm_hash)
    volumes_dir.mkdir(parents=True)
    (volumes_dir / "rootfs.qcow2").write_bytes(b"x" * 1024)
    (volumes_dir / "data.qcow2").write_bytes(b"y" * 2048)

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    execution = MagicMock()
    execution.vm_hash = vm_hash
    execution.is_running = True

    async def fake_compress(src: Path, dst: Path):
        dst.write_bytes(b"compressed")

    async def fake_shutdown(_exec):
        return None

    monkeypatch.setattr("aleph.vm.migration.runner.graceful_shutdown", fake_shutdown)
    monkeypatch.setattr("aleph.vm.migration.runner.compress_disk", fake_compress)

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    await _run_export(job, execution)

    assert job.state == MigrationState.EXPORTED
    assert job.finished_at is not None
    assert job.error is None
    assert job.token is not None and len(job.token) > 16
    assert job.disk_files is not None and len(job.disk_files) == 2
    assert {df.name for df in job.disk_files} == {"rootfs.qcow2", "data.qcow2"}
    assert all(Path(p).exists() for p in job.export_paths)


@pytest.mark.asyncio
async def test_run_export_compression_failure(tmp_path, monkeypatch):
    """If compress_disk raises on any file, state goes to EXPORT_FAILED and partial exports are deleted."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    volumes_dir = tmp_path / str(vm_hash)
    volumes_dir.mkdir(parents=True)
    (volumes_dir / "rootfs.qcow2").write_bytes(b"x")
    (volumes_dir / "data.qcow2").write_bytes(b"y")

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    calls = {"n": 0}

    async def flaky_compress(src: Path, dst: Path):
        calls["n"] += 1
        if calls["n"] == 1:
            dst.write_bytes(b"first")
        else:
            raise RuntimeError("boom")

    execution = MagicMock()
    execution.vm_hash = vm_hash
    execution.systemd_manager = MagicMock()
    execution.systemd_manager.enable_and_start = AsyncMock()
    execution.controller_service = "fake.service"

    monkeypatch.setattr("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())
    monkeypatch.setattr("aleph.vm.migration.runner.compress_disk", flaky_compress)

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    await _run_export(job, execution)

    assert job.state == MigrationState.EXPORT_FAILED
    assert "boom" in job.error
    # No partial export files should remain.
    assert list(volumes_dir.glob("*.export.qcow2")) == []
    # VM restart attempted.
    execution.systemd_manager.enable_and_start.assert_awaited_once_with("fake.service")
```

- [ ] **Step 2: Run, confirm fail**

Run: `pytest tests/migration/test_runner.py -v`
Expected: `ModuleNotFoundError: No module named 'aleph.vm.migration.runner'`

- [ ] **Step 3: Implement `runner.py` (export only for now)**

In `src/aleph/vm/migration/runner.py`:

```python
"""Background coroutines that drive ExportJob and ImportJob to terminal state."""

import logging
import secrets
from datetime import datetime, timezone
from pathlib import Path

from aleph.vm.conf import settings
from aleph.vm.migration.helpers import compress_disk, graceful_shutdown
from aleph.vm.migration.jobs import (
    DiskFileInfo,
    ExportJob,
    get_migration_semaphore,
)
from aleph.vm.models import MigrationState, VmExecution

logger = logging.getLogger(__name__)


async def _run_export(job: ExportJob, execution: VmExecution) -> None:
    """Drive an ExportJob from EXPORTING to a terminal state.

    Mutates the job in place. Never raises; failures are recorded on the job.
    """
    sem = get_migration_semaphore()
    export_paths: list[Path] = []
    async with sem:
        try:
            await graceful_shutdown(execution)

            namespace = execution.vm_hash
            volumes_dir = settings.PERSISTENT_VOLUMES_DIR / namespace
            job.volumes_dir = volumes_dir

            disk_files: list[DiskFileInfo] = []

            if volumes_dir.exists():
                for qcow2_file in sorted(volumes_dir.glob("*.qcow2")):
                    export_path = qcow2_file.with_suffix(".qcow2.export.qcow2")
                    await compress_disk(qcow2_file, export_path)
                    export_paths.append(export_path)
                    disk_files.append(
                        DiskFileInfo(
                            name=qcow2_file.name,
                            size_bytes=export_path.stat().st_size,
                            download_path=f"/control/machine/{job.vm_hash}/migration/disk/{qcow2_file.name}",
                        )
                    )

            if not disk_files:
                msg = "No disk files found to export"
                raise RuntimeError(msg)

            job.export_paths = export_paths
            job.disk_files = disk_files
            job.token = secrets.token_urlsafe(32)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.EXPORTED

        except Exception as error:
            logger.exception("Export failed for %s: %s", job.vm_hash, error)
            job.state = MigrationState.EXPORT_FAILED
            job.error = str(error)
            job.finished_at = datetime.now(timezone.utc)

            for path in export_paths:
                try:
                    path.unlink(missing_ok=True)
                except Exception as e:
                    logger.warning("Failed to delete partial export %s: %s", path, e)

            try:
                if execution.systemd_manager:
                    await execution.systemd_manager.enable_and_start(execution.controller_service)
                    logger.info("Restarted VM %s after failed export", job.vm_hash)
            except Exception as restart_error:
                logger.error("Failed to restart VM %s after export failure: %s", job.vm_hash, restart_error)
```

`export_paths` is initialised before the `try` so the failure-cleanup branch can iterate it without checking whether it was assigned. The list is empty if `graceful_shutdown` raised before any compression started — the cleanup loop is then a no-op.

- [ ] **Step 4: Run tests, confirm pass**

Run: `pytest tests/migration/test_runner.py -v`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/migration/runner.py tests/migration/test_runner.py
git commit -m "migration: implement async export runner with failure cleanup"
```

---

### Task 9: Rewrite `migration_export` HTTP handler to spawn job + return 202

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/migration.py`

- [ ] **Step 1: Rewrite the handler**

Replace the `migration_export` function in `src/aleph/vm/orchestrator/views/migration.py` with this version. Keep the existing imports for `cors_allow_all`, `authenticate_api_request`, `get_execution_or_404`, `get_itemhash_or_400`, `dumps_for_json`, `create_task_log_exceptions`. Add new imports for the migration package.

```python
from datetime import datetime, timezone
from http import HTTPStatus

from aleph.vm.migration.jobs import ExportJob, _export_jobs
from aleph.vm.migration.runner import _run_export
from aleph.vm.models import MigrationState

EXPORT_TTL_SECONDS = 1800


@cors_allow_all
async def migration_export(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/export — start an async export job.

    Returns 202 immediately. Caller polls GET /export/status for progress.
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = get_execution_or_404(vm_hash, pool)

    if not execution.is_running:
        return web.json_response({"status": "error", "error": "VM is not running"}, status=HTTPStatus.BAD_REQUEST)
    if execution.hypervisor != HypervisorType.qemu:
        return web.json_response({"status": "error", "error": "Migration only supported for QEMU instances"}, status=HTTPStatus.BAD_REQUEST)
    if execution.is_confidential:
        return web.json_response({"status": "error", "error": "Migration is not supported for confidential VMs"}, status=HTTPStatus.BAD_REQUEST)

    existing = _export_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.EXPORTING:
            return _export_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        return _export_job_descriptor_response(existing, status=HTTPStatus.CONFLICT)

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    _export_jobs[vm_hash] = job
    job.task = create_task_log_exceptions(_run_export(job, execution), name=f"export-{vm_hash}")

    return _export_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _export_job_descriptor_response(job: ExportJob, status: int) -> web.Response:
    return web.json_response(
        {
            "status": job.state.value,
            "vm_hash": str(job.vm_hash),
            "started_at": job.started_at.isoformat(),
            "status_url": f"/control/machine/{job.vm_hash}/migration/export/status",
            **({"error": job.error} if job.error else {}),
        },
        status=status,
        dumps=dumps_for_json,
    )
```

- [ ] **Step 2: Verify there are no remaining references to `_export_state` or `MigrationState.FAILED` / `COMPLETED` in `views/migration.py`**

Run: `grep -n "_export_state\|MigrationState.FAILED\|MigrationState.COMPLETED" src/aleph/vm/orchestrator/views/migration.py`
Expected: no matches. (If matches remain, they belong to other handlers in the same file that are rewritten in Tasks 10–14.)

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/orchestrator/views/migration.py
git commit -m "migration: return 202 from /export and spawn job in background"
```

---

### Task 10: Add `migration_export_status` endpoint

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/migration.py`
- Modify: `src/aleph/vm/orchestrator/supervisor.py:226`

- [ ] **Step 1: Add the handler**

Append to `src/aleph/vm/orchestrator/views/migration.py`:

```python
@cors_allow_all
async def migration_export_status(request: web.Request) -> web.Response:
    """GET /control/machine/{ref}/migration/export/status — return live export job state."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    job = _export_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"status": "error", "error": "No export job"}, status=HTTPStatus.NOT_FOUND)

    return web.json_response(
        {
            "vm_hash": str(job.vm_hash),
            "state": job.state.value,
            "started_at": job.started_at.isoformat(),
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "error": job.error,
            "disk_files": [df.model_dump() for df in job.disk_files] if job.disk_files else None,
            "export_token": job.token,
        },
        status=HTTPStatus.OK,
        dumps=dumps_for_json,
    )
```

- [ ] **Step 2: Register the route in `supervisor.py`**

In `src/aleph/vm/orchestrator/supervisor.py`, find the migration route block (line ~226) and add the new route:

```python
        web.post("/control/machine/{ref}/migration/export", migration_export),
        web.get("/control/machine/{ref}/migration/export/status", migration_export_status),
        web.get("/control/machine/{ref}/migration/disk/{filename}", migration_disk_download),
        web.post("/control/migrate", migration_import),
        web.post("/control/machine/{ref}/migration/cleanup", migration_cleanup),
```

Add `migration_export_status` to the import list near line 60:

```python
from .views.migration import (
    migration_cleanup,
    migration_disk_download,
    migration_export,
    migration_export_status,
    migration_import,
)
```

- [ ] **Step 3: Smoke test the route registers**

Run: `python -c "from aleph.vm.orchestrator.supervisor import setup_webapp; from unittest.mock import Mock; app = setup_webapp(pool=Mock()); print([str(r) for r in app.router.routes() if 'migration' in str(r.resource)])"`
Expected: contains `/control/machine/{ref}/migration/export/status`.

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/orchestrator/views/migration.py src/aleph/vm/orchestrator/supervisor.py
git commit -m "migration: expose GET /migration/export/status"
```

---

### Task 11: TTL cleanup for export jobs and idempotency tests

**Files:**
- Modify: `src/aleph/vm/migration/runner.py`
- Modify: `src/aleph/vm/orchestrator/views/migration.py`
- Modify: `tests/supervisor/views/test_migration.py`

- [ ] **Step 1: Add `_schedule_export_ttl_cleanup` helper**

Append to `src/aleph/vm/migration/runner.py`:

```python
import asyncio


async def _export_ttl_cleanup(job: ExportJob, timeout: int) -> None:
    """Background task: delete export files and forget the job after TTL."""
    try:
        await asyncio.sleep(timeout)
        logger.info("Export TTL expired for %s, cleaning up", job.vm_hash)
        for path in job.export_paths:
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete export file %s: %s", path, e)
        from aleph.vm.migration.jobs import _export_jobs
        _export_jobs.pop(job.vm_hash, None)
    except asyncio.CancelledError:
        pass


def schedule_export_ttl(job: ExportJob, timeout: int) -> None:
    """Cancel any prior TTL task and schedule a fresh one."""
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    job.ttl_task = asyncio.create_task(_export_ttl_cleanup(job, timeout))
```

Add a module-level constant near the top of `runner.py`:

```python
EXPORT_TTL_SECONDS = 1800  # 30 minutes — matches today's behaviour
IMPORT_TTL_SECONDS = 1800
```

In `_run_export`, on the success path (after setting `job.state = MigrationState.EXPORTED`), schedule TTL:

```python
            schedule_export_ttl(job, EXPORT_TTL_SECONDS)
```

Do the same on the EXPORT_FAILED path so failed jobs also age out.

- [ ] **Step 2: Write idempotency test**

In `tests/supervisor/views/test_migration.py`, add a new test class:

```python
class TestMigrationExportIdempotency:
    @pytest.mark.asyncio
    async def test_second_post_returns_existing_job(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        """Two POSTs while a job is EXPORTING return 202 referencing the same job."""
        from aleph.vm.migration.jobs import _export_jobs
        _export_jobs.clear()

        # Make compress_disk hang so the job stays in EXPORTING.
        slow = asyncio.Event()
        async def fake_compress(src, dst):
            await slow.wait()
            dst.write_bytes(b"x")

        mocker.patch("aleph.vm.migration.runner.compress_disk", fake_compress)
        mocker.patch("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        # Pre-create the volumes dir so the runner finds disk files to compress.
        (settings.PERSISTENT_VOLUMES_DIR / str(mock_vm_hash)).mkdir(parents=True, exist_ok=True)
        (settings.PERSISTENT_VOLUMES_DIR / str(mock_vm_hash) / "rootfs.qcow2").write_bytes(b"x")

        r1 = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r1.status == HTTPStatus.ACCEPTED

        r2 = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r2.status == HTTPStatus.ACCEPTED

        d1, d2 = await r1.json(), await r2.json()
        assert d1["started_at"] == d2["started_at"]  # same job

        # Let the job finish.
        slow.set()
        # Cleanup
        _export_jobs.clear()
```

- [ ] **Step 3: Run, confirm pass**

Run: `pytest tests/supervisor/views/test_migration.py::TestMigrationExportIdempotency -v`
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/migration/runner.py src/aleph/vm/orchestrator/views/migration.py tests/supervisor/views/test_migration.py
git commit -m "migration: add export TTL cleanup and idempotent retry"
```

---

### Task 12: Update `migration_cleanup` with new state-check guard

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/migration.py`
- Modify: `tests/supervisor/views/test_migration.py`

- [ ] **Step 1: Rewrite the cleanup handler**

Replace the existing `migration_cleanup` function:

```python
@cors_allow_all
async def migration_cleanup(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/cleanup — release source after dest reports IMPORTED.

    Refuses if no EXPORTED job exists (catches scheduler bugs that call cleanup too early).
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]

    job = _export_jobs.get(vm_hash)
    if job is None or job.state != MigrationState.EXPORTED:
        return web.json_response(
            {"status": "error", "error": "No completed export to clean up"},
            status=HTTPStatus.CONFLICT,
        )

    try:
        if job.ttl_task is not None and not job.ttl_task.done():
            job.ttl_task.cancel()
        await pool.stop_vm(vm_hash)
        pool.forget_vm(vm_hash)
        for path in job.export_paths:
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete export file %s: %s", path, e)
        _export_jobs.pop(vm_hash, None)

        return web.json_response({"status": "completed", "vm_hash": str(vm_hash)}, status=HTTPStatus.OK)

    except Exception as error:
        logger.exception("Cleanup failed for %s: %s", vm_hash, error)
        return web.json_response(
            {"status": "error", "error": f"Cleanup failed: {error}"},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
```

- [ ] **Step 2: Add the guard test**

In `tests/supervisor/views/test_migration.py`:

```python
class TestMigrationCleanupGuard:
    @pytest.mark.asyncio
    async def test_cleanup_without_exported_job_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        from aleph.vm.migration.jobs import _export_jobs
        _export_jobs.clear()

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "No completed export" in body["error"]
```

- [ ] **Step 3: Run, confirm pass**

Run: `pytest tests/supervisor/views/test_migration.py::TestMigrationCleanupGuard -v`
Expected: 1 passed.

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/orchestrator/views/migration.py tests/supervisor/views/test_migration.py
git commit -m "migration: cleanup refuses without an EXPORTED job"
```

---

### Task 13: Track in-flight disk downloads and refuse cleanup while streaming

**Files:**
- Modify: `src/aleph/vm/migration/jobs.py`
- Modify: `src/aleph/vm/orchestrator/views/migration.py`
- Modify: `tests/supervisor/views/test_migration.py`

The cleanup endpoint must refuse with `409 Conflict` if a disk download is currently streaming for the same `vm_hash`, so the scheduler can't yank export files out from under an in-flight transfer. We track the count of active downloads on the `ExportJob` and check it in `migration_cleanup`.

- [ ] **Step 1: Add `active_downloads` to `ExportJob`**

In `src/aleph/vm/migration/jobs.py`, add to the `ExportJob` dataclass:

```python
    active_downloads: int = 0
```

- [ ] **Step 2: Wrap the disk-download handler with increment / decrement**

Replace `migration_disk_download` in `src/aleph/vm/orchestrator/views/migration.py` with a streaming implementation that brackets the response with counter updates:

```python
@cors_allow_all
async def migration_disk_download(request: web.Request) -> web.StreamResponse:
    """GET /control/machine/{ref}/migration/disk/{filename} — stream a compressed disk file.

    Auth via ?token= query parameter. Increments job.active_downloads while the
    response is in flight so cleanup can refuse to run during a transfer.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    filename = request.match_info.get("filename", "")

    job = _export_jobs.get(vm_hash)
    if job is None or job.token is None:
        return web.HTTPUnauthorized(text="Invalid or missing export token")

    token = request.query.get("token", "")
    if not secrets.compare_digest(token, job.token):
        return web.HTTPUnauthorized(text="Invalid or missing export token")

    if job.volumes_dir is None:
        return web.HTTPNotFound(text=f"Disk file not found: {filename}")
    export_path = job.volumes_dir / f"{filename}.export.qcow2"
    if not export_path.exists():
        return web.HTTPNotFound(text=f"Disk file not found: {filename}")

    job.active_downloads += 1
    try:
        response = web.StreamResponse(
            status=200,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(export_path.stat().st_size)},
        )
        await response.prepare(request)
        with open(export_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                await response.write(chunk)
        await response.write_eof()
        return response
    finally:
        job.active_downloads -= 1
```

(The `secrets` module is already imported at the top of the file.)

- [ ] **Step 3: Refuse cleanup if active downloads > 0**

In `migration_cleanup`, add the check after the existing `EXPORTED` guard:

```python
    if job.active_downloads > 0:
        return web.json_response(
            {"status": "error", "error": "Cannot clean up while disk download in progress"},
            status=HTTPStatus.CONFLICT,
        )
```

- [ ] **Step 4: Write a test for the guard**

In `tests/supervisor/views/test_migration.py`:

```python
class TestMigrationCleanupActiveDownload:
    @pytest.mark.asyncio
    async def test_cleanup_during_download_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, _export_jobs
        from aleph.vm.models import MigrationState

        _export_jobs.clear()
        job = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            active_downloads=1,
        )
        _export_jobs[mock_vm_hash] = job

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "download" in body["error"].lower()
        _export_jobs.clear()
```

- [ ] **Step 5: Run the new test**

Run: `pytest tests/supervisor/views/test_migration.py::TestMigrationCleanupActiveDownload -v`
Expected: 1 passed.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/migration/jobs.py src/aleph/vm/orchestrator/views/migration.py tests/supervisor/views/test_migration.py
git commit -m "migration: refuse cleanup while disk downloads are in flight"
```

---

### Task 14: Update existing export tests to new 202 + status pattern

**Files:**
- Modify: `tests/supervisor/views/test_migration.py`

- [ ] **Step 1: Add a polling helper at the top of the test file**

After the `_make_running_qemu_execution` helper, add:

```python
async def wait_for_export_state(client: TestClient, vm_hash, target_state: str, timeout: float = 5.0):
    """Poll /export/status until job.state == target_state or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        r = await client.get(f"/control/machine/{vm_hash}/migration/export/status")
        if r.status == HTTPStatus.OK:
            data = await r.json()
            if data["state"] == target_state:
                return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"export job did not reach {target_state} within {timeout}s")
```

- [ ] **Step 2: Update the existing happy-path export test**

Locate the test currently checking that `migration_export` returns `200` with the disk-files payload (likely named `test_export_success` or similar). Rewrite to:

```python
    @pytest.mark.asyncio
    async def test_export_returns_202_and_completes(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        from aleph.vm.migration.jobs import _export_jobs
        _export_jobs.clear()

        mocker.patch("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())

        async def fake_compress(src, dst):
            dst.write_bytes(b"compressed")
        mocker.patch("aleph.vm.migration.runner.compress_disk", fake_compress)

        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r.status == HTTPStatus.ACCEPTED
        body = await r.json()
        assert body["status_url"].endswith("/migration/export/status")

        data = await wait_for_export_state(client, mock_vm_hash, "exported")
        assert data["disk_files"] is not None
        assert data["export_token"]
        _export_jobs.clear()
```

Also update `_make_running_qemu_execution` to drop the `migration_state` and `export_token` mock attributes (those fields no longer exist on `VmExecution`):

```python
def _make_running_qemu_execution(mocker, vm_hash):
    execution = mocker.Mock()
    execution.vm_hash = vm_hash
    execution.is_running = True
    execution.is_stopping = False
    execution.hypervisor = HypervisorType.qemu
    execution.is_confidential = False
    execution.systemd_manager = mocker.Mock()
    execution.controller_service = f"aleph-vm-controller@{vm_hash}.service"
    execution.vm = mocker.Mock()
    execution.vm.qmp_socket_path = mocker.Mock()
    execution.vm.qmp_socket_path.exists.return_value = True
    return execution
```

- [ ] **Step 3: Delete or update other tests that asserted the old 200-with-disk-files response**

Search for any remaining references to `MigrationState.EXPORTED` set on the execution mock, or assertions on `await response.json()` shape that match the old sync response — update them to use `wait_for_export_state` then read disk_files from the status payload.

Run: `grep -n "migration_state\|export_token" tests/supervisor/views/test_migration.py`
Expected: no matches in test fixtures (only inside `wait_for_export_state` polling, if any).

- [ ] **Step 4: Run all export tests**

Run: `pytest tests/supervisor/views/test_migration.py -k Export -v`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add tests/supervisor/views/test_migration.py
git commit -m "tests: migrate export tests to 202+poll pattern"
```

---

## Phase 4 — Import side: async runner and HTTP layer

### Task 15: Implement `_run_import` background coroutine

**Files:**
- Modify: `src/aleph/vm/migration/runner.py`
- Modify: `tests/migration/test_runner.py`

- [ ] **Step 1: Write failing test for happy-path import**

Append to `tests/migration/test_runner.py`:

```python
from aleph.vm.migration.jobs import ImportJob


@pytest.mark.asyncio
async def test_run_import_success(tmp_path, monkeypatch):
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    # Simulate a parent image already cached.
    parent_path = tmp_path / "parent.qcow2"
    parent_path.write_bytes(b"parent")

    fake_message = MagicMock()
    fake_message.type.value = "instance"
    fake_message.content.environment.hypervisor.value = "qemu"
    fake_message.content.environment.trusted_execution = None
    fake_message.content.rootfs.parent.ref = "parentref"

    async def fake_load_message(_hash):
        return (fake_message, fake_message)

    async def fake_get_rootfs_base_path(_ref):
        return parent_path

    async def fake_detect_format(_path):
        return "qcow2"

    async def fake_download(session, url, dest_path, token, on_chunk=None):
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"downloaded")
        if on_chunk is not None:
            on_chunk(10)
        return 10

    async def fake_rebase(overlay, parent, fmt):
        return None

    pool = MagicMock()
    pool.executions = {}
    pool.create_a_vm = AsyncMock(return_value=MagicMock())

    monkeypatch.setattr("aleph.vm.migration.runner.load_updated_message", fake_load_message)
    monkeypatch.setattr("aleph.vm.migration.runner.get_rootfs_base_path", fake_get_rootfs_base_path)
    monkeypatch.setattr("aleph.vm.migration.runner.detect_parent_format", fake_detect_format)
    monkeypatch.setattr("aleph.vm.migration.runner.download_disk_from_source", fake_download)
    monkeypatch.setattr("aleph.vm.migration.runner.rebase_overlay", fake_rebase)

    from aleph.vm.migration.jobs import DiskFileInfo
    from aleph.vm.migration.runner import _run_import

    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src.example",
        source_port=443,
    )
    disk_files = [DiskFileInfo(name="rootfs.qcow2", size_bytes=10, download_path=f"/control/machine/{vm_hash}/migration/disk/rootfs.qcow2")]

    await _run_import(job, pool, disk_files=disk_files, export_token="t0k3n")

    assert job.state == MigrationState.IMPORTED
    assert job.error is None
    assert job.bytes_downloaded == 10
    assert job.transfer_time_ms is not None
    pool.create_a_vm.assert_awaited_once()
```

- [ ] **Step 2: Run, confirm fail**

Run: `pytest tests/migration/test_runner.py::test_run_import_success -v`
Expected: `ImportError` for `_run_import`.

- [ ] **Step 3: Implement `_run_import`**

Append to `src/aleph/vm/migration/runner.py`:

```python
import shutil
import time

import aiohttp
from aleph_message.models import MessageType
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.migration.helpers import (
    detect_parent_format,
    download_disk_from_source,
    rebase_overlay,
)
from aleph.vm.migration.jobs import DiskFileInfo, ImportJob
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.storage import get_rootfs_base_path


async def _run_import(
    job: ImportJob,
    pool,
    *,
    disk_files: list[DiskFileInfo],
    export_token: str,
) -> None:
    """Drive an ImportJob from IMPORTING to a terminal state. Mutates job in place; never raises."""
    sem = get_migration_semaphore()
    start = time.monotonic()
    async with sem:
        try:
            job.current_step = "fetching_message"
            message, original_message = await load_updated_message(job.vm_hash)

            if message.type != MessageType.instance:
                raise RuntimeError("Message is not an instance")
            hypervisor = message.content.environment.hypervisor or HypervisorType.firecracker
            if hypervisor != HypervisorType.qemu:
                raise RuntimeError("Migration only supported for QEMU instances")
            if message.content.environment.trusted_execution is not None:
                raise RuntimeError("Migration not supported for confidential VMs")

            job.current_step = "downloading_parent"
            parent_ref = message.content.rootfs.parent.ref
            parent_path = await get_rootfs_base_path(parent_ref)
            parent_format = await detect_parent_format(parent_path)

            dest_dir = settings.PERSISTENT_VOLUMES_DIR / str(job.vm_hash)
            dest_dir.mkdir(parents=True, exist_ok=True)
            job.dest_dir = dest_dir
            job.total_bytes_expected = sum(df.size_bytes for df in disk_files)

            job.current_step = "downloading_disks"
            scheme = "https" if job.source_port == 443 else "http"
            base_url = f"{scheme}://{job.source_host}:{job.source_port}"

            async with aiohttp.ClientSession() as session:
                for disk_file in disk_files:
                    url = f"{base_url}{disk_file.download_path}"
                    dest_path = dest_dir / disk_file.name
                    job.downloaded_files.append(dest_path)
                    base_so_far = job.bytes_downloaded

                    def _progress(file_total: int) -> None:
                        job.bytes_downloaded = base_so_far + file_total

                    await download_disk_from_source(
                        session, url, dest_path, export_token, on_chunk=_progress
                    )

            job.current_step = "rebasing"
            for disk_file in disk_files:
                overlay_path = dest_dir / disk_file.name
                if overlay_path.exists():
                    await rebase_overlay(overlay_path, parent_path, parent_format)

            job.current_step = "creating_vm"
            await pool.create_a_vm(
                vm_hash=job.vm_hash,
                message=message.content,
                original=original_message.content,
                persistent=True,
            )

            job.transfer_time_ms = int((time.monotonic() - start) * 1000)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.IMPORTED

        except Exception as error:
            logger.exception("Import failed for %s: %s", job.vm_hash, error)
            job.state = MigrationState.IMPORT_FAILED
            job.error = str(error)
            job.finished_at = datetime.now(timezone.utc)

            if job.dest_dir is not None and pool.executions.get(job.vm_hash) is None:
                shutil.rmtree(job.dest_dir, ignore_errors=True)


async def _import_ttl_cleanup(job: ImportJob, timeout: int) -> None:
    try:
        await asyncio.sleep(timeout)
        from aleph.vm.migration.jobs import _import_jobs
        _import_jobs.pop(job.vm_hash, None)
    except asyncio.CancelledError:
        pass


def schedule_import_ttl(job: ImportJob, timeout: int) -> None:
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    job.ttl_task = asyncio.create_task(_import_ttl_cleanup(job, timeout))
```

Then in `_run_import`, after the success branch and after the failure branch, schedule the TTL:

```python
            schedule_import_ttl(job, 1800)
```

- [ ] **Step 4: Run import test, confirm pass**

Run: `pytest tests/migration/test_runner.py::test_run_import_success -v`
Expected: 1 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/migration/runner.py tests/migration/test_runner.py
git commit -m "migration: implement async import runner with progress tracking"
```

---

### Task 16: Rewrite `migration_import` HTTP handler to spawn job + return 202

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/migration.py`

- [ ] **Step 1: Replace the handler**

Replace `migration_import` in `src/aleph/vm/orchestrator/views/migration.py`:

```python
from aleph.vm.migration.jobs import ImportJob, _import_jobs
from aleph.vm.migration.runner import _run_import


class ColdMigrationImportRequest(BaseModel):
    vm_hash: str
    source_host: str
    source_port: int = 443
    export_token: str
    disk_files: list[DiskFileInfo]


@cors_allow_all
async def migration_import(request: web.Request) -> web.Response:
    """POST /control/migrate — start an async import job."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    try:
        data = await request.json()
        params = ColdMigrationImportRequest.model_validate(data)
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=HTTPStatus.BAD_REQUEST)

    pool: VmPool = request.app["vm_pool"]
    vm_hash = ItemHash(params.vm_hash)

    existing_exec = pool.executions.get(vm_hash)
    if existing_exec is not None and existing_exec.is_running:
        return web.json_response(
            {"status": "error", "error": "VM already running on this host"},
            status=HTTPStatus.CONFLICT,
        )

    existing = _import_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.IMPORTING:
            return _import_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        return _import_job_descriptor_response(existing, status=HTTPStatus.CONFLICT)

    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host=params.source_host,
        source_port=params.source_port,
    )
    _import_jobs[vm_hash] = job
    job.task = create_task_log_exceptions(
        _run_import(job, pool, disk_files=params.disk_files, export_token=params.export_token),
        name=f"import-{vm_hash}",
    )

    return _import_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _import_job_descriptor_response(job: ImportJob, status: int) -> web.Response:
    return web.json_response(
        {
            "status": job.state.value,
            "vm_hash": str(job.vm_hash),
            "started_at": job.started_at.isoformat(),
            "status_url": f"/control/migrate/{job.vm_hash}/status",
            **({"error": job.error} if job.error else {}),
        },
        status=status,
        dumps=dumps_for_json,
    )
```

Also drop the now-unused `migration_lock`, `_export_state`, `_export_cleanup_tasks` module-level globals from this file — they've been replaced by the registries in `migration.jobs`.

- [ ] **Step 2: Verify file no longer references removed globals**

Run: `grep -n "migration_lock\|_export_state\|_export_cleanup_tasks" src/aleph/vm/orchestrator/views/migration.py`
Expected: no matches.

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/orchestrator/views/migration.py
git commit -m "migration: return 202 from /control/migrate and spawn import job"
```

---

### Task 17: Add `migration_import_status` endpoint

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/migration.py`
- Modify: `src/aleph/vm/orchestrator/supervisor.py`

- [ ] **Step 1: Add the handler**

Append to `src/aleph/vm/orchestrator/views/migration.py`:

```python
@cors_allow_all
async def migration_import_status(request: web.Request) -> web.Response:
    """GET /control/migrate/{vm_hash}/status — return live import job state."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    raw = request.match_info.get("vm_hash", "")
    try:
        vm_hash = ItemHash(raw)
    except Exception:
        return web.json_response({"status": "error", "error": "Invalid vm_hash"}, status=HTTPStatus.BAD_REQUEST)

    job = _import_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"status": "error", "error": "No import job"}, status=HTTPStatus.NOT_FOUND)

    return web.json_response(
        {
            "vm_hash": str(job.vm_hash),
            "state": job.state.value,
            "started_at": job.started_at.isoformat(),
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "bytes_downloaded": job.bytes_downloaded,
            "total_bytes_expected": job.total_bytes_expected,
            "current_step": job.current_step,
            "error": job.error,
            "transfer_time_ms": job.transfer_time_ms,
        },
        status=HTTPStatus.OK,
        dumps=dumps_for_json,
    )
```

- [ ] **Step 2: Register the route**

In `src/aleph/vm/orchestrator/supervisor.py`, add to the migration block and the import list:

```python
        web.post("/control/migrate", migration_import),
        web.get("/control/migrate/{vm_hash}/status", migration_import_status),
```

```python
from .views.migration import (
    migration_cleanup,
    migration_disk_download,
    migration_export,
    migration_export_status,
    migration_import,
    migration_import_status,
)
```

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/orchestrator/views/migration.py src/aleph/vm/orchestrator/supervisor.py
git commit -m "migration: expose GET /migrate/{vm_hash}/status"
```

---

### Task 18: Update existing import tests to new 202 + poll pattern

**Files:**
- Modify: `tests/supervisor/views/test_migration.py`

- [ ] **Step 1: Add an import polling helper**

```python
async def wait_for_import_state(client: TestClient, vm_hash, target_state: str, timeout: float = 5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        r = await client.get(f"/control/migrate/{vm_hash}/status")
        if r.status == HTTPStatus.OK:
            data = await r.json()
            if data["state"] == target_state:
                return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"import job did not reach {target_state} within {timeout}s")
```

- [ ] **Step 2: Rewrite the existing import happy-path test to await 202 then poll**

The existing test (likely `test_import_success`) should become:

```python
    @pytest.mark.asyncio
    async def test_import_returns_202_and_completes(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        from aleph.vm.migration.jobs import _import_jobs
        _import_jobs.clear()

        # Patch every external call inside _run_import.
        fake_message = mocker.Mock()
        fake_message.type = MessageType.instance
        fake_message.content.environment.hypervisor = HypervisorType.qemu
        fake_message.content.environment.trusted_execution = None
        fake_message.content.rootfs.parent.ref = "parent"

        mocker.patch("aleph.vm.migration.runner.load_updated_message", AsyncMock(return_value=(fake_message, fake_message)))
        mocker.patch("aleph.vm.migration.runner.get_rootfs_base_path", AsyncMock(return_value=tmp_path / "parent.qcow2"))
        mocker.patch("aleph.vm.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.migration.runner.rebase_overlay", AsyncMock())

        async def fake_download(session, url, dest_path, token, on_chunk=None):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            if on_chunk:
                on_chunk(1)
            return 1

        mocker.patch("aleph.vm.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        pool = mocker.Mock(executions={})
        pool.create_a_vm = AsyncMock()
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src.example",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [{"name": "rootfs.qcow2", "size_bytes": 1, "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2"}],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.ACCEPTED

        data = await wait_for_import_state(client, mock_vm_hash, "imported")
        assert data["transfer_time_ms"] is not None

        _import_jobs.clear()
```

- [ ] **Step 3: Run import tests, confirm pass**

Run: `pytest tests/supervisor/views/test_migration.py -k Import -v`
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/supervisor/views/test_migration.py
git commit -m "tests: migrate import tests to 202+poll pattern"
```

---

## Phase 5 — Startup reaper

### Task 19: Implement `reap_orphan_migration_files`

**Files:**
- Create: `src/aleph/vm/migration/reaper.py`
- Create: `tests/migration/test_reaper.py`

- [ ] **Step 1: Write failing tests**

In `tests/migration/test_reaper.py`:

```python
"""Tests for the startup migration reaper."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.migration.reaper import reap_orphan_migration_files


@pytest.mark.asyncio
async def test_reaper_deletes_export_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abc123"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"keep")
    (vm_dir / "rootfs.qcow2.export.qcow2").write_bytes(b"orphan")
    (vm_dir / "data.qcow2.export.qcow2").write_bytes(b"orphan2")

    pool = MagicMock()
    pool.executions = {ItemHash("abc123"): MagicMock()} if False else {"abc123": MagicMock()}

    await reap_orphan_migration_files(pool)

    assert (vm_dir / "rootfs.qcow2").exists()
    assert not (vm_dir / "rootfs.qcow2.export.qcow2").exists()
    assert not (vm_dir / "data.qcow2.export.qcow2").exists()


@pytest.mark.asyncio
async def test_reaper_removes_orphan_dest_dir_with_part_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abandoned"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2.part").write_bytes(b"partial")

    pool = MagicMock()
    pool.executions = {}

    await reap_orphan_migration_files(pool)

    assert not vm_dir.exists()


@pytest.mark.asyncio
async def test_reaper_keeps_complete_orphan_volumes(tmp_path, monkeypatch, caplog):
    """Directory with completed qcow2 files but no execution: keep, log a warning."""
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "complete-but-orphan"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"complete")

    pool = MagicMock()
    pool.executions = {}

    await reap_orphan_migration_files(pool)

    assert vm_dir.exists()
    assert (vm_dir / "rootfs.qcow2").exists()
```

- [ ] **Step 2: Run, confirm fail**

Run: `pytest tests/migration/test_reaper.py -v`
Expected: `ImportError: cannot import name 'reap_orphan_migration_files'`.

- [ ] **Step 3: Implement the reaper**

In `src/aleph/vm/migration/reaper.py`:

```python
"""Startup reaper for orphan cold-migration files."""

import logging
import shutil
from pathlib import Path

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)


async def reap_orphan_migration_files(pool) -> None:
    """Reap orphan export and partial-import files left behind by a prior supervisor run.

    On each <vm_hash> directory under PERSISTENT_VOLUMES_DIR:
      - Always delete *.qcow2.export.qcow2 (orphan exports — pool can't claim them).
      - If pool has no execution for this vm_hash AND the dir contains *.part files:
          → rmtree the directory (clear evidence of an aborted import).
      - If pool has no execution AND the dir has only completed .qcow2 files:
          → keep, log warning. A subsequent import retry can detect the existing files.
    """
    base = settings.PERSISTENT_VOLUMES_DIR
    if not base.exists():
        return

    # Pool keys may be strings or ItemHash objects; normalise to strings for matching.
    known = {str(k) for k in pool.executions}

    for entry in base.iterdir():
        if not entry.is_dir():
            continue

        # Pass 1: orphan .export.qcow2 files always go.
        for export_file in entry.glob("*.qcow2.export.qcow2"):
            try:
                export_file.unlink()
                logger.info("Reaped orphan export file %s", export_file)
            except Exception as e:
                logger.warning("Failed to delete orphan export %s: %s", export_file, e)

        # Pass 2: orphan dest dirs.
        if entry.name in known:
            continue

        part_files = list(entry.glob("*.part"))
        if part_files:
            try:
                shutil.rmtree(entry)
                logger.info("Reaped orphan import dir %s (had %d .part files)", entry, len(part_files))
            except Exception as e:
                logger.warning("Failed to reap orphan dir %s: %s", entry, e)
        else:
            qcow_files = list(entry.glob("*.qcow2"))
            if qcow_files:
                logger.warning(
                    "Found orphan complete volumes dir %s with %d qcow2 files; leaving in place",
                    entry, len(qcow_files),
                )
```

- [ ] **Step 4: Run reaper tests, confirm pass**

Run: `pytest tests/migration/test_reaper.py -v`
Expected: 3 passed.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/migration/reaper.py tests/migration/test_reaper.py
git commit -m "migration: add startup reaper for orphan export and import files"
```

---

### Task 20: Wire reaper into supervisor startup

**Files:**
- Modify: `src/aleph/vm/orchestrator/supervisor.py`

- [ ] **Step 1: Register the reaper as an `on_startup` hook**

In `src/aleph/vm/orchestrator/supervisor.py`, near the other `app.on_startup.append(...)` calls (around line 280–300), add:

```python
from aleph.vm.migration.reaper import reap_orphan_migration_files


async def _run_migration_reaper(app: web.Application) -> None:
    pool = app.get("vm_pool")
    if pool is not None:
        await reap_orphan_migration_files(pool)
```

```python
    app.on_startup.append(_run_migration_reaper)
```

It must run **after** the pool is loaded (because the reaper consults `pool.executions`), so place this `append` call after the line that loads the pool.

- [ ] **Step 2: Smoke test that startup runs the reaper**

Run: `pytest tests/supervisor/ -k startup -v`
Expected: existing supervisor-startup tests still pass; if there's no existing startup test, skip this step.

- [ ] **Step 3: Commit**

```bash
git add src/aleph/vm/orchestrator/supervisor.py
git commit -m "migration: run reaper on supervisor startup"
```

---

## Phase 6 — End-to-end validation

### Task 21: Run the full test suite + manual smoke check on the routes

**Files:** none

- [ ] **Step 1: Run full migration test suite**

Run: `pytest tests/migration/ tests/supervisor/views/test_migration.py -v`
Expected: all pass.

- [ ] **Step 2: Run the broader test suite to catch unrelated breakage**

Run: `pytest tests/ -x -q`
Expected: no new failures vs `main`. Document any pre-existing failures separately.

- [ ] **Step 3: Boot the supervisor and confirm route registration**

Run:

```bash
python -c "
from unittest.mock import Mock
from aleph.vm.orchestrator.supervisor import setup_webapp
app = setup_webapp(pool=Mock())
for r in app.router.routes():
    if 'migration' in str(r.resource) or 'migrate' in str(r.resource):
        print(r.method, r.resource)
"
```

Expected: lists all six migration-related routes:
- `POST /control/machine/{ref}/migration/export`
- `GET  /control/machine/{ref}/migration/export/status`
- `GET  /control/machine/{ref}/migration/disk/{filename}`
- `POST /control/migrate`
- `GET  /control/migrate/{vm_hash}/status`
- `POST /control/machine/{ref}/migration/cleanup`

- [ ] **Step 4: Final commit (if any tidying needed)**

```bash
git status
# If there are leftover formatting/imports changes:
git add -p
git commit -m "migration: final tidy-up after async refactor"
```

---

## Out of scope (deferred per design)

- Public cancel endpoint (`DELETE /control/migrate/{vm_hash}/status`).
- Durable job persistence across supervisor restarts.
- Resumable downloads via HTTP `Range`.
- Splitting the migration semaphore into separate export and import semaphores. The current single-semaphore design is documented as revisitable based on operational experience.
