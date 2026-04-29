# Async Cold Migration — Design

## Background

The current cold-migration code on branch `od/cold-migration` (file:
`src/aleph/vm/orchestrator/views/migration.py`) exposes four endpoints:

```
POST /control/machine/{ref}/migration/export
GET  /control/machine/{ref}/migration/disk/{filename}
POST /control/migrate
POST /control/machine/{ref}/migration/cleanup
```

Two of these — `migration/export` and `/control/migrate` — block the HTTP
request for the entire duration of long-running work:

- **export:** graceful shutdown of the VM (up to 30 s), then
  `qemu-img convert -c` over every qcow2 in the VM's volumes dir. For
  multi-GB volumes this takes minutes.
- **import:** fetches the Aleph message, downloads the parent image,
  downloads every compressed disk file from the source CRN over HTTP,
  rebases each overlay, and creates the VM in the pool. Bounded by
  network throughput times disk size.

The scheduler (which calls these endpoints) experiences HTTP timeouts
when the work exceeds its client-side request timeout. Beyond the
timeouts, having such long-lived synchronous requests is the wrong
shape: a connection drop yields ambiguous "did it succeed?" state
that, in the worst case, can lead the scheduler to call `cleanup`
on a successful but timed-out export — which deletes source data
that the destination might never have received.

This design replaces the synchronous shape with an asynchronous
job-and-poll API on both sides.

## Goals

- POST handlers return within milliseconds with `202 Accepted` and a
  status URL.
- The scheduler polls a `GET …/status` endpoint until terminal state.
- The disk-download endpoint stays as-is (already streamed).
- `cleanup` stays synchronous (it's quick).
- The data-loss window from "scheduler thinks import failed but it
  actually succeeded" shrinks to zero, because the scheduler now sees
  an explicit `IMPORTED` state before calling `cleanup`.

## Non-goals

- No durable job state across supervisor restarts. In-flight jobs are
  killed on restart; the scheduler is expected to retry.
- No public job-cancel endpoint. Failed jobs sit in the registry until
  TTL; `cleanup` is the official "release this slot" call.
- No backwards compatibility with the existing sync API. The branch is
  pre-release.

## Architecture

The pattern is symmetric on source and destination:

1. POST handler validates synchronously, registers a job in an
   in-memory dict keyed by `vm_hash`, spawns a background
   `asyncio.Task`, and returns `202` with a status URL.
2. Background task mutates the job object as it progresses; the GET
   status endpoint reads the live object so polling sees fresh values.
3. On terminal state (success or failure), a TTL task is scheduled to
   GC the job from the registry after `EXPORT_TTL_SECONDS` /
   `IMPORT_JOB_TTL` (30 minutes each).

```
┌──────── source CRN ────────┐                  ┌──── destination CRN ────┐
│                            │                  │                          │
│ POST /export   ─► 202      │                  │ POST /control/migrate    │
│  (spawns export task,      │                  │   ─► 202                 │
│   returns job descriptor)  │                  │  (spawns import task,    │
│                            │                  │   returns job descriptor)│
│ GET  /export/status ─► JSON│                  │ GET  /import/status      │
│                            │ ◄── disk download│   ─► JSON                │
│ POST /cleanup (sync, fast) │      (streamed,  │                          │
│                            │       unchanged) │                          │
└────────────────────────────┘                  └──────────────────────────┘
                       ▲                                       ▲
                       └─────── scheduler polls both ──────────┘
```

State on both sides lives in module-level registries keyed by
`vm_hash`: `_export_jobs` on the source (replacing the current
`_export_state` dict) and a new `_import_jobs` on the destination.
The pool is not involved in the import job's lifecycle until the
very end, when `pool.create_a_vm` is called on success. Two fields
on `VmExecution` (`migration_state`, `export_token`) are removed —
see Section "State model".

## Endpoints

### `POST /control/machine/{ref}/migration/export`

Request: unchanged (path-only, scheduler auth token).

Response (new job):

```http
202 Accepted
Content-Type: application/json

{
  "status": "exporting",
  "vm_hash": "abc123…",
  "started_at": "2026-04-29T12:00:00Z",
  "status_url": "/control/machine/abc123…/migration/export/status"
}
```

Response (idempotent return — job already `EXPORTING`): identical 202
payload referencing the existing job.

Response (terminal job exists, i.e. `EXPORTED` / `EXPORT_FAILED`):

```http
409 Conflict

{ "status": "<terminal state>", "error": "...", ... }
```

Synchronous validation done before returning 202: VM exists, is
running, is QEMU, not confidential. Failing any returns the
appropriate 4xx synchronously.

### `GET /control/machine/{ref}/migration/export/status`

Auth: scheduler token.

```json
{
  "vm_hash": "abc123…",
  "state": "exporting" | "exported" | "export_failed",
  "started_at": "...",
  "finished_at": null | "...",
  "error": null | "qemu-img convert failed: ...",
  "disk_files": null | [...],
  "export_token": null | "..."
}
```

`disk_files` and `export_token` populate when state reaches
`exported` — these are the same fields the old sync endpoint used to
return at the end. `404` if no job exists for the given `vm_hash`.

### `GET /control/machine/{ref}/migration/disk/{filename}`

Unchanged. Streamed, gated by the `?token=` export token.

### `POST /control/machine/{ref}/migration/cleanup`

Unchanged interface. New guards:

- If no `EXPORTED` was ever recorded for this `vm_hash` on this CRN,
  return `409 Conflict` with `error: "No completed export to clean up"`.
- If a download is currently streaming the export files, return
  `409 Conflict` (the scheduler shouldn't be issuing cleanup while it
  knows downloads are in flight; making this an error surfaces bugs).

### `POST /control/migrate`

Request body unchanged: `vm_hash`, `source_host`, `source_port`,
`export_token`, `disk_files`.

Response (new job):

```http
202 Accepted

{
  "status": "importing",
  "vm_hash": "abc123…",
  "started_at": "2026-04-29T12:00:00Z",
  "status_url": "/control/migrate/abc123…/status"
}
```

Response (idempotent return — job already `IMPORTING`): identical 202.

Response (existing terminal `IMPORTED` or VM already running on
destination): `409`.

### `GET /control/migrate/{vm_hash}/status`

```json
{
  "vm_hash": "abc123…",
  "state": "importing" | "imported" | "import_failed",
  "started_at": "...",
  "finished_at": null | "...",
  "bytes_downloaded": 1234567890,
  "total_bytes_expected": 5000000000,
  "current_step": null | "downloading_parent" | "downloading_disks" | "rebasing" | "creating_vm",
  "error": null | "...",
  "transfer_time_ms": null | 12345
}
```

Progress fields (`bytes_downloaded`, `current_step`,
`total_bytes_expected`) are best-effort — the import task updates them
as it goes. `404` if no job exists for the given `vm_hash`.

## State model

### `MigrationState` enum (replaces current values)

```python
class MigrationState(str, Enum):
    NONE = "none"
    EXPORTING = "exporting"
    EXPORTED = "exported"
    EXPORT_FAILED = "export_failed"
    IMPORTING = "importing"
    IMPORTED = "imported"
    IMPORT_FAILED = "import_failed"
```

Splitting `FAILED` into `EXPORT_FAILED` / `IMPORT_FAILED` keeps source
and destination state vocabularies disjoint. `COMPLETED` from the
current enum is removed (it was unused-ish).

### `ExportJob` dataclass (replaces `_export_state` dict)

```python
@dataclass
class ExportJob:
    vm_hash: ItemHash
    state: MigrationState              # EXPORTING | EXPORTED | EXPORT_FAILED
    started_at: datetime
    finished_at: datetime | None = None
    token: str | None = None           # populated when EXPORTED
    disk_files: list[DiskFileInfo] | None = None  # populated when EXPORTED
    export_paths: list[Path] = field(default_factory=list)
    volumes_dir: Path | None = None
    error: str | None = None
    task: asyncio.Task | None = None   # the running export coroutine
    ttl_task: asyncio.Task | None = None
```

Stored in `_export_jobs: dict[ItemHash, ExportJob]`.

### `ImportJob` dataclass (new)

```python
@dataclass
class ImportJob:
    vm_hash: ItemHash
    state: MigrationState              # IMPORTING | IMPORTED | IMPORT_FAILED
    started_at: datetime
    finished_at: datetime | None = None
    source_host: str
    source_port: int
    bytes_downloaded: int = 0
    total_bytes_expected: int | None = None
    current_step: str | None = None
    transfer_time_ms: int | None = None
    error: str | None = None
    dest_dir: Path | None = None
    downloaded_files: list[Path] = field(default_factory=list)
    task: asyncio.Task | None = None
    ttl_task: asyncio.Task | None = None
```

Stored in `_import_jobs: dict[ItemHash, ImportJob]`.

### Removed fields on `VmExecution`

- `migration_state: MigrationState`
- `export_token: str | None`

Both were redundant with `_export_state` / would be redundant with
`_export_jobs`, and only the migration view itself ever read them.
Anyone who needs to know "is this VM mid-export?" consults
`_export_jobs.get(vm_hash)`.

### Concurrency

A single `migration_semaphore: asyncio.Semaphore` is shared by
`_run_export` and `_run_import`. Both coroutines acquire it *inside*
their body (not in the request handler) so the POST returns
immediately even when the semaphore is saturated; jobs that can't
acquire wait in their `IMPORTING` / `EXPORTING` state and the
status-poll endpoint reflects the wait truthfully.

Two POSTs for the same `vm_hash` are de-duplicated by the
idempotent-return check *before* the semaphore is involved, so
duplicate retries don't consume a slot.

Capacity is configurable via a new setting:

```python
# in aleph.vm.conf.Settings
MAX_CONCURRENT_MIGRATIONS: int = 1
```

Default is `1` (matches today's de-facto behaviour: the current
sync code serialises imports via a global lock, and the CRN host has
no other parallel-export concept). Operators with beefier CRNs raise
this to 2+ to allow simultaneous export/import or batched
migrations. The setting is read at supervisor startup; the
semaphore is constructed once and parked on the aiohttp app object
(or on the migration view's module state, matching the existing
`_export_state` pattern).

A single semaphore (rather than separate export and import
semaphores) reflects the operator's actual concern — total
migration-related I/O and CPU pressure on the host — and keeps the
configuration surface to one knob. Split into two settings later if
operational experience shows export and import bottleneck on
different resources.

## Idempotency

Per the design discussion (option B):

- POST against a `vm_hash` whose job is in a non-terminal state
  (`EXPORTING` / `IMPORTING`) returns `202` with the existing job
  descriptor — silently absorbing lost-response retries.
- POST against a `vm_hash` whose job is in a terminal state
  (`EXPORTED` / `EXPORT_FAILED` / `IMPORTED` / `IMPORT_FAILED`)
  returns `409` — the caller must explicitly clear the slot before
  re-trying.

## Error handling

### Source-side (export)

| Failure | Outcome |
|--------|---------|
| Synchronous validation (running, QEMU, etc.) | `4xx` from POST, no job created |
| `_graceful_shutdown` raises | `state = EXPORT_FAILED`, `error` populated, attempt to restart VM via systemd |
| `_compress_disk` raises | `state = EXPORT_FAILED`, delete every partial `*.qcow2.export.qcow2`, attempt to restart VM |
| Background task crashes uncaught | Wrapper sets `state = EXPORT_FAILED`, runs above cleanup |

### Destination-side (import)

| Failure | Outcome |
|--------|---------|
| Synchronous validation | `4xx` from POST, no job created |
| Aleph message fetch fails | `state = IMPORT_FAILED`, no on-disk state to clean |
| Parent image download fails | `state = IMPORT_FAILED`, leave shared parent image alone |
| Disk download fails | `state = IMPORT_FAILED`, `rmtree(dest_dir)` (after asserting no `VmExecution` claims it) |
| `_rebase_overlay` fails | Same as disk download |
| `pool.create_a_vm` fails | Same |

The `pool.executions.get(vm_hash) is None` check before `rmtree` is
defence in depth against scheduler retries that race a successful
import.

### Restart resilience

In-flight jobs do not survive a supervisor restart. Recovery hinges
on a single contract: **the scheduler MUST observe `IMPORTED` on
the destination's status endpoint before calling `cleanup` on the
source.** With that rule, every failure path is recoverable:

| Phase when node restarts | Outcome |
|--------------------------|---------|
| Source restarts during `EXPORTING` | The VM's persistent record still says it should be running, so the supervisor's normal start-up flow restores it. Orphan `.export.qcow2` files reaped on startup. Scheduler retries. (Implementation note: this assumes the existing supervisor-startup flow, which already reloads persistent VMs and recently gained orphan-controller-service handling.) |
| Source restarts during `EXPORTED` (waiting for download) | Same as above — the VM's persistent record causes the supervisor to restart it. Orphan exports reaped. Scheduler retries. |
| Destination restarts during `IMPORTING` | Reaper deletes any volumes dir without an execution record. Scheduler observes `404` on `/import/status`, retries. |
| Destination restarts after `IMPORTED` | VM persists in pool like any other. |
| **Source restarts after `cleanup` AND destination never reached `IMPORTED`** | **Data loss.** Prevented by the contract above. |

### Startup reaper

Runs once at supervisor boot, before HTTP server accepts connections.

1. **Source export-file reaper.** For every directory under
   `settings.PERSISTENT_VOLUMES_DIR/<vm_hash>/`, glob for
   `*.qcow2.export.qcow2` and delete. Always safe — these files are
   only consumed by the disk-download endpoint, which loses state on
   restart.
2. **Destination orphan-volumes reaper.** For every `<vm_hash>`
   directory under `PERSISTENT_VOLUMES_DIR`:
   - If the pool has a `VmExecution` for this hash → leave alone.
   - If not, and the directory contains `*.part` files → delete the
     whole directory (clear evidence of an aborted download).
   - If not, and the directory contains only completed `.qcow2`
     files → leave alone, log a warning. A subsequent import retry
     can detect the existing files and skip the re-download.

## Authentication

- All four POSTs and both GETs of the status endpoints: gated by the
  existing `authenticate_api_request` (scheduler token).
- The disk-download endpoint: gated by the per-job `export_token`
  query parameter, as today.

## Testing

Existing test file: `tests/supervisor/views/test_migration.py`.

### New tests

- `POST /export` returns `202` immediately even when `_compress_disk`
  is patched to take seconds. Status URL is well-formed.
- `GET /export/status` reflects state transitions
  `EXPORTING → EXPORTED` and `EXPORTING → EXPORT_FAILED` under
  failure injection at each stage (graceful shutdown, compress).
- Idempotency: second `POST /export` while first is in flight
  returns `202` referencing the same job.
- `409` when posting export against a `vm_hash` already in `EXPORTED`.
- Symmetric tests for `POST /control/migrate` and
  `GET /control/migrate/{vm_hash}/status`, including failure
  injection at each step (parent fetch, disk download, rebase,
  `create_a_vm`) and assertion that partial files are cleaned.
- Startup reaper: prepopulate orphan `.export.qcow2` and `.part`
  files; assert reaper deletes them on supervisor start; assert
  completed-but-orphan `.qcow2` directories are left alone.
- Cleanup guard: `POST /cleanup` with no `EXPORTED` job returns `409`.
- Cleanup guard: `POST /cleanup` while a disk download is in flight
  returns `409`.

### Tests to update

The current end-to-end "export → download → import" test still runs,
but each long step now waits on a status-poll helper rather than the
POST blocking.

### New test helper

```python
async def wait_for_state(client, status_url, target_state, timeout=5):
    """Poll status_url until state == target_state or timeout."""
```

## Deferred / out of scope

- Public cancel endpoint (`DELETE /control/migrate/{vm_hash}/status`).
  Not built now; failed jobs sit until TTL.
- Durable job persistence across supervisor restarts. Not built now;
  scheduler is expected to retry.
- Resumable downloads (HTTP `Range` on the disk-download endpoint).
  Could be added later for very large disks; current full-restart
  retry is acceptable for MVP.
