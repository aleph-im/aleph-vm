# Disk reclamation and volume retention (aleph-vm 2.1)

Status: design, approved in discussion 2026-08-24. Builds on the storage
ownership boundary shipped in PR #1149 (agent owns storage, supervisor owns
quiescence) and on the backup move (PR `od/backups-agent-side`, in flight),
which removes the last storage-shaped responsibility from the supervisor.

## Problem

An audit of `origin/dev` found that almost every path that ends a VM leaves
its on-host storage behind:

| Id | Severity | Finding | Status |
|----|----------|---------|--------|
| S1 | Critical | Terminal-message, expiry and payment-stop deletes (`tasks.py`, `expiry.py`, `run.py`, `views/__init__.py`, `update_watcher.py`) never reclaim disks. | this design |
| S2 | Critical | Owner erase left the rootfs behind. | fixed in #1149 |
| S3 | High | Failed creates leak volumes: capacity is checked after the download. | this design |
| S4 | High | `RUNTIME_CACHE`, `CODE_CACHE`, `DATA_CACHE`, `MESSAGE_CACHE` are unbounded. | this design |
| S5 | High | No download size cap during streaming; `MAX_*_ARCHIVE_SIZE` is checked after the file is complete. | this design |
| S6 | Medium | Backups expire only inside `start_backup`; a deleted VM's backups are never touched. | this design (after the backup move) |
| S7 | Medium | Per-VM namespace dirs, session dirs, `/mnt/{ns}_{vol}`, staging dirs and execution logs are never removed. | this design |
| S8 | Medium | Program reinstall unlinked the shared runtime cache entry. | fixed in #1149 |
| S9 | Low | Loop and device-mapper devices are never detached. | this design |
| S10 | Low | Orphan `.part` files after a crashed download. | this design |
| S11 | Regression | Reinstall deleted the registry record. | fixed in #1149 |

Capacity admission reads real free bytes, so every leak lowers the capacity
the node advertises. That makes leaks an attack: create, forget, repeat,
until the node refuses paying VMs. The same attack applies to any retention
feature that keeps disks of deleted VMs, so retention has to be budgeted.

## Goals and non-goals

Goals:

- Every path that ends a VM reclaims its storage, or deliberately retains
  it under a node-wide policy.
- Two retention policies: `reap` (delete on VM deletion, the default) and
  `keep` (retain, so operators can sell disk retention as a service and use
  it for debugging). A finite TTL is the implementation underneath and can
  be exposed later without structural change.
- Retained storage can never starve paying VMs.
- Caches and downloads are bounded.
- The filesystem is the source of truth (approach B): markers sit next to
  the data, there is no ledger and no quarantine move.

Non-goals:

- Per-VM or per-owner retention settings.
- An operator "pin this disk" flag (trivially added to the marker later).
- Cross-node restore.

## Ownership

Unchanged from #1149 and the backup move: whoever allocates, deallocates.
The agent allocates volumes, caches, session and staging directories,
device-mapper devices, and (after the backup move) backups; it deallocates
all of them. The supervisor holds only transient runtime state (jailer
chroots, sockets, hypervisor config files) which it removes at `DeleteVm`.
Nothing about storage policy crosses the wire; the supervisor's contribution
is quiescence: `DeleteVm`/`StopVm` return only after the hypervisor process
has released its handles, and `FreezeGuest`/`ThawGuest` bracket a backup.

## 1. Retention model

### Settings

- `VOLUME_RETENTION`: `"reap"` (default) or `"keep"`. Internally `reap` is
  a TTL of zero and `keep` a TTL of infinity.
- `VOLUME_RETENTION_BUDGET`: cap on reclaimable bytes per pool, as a
  fraction of the pool (default 10%) or an absolute size.

### One deletion function with a mandatory reason

Every agent path that deletes a VM today calls `supervisor.delete_vm` and
then some ad-hoc subset of `registry.forget`, `delete_records_for_vm` and
`remove_*_staging`. They all become one call:

```python
class RetireReason(Enum):
    RECREATE = "recreate"        # the same VM comes back immediately
    GONE = "gone"                # positive knowledge it will not return
    ERASE = "erase"              # the owner asked for a wipe
    FAILED_CREATE = "failed"     # a create that never committed

async def retire_vm(vm_hash: ItemHash, reason: RetireReason) -> None
```

| Reason | Volumes | Registry, ports | Session, staging, dm, backups |
|--------|---------|-----------------|-------------------------------|
| `RECREATE` | untouched | kept | untouched |
| `GONE` | `reap`: purge; `keep`: mark reclaimable | dropped | removed |
| `ERASE` | purge, regardless of policy | dropped | removed |
| `FAILED_CREATE` | purge, regardless of policy | dropped | removed |

The enum has no default; a new call site must say what it means, which is
what was missing in S1. Call sites and their reasons:

- Message amend, crash recovery, idle program reap, reboot: `RECREATE`.
- Message forgotten or removed, payment stopped, scheduler deallocation,
  migration hand-off completed: `GONE`.
- `operate_erase`: `ERASE`.
- Any exception between allocation and the registry commit: `FAILED_CREATE`.

`ERASE` ignores `keep` on purpose: retention protects against
administrative deletion, not against the owner's own request.

### What counts as positive knowledge

The scheduler/API answer is the only source of truth the node has about a
VM's existence. An explicit terminal status (message forgotten or removed,
payment stopped) is positive knowledge and triggers `GONE`. An API error or
timeout is not an answer and triggers nothing. There is no confirmation
count and no grace period on `GONE`.

### Retention is a budgeted cache, not a promise

Reclaimable disks are unpaid storage by definition, and an attacker does not
need to stop paying to create them: create, forget, repeat. So `keep` cannot
mean "forever":

- Reclaimable bytes on a pool never exceed `VOLUME_RETENTION_BUDGET`; the
  rest of the pool is only ever occupied by live VMs.
- Reclaimable space does not count as used for admission: advertised
  capacity is free plus reclaimable. When an admission would fail, the
  reconciler evicts reclaimable dirs oldest-first until the create fits.
- Over budget at any time (burst, lowered setting): evict oldest-first down
  to the cap on the next reconciler pass, which also runs after every
  `GONE`.

`keep` therefore means "keep as long as the budget and live demand allow,
oldest goes first". That is the only promise a node can honestly sell, and
the operator knows the budget they are selling.

## 2. Transactional create (S3, S10)

The create becomes admit, allocate, `CreateVm`, registry commit, with one
failure path.

- **Admission before allocation.** The disk part of `check_capacity` (and
  the CPU/memory part with it) moves ahead of the downloader. The message
  carries the sizes (rootfs `size_mib`, each persistent volume's
  `size_mib`) and the sizes of the cache downloads the create will perform
  are known from the message or from `Content-Length` before writing. The
  post-creation check goes away.
- **One failure path.** Any exception after allocation and before the
  registry commit runs `retire_vm(vm_hash, RetireReason.FAILED_CREATE)`.
  Today's ad-hoc `remove_*_staging` calls at the failure sites collapse
  into it.
- **`.part` files.** Downloads already write `<name>.part` then rename. The
  reconciler removes any `.part` older than `VOLUME_CREATE_GUARD` in the
  caches and the pools. No change to the downloader.
- **Crash between allocate and commit.** Covered by the reconciler's orphan
  rule (Section 3) once the create guard expires.

After this, "the VM's storage exists" and "the VM is in the registry" can
only disagree for the duration of one create.

## 3. The marker and the reconciler (S7, crash gaps)

### The `.reclaimable` marker

A VM directory without a marker is owned by a live VM. When the registry
record drops at `GONE` under `keep`, the directory has no owner and the
marker records what the registry no longer will:

```
{pool}/{vm_hash}/.reclaimable
{
  "version": 1,
  "reclaimable_since": "<iso timestamp>",
  "reason": "gone" | "orphan",
  "size_bytes": N,
  "depends_on": ["<parent ref>", ...]
}
```

One marker per namespace directory on each pool the VM spans, so each pool's
budget is computed from its own tree. `depends_on` lists the cache entries
(parent images) the volumes need, so the cache pass does not evict them
from under a retained disk. Under `reap` the marker is never written: the
purge is immediate. The marker's meaning is "no VM owns this, the collector
may take it"; the policy only decides how eagerly.

### The reconciler

One agent-side task, `reconcile_storage()`, running at startup, every
`VOLUME_RECONCILE_INTERVAL` (default 1h), after every `GONE`, and on
admission pressure. Per pass, per pool:

1. Walk `{pool}/*/`. Each directory is live (registry record exists),
   reclaimable (marker present), or orphan (neither). Orphans younger than
   `VOLUME_CREATE_GUARD` (default 10 min) or whose hash is in the agent's
   in-process "creating" set are skipped. Other orphans are purged under
   `reap`, marked `reason: orphan` under `keep`.
2. Delete `*.part` older than the guard in the pools and the caches.
3. Sweep the side directories keyed by VM hash that nothing walks today:
   `CONFIDENTIAL_SESSION_DIRECTORY/<hash>`, the V-PROGRAM and SNP staging
   dirs, `/mnt/{ns}_{vol}` mount points, per-VM execution log directories.
   Anything whose hash is neither live nor reclaimable is removed.
   Reclaimable VMs keep only their volumes; session and staging dirs are
   removed at `GONE` time since the next create rebuilds them.
4. Enforce the budget: sum `size_bytes` over the pool's reclaimable dirs and
   evict oldest-first (`reclaimable_since`) until under
   `VOLUME_RETENTION_BUDGET`.
5. Cache pass (Section 4) and backup pass (Section 5).

Everything the reconciler touches is under a directory the agent created
and is keyed by an item hash validated by `_checked_namespace`; it never
reaches a cache entry by way of a VM directory. The device-mapper guard in
`purge.py` stays: a directory still held by a dm target is logged and left
for the next pass (Section 5 removes that condition at the source).

The `keep` policy decides what stays on disk, not what stays in the
registry: a retired VM's registry record and port mappings are dropped at
`GONE` as today. The marker is the only record of a reclaimable disk.

### Adoption on re-create

Under `keep`, a create for hash X that finds `{pool}/X/.reclaimable` adopts
the directory: it unlinks the marker and reuses the volumes through the
existing sticky placement in `volume_path_for`. A VM re-scheduled to the
same node gets its disks back, which is the service being sold. There is no
explicit restore command. `FAILED_CREATE` and `ERASE` never adopt.

## 4. Caches (S4, S5)

### Size enforced during download

`storage.download_file` streams into `<hash>.part`; the `MAX_*_ARCHIVE_SIZE`
checks move into the stream: reject up front when `Content-Length` exceeds
the limit for that cache, and count bytes as chunks arrive, aborting and
unlinking the `.part` the moment the count passes the limit. Same limits,
per-cache settings with today's values as defaults.

### Cache budget and eviction

Each cache root gets `CACHE_BUDGET` (default 20% of the filesystem it sits
on). The reconciler's cache pass:

1. Compute the referenced set: every item hash named by a live VM (runtime,
   code, data, parent refs) plus every hash in a `.reclaimable` marker's
   `depends_on`.
2. Over budget: evict unreferenced entries LRU (mtime, touched by the
   downloader on each hit). If still over budget with only
   reclaimable-referenced entries left, reclaim those `.reclaimable` dirs
   oldest-first and then the entries they pinned. Entries referenced by
   live VMs are never evicted; if live references alone exceed the budget,
   log and stop: that is a capacity problem admission should have refused.
3. Evicting a parent image also removes its shared device-mapper device and
   read-only loop device (Section 5).

Admission (Section 2) counts the cache downloads a create will perform
against the cache budget, so a create that would blow the budget is refused
rather than triggering an eviction storm. `MESSAGE_CACHE` follows the same
path with a small budget.

## 5. Device-mapper teardown and backups (S6, S9)

### Device-mapper is agent-created

`downloader.py` resolves parent-backed volumes through `get_volume_path`,
which calls `create_devmapper`: the agent builds the loop devices and the dm
snapshot during allocation and hands the supervisor `/dev/mapper/<ns>_<vol>`
as `path_on_host`. So the agent tears them down. `create_devmapper` gets its
inverse:

```python
async def remove_devmapper(namespace: str, volume_name: str) -> None
```

`dmsetup remove <ns>_<vol>`, `dmsetup remove <ns>_base`, `losetup -d` of the
extended loop device, `rmdir /mnt/<ns>_<vol>`. The parent image's dm device
and read-only loop are shared across VMs using that image and are removed by
the cache pass when the parent is evicted, never per VM.

`retire_vm` calls it after `delete_vm` returns for `GONE`, `ERASE` and
`FAILED_CREATE`; `RECREATE` leaves the devices in place (the next create
finds and reuses them, today's behaviour). The reinstall path calls it after
`stop_vm`. A reclaimable directory therefore never has devices attached; a
retained volume is just a file, and adoption rebuilds the device.

### Backups are a reclaimable class

After the backup move, `BACKUP_DIRECTORY` is agent-owned. The reconciler's
backup pass applies the existing 24h TTL to every archive at every pass,
not only inside `start_backup`. Archives of a `GONE`/`ERASE` VM are removed
by `retire_vm` regardless of `VOLUME_RETENTION` (retention covers volumes,
not backups, which the owner can re-fetch while the VM is live). Archives
of an unknown hash are removed by the sweep after the TTL. `start_backup`
counts the projected archive size against the pool budget the same way a
create does.

## 6. Operator surface and settings

### CLI

Storage is agent-side and readable from the filesystem plus the registry
DB, so the commands need no daemon. They live on the agent's CLI
(`aleph-vm storage ...`), not on `alephctl`, which speaks supervisor gRPC:

- `storage status`: per pool, live / reclaimable / cache / free bytes
  against the budgets.
- `storage list [--reclaimable]`: hash, pool, size, reason, age.
- `storage reclaim <hash>`: purge one reclaimable directory now.
- `storage reconcile [--dry-run]`: one reconciler pass, printing what it
  would remove.

### Settings

| Setting | Default | Section |
|---------|---------|---------|
| `VOLUME_RETENTION` | `reap` | 1 |
| `VOLUME_RETENTION_BUDGET` | 10% per pool | 1 |
| `VOLUME_RECONCILE_INTERVAL` | 1h | 3 |
| `VOLUME_CREATE_GUARD` | 10 min | 2, 3 |
| `CACHE_BUDGET` | 20% of the cache filesystem | 4 |
| `MAX_*_ARCHIVE_SIZE` | unchanged, enforced in-stream | 4 |
| `BACKUP_TTL` (existing) | 24h, swept periodically | 5 |

All defaults keep today's behaviour except the reaping itself.

### Migration

On first start on an existing node the reconciler finds every directory
leaked by today's bugs as an orphan. Under `reap` that is a one-shot
cleanup of potentially a lot of data; startup logs a summary line per pool
(count, bytes) before purging so an operator reading the log knows why free
space jumped. Under `keep` they become reclaimable with `reason: orphan`
and are subject to the budget.

## 7. Testing

All Tier 1 (no KVM), following `tests/supervisor/test_vm_purge.py`: real
temporary directories for pools, caches, sessions and staging with
`settings` monkeypatched, and `dmsetup`/`losetup`/`qemu-img` behind the
existing subprocess seams.

- **`retire_vm` reasons.** A parametrized matrix over reason and policy
  asserting exactly which of {volumes, marker, session dir, staging,
  backups, dm teardown, registry record, port mappings} are touched. Every
  existing delete-site test moves from "asserts `supervisor.delete_vm`
  called" to "asserts `retire_vm` called with the expected reason".
- **Transactional create.** Admission refused before any file exists;
  downloader failure, `CreateVm` rejection and an injected exception before
  the registry commit each leave the pools empty; a `.part` older than the
  guard is removed, a younger one kept.
- **Reconciler.** Table-driven directory fixtures (live, marked,
  orphan-in-guard, orphan-expired, unknown-hash side dirs, over-budget
  reclaimable set) with expected end states per policy; eviction order by
  `reclaimable_since`; adoption on re-create removes the marker and reuses
  the file at the same path; a dm-held directory is skipped and logged.
- **Caches.** In-stream size cap aborts and unlinks the `.part` at the byte
  limit, with and without `Content-Length`; LRU eviction respects the live
  and reclaimable reference sets including `depends_on`; never evicts a
  live reference.
- **Device-mapper teardown.** `remove_devmapper` issues the inverse
  commands in order and never touches the shared parent device; the
  reinstall path calls it after stop.
- **Migration.** A pool seeded with today's leak shapes (leftover namespace
  dirs, orphan `.part`, stale session and staging dirs) is clean after one
  startup pass under `reap`, and marked under `keep`.
- **Integration.** One end-to-end create, forget, reconcile check per
  policy against the fake supervisor in `tests/supervisor/integration`.

## Dependencies and sequencing

1. Backup move (`od/backups-agent-side`, pre-2.0): Section 5's backup pass
   assumes it.
2. `retire_vm` and the call-site conversion (Section 1) plus `.reclaimable`
   and the reconciler (Section 3): the core, one PR.
3. Transactional create (Section 2).
4. Device-mapper teardown (Section 5).
5. Cache bounds and in-stream size cap (Section 4).
6. CLI (Section 6).

Each step is independently shippable and leaves the node strictly less
leaky than before.
