# Storage

> Verified against: 06c30936 (2026-09-09)

## What this covers

Where a VM's disks live on the host and how they get there: the volume-pool
model that spreads persistent VM data across multiple local disks
(`VOLUME_POOLS`, media classes, pool-0 pinning), the on-disk formats used for
rootfs and extra data volumes (qcow2 overlays, the devmapper copy-on-write
chain, plain ext4), cloud-init seed image generation, and the artifacts
produced by cold VM migration (export/import). All of this is agent-side
policy (`src/aleph/vm/`); the Rust supervisor daemon
(`rust/crates/supervisor-daemon`) is deliberately disk-path agnostic and only
re-parses the pool configuration for capacity accounting. Backup archives,
restore, and erase-on-delete rules are covered in
[`vm-lifecycle.md`](vm-lifecycle.md) and only referenced here where they
touch the pool model. Measured Nix guest images and dm-verity workload
volumes for confidential VMs are covered in
[`confidential.md`](confidential.md).

## The model

### Volume pools: layout and configuration

A storage pool is a plain directory, typically the mountpoint of one
dedicated SSD/NVMe filesystem, holding per-VM subdirectories
(`{pool}/{namespace}/`, namespace being the VM hash) with the VM's rootfs
overlay and extra volumes. Pool 0 is always
`settings.PERSISTENT_VOLUMES_DIR`; any extra pools come from
`settings.VOLUME_POOLS`, a list of `"path"` or `"path=class"` entries
(class: `nvme`, `ssd`, or `hdd`), parsed and validated in
`src/aleph/vm/storage_pools.py`. An empty `VOLUME_POOLS` reproduces
single-disk behavior exactly, since pool 0 is prepended unconditionally.

Multi-disk support is deliberately app-level aggregation over independent
directories rather than below-the-filesystem pooling (LVM, mdraid, btrfs
multi-device, ZFS). A dead disk under a pooling layer can take the whole
pool down and forces a migration to adopt; plain directories confine a
disk failure to the VMs whose volumes happen to live there. Nothing in
`aleph_message` or the supervisor proto changes for this: `DiskConfig.path`
already carries resolved absolute host paths the supervisor treats as
opaque (see `rust/crates/supervisor-daemon/src/config.rs`, which parses
`VOLUME_POOLS` only to sum free bytes for `HostInfo.available_disk_bytes`),
so the network keeps seeing one scalar disk-capacity number per node.

Each pool carries a media class detected from sysfs
(`detect_media_class` in `storage_pools.py`, which walks a dm/md stack down
to its slowest member device and reads `queue/rotational`) or an explicit
override in the `VOLUME_POOLS` entry. The class exists for future tiering
policy; today it is used only for one gate: `hdd` pools are never eligible
to hold VM volumes (`MediaClass.vm_eligible`). Rotational disks are for
`CACHE_ROOT` or `BACKUP_DIRECTORY` instead, both of which stay outside the
pool model entirely (`conf.py`: neither setting is derived from
`VOLUME_POOLS`). Pool 0 is the one exception to the HDD rule: it is always
VM-eligible regardless of media class, so an existing single-disk node
never breaks; `setup_pools` only logs a warning when `PERSISTENT_VOLUMES_DIR`
turns out to be rotational.

### Pool selection, adoption, and the marker/registry guard

`setup_pools()` runs once at agent startup and is the only place pools get
validated, classified, and adopted; `get_pools()` returns the cached result
(falling back to pool 0 alone for library/test callers that never called
setup). Every configured pool directory must already exist (`is_dir()`);
setup fails hard, not silently, on a missing directory, an undetectable or
HDD media class, or an unknown class override, because a startup that
degraded silently here could place volumes wherever a misconfigured path
happens to point.

Adoption uses two mechanisms together: a per-pool marker file
(`.aleph-vm-pool`, `POOL_MARKER_NAME`) written the first time a pool is
used, and a central registry (`{EXECUTION_ROOT}/volume-pools.json`) of every
pool path ever adopted. Neither alone is enough: the marker can't tell
"never used" from "used before but now unmounted" (an unmounted disk
presents an empty directory indistinguishable from a fresh one), and the
registry alone can't detect that the marker itself is missing. `_adopt_pool`
combines them: a present marker heals the registry (covers a restore); a
registry entry with no marker is a hard `StoragePoolConfigError`, since that
combination means the disk is very likely not mounted and writes would
otherwise silently land on whatever filesystem is under the mountpoint.
The same fail-fast stance applies to registry corruption (non-JSON or
non-list content is a hard error, since a silently-reset-to-empty registry
would disable the unmounted-disk guard) and to a registry-recorded pool that
disappeared from `VOLUME_POOLS` (also a hard error: dropping it silently
would leave its volumes findable only by accident, and fresh volumes for the
same namespace could get recreated on a different pool). The documented
escape hatch is to migrate the pool's volumes off, then remove its entry
from the registry file by hand.

Placement itself is not persisted anywhere (no `executions.sqlite3` column,
no separate index): `select_pool` picks the eligible pool with the most
free bytes at creation time, and `find_existing_volume` /
`iter_namespace_dirs` answer "where is it" by scanning
`{pool}/{namespace}/` across every configured pool, first match in pool
index order. A pool directory being unreadable (`shutil.disk_usage` or
`iterdir` raising `OSError`) is logged and skipped rather than raised, so
one dead disk does not stop admission for the rest of the pools, and a
cross-pool duplicate of the same file (e.g. a manual copy) resolves to the
lowest-index pool's copy with a warning, never both.

### Capacity accounting and admission

`pools_disk_usage()` sums `(total, free)` bytes across every pool,
deduplicating by `st_dev` so two pool directories that happen to be on the
same filesystem are counted once; this is what backs both
`about_system_usage`'s disk figures (`src/aleph/vm/agent/resources.py`) and
`CapacityManager._available_disk_bytes` (`src/aleph/vm/agent/capacity.py`).
Admission checks two things, not one: the aggregate free bytes against the
requested `disk_mib`, and (via `_check_max_volume`, when a max single-volume
size is known) that the largest requested volume alone fits the emptiest
eligible pool, `max()` over `eligible_pool_free_bytes()` plus each pool's own
reclaimable bytes. The second check exists because a volume never spans
pools: an aggregate-only check would happily admit, say, a 900 GiB volume
onto two half-full 500 GiB disks and then fail at creation time. Either check
failing raises `InsufficientResourcesError`.

Admission counts retained (reclaimable) bytes as free:
`_available_disk_bytes` adds `reclaimable_bytes()` to the pooled free sum,
and `select_pool`, before refusing a placement, calls the room maker the
agent registered at startup (`storage_pools.set_room_maker`, wired to
`reconciler.make_room`) so the retained directories on the target pool are
evicted oldest-first until the create fits. See "Reclamation" below: a
retained disk is a cache entry, not usage, so counting it as used would sell
less capacity than the node actually has. The rule holds for all three disk
figures the agent produces, and they have to agree: the aggregate
(`_available_disk_bytes`), the largest-single-volume check (`_check_max_volume`,
which adds each pool's own `reclaimable_bytes(pool.path)` to that pool's free
space) and the advertised capacity (`about_system_usage` /
`_disk_usage_from_pools`). A node that advertises less than admission accepts
is a node the scheduler stops sending work to.

The Rust supervisor daemon does none of this pool selection or admission
work. It parses `VOLUME_POOLS` (`config.rs`) for its own purpose, the
statvfs targets for available-disk reporting, and its validation is looser
than the agent's: `parse_pool_entry` accepts an `hdd` class entry and never
checks that the path exists, both of which fail `setup_pools()` on the
agent side. A pool config the daemon boots on can still fail the agent, so
they are not one gate. It exposes `available_disk_bytes_pooled`
(`rust/crates/supervisor-daemon/src/host.rs`, the same st_dev-deduplicated
sum, unreachable pools contributing zero) for `GetHostInfo`. It never writes
a marker, never touches `volume-pools.json`, and never picks a pool for a
new volume: `CreateVmSpec` always carries resolved, already-placed absolute
paths built by the agent.

### Rootfs vs data volumes: what lives in a pool

Three volume kinds show up in an Aleph message, and they resolve to disk
very differently:

- **`RootfsVolume`** (the instance's own disk, based on a parent runtime or
  base image). For a QEMU instance, `QemuDownloader.download_runtime`
  (`src/aleph/vm/agent/vm/downloader.py`) creates a qcow2 overlay backed by
  the parent image (`qemu-img create -b <parent> -F <format> -f qcow2`),
  placed by `volume_path_for` like any other pool file; an existing
  host-persistence overlay is reused rather than recreated. For a Firecracker
  program, the rootfs is the read-only runtime squashfs itself
  (`get_runtime_path` in `src/aleph/vm/storage.py`), verified with
  `unsquashfs -stat` and never copied into a pool, since programs are
  ephemeral and never write to it directly.
- **`PersistentVolume`** (extra mounted data volumes). Resolved through
  `host_volumes_from_message` (`src/aleph/vm/host_volumes.py`) into
  `get_volume_path` (`storage.py`): a volume that declares a `parent` base
  image goes through the devmapper chain described below; a bare volume
  with no parent becomes a plain preallocated ext4 file
  (`create_ext4`, `fallocate` + `mkfs.ext4`), placed the same pool-aware way.
- **`ImmutableVolume`** (a read-only reference to existing Aleph-hosted
  content, e.g. shared code or data). This never touches a storage pool at
  all: `get_existing_file` downloads it straight into `DATA_CACHE`.

Firecracker's jailer hardlinks drive files into its chroot, and a hardlink
across filesystems silently becomes a full copy: any guest write to a
writable Firecracker volume placed off pool 0 would be lost on the chroot
copy while the "real" file on the extra pool stays untouched. Every
Firecracker resolution path threads a `pool0_only=True` flag down to
`volume_path_for` for exactly this reason (`ProgramDownloader.download_volumes`
in `downloader.py`); QEMU volumes and read-only squashfs assets are
unaffected and use `pool0_only=False`. Lookup still scans every pool even
with `pool0_only=True`, so a legacy volume already sitting on an extra pool
keeps booting, but `volume_path_for` logs an error when it finds one there.

### The devmapper chain (copy-on-write volumes with a parent image)

`create_devmapper` in `storage.py` builds a `/dev/mapper/{namespace}_{name}`
block device for a `PersistentVolume` or `RootfsVolume` that declares a
`parent` base image, layering loopback and device-mapper devices:

1. A read-only loop device over the parent base image
   (`get_rootfs_base_path`).
2. A linear dm target the size of the parent image, over that loop device
   (`{namespace}_base`'s image half).
3. The same target extended with a `zero` segment out to the volume's full
   requested size, giving a device the parent's data followed by zeros.
4. A writable, pool-placed volume file (`create_volume_file`, `.btrfs`
   suffix, sized via `fallocate` alone, no filesystem of its own), loop-mounted
   as the copy-on-write store the next step builds on.
5. A persistent dm-snapshot (`snapshot ... P 8`) combining the extended base
   device with the writable loop device as its copy-on-write store; this
   final device is what the VM boots from.

The resulting block device is mounted once to run `btrfstune -m` (assigns a
random fsid, needed because the image was cloned) and `btrfs filesystem
resize max` before being unmounted again and handed to the VM. This chain
is `pool0_only`-aware the same way as any other volume placement (the
writable btrfs file threads the flag through `create_volume_file`), even
though in practice it is exercised only for extra volumes today; QEMU
instance rootfs volumes use the simpler qcow2-overlay path above instead.

### Cloud-init seed images

QEMU instances get their hostname, SSH keys, and static network
configuration from a NoCloud cloud-init seed image
(`cloud-localds`), built fresh on every create at
`EXECUTION_ROOT/cloud-init-{vm_hash}.img`. The Rust daemon's
`CloudInitDrive` (`rust/crates/supervisor-daemon/src/cloudinit.rs`) is a
byte-for-byte-equivalent port of the deleted Python builder
(`supervisor/controllers/qemu/cloudinit.py` plus the `build_cloud_init_drive`
half of the legacy `qemu_build.py`): it writes a `#cloud-config` user-data
document (network addresses derived from the VM's tap assignment, see
[`networking.md`](networking.md)), a netplan v2 network config keyed on the
`virtio_net` driver, and a JSON instance-id/hostname metadata document, then
shells out to `cloud-localds` to assemble the seed ISO. The Rust port emits
JSON instead of YAML for the user-data body (JSON is a YAML subset, so
`cloud-init` parses both into the same structure); the parity claim is now
pinned by committed fixtures under `rust/crates/supervisor-daemon/tests/fixtures/cloudinit/`, byte-compared
against what the builder produces (`cloudinit.rs` tests,
`UPDATE_CLOUDINIT_FIXTURES=1` to regenerate them), since the Python side they
were generated against is gone.
Confidential (LUKS-encrypted) instances get extra `bootcmd` entries
(`growpart` + `cryptsetup resize` + `resize2fs`) ahead of cloud-init's own
resize modules, since cloud-init's `growpart` alone cannot resize a LUKS
container, and they skip installing the QEMU guest agent.

### Cold migration: export and import artifacts

Moving a running QEMU instance to another node is agent-side and disk-only,
distinct from the agent's backup/restore mechanism in
[`vm-lifecycle.md`](vm-lifecycle.md): it produces and consumes files
directly under a pool's namespace directory, driven by
`src/aleph/vm/agent/migration/runner.py`.

Export (`run_export`): the supervisor stops the VM (a graceful,
disk-quiescing shutdown), then the runner collects every `*.qcow2` file
under the VM's namespace directory across pools (`_collect_export_disks`,
skipping any leftover `.export.qcow2` from a prior failed run, and
resolving cross-pool duplicates to the same lowest-index-pool rule the
boot-time lookup uses), and `qemu-img convert -c` each one to a sibling
`<name>.qcow2.export.qcow2` compressed copy, hashed with sha256 and served
over `/control/machine/{vm_hash}/migration/disk/{name}` for the destination
to pull. In practice this exports only the rootfs overlay: extra
`PersistentVolume`s resolve to ext4 or devmapper-backed btrfs files, not
qcow2, so `_collect_export_disks`'s `*.qcow2` glob does not pick them up
today. Export artifacts are TTL-cleaned (`EXPORT_TTL_SECONDS`, 30 minutes)
whether or not the destination ever pulled them.

Import (`run_import`): the runner downloads each disk file into a staging
directory chosen by `select_pool` on the incoming transfer size
(`dest_dir = select_pool(incoming_mib).path / vm_hash`), then rebases each
downloaded overlay onto the locally resolved parent image
(`qemu-img rebase -u -b <parent> -F <format>`) so the overlay no longer
depends on a backing-file path that only existed on the source node. It
then builds a normal `CreateVmSpec` from the fetched message and calls the
same `create_vm` RPC a fresh instance create uses; because the downloader's
volume lookup scans every pool, `build_create_vm_spec` finds the
already-staged, already-rebased overlay in place instead of trying to
recreate it. Migration is restricted to QEMU, non-confidential instances
(`run_import` raises before touching disk for anything else). An agent
restart runs `reap_orphan_migration_files`
(`src/aleph/vm/agent/migration/reaper.py`) once at startup: it always
deletes stray `*.export.qcow2` files, and it `rmtree`s any namespace
directory that is not a known live VM and still has `.part` (incomplete
download) files, since that combination is unambiguous evidence of an
aborted import; a namespace with only complete `.qcow2` files but no known
VM is left alone and only logged, since a retried import can still adopt it.

## Reclamation

Every agent path that ends a VM goes through one function,
`retire_vm(vm_hash, reason, ...)` (`src/aleph/vm/agent/vm/retire.py`), and
the reason decides what happens to the disks. There is no default: a call
site has to say what it means, which is exactly what was missing when disks
leaked.

| Reason | Volumes | Registry, ports | Session, staging, backups |
|--------|---------|-----------------|---------------------------|
| `RECREATE` | untouched | kept | untouched |
| `GONE` | `reap`: purged; `keep`: marked reclaimable | dropped | removed |
| `ERASE` | purged, whatever the policy | dropped | removed |
| `FAILED_CREATE` | purged, whatever the policy | dropped | removed |

`RECREATE` is the same VM coming straight back (message amend, crash
recovery, idle program reap, reboot). `GONE` needs positive knowledge that
it will not: a forgotten or removed message, a stopped payment, a scheduler
deallocation, a completed migration hand-off. An API error or a timeout is
not an answer and retires nothing. `ERASE` ignores `keep` on purpose:
retention protects against administrative deletion, not against the owner's
own request, and a `FAILED_CREATE` never ran, so it has nothing worth
keeping. A create that fails on a VM whose volumes already existed retires
`RECREATE` instead, since the create paths are also the re-create paths for
a host-persistent VM.

A payment shortfall is a stopped payment: when the held balance, the credit
balance or the stream no longer covers the VMs it pays for, the payment
monitor retires them `GONE`, so under the default `reap` their volumes are
purged at once. This is a change from 1.x, which stopped such a VM but kept
its record and disks for a later top-up, and then never reclaimed them. A
node that wants to give a re-paying owner a grace period runs
`VOLUME_RETENTION=keep`: the marker carries the owner, and a re-created VM
adopts its retained directory untouched.

### The `.reclaimable` marker

A namespace directory with no marker belongs to a live VM. Under
`VOLUME_RETENTION=keep`, `GONE` drops the registry record and writes
`{pool}/{vm_hash}/.reclaimable` in its place
(`src/aleph/vm/agent/vm/reclaimable.py`):

```json
{
  "version": 1,
  "reclaimable_since": "<iso timestamp>",
  "reason": "gone | orphan",
  "size_bytes": 12345,
  "depends_on": ["<parent image ref>", "..."],
  "owner": "<owner address>"
}
```

One marker per pool the VM spans, so each pool's budget is computed from its
own tree. `depends_on` names the cache entries (parent images) the volumes
still need, so the cache pass cannot evict a parent from under a retained
overlay. `owner` is the address from the VM's message, copied in at `GONE`
because the marker outlives every other record of it (the registry record is
forgotten and the DB rows are deleted), and it is what lets the node
authorize the owner's own erase of retained data; it is optional, so markers
written before the field and orphan markers for a VM whose message the node
never held simply have none. `reclaimable_since` is written in UTC with an
offset; a timestamp that arrives without one (a marker restored or edited by
hand) is read as UTC rather than as a naive datetime, since a naive one
cannot be compared with the aware clock the rest of the agent uses and every
subtraction against it raises, costing a whole listing or eviction pass for
one marker. Under `reap` no marker is ever written: the purge is immediate.
A create for the same hash adopts the directory (the marker is unlinked and
the volumes are reused through the existing sticky placement in
`volume_path_for`), which is what `reconciler.creating()` does on entry.

### The reconciler

`reconcile_storage()` (`src/aleph/vm/agent/vm/reconciler.py`) treats the
filesystem as the truth and asks two sources who the owners are: the agent
registry, and the VMs the supervisor lists. The union is the live set. The
registry alone is not enough, because it is refilled at boot from the agent
DB and that rehydration skips any record with an empty or unparseable
message. One pass does, in order:

0. Tear down the device-mapper snapshots and loop devices of every namespace
   `/dev/mapper` still names and no live VM owns
   (`teardown_namespace_devices`). Before the walk, not inside it: a volume
   file a dm target still holds cannot be unlinked usefully, so a directory
   whose devices are still up is refused by step 1 and would be refused
   again on every later pass. This runs on the event loop (dmsetup has to be
   awaited) and only when the supervisor answered `list_vms`, since removing
   the device of a VM that is merely unlisted takes that VM's disk with it.
1. Walk `{pool}/*/`. Each directory is live (the registry or the supervisor
   knows its hash), reclaimable (a marker is present) or an orphan
   (neither). Orphans are purged under `reap` and marked `reason: orphan`
   under `keep`. Liveness is asked again immediately before anything is
   marked, purged or evicted, so a create that commits while the pass walks
   is not mistaken for an orphan.
2. Delete `*.part` and `*.tmp` files older than the guard, in the four
   download caches and in the pools (the downloader streams volumes in
   place). Every write-then-rename in the agent uses one of the two suffixes,
   and an interrupted one leaks the same way.
3. Sweep the side directories keyed by VM hash: the confidential session
   directory, the SNP and V-PROGRAM staging directories, and
   `/mnt/{namespace}_{volume}` mount points. A directory that is still a
   mount point is logged and left alone, and under `/mnt` only empty
   mount-point directories are removed (with `rmdir`, never `rmtree`): `/mnt`
   is the operator's directory, and an unmounted agent mount point is empty
   by construction.
4. Enforce the retention budget per pool: sum the markers' `size_bytes` and
   evict oldest-first (by `reclaimable_since`) until under
   `VOLUME_RETENTION_BUDGET`. Under `reap` everything marked is given back,
   which is how a node switched from `keep` to `reap` drains.
5. Bring the four download caches under `CACHE_BUDGET` (see below). Skipped
   entirely, with an ERROR, when the supervisor could not be listed: what a
   cache holds for a live VM is read from that VM's message, so a live set
   that is the registry alone cannot answer the question, and evicting on it
   would unlink a running VM's runtime.
6. Sweep expired backups.

Nothing a create is still building is touched. Two independent guards say
so: a hash registered in the in-process "creating" set (every create path in
`run.py` and `_ensure_program_vm` runs inside `reconciler.creating()`), and
an mtime younger than `VOLUME_CREATE_GUARD`. Both matter, since a create
that outlives the guard is only protected by the first, and a create that
somehow escaped the context manager is still protected by the second.
Everything a pass touches is under a directory the agent created and is
keyed by a hash that `storage.vm_namespace` accepted: the name has to parse
as an `ItemHash` (64 lowercase hex characters, or an IPFS CID), so a
directory an operator dropped on a volume pool is never a VM. The delete
paths go through `purge._checked_namespace`, which refuses on the same rule
before any filesystem access; the passes that walk the pools ask
`is_vm_namespace` first and skip what the guard would refuse.

The startup pass is stricter than the rest: it refuses to purge anything
(it runs dry and logs why) when the supervisor did not answer `list_vms`,
or when rehydration left the registry empty while the supervisor still runs
at least one VM. Both states mean the live set cannot be trusted, and the
first pass on a node is the one acting on the biggest backlog.

Passes run at startup, every `VOLUME_RECONCILE_INTERVAL` (jittered, so a
fleet of nodes does not sweep in lockstep), after every `GONE` under `keep`
(`retire.set_after_gone_hook`, best effort: a failing pass never breaks the
sweep that retired the VM), and on admission pressure (`make_room`, through
`storage_pools.set_room_maker`). A pass runs in a worker thread, so the
live-VM set is snapshotted on the event loop first (`live_hashes`) and handed
over; `make_room` never evicts a hash in it, even if a stale marker says it
could. Loop-triggered passes serialize on a lock (`reconcile_now`); they are
serialized, not coalesced, so a sweep that retires N VMs `GONE` queues N
passes. And
placement runs `make_room` through `asyncio.to_thread`, so it can still
overlap a pass: every removal therefore tolerates a directory that another
pass took first, and counts only what it actually removed.

The create guard covers more than the create paths in `run.py`: a migration
import stages multi-GB disks into `{pool}/{vm_hash}/` for a namespace the
registry knows nothing about yet, so `run_import` holds `creating()` across
the whole transfer and records the imported VM in the registry (and the agent
DB) once `CreateVm` returns. A namespace under the guard is skipped whole,
`.part` files included: the directory mtime does not advance while a file
inside it grows, so age is no evidence that a transfer has stopped.

### The download caches

The runtime, code, data and message caches are flat directories keyed by item
hash and shared by every VM naming the same hash, and nothing used to remove
anything from them. Two things now bound them
(`src/aleph/vm/agent/vm/cache.py`).

In the stream: `download_file_in_chunks` refuses a `Content-Length` above the
cache's `MAX_*_ARCHIVE_SIZE` before it opens the file, and independently
aborts as soon as the bytes actually written exceed that same cap. The
second check is a hard ceiling on the written body, not a comparison against
the header, so it stops a disk-filling body whether `Content-Length` lied,
was absent, or was honest.

Per root: each cache gets `CACHE_BUDGET` (20% of the filesystem it sits on by
default, `shutil.disk_usage` called separately per root), the message cache
included. Unlike the storage pools' aggregate figure, this is not
deduplicated by `st_dev`: four caches that happen to share one filesystem
each get their own 20% of it. The spec suggested a smaller budget for
it; it does not have one, and does not need one: its entries are a few
kilobytes of JSON each, so it never approaches a budget sized for runtime
images, and one setting is one thing for an operator to reason about. A root's
usage is its finished entries plus what it owes to downloads that have not
finished (`in_flight_bytes`): the allocated blocks of `.part` and `.tmp`
files, and the size any admitted download was promised (the greater of the
two for a download still being written, never their sum).

The pass evicts least recently used first, mtime being a real
signal because the downloader touches an entry on every cache hit
(`_touch_cache_hit`, called by `download_file` for the caches it serves and
by `get_runtime_path` / `get_rootfs_base_path`, which short-circuit a hit
before reaching it). What it may not touch is the point:

- Entries a **live VM** names. `reclaimable.iter_content_refs` is the single
  enumeration of those, so the two questions asked of a message (what a
  retained volume depends on, what a live VM still needs) cannot drift apart:
  `runtime`, `code`, `data`, the rootfs parent, volume parents and immutable
  volume `ref`s, a V-PROGRAM's `workload.ref` and `workload.hash_tree`, a TEE
  instance's `trusted_execution.firmware` and `trusted_execution.runtime`, and
  the VM's own message entry (`<vm_hash>.json`). The confidential ones are not
  a detail: a V-PROGRAM's workload image and hash tree are attached as the
  VM's disks straight out of `DATA_CACHE`, so evicting one unlinks a running
  VM's disk. The runtime bundle tarball is the one ref no message carries
  (only the manifest names it); it is protected whenever the manifest itself
  is cached, and is otherwise a re-downloadable artifact, since nothing runs
  off the tarball (it is verified and extracted into the VM's staging
  directory at create time).
  If live references alone exceed the budget the pass logs an
  error and stops: that is a capacity problem admission should have refused,
  and eviction cannot fix it. The referenced set is read from the registry's
  messages, so a pass whose live set holds a hash the registry has no record
  for skips the cache pass entirely rather than guess.
- Entries a `.reclaimable` marker names in `depends_on`, the parent images
  retained overlays are built on. Over budget with only those left, the
  retained directories go first (oldest marker first, through
  `purge_vm_storage`), and a parent is evicted only once every retained VM
  that named it is gone and its purge actually removed the disks.

The pass also sweeps what an earlier teardown left behind: a loop device
still backed by a cache entry that is already unlinked (the kernel shows it as
` (deleted)` in `/sys/block/loop*/loop/backing_file`). That is the recovery
path for a teardown that crashed or failed, because once the entry is gone
nothing else can name the loop that pins its blocks; the same holders check
applies, so a leaked loop whose device is in use after all is left alone.

Evicting a parent image also removes what `create_devmapper` builds once per
image rather than once per VM: the `/dev/mapper/<ref>` target and the
read-only loop device under it. A parent whose device still has holders (a
VM's `<ns>_base` device is stacked on it) is not evicted at all, and an
unanswerable question counts as held. The teardown runs on the event loop
after the pass (`reconcile_now`), because the entry is already unlinked by
then; `losetup -j` can no longer find the loop that pins its blocks, so the
loop devices are found through sysfs, which keeps the backing path with a
` (deleted)` suffix. An image a create downloaded again in the meantime is
left alone: its devices belong to that create now.

Admission is the same question one download ahead: `storage`'s cache
admission hook (registered by the agent on `set_cache_admission`) runs inside
`download_file_in_chunks` once the size is known and before the file is
opened. It evicts what it can, and raises `InsufficientResourcesError`
(mapped to 503 on the create path) when the download still would not fit,
rather than writing bytes that trigger an eviction storm. A response with no
`Content-Length` is a different question, and the hook is told the two
figures separately (`content_length`, `max_bytes`) so it can tell them apart.
A cap is not a measurement: `MAX_RUNTIME_ARCHIVE_SIZE` is 100 GiB, the
ceiling for a runtime image and equally the ceiling for a few kilobytes of
manifest, so charging it as a size would evict a whole cache root for a
download that never needed the room. An unknown-length download therefore
never evicts, is refused only when the root is already over its budget, and
is charged `UNKNOWN_LENGTH_RESERVE` (2 GiB by default), never more than its
own cap nor than the whole budget. The reserve is a modest, deliberately
arbitrary figure: charging the budget itself let one chunked response hold a
whole root, so every other download on it was refused for as long as that one
ran. It is still charged against the next admission, so a stream of
unknown-length downloads ends in a refusal, and it is reconciled against the
truth as the body lands, since the bytes on disk are counted the moment they
are written. A ceiling never sets the eviction target either: a root's usage
counts a guessed reservation only at the bytes it has actually written when
the question is how much to evict, and at the full figure when the question
is whether the next download fits. What is admitted is then charged to
the download's `.part` path (`reserve_download`) until `download_file`
releases it, so a second create arriving while the first is still writing
sees the room the first was promised rather than only the bytes it has
managed to write. Directories that
are not cache roots are none of its business: the downloader streams per-VM
volumes in place, and those are admitted by the capacity checks and the pool
budget.

It is deliberately weaker than the pass, because it runs on the event loop
inside a create. It unlinks unreferenced cache entries and nothing else: it
never reclaims a retained VM directory (that is an `rmtree`, which belongs in
the reconciler's worker thread), so what it cannot free it refuses and leaves
to the next pass. And it evicts nothing at all unless the live set can be
trusted: a pass publishes the live set only when both halves agree (the
registry and a supervisor that answered `list_vms`), and admission additionally
requires that every hash in it has a registry record, since a live VM without a
message means the referenced set is incomplete. Before the first pass there is
no live set, so admission evicts nothing and simply admits or refuses on the
budget as it stands.

A pass is not the only thing that changes the published set: `retire_vm` drops
the VM it retires from it, right where it forgets the registry record. The two
halves have to move together, and under `reap` no pass follows a retire, so a
hash left behind would read as a live VM with no record until the next periodic
pass (an hour by default) and stop admission evicting for that whole window. A
retire never turns an unset live set into an empty one: only a pass may say
that nothing is live.

### Settings

| Setting | Default | What it does |
|---------|---------|--------------|
| `VOLUME_RETENTION` | `reap` | `reap` purges a `GONE` VM's volumes at once; `keep` retains them |
| `VOLUME_RETENTION_BUDGET` | `10%` | Cap on reclaimable bytes per pool (percentage or absolute, e.g. `50G`) |
| `VOLUME_RECONCILE_INTERVAL` | `3600` | Seconds between periodic passes |
| `VOLUME_CREATE_GUARD` | `600` | Seconds a young directory or `.part` file is assumed to be an in-flight create |
| `CACHE_BUDGET` | `20%` | Cap on each download cache (runtime, code, data, message) |
| `UNKNOWN_LENGTH_RESERVE` | `2G` | Room held for a download whose response carries no `Content-Length` |

`keep` is not a promise of "forever": reclaimable disks are unpaid storage,
and an attacker does not need to stop paying to create them (create, forget,
repeat). It means "kept as long as the budget and live demand allow, oldest
goes first", which is the only promise a node can honestly sell.

### CLI

Storage is agent-side and readable from the filesystem plus the agent DB, so
`aleph-vm storage ...` (`src/aleph/vm/agent/storage_cli.py`, registered as a
subparser on `agent/cli.py`'s own parser, which points at `storage --help`
in its `--help` epilog) needs no running *agent process*:

- `storage status`: per pool, live / reclaimable / cache / free bytes
  against the budgets. Read-only, registry live set only. A figure this
  process could not measure prints `unknown`, never `0 B`: the free space and
  the budget of a pool whose filesystem cannot be stat'ed (a mountpoint that
  went away, a directory this user may not read) would otherwise be
  indistinguishable from a pool that is genuinely full, which is the state an
  operator runs this command to find. The cache budget is a share of the
  filesystem holding the cache root, so it says `unknown` for the same
  reason. A budget under `VOLUME_RETENTION=reap` is a real zero and prints
  as one.
- `storage list [--reclaimable]`: hash, pool, size, reason, age. The reason
  is the marker's for a reclaimable directory; an unmarked directory reads
  `live` when the registry knows its hash and `unmarked` otherwise (an
  orphan no pass has reached yet is not a live VM). Read-only, registry
  live set only.

  Read-only here is literal, and it took work to make it so, because three
  writes were hiding under a listing. `settings.setup()` makes every
  configured directory, so the two verbs skip it entirely and refuse a
  missing database before it would have run (an operator who mistyped the
  execution root used to get the refusal and a tree of empty directories at
  the typo; nothing these verbs read needs `setup()`, since every path is
  derived when the settings object is built). `setup_pools()` adopts a pool
  on first sight, writing the in-pool marker and the adoption registry, so
  they call it with `read_only=True`: it still validates and classifies, and
  still refuses a pool whose marker vanished after adoption, but it adopts
  nothing (on a node whose second disk is not mounted, adopting that path is
  precisely the write the guard exists to prevent). And a `.reclaimable`
  marker that does not parse is read with `repair=False`: removing it is the
  reconciler's repair, a listing that unlinks a file is not read-only, and
  the unlink raises for an operator without the agent's privileges, which
  cost the whole command rather than that one row. The one write they do
  make is the schema migration of a database that is already there, without
  which the registry cannot be read at all.
- `storage reclaim <hash> [--trust-registry]`: purge one reclaimable
  directory now. Checks the name and the `.reclaimable` marker first, purely
  locally, so a typo or an unrelated hash fails instantly rather than
  waiting on a probe or a dial that could only ever confirm what those
  checks already know; a name that is not a VM hash (a hand-made marker
  under `backup_old`) and a directory with no marker (it may belong to a
  live VM) are refused the same way. Then refused outright (exit 3) while
  the agent may be running, for the reason `reconcile` is: a marked
  directory is not safe to purge merely because it is marked, since a
  create adopts one by clearing its marker. Then refuses a hash the agent
  registry or the supervisor considers live, and refuses without
  `--trust-registry` when the supervisor cannot be asked. The marker is
  read once more immediately before the purge: a re-create adopts its
  retained directories by clearing their markers, and one that started
  while the supervisor was being asked is in no answer this process holds,
  so the second read is what keeps the purge off the disks a create is at
  that moment building on. Finally, if the purge itself leaves a directory
  behind, reclaim names each one with the reason `purge_vm_storage` gives
  for it and exits non-zero rather than claiming success. There are two
  such reasons and they need different answers: a live device-mapper target
  holding the volumes (the guard `purge_vm_storage` always applies), which
  is freed by tearing that target down, and the removal itself failing (a
  read-only filesystem, an immutable file, a directory this user may not
  write), which no teardown fixes. Only the first sends the operator to
  `storage reconcile`, which is the CLI path that tears devices down, for
  every VM nothing owns; `reclaim` never does it itself.
- `storage reconcile [--dry-run] [--trust-registry]`: run one
  `reconcile_storage()` pass. Two processes decide what it may do, and they
  are not the same one. The **agent** is this Python service
  (`aleph-vm-agent`, bound to `SUPERVISOR_HOST`/`SUPERVISOR_PORT`); it owns
  the reconciler and the creates. The **supervisor** is the Rust daemon that
  runs the VMs and answers `list_vms`. Either can be up without the other,
  and the state an operator needs this command for is exactly the awkward
  one: VMs running under a healthy supervisor while the agent is down or
  will not start. Hence three states:
  - **The agent is running, or cannot be ruled out as running.** A real pass
    is refused (exit 3, the reason on stderr, nothing written). The set of
    creates the agent has in flight is in-process state this command cannot
    see, so a create that outlives `VOLUME_CREATE_GUARD` before its DB
    record exists (a long migration import routinely does) would read as an
    orphan here, and a CLI pass holds no lock against the agent's own. The
    agent runs that pass itself at startup, periodically and after every VM
    goes away, and it sees the creates too, so there is nothing here for a
    CLI pass to add. `--dry-run` is still allowed and is how a running node
    is inspected; it says on stderr that what it lists may include a
    directory the agent is at that moment creating.
  - **The agent is down and the supervisor answers.** The full pass runs.
    Nothing is being created, so the age of the directory is a sound guard
    again, and the live set is a known one (registry union `list_vms`), so
    `_teardown_orphan_devices` removes the dm devices of every namespace no
    live VM owns before the walk, or the purge that follows would be refused
    on a volume file a target still holds.
  - **The supervisor does not answer.** The live set is the registry alone,
    which is not a safe one, so the pass runs dry, warns on stderr and exits
    3 unless `--trust-registry` says to proceed on the registry's word. No
    device is torn down on that path, `--trust-registry` included: it buys a
    purge on the registry's word, not a teardown, and removing the device of
    a VM that is merely unlisted takes that VM's disk with it.
  After the pass, and printing what it removed (or, under `--dry-run`, what
  it would remove), it tears down the devices of any evicted runtime cache
  parent the same way `reconcile_now` / `reconcile_at_startup` do
  (`remove_parent_device` per evicted ref, then `sweep_leaked_cache_loops`),
  so an evicted entry never leaves `/dev/mapper/<ref>` and its loop device
  pinning the deleted inode.

Both purge paths call the daemon's own `_startup_refusal` rather than
restating its conditions, so a CLI pass and a daemon pass cannot drift
apart: an empty registry while the supervisor runs VMs means the agent DB
was lost, and both refuse on that alone (exit 3, not 1: nothing about the
hash or the node's disks is wrong, the command simply may not run here).

Both "is it running" questions are answered fail-closed, and neither claims
more than it can back up. The **agent** is called stopped only when nothing
accepts a connection on its bind address; that is a loopback connect with a
2 s timeout, it needs no privileges and no unit name, and anything listening
there counts as the agent. A wildcard bind (`0.0.0.0`, `::`, empty) is
probed on *both* loopbacks and called stopped only when both refuse, because
asyncio's `create_server` sets `IPV6_V6ONLY` on an `AF_INET6` socket: an
agent bound to `::` accepts on `::1` and refuses on `127.0.0.1`, so a probe
that asked only the IPv4 loopback would call a running agent stopped and
purge behind it. An address family the kernel cannot reach at all
(`EAFNOSUPPORT`, `ENETUNREACH` and friends) counts with the refusals, since
nothing can be serving on a loopback that is not there. A probe that fails
any other way (a name that does not resolve, a socket this user may not
open, the timeout) leaves the agent possibly running, and the refusal
stands: being wrong that way costs an operator one refused command, being
wrong the other way deletes the disks of a VM mid-create. The **supervisor**
is called *down* only when *its own socket* is missing (`os.stat`, not
`Path.exists()`, which turns a stat this user may not make into a plain
False) or refuses a connection. A refused connection in the dial's exception
chain counts too, but a missing *file* there does not: the client opens more
than its socket, and only a stat of the socket path can tell a stopped
daemon from a running one that tripped over something else. Every other
failed dial (a socket this user may not open, the 3 s deadline, a reply that
does not parse) leaves the daemon's state unknown. The difference is what the
operator is told: the exception class and message always, and the advice to
pass `--trust-registry` only when the daemon is verified down, since on
anything else it would invite exactly the purge the supervisor union exists
to prevent. An explicit `--dry-run` is told its preview is registry-only
instead, having asked for nothing that could be downgraded.

Every verb writes what it found or achieved (the status table, the listing,
the reconcile report, the "Purged ..." line) to stdout, and every warning,
refusal and diagnostic to stderr, `reclaim` included: a wrapper parses one
stream without filtering the other, and a refusal leaves stdout empty rather
than mixing a reason into a report that does not exist. The verbs take both
streams as arguments, so the tests read them apart without capturing the
process's own.

`--trust-registry` remains the sharpest tool here even so, and the narrow
advice does not blunt it: a supervisor that is verifiably down has not
necessarily stopped its VMs (a supervisor process that dies leaves its QEMU
processes running), so purging on the registry's word can still delete the
disks under a live VM whose registry record was lost. It is the flag for an
operator who knows what the node is doing, not a way to get past a warning.

Running with no agent process also means setting the process up the way the
systemd units set it up for the daemon, which the CLI does before it reads
anything:

- **Configuration.** `EnvironmentFile=/etc/aleph-vm/supervisor.env` in the
  units is what gives the daemon its settings; nothing gives them to an
  operator's shell, and pydantic reads only the process environment and a
  `.env` in the working directory. The CLI therefore loads that file itself
  (`--env-file`, else `$ALEPH_VM_ENV_FILE`, else the packaged path) and
  rebuilds the settings singleton from it, logging which file it used or
  that there was none. The file is read without `${}` expansion, the way
  systemd's `EnvironmentFile=` reads it, so the CLI sees exactly the value
  the daemon sees and a secret containing a dollar sign is not silently
  truncated. Values already in the environment win, so a one-off
  override on the command line still works, and a `--env-file` that does
  not exist is an error rather than a silent fall back to the defaults: a
  pass run with `VOLUME_RETENTION` at its `reap` default on a node
  configured to keep would evict every retained directory.
- **Logging.** Most of what a pass has to report it reports through the
  logger the reconciler, the purge and the marker already write to, so the
  CLI configures a stderr handler at `INFO` (`--loglevel`, or the agent
  CLI's own `-v` / `-vv` / `--loglevel` placed before the verb). Without it
  those lines are dropped and warnings arrive as bare last-resort lines.
- **Database.** `cli.initialise_database()` (the tables, then the alembic
  migrations) is shared with the daemon's startup and runs before the
  registry is rehydrated: an unmigrated or absent database otherwise fails
  with a raw sqlite error. `status` and `list` are the exception; being
  read-only, they refuse a database that does not exist and exit `1` rather
  than create an empty one, so an operator pointed at the wrong execution
  root sees the mistake instead of an empty listing. That refusal is the
  first thing they do, before the configuration is turned into directories
  and before the pools are set up, so the wrong execution root is reported
  rather than created.

`reconcile` and `reclaim` can purge, so they apply the same fail-closed rule
`reconciler._startup_refusal` applies to the daemon's own startup pass: a
live set built from the registry alone purges the disks of VMs the
supervisor still runs, since a fresh or partly-lost agent DB rehydrates into
an incomplete registry (this was PR A's Critical 1). A CLI process holding
only the registry is exactly that state, so both commands dial the
supervisor over the same gRPC socket the agent uses
(`settings.SUPERVISOR_GRPC_SOCKET`, a few seconds' timeout) and union its
`list_vms()` answer into the live set (`reconciler.supervisor_hashes`, the
same id-to-hash mapping the daemon pass uses). When the supervisor cannot be
reached and an explicit `--dry-run` was not requested, `reconcile` still
runs as a dry run (a preview, nothing removed) but treats this as an error:
it prints a warning to stderr (`"registry-only"`, not `"trusted"`: the
report on stdout stays parseable, uninterrupted by the warning) and exits
`3` (not `2`, which argparse uses for a usage error, so a wrapper script
can tell the two apart), unless `--trust-registry` says to purge on the
registry alone. An
explicit `--dry-run` always stays exit `0`, whether or not the supervisor
answered: nothing was silently downgraded, the caller asked for a preview
and got one. `reclaim` refuses outright unless `--trust-registry` is given.
`status` and `list` are read-only and never dial the supervisor.

Neither command can see a create the daemon is in the middle of:
`reconciler.is_creating()` is in-process state of the running agent, so a
CLI invocation (a separate process) never sees it. What protects such a
create from the CLI is the age of its directory alone: the directory purge
and the orphan-device teardown (`orphan_device_namespaces`) both skip a
namespace whose directory is younger than `VOLUME_CREATE_GUARD`. The
registry record reaches the DB only once the VM runs and `list_vms`
answers only once `create_vm` returned, so a create that has outlived the
guard before either happened looks exactly like an orphan to a real
`reconcile` run from the CLI, which can then remove its directory and its
devices out from under the daemon. A CLI pass also holds no lock against
the daemon's own passes (`_pass_lock` is in-process too) and can run
concurrently with one; that is benign, since purges are idempotent and
tolerate a directory that vanished mid-pass and markers are written
exclusively, but it is one more reason to prefer the daemon's pass.
`reconcile --help` says so; the daemon's own pass (startup, periodic,
at-GONE) is preferred whenever the daemon is up, and this command is mainly
for when it is not.

### First start on an existing node

The first pass on an upgraded node finds every directory leaked by the bugs
this machinery fixes, as an orphan. Under `reap` that is a one-shot cleanup
of potentially a lot of data, so the startup hook runs a dry pass first and
logs what it is about to remove, once as a total and once per pool
(count and bytes), before the real pass runs. An operator reading the log
can then explain why free space jumped. Under `keep` those directories
become reclaimable with `reason: orphan` and fall under the budget instead.
The startup hook is registered after registry rehydration on purpose: a
pass against an empty registry would call every running VM an orphan.

## Key invariants

- `PERSISTENT_VOLUMES_DIR` is always pool index 0 and is always VM-eligible
  even when detected as rotational; every other HDD-classed pool is rejected
  outright (`src/aleph/vm/storage_pools.py`).
- A registry-recorded pool (`volume-pools.json`) whose `.aleph-vm-pool`
  marker is missing is a hard startup failure, never a silent skip, because
  that state means the disk is very likely unmounted
  (`src/aleph/vm/storage_pools.py`).
- Writable Firecracker volumes are pinned to pool 0 at placement time
  (`pool0_only=True`); the jailer's hardlink-becomes-copy behavior across
  filesystems would otherwise silently lose guest writes on any other pool
  (`src/aleph/vm/storage.py`, `src/aleph/vm/agent/vm/downloader.py`).
- A volume's pool assignment is never persisted in a database; it is found
  by scanning `{pool}/{namespace}/` in pool index order, and a fresh
  placement lands on whichever eligible pool currently has the most free
  bytes (`src/aleph/vm/storage_pools.py`).
- Disk admission checks aggregate free space and, separately, that the
  single largest requested volume fits the roomiest eligible pool, since no
  pool splits a volume across disks (`src/aleph/vm/agent/capacity.py`).
- Reclaimable bytes are advertised as free, not as used, in every disk figure
  the agent reports (aggregate, largest single volume, advertised capacity),
  and a placement that does not fit evicts them (oldest first) before it is
  refused (`src/aleph/vm/agent/capacity.py`,
  `src/aleph/vm/agent/resources.py`, `src/aleph/vm/storage_pools.py`).
- A cache entry a live VM's message names is never evicted, and a parent
  image whose device-mapper device still has holders is never evicted; both
  questions fail closed when they cannot be answered
  (`src/aleph/vm/agent/vm/cache.py`).
- Every agent-side deletion goes through `retire_vm` with an explicit
  reason; nothing else under `src/aleph/vm/agent/` calls
  `supervisor.delete_vm` (`src/aleph/vm/agent/vm/retire.py`).
- The reconciler never removes a directory whose hash is live in the agent
  registry or listed by the supervisor, is in the in-process creating set,
  or whose mtime is inside `VOLUME_CREATE_GUARD`
  (`src/aleph/vm/agent/vm/reconciler.py`).
- The Rust supervisor daemon never selects, adopts, or writes to a pool; it
  only re-validates `VOLUME_POOLS` and sums free bytes for host-info
  reporting. All placement is agent-side
  (`rust/crates/supervisor-daemon/src/config.rs`,
  `rust/crates/supervisor-daemon/src/host.rs`,
  `src/aleph/vm/storage_pools.py`).
- `BACKUP_DIRECTORY` and `CACHE_ROOT` are independent settings outside the
  volume-pool model; only rootfs and persistent-volume placement goes
  through `VOLUME_POOLS` (`src/aleph/vm/conf.py`).
- Cold-migration export only picks up `*.qcow2` files in a VM's namespace
  directories, so it currently exports the QEMU rootfs overlay only; ext4
  and devmapper/btrfs extra volumes are not part of an export
  (`src/aleph/vm/agent/migration/runner.py`).

## Pointers into code

- `src/aleph/vm/storage_pools.py`: pool parsing, media-class detection,
  adoption marker/registry, placement (`select_pool`, `find_existing_volume`,
  `volume_path_for`), and capacity helpers (`pools_disk_usage`,
  `eligible_pool_free_bytes`).
- `src/aleph/vm/conf.py`: `VOLUME_POOLS`, `PERSISTENT_VOLUMES_DIR`,
  `CACHE_ROOT`, `BACKUP_DIRECTORY` settings.
- `src/aleph/vm/storage.py`: rootfs/runtime/code/data download and cache
  resolution, `create_ext4`, the devmapper chain (`create_devmapper`,
  `create_loopback_device`, `create_mapped_device`).
- `src/aleph/vm/host_volumes.py`: the shared, hypervisor-neutral extra-volume
  resolution (`host_volumes_from_message`) used by both downloaders.
- `src/aleph/vm/agent/vm/downloader.py`: `QemuDownloader` and
  `ProgramDownloader`, including the qcow2 overlay builder
  (`_make_writable_volume`) and the `pool0_only` wiring for Firecracker.
- `src/aleph/vm/agent/capacity.py`: `CapacityManager.check_capacity` and the
  disk-admission checks.
- `src/aleph/vm/agent/vm/retire.py`: `retire_vm` and `RetireReason`, the one
  way a VM's storage is released.
- `src/aleph/vm/agent/vm/reclaimable.py`: the `.reclaimable` marker
  (`mark_reclaimable`, `adopt`, `iter_reclaimable`, `reclaimable_bytes`) and
  the one enumeration of the cache entries a message names
  (`iter_content_refs`, `refs_from_content`, `depends_on_from_content`).
- `src/aleph/vm/agent/vm/cache.py`: the cache budget, LRU eviction
  (`evict_caches`), the download admission hook (`admit_download`) and the
  parent image's device teardown (`remove_parent_device`).
- `src/aleph/vm/agent/vm/reconciler.py`: `reconcile_storage`, the create
  guard (`creating`), the evictor (`make_room`) and the startup/periodic
  hooks the agent registers in `src/aleph/vm/agent/supervisor.py`.
- `src/aleph/vm/agent/resources.py`: `about_system_usage`'s pooled disk
  figures.
- `rust/crates/supervisor-daemon/src/config.rs`: `VOLUME_POOLS`/`MediaClass`
  parsing on the daemon side (validation only, no placement).
- `rust/crates/supervisor-daemon/src/host.rs`: `available_disk_bytes_pooled`
  for `GetHostInfo`.
- `rust/crates/supervisor-daemon/src/cloudinit.rs`: the cloud-init seed image
  builder, and the byte-compared fixtures under `rust/crates/supervisor-daemon/tests/fixtures/cloudinit/`
  that pin its parity with the deleted Python builder.
- `src/aleph/vm/agent/migration/runner.py`,
  `src/aleph/vm/agent/migration/helpers.py`,
  `src/aleph/vm/agent/migration/reaper.py`: cold-migration export/import and
  orphan-artifact cleanup.
