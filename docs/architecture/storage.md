# Storage

> Verified against: b2b31381 (2026-08-14)

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
size is known) that the largest requested volume alone fits
`roomiest_pool_free_bytes()`, the emptiest eligible pool. The second check
exists because a volume never spans pools: an aggregate-only check would
happily admit, say, a 900 GiB volume onto two half-full 500 GiB disks and
then fail at creation time. Either check failing raises
`InsufficientResourcesError`.

The Rust supervisor daemon does none of this pool selection or admission
work. It parses `VOLUME_POOLS` (`config.rs`) with the same validation rules
purely so a configuration the agent would refuse to boot on also fails
daemon startup, and it exposes `available_disk_bytes_pooled`
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
4. A writable, pool-placed btrfs-formatted volume file
   (`create_volume_file`, `.btrfs` suffix, sized via `fallocate`), loop-mounted.
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
byte-for-byte-equivalent port of the Python builder
(`src/aleph/vm/supervisor/controllers/qemu/cloudinit.py` plus the
`build_cloud_init_drive` half of the legacy `qemu_build.py`): both write a
`#cloud-config` user-data document (network addresses derived from the VM's
tap assignment, see [`networking.md`](networking.md)), a netplan v2 network
config keyed on the `virtio_net` driver, and a JSON instance-id/hostname
metadata document, then shell out to `cloud-localds` to assemble the seed
ISO. The Rust port emits JSON instead of YAML for the user-data body (JSON
is a YAML subset, so `cloud-init` parses both into the same structure); a
conformance suite asserts the parsed result matches, not the raw bytes.
Confidential (LUKS-encrypted) instances get extra `bootcmd` entries
(`growpart` + `cryptsetup resize` + `resize2fs`) ahead of cloud-init's own
resize modules, since cloud-init's `growpart` alone cannot resize a LUKS
container, and they skip installing the QEMU guest agent.

### Cold migration: export and import artifacts

Moving a running QEMU instance to another node is agent-side and disk-only,
distinct from the supervisor-owned backup/restore mechanism in
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
  `roomiest_pool_free_bytes`).
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
- `src/aleph/vm/agent/resources.py`: `about_system_usage`'s pooled disk
  figures.
- `rust/crates/supervisor-daemon/src/config.rs`: `VOLUME_POOLS`/`MediaClass`
  parsing on the daemon side (validation only, no placement).
- `rust/crates/supervisor-daemon/src/host.rs`: `available_disk_bytes_pooled`
  for `GetHostInfo`.
- `rust/crates/supervisor-daemon/src/cloudinit.rs` and
  `src/aleph/vm/supervisor/controllers/qemu/cloudinit.py`: the cloud-init
  seed image builders (Rust and Python).
- `src/aleph/vm/agent/migration/runner.py`,
  `src/aleph/vm/agent/migration/helpers.py`,
  `src/aleph/vm/agent/migration/reaper.py`: cold-migration export/import and
  orphan-artifact cleanup.
