# Using multiple disks on a CRN

aleph-vm can spread VM volumes (instance rootfs overlays and persistent
volumes) across several fast disks, and use slow disks for caches.

## Fast disks (NVMe / SATA SSD): volume pools

Mount each extra disk, then declare the mountpoints in
`/etc/aleph-vm/supervisor.env`:

    ALEPH_VM_VOLUME_POOLS=["/mnt/nvme1/aleph-volumes", "/mnt/sata1/aleph-volumes=ssd"]

- The value is a JSON list. Each entry is a directory on the extra disk.
- `PERSISTENT_VOLUMES_DIR` (default `/var/lib/aleph/vm/volumes/persistent`)
  is always the first pool; existing nodes need no migration.
- The media class (`nvme`/`ssd`/`hdd`) is detected from the backing block
  device. Append `=nvme`/`=ssd` to override a wrong detection. Stacked or
  unnamed-device setups (LVM, btrfs multi-device, mdraid, ZFS, network
  filesystems) may detect as *undetectable*, which is a startup error: give
  those pools an explicit `=nvme`/`=ssd` override.
- New volumes land on the eligible pool with the most free space. A volume
  never spans pools. The capacity advertised to the network is the sum of
  all pools.
- Rotational disks (HDD) are refused as *extra* volume pools: VMs need fast
  storage. The first pool (`PERSISTENT_VOLUMES_DIR`) is the exception: on an
  HDD it only logs a warning and stays eligible, so existing nodes keep
  working unchanged.

On first use the agent writes a `.aleph-vm-pool` marker into the pool and
records the adoption under `EXECUTION_ROOT`. If the marker later disappears
(typically: the disk is not mounted), the agent refuses to start rather than
silently writing to the filesystem underneath the mountpoint.

### Firecracker programs

Writable volumes of Firecracker programs always stay on the first pool,
regardless of free space. The Firecracker jailer hardlinks drive files into
its chroot, and a hardlink across filesystems silently becomes a copy: guest
writes would land in the copy and be lost. Read-only program files (runtime,
code, data squashfs) are unaffected. Size the first pool accordingly if the
node runs many programs with persistent volumes.

### Removing a pool

Once a pool has been adopted (its `.aleph-vm-pool` marker written), the agent
refuses to start if the pool is later dropped from `VOLUME_POOLS`: the pool
holds (or held) VM volumes, and silently forgetting it would orphan them. To
really remove a pool: migrate or delete the volumes it holds, then remove the
pool's entry from `{EXECUTION_ROOT}/volume-pools.json` (default
`/var/lib/aleph/vm/volume-pools.json`).

If one pooled disk fails, only the VMs whose volumes live on it are lost;
the other pools keep serving their VMs. This is the main advantage over
LVM/RAID0 striping, which loses the whole pool with one disk. If you prefer
operating a single filesystem (LVM, btrfs multi-device, ZFS, mdraid), that
still works: leave `VOLUME_POOLS` unset and mount the pooled filesystem at
`PERSISTENT_VOLUMES_DIR`.

## Slow disks (HDD): caches and backups

HDDs must not hold running VMs, but they are fine for re-downloadable
content and backups. Point the existing settings at them:

    ALEPH_VM_CACHE_ROOT=/mnt/hdd0/aleph-cache
    ALEPH_VM_BACKUP_DIRECTORY=/mnt/hdd0/aleph-backups

`CACHE_ROOT` holds runtime/rootfs base images, program code archives,
message JSON and data volumes — all safe on slow media.
