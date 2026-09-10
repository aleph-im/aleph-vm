# Reclaiming VM storage on a CRN

Before 2.1 nothing on a node gave disk space back: a VM that went away left
its volumes behind, and the download caches grew without a bound. 2.1 adds a
retention policy for the disks of VMs that are gone, budgets for the caches,
a background reconciler that enforces both, and the `aleph-vm storage`
command to inspect and drive it by hand.

## What happens to a VM's disks

A VM's volumes are removed only when the node knows the VM will not come
back: its message was forgotten or removed, its payment stopped, the
scheduler deallocated it, or a migration handed it over. A restart, a
reboot, an amended message, an idle reap or a crash is not that, and leaves
the volumes alone.

For a VM that is gone for good, `VOLUME_RETENTION` decides:

- `reap` (the default) deletes the volumes immediately.
- `keep` leaves the directory on disk and writes a `.reclaimable` marker in
  it, so the same VM can be re-created against its data. Retained
  directories are unpaid storage, so they are capped per pool by
  `VOLUME_RETENTION_BUDGET` and evicted oldest first once the cap is
  reached. `keep` therefore means "kept as long as the budget and live
  demand allow", not "kept forever".

One behaviour changed from 1.x: a payment shortfall (the held balance, the
credit balance or the stream no longer covering the VM) is a stopped
payment, so the VM is gone for good and, under the default `reap`, its
volumes are purged at once. 1.x kept the record and the disks for a later
top-up and then never reclaimed them. A node that wants to offer a
re-paying owner a grace period runs `VOLUME_RETENTION=keep`: the marker
carries the owner address, and a re-created VM adopts its retained
directory untouched.

The reconciler also removes what no VM owns at all: directories on a pool
that belong to no VM (orphans left by older releases), interrupted downloads
(`.part` and `.tmp` files older than the create guard), stale session and
staging directories, empty `/mnt` mount points, and expired backups. It then
brings each download cache (runtime, code, data, message) under
`CACHE_BUDGET`.

Passes run at agent startup, every `VOLUME_RECONCILE_INTERVAL` (jittered
across the fleet), after a VM is retired, and when a create needs room. The
first pass on an upgraded node finds everything older releases leaked, so
under `reap` it logs a dry preview of what it is about to remove, as a total
and per pool, before removing it. That log is the explanation for a large
jump in free space right after the upgrade.

## Settings

All of these go in `/etc/aleph-vm/supervisor.env` with the `ALEPH_VM_`
prefix, for example `ALEPH_VM_VOLUME_RETENTION=keep`.

| Setting | Default | What it does |
|---------|---------|--------------|
| `VOLUME_RETENTION` | `reap` | `reap` deletes a gone VM's volumes at once, `keep` retains them |
| `VOLUME_RETENTION_BUDGET` | `10%` | Cap on retained bytes per volume pool: a percentage of the pool, or an absolute size such as `50G` |
| `VOLUME_RECONCILE_INTERVAL` | `3600` | Seconds between periodic reconciler passes |
| `VOLUME_CREATE_GUARD` | `600` | Seconds a young directory or `.part` file counts as an in-flight create and is left alone |
| `CACHE_BUDGET` | `20%` | Cap on each download cache (runtime, code, data, message): a percentage of the filesystem holding it, or an absolute size |
| `MAX_RUNTIME_ARCHIVE_SIZE` | `107374182400` (100 GiB) | Largest runtime or instance base image the node will download. A download whose `Content-Length` exceeds it is refused before the file is opened, and one that grows past it is aborted mid-stream |

`MAX_PROGRAM_ARCHIVE_SIZE` and `MAX_DATA_ARCHIVE_SIZE` (10 MB each) work the
same way for program code and data archives.

Both budget settings are validated at startup, so a typo fails the agent
immediately rather than at the first pass.

## The `aleph-vm storage` command

Storage is agent-side and readable from the filesystem plus the agent
database, so these verbs need no running agent process. That is the point:
the case they exist for is a node whose agent is down or will not start
while the supervisor daemon under it keeps running VMs.

```
aleph-vm storage status
aleph-vm storage list [--reclaimable]
aleph-vm storage reclaim <vm_hash> [--trust-registry]
aleph-vm storage reconcile [--dry-run] [--trust-registry]
```

- `status`: two tables. One row per volume pool (`POOL`, `LIVE`,
  `RECLAIMABLE`, `BUDGET`, `FREE`), then one row per download cache root
  (`CACHE`, `USED`, `BUDGET`). A figure the command could not measure prints
  `unknown`, never `0 B`, so a pool whose filesystem cannot be read is never
  mistaken for a pool that is full.
- `list [--reclaimable]`: hash, pool, size, reason and age for every VM
  directory on every pool. `--reclaimable` narrows it to the directories no
  VM owns. A directory reads `live` when the registry knows its hash, the
  marker's reason (`gone` or `orphan`) when it is marked, and `unmarked`
  otherwise: an orphan no pass has reached yet is not a live VM.
- `reclaim <vm_hash>`: purge one reclaimable directory now. The hash must
  name a VM and its directory must carry a `.reclaimable` marker; anything
  else is refused. If the purge leaves files behind, the command names each
  one with the reason and exits non-zero rather than reporting success.
- `reconcile [--dry-run]`: run one full reconciler pass, the same one the
  agent runs on its own.

`status` and `list` are read-only in the literal sense. They do not create
the agent database, do not create any configured directory, and do not adopt
a storage pool. An operator who mistypes the execution root gets a refusal,
not an empty listing and a tree of empty directories at the typo, and a node
whose second disk is not mounted does not get that mountpoint adopted as a
pool. The one write they make is the schema migration of a database that
already exists, without which the registry cannot be read at all.

### Configuration for a hand-run command

The systemd units hand the daemon its configuration with
`EnvironmentFile=/etc/aleph-vm/supervisor.env`; nothing hands it to an
operator's shell. The command therefore loads that file itself before it
reads any setting, so a pass on a node configured with
`VOLUME_RETENTION=keep` is not run against the built-in `reap` default. The
file it uses is `--env-file`, else `$ALEPH_VM_ENV_FILE`, else
`/etc/aleph-vm/supervisor.env`. Values already in the environment win, so a
one-off override on the command line still works. A file the operator
named, by `--env-file` or by `$ALEPH_VM_ENV_FILE`, that does not exist is an
error (exit 1) rather than a silent fall back to the defaults, since running
on the defaults an operator was trying to override is worse than refusing;
only a missing file at the default path is logged and the command continues
on the process environment alone. It logs which file it used either way.

Everything a verb found or achieved goes to stdout, and every warning,
refusal and diagnostic goes to stderr, so a wrapper script can parse one
without filtering the other.

### When a purge is refused

Two processes decide what `reclaim` and `reconcile` may do, and they are not
the same one. The **agent** is the Python service (`aleph-vm-agent`), which
owns the reconciler and the VM creates. The **supervisor** is the Rust
daemon that runs the VMs. Either can be up without the other, so there are
three cases:

1. **The agent is running, or cannot be ruled out as running.** A real pass
   and `reclaim` are refused (exit 3). This process cannot see the creates
   the agent has in flight, so a long create (a migration import, typically)
   would look like an orphan here, and the agent runs the same pass itself
   anyway. `reconcile --dry-run` is still allowed, and is how a running node
   is inspected; it says on stderr that its preview may name a directory the
   agent is at that moment creating.
2. **The agent is down and the supervisor answers.** The full pass runs:
   the device-mapper targets and loop devices of namespaces no live VM owns
   are torn down first, then the walk.
3. **The supervisor does not answer.** The live set is the agent registry
   alone, which is not safe to purge on, so `reconcile` runs as a dry run,
   warns and exits 3, and `reclaim` refuses. `--trust-registry` proceeds on
   the registry's word.

Both "is it running" questions are answered fail closed. The agent is
called stopped only when nothing accepts a connection on its bind address
(on every loopback a wildcard bind could be answering on); any other probe
failure leaves it possibly running and the refusal stands. The supervisor is
called down only when its socket is missing or refuses a connection; any
other dial failure leaves its state unknown, and the command then does not
suggest `--trust-registry`.

`--trust-registry` is the sharpest tool here. A supervisor that is verifiably
down has not necessarily stopped its VMs: a daemon process that dies leaves
its QEMU processes running. Purging on the registry alone can therefore
delete the disks under a live VM whose registry record was lost. It is the
flag for an operator who knows what the node is doing, not a way to get past
a warning. It also never tears down a device: it buys a purge on the
registry's word, and removing the device of a VM that is merely unlisted
would take that VM's disk with it.

A node whose agent database was lost is refused separately, by both `reclaim`
and `reconcile`: an empty registry while the supervisor still runs VMs means
every marker on the node looks purgeable, which is exactly the state that
must not drive a purge.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success. An explicit `--dry-run` is a success: the caller asked for a preview and got one |
| 1 | The command ran and refused, or could not finish: the hash is not reclaimable, it is a live VM, an env file named by `--env-file` or `$ALEPH_VM_ENV_FILE` does not exist, `status`/`list` found no agent database, or the purge left files behind |
| 2 | Usage error (argparse), or an invalid node configuration: a value in the env file the settings refuse, named on stderr as `Invalid node configuration for <field>` |
| 3 | The pass did not run: refused because the agent may be running or its database was lost, or silently downgraded to a dry run because the supervisor could not be asked and `--trust-registry` was not given |

Exit 3 exists so a wrapper can tell "the node refused to run this" from
"the node ran it and said no" without parsing stderr.

### Recovering a directory a device still holds

A purge cannot unlink a volume file that a device-mapper target still holds.
`reclaim` reports that case by name and points at `storage reconcile`, which
is the path that tears devices down, for every VM nothing owns. A purge that
failed for any other reason (a read-only filesystem, an immutable file, a
directory this user may not write) is reported as such: no teardown fixes it.
