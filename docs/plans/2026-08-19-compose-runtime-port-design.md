# aleph.compose/1 runtime port: design and contract

Date: 2026-08-19
Status: complete on `od/vprogram-compose-runtime`
Related: `docs/architecture/divergences.md` entry 64 (measured-boot Nix flake
scope, amended alongside this doc), `docs/architecture/confidential.md`
(the base `aleph.builtin/1` / `aleph.exec/1` V-PROGRAM launch path this
flavor reuses unmodified), aleph-rs PR #344 (the CLI-side `aleph.compose/1`
subset validator and fixture)

This is the contract of record for the `aleph.compose/1` runtime flavor: a
platform rootfs that boots a caller-supplied `docker-compose` stack instead
of a single executable or the no-workload builtin fallback. It documents
what is actually implemented on this branch, not a proposal; every claim
below is traceable to a specific file at a specific line, listed in the task
report that accompanies this commit.

## The `aleph.compose/1` contract

### Workload volume layout

The workload is a separate dm-verity-protected ext4 volume (the same
V-PROGRAM workload-volume mechanism `aleph.exec/1` uses), built by the
aleph-rs CLI and mounted read-only by the guest as `/mnt/workload`. Its
content convention:

- `docker-compose.yml` at the volume root.
- `images/*.tar` under the volume: OCI image archives, each loadable by
  `podman load`. At least one is required; the guest init counts loaded
  archives and powers off if the count is zero.
- Any other file in the volume is ignored. The guest init does not enumerate
  or validate anything beyond `docker-compose.yml` and the `images/*.tar`
  glob (the compose-flavor `/sbin/init` embedded in `nix/compose-rootfs.nix`
  lines 165-176, not the outer `nix/init-compose.sh`), so the archive
  filenames themselves carry no meaning; the aleph-rs CLI's own staging convention
  (`images/NNN-<sanitized-name>.tar`) is filesystem bookkeeping only, not
  part of the in-guest contract.

Images are matched to compose service references purely by what `podman
load` imports from each archive's own embedded image manifest (its `RepoTags`
or, for a digest-pinned pull, its `RepoDigests`), not by any side-channel
mapping file. The aleph-rs CLI guarantees the two agree: a registry-pulled
image is resolved to `registry/name@sha256:...` (`ContainerTool::resolve_digest`,
`crates/aleph-cli/src/container.rs` on the aleph-rs side) and the compose
file's `image:` value is rewritten to that exact digest-pinned string
(`compose::pin_images`) before the archive is saved from that same pinned
ref, so the tag baked into the archive and the tag written into
`docker-compose.yml` are identical by construction. A caller-supplied
`--image-archive IMAGE=PATH` archive is not rewritten at all: `pin_images`
maps it to itself, so the compose file keeps the caller's original tag
verbatim, and matching depends on that archive's own `RepoTags` embedding
the same tag (an operator responsibility the CLI cannot verify without
opening the tarball, an unpinned image is only refused if the caller's
`--image-archive` key does not match a compose `image:` string, not if the
inner `RepoTags` are wrong).

### Compose subset

The subset is enforced by the aleph-rs CLI at `vprogram create --compose`
time (`crates/aleph-cli/src/compose.rs` in aleph-rs), before anything is
staged, hashed or uploaded. It is closed: every service key is either
accepted, rejected with a specific reason, or an unknown-key schema error
(`#[serde(deny_unknown_fields)]` on both `ComposeFile` and `ComposeService`).

Accepted, per service: `image`, `command`, `entrypoint`, `environment`,
`depends_on`, `tmpfs`. `network_mode: host` is not merely accepted, it is
**required** on every service (a service without it, or with any other
value, is rejected with a message naming the offending service). `restart`
is accepted but ignored, with a warning explaining why: a stack that exits
powers the VM off (see Fail-closed semantics below), so a container-level
restart policy has nothing to restart into once the guest itself is gone.

Rejected, per service: `build` (nothing can be built in-guest), `volumes`
(no persistent storage in v1, use `tmpfs` for scratch space), `ports` (the
guest exposes exactly one attested endpoint, see below), `secrets` and
`env_file` (there is no unmeasured input channel: `environment` is inline
because inline is measured, an env file would hide unmeasured content),
`privileged`, `devices`, `cap_add` (no elevated container capabilities).
Rejected at the top level: `volumes`, `networks`, `secrets`, `configs`, for
the same reasons as their service-level counterparts. Every service must
declare a non-empty `image`; there is no in-guest build path to fall back
to. An unknown key present with an explicit YAML `null` value still fails
`deny_unknown_fields` the same as any other value; `serde` does not treat a
present-but-null key as absent, so "not supported" applies to unknown keys
outright regardless of the value assigned to them.

### Single attested entrypoint

Exactly one port is ever reachable from outside the VM: `tcp/8443`, served
by `aleph-attest-agent`, which reverse-proxies to `127.0.0.1:8080`
(`nix/init-compose.sh` line 351, matching the base flavor's agent
invocation byte-for-byte per the file's header comment). The guest firewall
(`setup_firewall` in `nix/init-compose.sh`, shared verbatim with
`nix/init.sh`) is a stateless nftables `input` chain with `policy drop`:
`iif "lo" accept`, `tcp dport 8443 accept`, and the ICMPv6
control-plane exceptions needed to keep IPv6 routing alive (router
advertisements, neighbor discovery, path-MTU). Nothing a compose service
binds, whether on `127.0.0.1:8080` as intended or accidentally on `0.0.0.0`
on some other port, is reachable except through that one proxy. There is no
`ports:` mechanism in the compose subset for a stack to ask for more (see
above), so this is not just a firewall default, it is the only path the
schema allows a service to be reached through at all.

### Fail-closed semantics

Fail-closed applies at two layers, the outer initramfs init and the
platform init it eventually chroots into, and every `poweroff -f` in both
was walked line by line (`grep -c "poweroff -f"` cross-checked against the
enumeration below: 14 in `nix/init-compose.sh`, 1 `fatal()` helper site in
`nix/compose-rootfs.nix`'s embedded init reused across 11 call sites there).

**Layer 1, the compose-flavor platform init** (`rootfs/sbin/init` embedded
in `nix/compose-rootfs.nix` lines 138-182) treats every setup step as
fatal: each `tmpfs`/`cgroup2` mount, the `fuse.ko` module load, the
`docker-compose.yml` presence check, every `podman load`, and the
"at least one image loaded" count all call a shared `fatal()` helper on
failure, which prints the reason and `exec`s `/bin/busybox poweroff -f`.
`podman-compose up --no-build` itself is not backgrounded or fire-and-forget:
its exit status is captured and treated as fatal too (`fatal "compose stack
exited with status $?"`), so a stack that exits, whether it crashes or exits
zero, powers the VM off rather than leaving the attest-agent proxying to a
dead upstream.

**Layer 2, the outer initramfs init** (`nix/init-compose.sh`) has 14
`poweroff -f` sites. Nine are byte-identical to `nix/init.sh` (the
`aleph.exec/1` / no-workload flavor's outer init), inherited from the
shared measured-boot prologue: no block device found for the platform
rootfs (line 136, `init.sh` line 116); the nftables firewall failing to
install inside `setup_firewall` (line 248, `init.sh` line 228); the
platform dm-verity hash-tree device (`/dev/vdb`) not appearing (line 270,
`init.sh` line 250); the platform verity mount failing (line 279, `init.sh`
line 259); `veritysetup open` failing on the platform rootfs (line 283,
`init.sh` line 263); and, once a workload volume is actually being
attached, the same four-way pattern repeated for it: the workload data
device (`/dev/vdc`) not appearing (line 301, `init.sh` line 284), the
workload hash-tree device (`/dev/vdd`) not appearing (line 305, `init.sh`
line 288), the workload verity mount failing (line 315, `init.sh` line
298), and `veritysetup open` failing on the workload volume (line 319,
`init.sh` line 302).

The remaining five are compose-specific, the same five the file's own
header comment calls out as "compose delta 1" through "5":

1. **No `roothash`** (line 290): where `init.sh`'s else-branch instead logs
   a WARNING and falls back to an unverified plain mount (`init.sh` lines
   265-273), the compose flavor treats a missing platform roothash as fatal
   outright, because a compose runtime is always measured.
2. **No `workload_roothash`** (line 325): where `init.sh` simply skips the
   whole workload block and continues platform-only when no workload is
   attached (`init.sh` line 281's `if` has no `else`), the compose flavor
   has no workload-less mode, so an absent workload volume is fatal.
3. **Workload bind-mount failure** (line 335): `mount --bind /mnt/workload
   /mnt/root/mnt/workload` has no equivalent in `init.sh` at all, since the
   exec flavor never bind-mounts the workload into the platform chroot (see
   the topology inversion below); a failure here is unique to the compose
   flavor's data-volume-as-bind-mount design.
4. **Missing or non-executable `/mnt/root/sbin/init`** (line 346): where
   `init.sh`'s equivalent platform-rootfs check is a non-fatal WARNING when
   no workload is present (`init.sh` lines 335-340, `elif`/`else`), the
   compose flavor always needs the platform `/sbin/init` (it is always the
   chroot entrypoint) and fails closed rather than warning and continuing
   into a mounted-but-inert rootfs.
5. **Guest exit** (line 361): where `init.sh` ends in a bare `wait` with no
   poweroff (`init.sh` line 346), the compose flavor waits specifically on
   the chrooted platform init's PID and powers off as soon as it exits, so
   a fatal compose-init failure (layer 1, above) and a normal or abnormal
   compose-stack exit both terminate the VM through the same
   "attested-but-empty endpoint is never acceptable" policy.

## Launch-topology inversion vs `aleph.exec/1`, and why the CRN needs no changes

`aleph.exec/1` treats the workload volume as the thing that runs: the
guest's outer init chroots directly into `/mnt/workload` and execs *its*
`/sbin/init` (a single binary, e.g. `fib-service`), with the platform
rootfs's own `/sbin/init` (a busybox httpd placeholder) used only as the
no-workload fallback (`nix/init.sh`, the "workload runs INSTEAD OF the
platform `/sbin/init`" comment). The workload volume owns the entrypoint;
the platform rootfs is not chrooted into at all when a workload is present.

`aleph.compose/1` inverts this. The platform rootfs's `/sbin/init` (the
podman/podman-compose runner in `nix/compose-rootfs.nix`) is **always** the
chroot entrypoint; the workload volume is data, never entered directly. The
outer init prepares `/mnt/root` as usual, then bind-mounts the
already-verity-verified `/mnt/workload` at `/mnt/root/mnt/workload`
(`nix/init-compose.sh` lines 328-335, "compose delta 3" in that file's
header) so the platform init can read the compose file and image archives
from inside its own chroot. Concretely: `aleph.exec/1` needs no
`/sbin/init` at all inside the platform rootfs of an exec-flavor image (it
is never entered when a workload is present); `aleph.compose/1` needs no
`/sbin/init` inside the workload volume at all (the workload volume has no
init in its layout: `docker-compose.yml` plus `images/*.tar`, see above).
Ownership of the entrypoint moves from the data volume to the platform
image between the two flavors.

This inversion is exactly why the CRN (supervisor daemon + agent launch
path) needs no code changes to support `aleph.compose/1`. Every place that
would need to know which flavor it is looking at is generic across both:

- **Disks**: `build_vprogram_spec` (`src/aleph/vm/agent/vprogram_launch.py`)
  attaches the platform rootfs (`/dev/vda`), lets the daemon force-insert
  the platform hash tree (`/dev/vdb`), then attaches
  `content.workload.ref`/`content.workload.hash_tree` as the workload data
  and hash-tree disks (`/dev/vdc`/`/dev/vdd`). The message's own
  `VerifiedWorkload` model (`aleph_message.models.execution.vprogram`) has
  no contract field at all, only `ref`/`hash_tree`/`roothash`; contract
  identity ("this is an `aleph.compose/1` workload") lives solely in the
  runtime manifest's `workload.contract`, a value the CRN launch path never
  reads or branches on. It is driven entirely by
  `content.workload.roothash` (a bare hex string, format-checked but not
  flavor-checked) and the two file refs. A grep of
  `aleph.exec`/`aleph.compose`/`aleph.builtin` across `src/` and `rust/` in
  this repo turns up seven lines total: five in
  `src/aleph/vm/vprogram/bundle.py` (the three `WorkloadSpec` constants plus
  two docstring mentions) and two in `src/aleph/vm/vprogram/manifest.py`
  (a comment and a field description, both just example contract strings,
  not code that branches on one). None of the seven is in the launch or
  lifecycle path; nothing there inspects the contract string at all.
- **Sidecars**: `_ensure_verity_sidecars` writes the `<rootfs>.roothash` and
  `<rootfs>.verity` sidecars from `manifest.boot.platform_roothash` and the
  bundle's own hash-tree member, and `content.workload.roothash` is written
  to `<rootfs>.workload_roothash` the same way for both flavors
  (`vprogram_launch.py` lines 164-250).
- **Cmdline**: both flavors' manifests use the identical
  `CMDLINE_TEMPLATE_EXEC_V1` string
  (`console=ttyS0 root=/dev/mapper/verity-root ro
  roothash={platform_roothash} workload_roothash={workload_roothash}`,
  `src/aleph/vm/vprogram/bundle.py` lines 130-145); the daemon
  (`rust/crates/supervisor-daemon/src/lifecycle.rs`, `snp_config_slice`)
  derives the measured cmdline purely from the `.roothash`/
  `.workload_roothash` sidecar files, which is the same mechanism either
  way.

The only things that differ between the two flavors are Nix-build-time
artifacts, not runtime code: which platform rootfs and initrd get baked
into the bundle (`composeRootfs`/`composeInitrd` vs `rootfs`/`initrd` in
`nix/flake.nix`), and which manifest constant the bundle tool selects
(`COMPOSE_WORKLOAD` vs `EXEC_WORKLOAD`, `src/aleph/vm/vprogram/bundle.py`).
Both draw the cmdline template from the exact same `measurementFor`
function parameterized over `initrdDrv`/`verityDrv` (`nix/flake.nix` lines
253-291), so the compose flavor's launch measurement is computed by the
same code path as the exec flavor's, just pointed at different Nix outputs.

## Image trust: why `insecureAcceptAnything` is sound here

`nix/compose-rootfs.nix` ships `/etc/containers/policy.json` as
`{"default": [{"type": "insecureAcceptAnything"}]}`, i.e. podman performs no
signature verification on any image it loads. This would be a real hole in
a general-purpose container host; it is sound here only because of two
properties that are both part of the sealed contract, not incidental:

1. **No pull path exists.** The compose-init never calls anything that
   fetches from a registry. It loads archives with `podman load -i
   "$tarball"` for each file already present in the verity-verified
   `/mnt/workload/images/` directory, and it starts the stack with
   `podman-compose up --no-build` (`nix/compose-rootfs.nix` lines 170-180),
   which both disables any local image build step and, because every image
   a compose service can reference was already loaded from local storage by
   the tag-matching guarantee above, never needs to resolve a reference
   podman does not already have. There is no `registries.conf` shipped in
   the image either, so there is no configured mirror or upstream for a
   pull to even target if one were somehow attempted.
2. **Archives ride the measured verity volume.** Every byte a `podman load`
   reads comes from `/mnt/workload`, a dm-verity volume whose root hash is
   validated against `workload_roothash` on the measured kernel cmdline
   before it is ever mounted (`nix/init-compose.sh` lines 298-326). An
   attacker who could substitute a malicious image archive would first have
   to defeat dm-verity, at which point `policy.json`'s signature check
   would have been redundant anyway: the archive's own integrity is already
   covered by the SEV-SNP launch measurement, not by an image-signing
   scheme layered on top of it.

`insecureAcceptAnything` therefore does not mean "unverified"; it means
"verified upstream, by a stronger mechanism than container image signing,
so the redundant check is skipped."

## Sizing: everything a compose stack touches lives in guest RAM

Unlike the platform rootfs, which is a verity-backed disk the guest reads
from without ever loading it wholesale into memory, container storage for a
compose stack is entirely RAM-backed. The compose-flavor platform init mounts
`/var` (and `/tmp`, `/dev/shm`) as tmpfs before starting podman
(`nix/compose-rootfs.nix`'s embedded init), and `storage.conf`'s `graphroot`
(`/var/lib/containers/storage`, where `podman load` extracts every image
layer and where each container's writable layer lives) sits under that
tmpfs. So does `runroot`. None of it is disk-backed; all of it is guest
memory, competing with whatever the running containers themselves allocate.

For scale, the platform rootfs itself (the podman/podman-compose userland,
not the workload) is approximately 702 MiB uncompressed; that part is NOT
RAM-resident, it is the verity-backed disk the kernel reads pages from
on demand. The bundle actually staged per VM under `EXECUTION_ROOT` on the
host, by contrast, is approximately 311 MB. Neither figure bounds guest RAM
usage; both are host-side disk footprints. What bounds guest RAM usage is
the workload volume's `images/*.tar` archives once `podman load` extracts
them into the tmpfs `graphroot`, plus whatever each container's writable
layer grows to, plus the working set of every process the stack runs.

The practical rule: `resources.memory` on the V-PROGRAM manifest must exceed
the sum of the workload's image archive sizes by a comfortable multiple, not
just enough to hold them once. `podman load` decompresses and extracts each
archive's layers into RAM-backed storage, so the peak during image loading
can exceed the archives' own combined size, and that peak is additive with
whatever the compose stack itself consumes once running. A stack that
exhausts guest RAM fails closed by the same mechanism as every other setup
failure in this flavor: `podman load` or the running stack gets OOM-killed
or otherwise dies, `podman-compose up`'s exit status is caught as fatal
(see Fail-closed semantics above), and the VM powers off. There is no
degraded or partial-capacity mode, and no in-band signal beyond whatever
`podman`/the kernel OOM killer prints to the serial console before the
`poweroff -f` fires: diagnosing an undersized `resources.memory` value means
reading that console log, not any structured error surfaced through the
attested endpoint.

## Publish flow

Publishing a compose runtime bundle follows the same two-step
`scripts/vprogram_bundle.py` flow as the base flavor, with one manual
detour: `cmd_build`'s automatic path is hardcoded to
`nix build ...#image` (`scripts/vprogram_bundle.py`, `BUILD_COMMAND`), so a
compose bundle's image must be built explicitly first and handed in via
`--image-dir`.

```bash
# 1. Build the compose-flavor measured image explicitly (the script's
#    automatic build path only knows about #image).
nix build "git+file://$PWD?dir=nix#composeImage" \
    --extra-experimental-features "nix-command flakes" \
    -o .local/compose-publish/image-result
```

`composeImage`'s own `measurement.hex` member is the platform-only cmdline
measurement (`composeMeasurement`, no `workload_roothash`), the same
convention `image`'s `measurement.hex` follows for the base flavor. It is
informational only, not a launchable configuration: the compose flavor has
no workload-less mode (`init-compose.sh`'s compose delta 2), so booting a
VM with that cmdline powers off immediately for a missing
`workload_roothash` rather than starting anything. Real, launchable
measurements come from `composeMeasurementFor` given the actual workload's
root hash (`nix/flake.nix`), or equivalently from the aleph-rs CLI at
`vprogram create` time once the workload volume is staged and its root
hash is known.

```bash
# 2. Package it into a bundle tarball + bundle-info.json.
python scripts/vprogram_bundle.py build \
    --image-dir "$(readlink -f .local/compose-publish/image-result)" \
    --out .local/compose-publish

# 3. Upload the bundle tarball; note the printed STORE item hash.
aleph file upload .local/compose-publish/snp-image.tar.gz

# 4. Build the manifest with the compose workload contract, using the item
#    hash from step 3 as --bundle-ref.
python scripts/vprogram_bundle.py manifest \
    --bundle-info .local/compose-publish/bundle-info.json \
    --bundle-ref <BUNDLE_ITEM_HASH> \
    --name aleph-compose-runtime \
    --runtime-version <VERSION> \
    --compose

# 5. Upload the manifest; its STORE item hash is what V-PROGRAM messages
#    pin as runtime.ref.
aleph file upload .local/compose-publish/manifest.json
```

One operational nuance for whoever runs this: `cmd_build` always records
`source.build` as the literal constant `nix build
"git+file://$REPO?dir=nix#image"` regardless of which image directory was
actually packaged (`scripts/vprogram_bundle.py`, `BUILD_COMMAND`); it is not
parameterized by flavor. A published compose manifest's `source.build`
field will therefore read `#image` even though the bundle was built from
`#composeImage`. `source.repo` and `source.rev` are correct either way (the
script always resolves them from the actual git checkout). This is a
cosmetic gap in the tooling, not a trust problem: `source` is informational
only, never a validated or measured field.

After publishing, refresh the aleph-rs fixture
(`fixtures/vprogram/compose-runtime-manifest.json`, aleph-rs PR #344) with
the real `bundle.ref`, `bundle.sha256`, `bundle.size` and
`boot.platform_roothash` from the manifest published above, then re-run its
manifest test (`the_published_compose_runtime_manifest_parses` in
`crates/aleph-sdk/src/vprogram/manifest.rs`). This is a fixture refresh, not
a schema change: the generated manifest already parses with the aleph-rs
`RuntimeManifest` type and already passes its compose gate
(`check_compose_contract` in `crates/aleph-cli/src/commands/vprogram.rs`,
which refuses `--compose` against any runtime whose `workload.contract` is
not `aleph.compose/1`), verified against this branch's actual manifest
shape. The current fixture predates this port and carries a
`bundle.members.platform_roothash_file` key inherited from the aleph-cvm
donor's manifest shape; the aleph-vm flavor documented here does not emit
that key (`BundleMembers` in `src/aleph/vm/vprogram/manifest.py` has no such
field, and the model is `extra="forbid"`) and does not need it, because the
CRN launch path never reads a roothash out of the bundle members map at
all: `vprogram_launch.py`'s `_ensure_verity_sidecars` writes the
`<rootfs>.roothash` sidecar directly from `manifest.boot.platform_roothash`.
The aleph-rs side's own `BundleMembers` does not `deny_unknown_fields`
either, so the stale key is harmlessly ignored by the parser today; the
refresh should still drop it so the fixture reflects what this repo
actually publishes.

## Out of scope

- **`content.volumes` / `verified_volumes` positional data volumes.** These
  are a generic V-PROGRAM mechanism (up to `MAX_VERIFIED_VOLUMES` extra
  read-only verity-bound disks, `--volume` on the aleph-rs CLI) orthogonal
  to the compose contract; nothing here changes how they work, and the
  compose subset's own `tmpfs:` is the only in-contract scratch-space
  primitive.
- **Persistence.** The compose subset rejects `volumes:` outright (see
  above); there is no writable storage that survives a container restart,
  let alone a VM restart.
- **Registry pulls at runtime.** Every image reaches the guest pre-resolved
  and pre-archived; see Image trust above.
- **Restart policies.** `restart:` is accepted but ignored (see Fail-closed
  semantics); a dead stack always powers the VM off, regardless of what any
  individual service's restart policy says.
- **LUKS / encrypted rootfs.** Unrelated to the compose port; remains
  excluded on this branch (`docs/architecture/divergences.md` entry 64).
- **Attested secret injection (`/confidential/inject-secret`).** The agent
  endpoint still accepts the request and writes the secret to
  `/tmp/secrets` in the outer chroot, but the path from there to a compose
  container is inert, twice over. First, `prepare_chroot`'s bind mount of
  `/tmp/secrets` into `/mnt/root/tmp/secrets` happens before the platform
  init runs, and the compose-flavor platform init (`rootfs/sbin/init`
  embedded in `nix/compose-rootfs.nix`) then mounts a fresh tmpfs over
  `/tmp` (`mount -t tmpfs tmpfs /tmp`), which shadows that bind mount:
  whatever was injected becomes unreachable at `/tmp/secrets` the moment
  the platform init starts. Second, even if that shadowing were avoided,
  the compose subset rejects `volumes:` entirely (see Compose subset
  above), so there is no mechanism by which a container in the stack could
  be given a mount path into the guest's `/tmp/secrets` in the first
  place, injected-secret delivery to a container has no expression in the
  `aleph.compose/1` schema at all. This is a deliberate v1 scope decision,
  not an oversight: a future revision that wants to support secrets in
  compose workloads must both preserve the secrets bind mount across
  compose-init's tmpfs setup (for example by mounting the fresh `/tmp`
  tmpfs and then re-creating and re-bind-mounting `/tmp/secrets` inside
  it, rather than mounting over the top of it) and define an actual
  container delivery path (a `secrets:`-shaped compose primitive, or an
  implicit bind mount into every service). Neither exists on this branch.
