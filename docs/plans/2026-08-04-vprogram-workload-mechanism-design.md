# V-PROGRAM workload mechanism: fib-service via a measured workload volume

**Status:** design approved 2026-08-04. Supersedes the `aleph.builtin/1` baked-placeholder
workload with a real, message-delivered, attestation-bound user workload.

## Problem

A V-PROGRAM message already models a user workload (`content.workload = {ref, hash_tree,
roothash}`) and the manifest grammar reserves `{workload_roothash}` / `{verified_volumes}`
cmdline placeholders, but nothing downstream reads them. The measured guest runs a
hardcoded busybox httpd baked into the platform rootfs (`aleph.builtin/1`), which is a
test placeholder, not a mechanism. We want the fibonacci service (the aleph-cvm donor's
demo app) delivered as a real user workload through the actual mechanism, bound to
attestation.

## Approved shape (two load-bearing decisions)

1. **Message-delivered workload** (not bundled): the workload is a separate dm-verity
   ext4 volume the *message* references (`content.workload`), distinct from the runtime
   bundle. This is the real "run my code" path.
2. **Direct-exec runner** (not podman/compose): the workload volume is an ext4 whose
   well-known entrypoint the guest init execs directly. A new workload contract
   `aleph.exec/1` names this runner. fib-service is a single static-musl binary at that
   entrypoint listening on `127.0.0.1:8080`. The donor's container runner (podman /
   compose) is a deliberately deferred future `aleph.compose/1` runtime image.

## Security spine: the workload is measured

`workload_roothash` is a **measured** kernel cmdline parameter. The SEV-SNP launch
digest covers OVMF + kernel + initrd + cmdline + vCPU count + vCPU type; putting the
workload roothash in the cmdline binds the exact workload bytes (via dm-verity) into the
attestation. Consequences:

- The **measurement is per-workload**: the publisher computes it with `sev-snp-measure`
  from the fixed platform parts (OVMF/kernel/initrd/platform_roothash + cmdline_template
  + vcpus/vcpu-type) plus the workload roothash, and pins it in
  `verification.measurements[].digest`.
- A workload-less SNP launch (the existing `test_vm_snp` direct-gRPC path) must produce
  the **identical** cmdline it does today, so its pinned measurement is unchanged. All
  workload wiring is therefore **conditional on a workload being present**.

## Device / cmdline layout

```
vda = platform rootfs        (measured, roothash={platform_roothash})
vdb = platform hash tree     (force-inserted host-volume #0 by the daemon)
vdc = workload ext4          (measured, workload_roothash={workload_roothash})
vdd = workload hash tree
```
Measured cmdline (workload present):
`console=ttyS0 root=/dev/mapper/verity-root ro roothash={p} workload_roothash={w}`

## Components

Each is a reviewable increment. Increments 1-4 change the measured image and land
together (re-pin a new platform bundle); 5-6 are agent/tooling; 7 is the harness test.

### 1. fib-service port (nix)
Copy the donor's actix-web fib-service (`GET /fib/{n}` saturating u64, `GET /health`,
binds `127.0.0.1:8080`) into `nix/fib-service/`, built as a static-musl cargo binary via
crane (same pattern as `aleph-attest-agent`).

### 2. Workload volume + verity (nix)
Build an ext4 (`workload.ext4`) whose entrypoint is fib-service: a `/sbin/init` that
`exec`s the binary. `veritysetup format` (fixed salt/UUID, deterministic mkfs, like the
platform rootfs) emits `workload.ext4.verity` (hash tree) + `workload.ext4.roothash`.
This is exactly the artifact a real user would build for their own single-binary app.
Output the three files so the harness can upload them as STOREs.

### 3. Guest init (nix/init.sh)
- Parse `workload_roothash=` from `/proc/cmdline`. The regex must not also match the
  platform `roothash=` (mirror the donor's `\broothash=` guard).
- When `workload_roothash` is set: wait for `/dev/vdc` (data) + `/dev/vdd` (hash tree),
  `veritysetup open /dev/vdc verity-workload /dev/vdd <workload_roothash>`, mount ro,
  and exec its entrypoint (chroot into it or exec `/sbin/init`), instead of the baked
  httpd. Verity failure ⇒ refuse to boot (poweroff), same as the platform rootfs.
- Generalize the current hardcoded `/dev/vdb`-only hash-tree wait so the workload
  devices are handled explicitly.
- When `workload_roothash` is absent: unchanged (platform-only boot; the baked
  entrypoint remains for `test_vm_snp` and the workload-less path).

### 4. Daemon cmdline extension (Rust, `lifecycle.rs::snp_config_slice`)
Today the cmdline is `format!("...roothash={roothash}")` derived from the single
`{rootfs}.roothash` sidecar. Change: if a `{rootfs}.workload_roothash` sidecar exists,
validate it as bare hex and append ` workload_roothash={w}`. The workload disks already
flow through as `DiskRole::Extra` (→ vdc/vdd), so no disk-assembly change is needed.
**Conditional**: no workload sidecar ⇒ byte-identical cmdline ⇒ existing measurement
untouched. Sidecar-based, so the **frozen proto stays frozen** (no proto/spec field).

### 5. Python launch path (`vprogram_launch.py`)
When `content.workload` is present: `get_existing_file(content.workload.ref)` and
`content.workload.hash_tree`, attach both as `DiskRole.Extra` disks after the platform
hash tree (→ vdc, vdd), and write the `{rootfs}.workload_roothash` sidecar from
`content.workload.roothash` (hex-validated, fail-closed on mismatch/garbage). The
message schema makes `workload` required, but the launch path stays tolerant if a future
runtime declares no workload. `content.volumes` (multi-volume `verified_volumes`) is
explicitly **deferred**.

### 6. Manifest + measurement tooling (Python)
- Manifest `cmdline_template` gains a `{workload_roothash}` variant; new workload
  contract value `aleph.exec/1`. `bundle.py` grows an exec-runtime template alongside
  the existing platform-only `CMDLINE_TEMPLATE_V1`.
- A measurement helper computes the per-workload digest via the `sev-snp-measure` pip
  package (0.0.12, matching the nix pin) from (bundle OVMF/kernel/initrd +
  platform_roothash + workload_roothash + cmdline_template + vcpus/vcpu-type). This is
  what the publisher pins into `verification.measurements[].digest`.
- **Follow-up (out of scope here):** move measurement computation into aleph-rs (the
  Rust CLI) so publishing does not depend on a Python package; the pip helper is the
  transient solution.

### 7. Testnet test
The harness: builds the fib workload volume (nix output staged like the platform image),
uploads `workload.ext4` and `workload.ext4.verity` as two STOREs (→ `content.workload.ref`
and `content.workload.hash_tree`), computes the per-workload measurement, and publishes a
V-PROGRAM whose `workload` block points at them with `workload.roothash` = the volume's
roothash. Then: boot on the SNP CRN → `aleph-attest-cli` verifies the (now
workload-bound) measurement → `GET /fib/10` over the attested channel → assert `55`. This
tightens the current boot-only assertion into a full attested-execution assertion.

## Deferred (explicitly out of scope)
- `content.volumes` / `verified_volumes` (multiple positional workload volumes).
- The podman/compose runner (`aleph.compose/1`) for containerized apps.
- Measurement computation in aleph-rs (transient pip dependency for now).
- Arbitrary-language / non-single-binary workloads beyond "static entrypoint at a known
  path in the workload volume."

## Compatibility
- `test_vm_snp` (workload-less, direct gRPC): unchanged cmdline and measurement.
- The workload-less V-PROGRAM path (today's Milestone B) still boots the platform image;
  the baked entrypoint is retained as the no-workload fallback.
- The frozen supervisor proto is not modified (sidecar-based daemon change).

## Cross-repo touch points
- **aleph-vm nix/**: fib-service, workload volume + verity, init.sh, flake cmdline
  template.
- **aleph-vm Rust** (`supervisor-daemon/src/lifecycle.rs`): conditional workload roothash
  in the derived cmdline.
- **aleph-vm Python** (`agent/vprogram_launch.py`, `vprogram/manifest.py`,
  `vprogram/bundle.py`): workload disk attach + sidecar; template + measurement helper.
- **aleph-testnets**: build/upload the workload STOREs, compute the measurement, publish,
  attest, assert fib output.
