# SEV-SNP instances: on-node (first-boot) encryption from a generic base image

**Date:** 2026-09-02
**Status:** Design, pending review
**Author:** Olivier Desenfans
**Related:**
- `docs/plans/2026-08-18-snp-confidential-instances-design.md` (the
  pre-encrypted LUKS mode this extends; shipped in aleph-vm 2.0.1)
- `docs/plans/2026-09-02-snp-instance-cli-design.md` (the aleph-rs client;
  parallel track, gains one flag from this design)
- `docs/plans/2026-07-08-confidential-vm-protocol-design.md` (protocol)

## 1. Goal and scope

Let an owner deploy a confidential SEV-SNP instance from a **generic public
base image** (e.g. the stock Ubuntu image already in vm-images) with no
local image preparation: the guest encrypts its own rootfs on first boot.
The CRN sees the public base (which is public anyway) and never anything
written after; the owner keeps today's unlock UX on every boot.

Removes the current prerequisite that the owner LUKS-encrypts a rootfs
image locally (root shell, cryptsetup, multi-GB upload) before creating an
instance, and removes the per-owner republication of near-identical base
images.

In scope: message schema extension, agent disk layout and cmdline
instantiation, guest image first-boot branch, manifest/template rules,
client-visible contract. Out of scope (section 10): rollback detection,
authenticated (dm-integrity) encryption, non-EVM owners, TDX (the schema
field is platform-neutral and carries over).

## 2. Decisions

1. **Owner-injected passphrase, guest never generates keys.** First boot
   waits for the same owner-signed inject as the pre-encrypted mode, then
   `luksFormat`s with the injected passphrase. Every later boot is
   byte-for-byte today's luks-open path: one key model, one unlock UX, no
   key-retrieval protocol leg. Passphrase auto-generation for users who do
   not pick one is a client-only mechanism (CLI design).
2. **Base binding: whole-image sha256 in the measured cmdline.** A
   `base_sha256=<64 hex>` slot next to `owner=`. Rationale: the base is
   read exactly once in full (copy-once), so streaming sha256 equals
   dm-verity's guarantee with strictly less I/O; native STOREs are
   content-addressed by sha256, so every existing base image is usable
   today with no companion artifacts; and the instance image keeps its
   deliberately verity-free TCB. Requirement: the guest hashes the same
   byte stream it copies (section 5); separate hash and copy passes would
   be TOCTOU-vulnerable against a host that swaps device content between
   reads.
3. **Schema: `trusted_execution.rootfs_encryption`.** Optional enum field,
   `"guest"` = first-boot encryption, absent = pre-encrypted parent
   (today's mode, dump-stable). Same-block validator: requires
   `mode="sev_snp"`. Chosen over a rootfs-level flag for validation
   locality (the mode-dependent rules already live inside
   `TrustedExecutionEnvironment`, where both SDKs validate identically),
   and blast radius (`RootfsVolume` is shared by every instance message
   ever; this block is confidential-only). The enum leaves room for a
   future `"guest-integrity"` (dm-integrity) variant.
4. **Two-disk layout, guest decides the mode.** The agent attaches the
   blank persistent target and the read-only plain base on every boot; the
   guest branches on whether the target already carries a LUKS header. The
   agent stays stateless and the QEMU launch configuration is identical
   across boots.
5. **SSH keys over the attested secrets channel.** The owner's
   `authorized_keys` ride the same signed inject as the passphrase and the
   measured init installs them at first boot. Owner-signed and
   channel-bound: the CRN cannot inject a key (strictly better than the
   classic instances' cloud-init channel, which is unmeasured). The
   message-level `authorized_keys` field is rejected in guest mode so it
   cannot masquerade as a working channel.
6. **No new manifest field: per-mode manifests, widened placeholder set.**
   The first-boot mode uses its own `aleph-instance-runtime/1` manifest
   whose `cmdline_template` contains `{owner}` and `{base_sha256}`; the
   pre-encrypted manifest keeps `{owner}` only. Both manifests may point
   at the same bundle (one guest image implements both branches). The
   allowed placeholder set in the manifest models widens from `{owner}`
   to `{owner, base_sha256}`; 2.0.1 agents reject the unknown placeholder
   and fail closed, which is the intended version gate (they cannot parse
   the new message field either).

## 3. Message contract

Today (pre-encrypted): `rootfs.parent.ref` is the owner's LUKS image, the
agent builds one qcow2 overlay backed by it.

First-boot mode:

```json
"rootfs": {
  "parent": {"ref": "<plain public base STORE>", "use_latest": false},
  "size_mib": 20480,
  "persistence": "host"
},
"environment": {
  "trusted_execution": {
    "mode": "sev_snp",
    "policy": 196608,
    "runtime": "<first-boot manifest STORE>",
    "rootfs_encryption": "guest",
    "measurements": [ ... ]
  }
}
```

- `rootfs.parent.ref`: the plain base, exactly as a classic instance would
  reference it. Must be a raw ext4 filesystem image (the same object kind
  vm-images instance rootfs entries already are), not a partitioned disk
  image.
- No hash field is added: for native STOREs the file hash IS the sha256.
  The client bakes it into the measured cmdline when computing
  `measurements`; the agent instantiates the same slot from the file it
  downloaded. A CRN serving different bytes produces a different launch
  measurement, caught by attest/unlock. Same trust argument as `owner=`.
- Validators (aleph-message, mirrored in aleph-rs types):
  `rootfs_encryption` requires `mode="sev_snp"`; `authorized_keys` must be
  empty/absent when `rootfs_encryption="guest"`.

## 4. Agent and supervisor changes (aleph-vm)

`build_snp_instance_spec` grows a `rootfs_encryption == "guest"` branch:

- Disks: `[target (qcow2, no backing file, virtual size = size_mib,
  ROOTFS role, rw), base (downloaded parent file, raw, read-only, EXTRA
  role)]`. The existing pre-encrypted branch (single overlay-backed qcow2)
  is unchanged. `DiskSpec` already expresses read-only extra disks; no
  proto or daemon change is expected.
- Cmdline: instantiate the manifest template with
  `owner=<content.address lowercased>` and `base_sha256=<sha256 of the
  downloaded parent file>`. Mode/template pairing is validated both ways:
  guest mode requires a template containing `{base_sha256}`, the
  pre-encrypted mode requires one without it.
- The RA-TLS creation gate (attest endpoint must accept TCP within the
  existing window) applies unchanged; first boot waits indefinitely for
  the passphrase after that, like the pre-encrypted mode.

## 5. Guest image changes (nix/, measured)

`init-instance.sh` branches on the presence of `base_sha256=` in the
cmdline (measured, so the mode itself is attested):

**Open path (no `base_sha256=`, or target carries a completed container):**
today's behavior, unchanged: wait for injection, `luksOpen`, mount, chroot.
In first-boot mode the open path additionally requires the completion token
(below); a header without the token is treated as an incomplete or
tampered container: wipe the LUKS header and re-enter the first-boot path
(the base disk is always attached, so recovery needs no host cooperation).

**First-boot path (`base_sha256=` present, target has no LUKS header):**

1. Start the attest-agent in owner mode as today; wait for the owner
   inject. Required secret: `luks_passphrase`. Optional: `authorized_keys`.
2. `luksFormat` the target (LUKS2) with the passphrase, `luksOpen`.
3. **Single-pass verify-while-copy:** read the base device once, feeding
   the same stream to sha256 and to the opened mapper (`dd` through a
   `tee`-equivalent). Never a separate hash pass: the host backs the
   virtio device and could serve different bytes on a second read.
4. Compare the digest with the measured `base_sha256`. On mismatch: wipe
   the LUKS header (so the next boot cannot open a container holding
   unverified bytes) and power off with a FATAL serial line.
5. `e2fsck -fp` + `resize2fs` the mapper so the filesystem fills the
   container (base images are small; the disk is `size_mib`).
6. If `authorized_keys` was injected: create `/root/.ssh` (0700) in the
   mounted rootfs and write it (0600, overwrite).
7. Write the LUKS2 completion token (a `cryptsetup token` JSON entry
   recording completion and the verified `base_sha256`). Only now is the
   container considered complete; an interrupted first boot (crash
   mid-copy) leaves a token-less header, which the open path wipes and
   redoes rather than booting a partial filesystem.
8. Zeroize the passphrase copy, mount, chroot, same supervision as today.

Initrd additions: static `resize2fs`/`e2fsck` (e2fsprogs). This and the
init changes move all instance-mode measurements; nothing is published
yet, so there is no compatibility cost. `sha256sum` is already a busybox
builtin; `cryptsetup` (already present) covers format, token and header
wipe.

## 6. Client contract (aleph-rs, summarized; details in the CLI design)

- `create` gains `--base-image <ref|preset>` (vm-images presets work as-is)
  implying `rootfs_encryption: "guest"`; measurements are computed with
  `base_sha256` = the STORE file hash, no image download needed.
- `unlock` sends `authorized_keys` alongside the passphrase (same flags
  and defaults as create's SSH keys). Guard: the first unlock of a
  guest-encryption instance refuses to run without an SSH key unless
  explicitly overridden, because keys are installable at first boot only.
- Re-running unlock stays the recovery for reboots and wrong passphrases.

## 7. Trust model

- **What the CRN learns:** the public base image and everything it already
  learns in the pre-encrypted mode (ciphertext, access patterns, sizes).
  Nothing written after first boot.
- **What the CRN cannot do:** substitute the base (measured `base_sha256`,
  single-pass verify), inject SSH keys or secrets (owner-signed,
  channel-bound inject), fabricate an openable container (no passphrase),
  or boot unverified bytes (mismatch wipes the header before poweroff).
- **What the CRN can still do** (unchanged from the pre-encrypted mode):
  destroy or roll back the disk (a blank target re-triggers first boot; a
  snapshot rollback shows the owner stale state; both are state-loss
  events the owner observes, equivalent to the host's ever-present power
  to delete data), and tamper with ciphertext blocks (unauthenticated
  dm-crypt decrypts them to garbage). Rollback detection and
  `"guest-integrity"` (LUKS2 + dm-integrity AEAD, at real
  write-amplification cost) are the deferred upgrades for both modes.

## 8. Component changes and sequencing

1. **aleph-message**: `rootfs_encryption` field + validators (incl. the
   `authorized_keys` rejection). Should ride the same release window as
   the in-flight TDX schema work to avoid two ecosystem bumps.
2. **pyaleph**: aleph-message pin bump only (parse/price/store already
   generic); measurement cross-checking stays with the existing deferred
   CCN item.
3. **aleph-vm**: manifest placeholder-set widening, agent branch (disks +
   cmdline), nix first-boot init + initrd additions, golden measurement
   re-seed, conformance fixtures for the two-disk argv.
4. **Manifests**: publish the first-boot manifest (may share the bundle
   with the pre-encrypted one) once the image lands.
5. **aleph-rs**: types bump, `--base-image`, unlock `authorized_keys` +
   first-unlock guard (small delta on the CLI-design work).
6. **Scheduler**: no change (instances are placed as before; v1 pins the
   node).

Version gating is parse-level and fail-closed: a 2.0.1 CRN can parse
neither the new message field (pydantic forbids unknowns) nor the new
cmdline placeholder, so a guest-mode instance never half-launches on an
old node.

## 9. Testing

- Schema: validator matrix in aleph-message and aleph-rs (guest requires
  sev_snp, authorized_keys rejection, dump stability for absent field).
- Agent: unit tests for the disk layout and cmdline instantiation
  (mode/template pairing both ways), launch-spec goldens with two disks.
- Guest: the nix build stays deterministic; golden-measurement CI covers
  the new init. First-boot logic (verify-while-copy, mismatch wipe, token,
  interrupted-copy recovery, key install) is exercised by the testnet E2E
  scenario extension (first-boot create, unlock with keys, ssh, reboot,
  re-unlock, data persisted; negative: wrong base bytes must poweroff),
  blocked on the new SNP CRN like the rest of the E2E work.

## 10. Deferred

- Rollback detection and `"guest-integrity"` (authenticated encryption).
- Default base-image preset in vm-images for one-flag creates.
- Non-EVM owners (inherited limit of the owner-auth scheme).
- TDX: `rootfs_encryption` is platform-neutral; a TDX runtime reuses it.
- Live re-keying / passphrase rotation (owner can do it over SSH with
  cryptsetup inside the guest; no protocol support needed for v1).
