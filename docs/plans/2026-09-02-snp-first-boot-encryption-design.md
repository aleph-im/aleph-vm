# SEV-SNP instances: on-node (first-boot) encryption from a generic base image

**Date:** 2026-09-02 (revised 2026-09-03: key model, delegated unlock)
**Status:** Design, pending review
**Author:** Olivier Desenfans
**Related:**
- `docs/plans/2026-08-18-snp-confidential-instances-design.md` (the
  pre-encrypted LUKS mode this extends; shipped in aleph-vm 2.0.1)
- `docs/plans/2026-09-02-snp-instance-cli-design.md` (the aleph-rs client;
  implemented in aleph-rs PR #394, gains flags from this design)
- `docs/plans/2026-07-08-confidential-vm-protocol-design.md` (protocol)
- aleph-vm PR #1190 (unlock authority = message sender; already the shipped
  contract this design builds on)

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

The 2026-09-03 revision widens the goal in two ways, driven by the threat
model in section 7bis: the volume key is no longer the injected secret
itself (**two-man keying**, section 2 decision 1 and section 5bis), so that
disk snapshots cannot be decrypted offline by anyone, ever; and unlock may
be performed by **delegates** holding an owner-signed grant (section 7ter),
staged so the owner's signing UX never changes.

In scope: message schema extension, agent disk layout and cmdline
instantiation, guest image first-boot branch, key derivation, delegation
grant checking, manifest/template rules, client-visible contract. Out of
scope (section 10): rollback detection, authenticated (dm-integrity)
encryption, non-EVM unlock keys, TDX (the schema field is platform-neutral
and carries over), the revocation freshness oracle (designed in 7ter,
deliberately deferred).

## 2. Decisions

1. **Two-man volume keying: the owner injects a share, the volume key is
   derived in-guest and never exists outside it.** (Revised 2026-09-03;
   previously: the injected passphrase was the LUKS passphrase.) At first
   boot the measured init derives
   `volume_key = HKDF(psp_sealed_key, owner_share, vm_salt)` where
   `psp_sealed_key` comes from `SNP_GET_DERIVED_KEY` (VCEK-rooted, mixing
   GUEST_POLICY and MEASUREMENT — not TCB_VERSION or host-controlled
   fields), `owner_share` is the injected secret (wire key stays
   `luks_passphrase` for protocol continuity), and `vm_salt` is a random
   public per-VM salt persisted in the LUKS2 token. Every later boot
   re-derives the same key from the same inputs. Rationale and full attack
   walk in section 5bis; the headline: a disk snapshot is undecryptable
   without the physical chip AND a genuine measured guest AND an accepted
   injection, so "former secret holder + snapshot-retaining operator" — the
   attack that defeats any passphrase-is-the-key scheme — is dead. The
   guest still never *generates* long-term key material alone: without the
   owner share the sealed key is half a key.
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
5. **SSH keys over the attested secrets channel, consumed at first boot
   only.** The owner's `authorized_keys` ride the same signed inject as
   the share and the measured init installs them at first boot. Owner-
   signed and channel-bound: the CRN cannot inject a key (strictly better
   than the classic instances' cloud-init channel, which is unmeasured).
   The message-level `authorized_keys` field is rejected in guest mode so
   it cannot masquerade as a working channel. First-boot-only consumption
   is load-bearing for delegation (section 7ter): at first boot the target
   holds no user data yet, so a rogue grant holder who wins the first-boot
   race gets a fresh copy of the public base, never existing data.
6. **No new manifest field: per-mode manifests, widened placeholder set.**
   The first-boot mode uses its own `aleph-instance-runtime/1` manifest
   whose `cmdline_template` contains `{owner}` and `{base_sha256}`; the
   pre-encrypted manifest keeps `{owner}` only. Both manifests may point
   at the same bundle (one guest image implements both branches). The
   allowed placeholder set in the manifest models widens from `{owner}`
   to `{owner, base_sha256}`; 2.0.1 agents reject the unknown placeholder
   and fail closed, which is the intended version gate (they cannot parse
   the new message field either).
7. **The unlock authority is the message sender; grants extend it.**
   (Added 2026-09-03.) The measured `owner=` slot binds the address that
   signed the INSTANCE message (shipped in aleph-vm PR #1190). Delegated
   unlock adds in-band, owner-signed grant objects (section 7ter) checked
   by the measured init; v1 ships grants without revocation, justified by
   the risk analysis there.
8. **No security-relevant guest state across reboots.** (Added
   2026-09-03.) Every unlock attempt is evaluated from scratch from the
   measured cmdline, the presented request, and (v3) a fresh oracle
   statement. Anything the guest would persist, the operator can roll
   back; anything it keeps in RAM, a power cycle resets. Designs that need
   cross-boot guest state (generation floors, revocation lists) are
   rejected on principle.

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
- Cmdline: instantiate the manifest template with `owner=<message sender,
  lowercased>` (PR #1190 semantics) and `base_sha256=<sha256 of the
  downloaded parent file>`. Mode/template pairing is validated both ways:
  guest mode requires a template containing `{base_sha256}`, the
  pre-encrypted mode requires one without it.
- The RA-TLS creation gate (attest endpoint must accept TCP within the
  existing window) applies unchanged; first boot waits indefinitely for
  the share after that, like the pre-encrypted mode.

The host never participates in key derivation: `SNP_GET_DERIVED_KEY` is a
guest-to-PSP exchange, and the KDF inputs the host can see (vm_salt in the
LUKS token) are public by design.

## 5. Guest image changes (nix/, measured)

`init-instance.sh` branches on the presence of `base_sha256=` in the
cmdline (measured, so the mode itself is attested):

**Open path (no `base_sha256=`, or target carries a completed container):**
today's behavior with the key derivation swapped in: wait for injection,
derive the volume key (section 5bis) using the `vm_salt` and `tcb_version`
recorded in the LUKS2 token, `luksOpen` with the derived key, mount,
chroot. In first-boot mode the open path additionally requires the
completion token (below); a header without the token is treated as an
incomplete or tampered container: wipe the LUKS header and re-enter the
first-boot path (the base disk is always attached, so recovery needs no
host cooperation). **A failed open — wrong share, corrupted keyslot — is
never destructive:** the init logs and waits for re-injection. Destructive
cleanup keys exclusively off copy-integrity conditions the injector cannot
influence, so a hostile grant holder can never turn the injection channel
into remote data destruction.

**First-boot path (`base_sha256=` present, target has no LUKS header):**

1. Start the attest-agent in owner mode as today; wait for an accepted
   inject (owner-signed, or grant-authorized per section 7ter). Required
   secret: `luks_passphrase` (carrying the owner share). Optional:
   `authorized_keys`.
2. Generate `vm_salt` (random, public); derive the volume key (section
   5bis); record `vm_salt` and the derivation `tcb_version` for later
   boots (step 7's token).
3. `luksFormat` the target (LUKS2) with the derived volume key as the
   keyslot secret, `luksOpen`. Add the owner-recovery keyslot (section
   5bis) wrapping the same volume key.
4. **Single-pass verify-while-copy:** read the base device once, feeding
   the same stream to sha256 and to the opened mapper (`dd` through a
   `tee`-equivalent). Never a separate hash pass: the host backs the
   virtio device and could serve different bytes on a second read.
5. Compare the digest with the measured `base_sha256`. On mismatch: wipe
   the LUKS header (so the next boot cannot open a container holding
   unverified bytes) and power off with a FATAL serial line. (This wipe is
   the copy-integrity exception noted above: it can only ever destroy a
   container holding an unverified copy of the public base, never user
   data.)
6. `e2fsck -fp` + `resize2fs` the mapper so the filesystem fills the
   container (base images are small; the disk is `size_mib`).
7. If `authorized_keys` was injected: create `/root/.ssh` (0700) in the
   mounted rootfs and write it (0600, overwrite). First boot is the only
   time this secret is consumed (decision 5).
8. Write the LUKS2 completion token (a `cryptsetup token` JSON entry
   recording completion, the verified `base_sha256`, `vm_salt`, and the
   `tcb_version` used for key derivation). Only now is the container
   considered complete; an interrupted first boot (crash mid-copy) leaves
   a token-less header, which the open path wipes and redoes rather than
   booting a partial filesystem.
9. Zeroize the share and derived key copies, mount, chroot, same
   supervision as today.

Initrd additions: static `resize2fs`/`e2fsck` (e2fsprogs); the derive-key
helper (a small static binary over the `/dev/sev-guest`
`SNP_GET_DERIVED_KEY` ioctl — the sev-guest driver is already in the
minimal kernel for `SNP_GET_REPORT`). This and the init changes move all
instance-mode measurements; nothing is published yet, so there is no
compatibility cost. `sha256sum` is already a busybox builtin; `cryptsetup`
(already present) covers format, token and header wipe.

## 5bis. Key model: two-man volume keying (added 2026-09-03)

**The problem it solves.** With passphrase-as-the-key, anyone who ever
legitimately held the passphrase can, with an operator who retains disk
snapshots, decrypt every snapshot from their era offline — no guest, no
attestation, no protocol in the loop. Rotation only protects future
writes. Under the threat model of section 7bis this is the dominant risk,
and no amount of in-guest authorization logic touches it, because it is an
offline attack.

**The construction.**

```
psp_sealed_key = SNP_GET_DERIVED_KEY(root = VCEK,
                                     mix  = GUEST_POLICY | MEASUREMENT,
                                     tcb  = tcb_version from the token,
                                            or current at first boot)
volume_key     = HKDF-SHA256(ikm  = psp_sealed_key || owner_share,
                             salt = vm_salt)
```

- `psp_sealed_key` exists only inside a genuine guest of this exact
  measurement on this physical chip; the PSP never reveals it to the
  host. Mixing MEASUREMENT binds it to the measured runtime (which
  includes the `owner=` unlock authority via the cmdline); mixing
  TCB_VERSION is deliberately avoided at the flag level — instead the TCB
  version used at format time is recorded in the LUKS token and passed to
  the derivation request on later boots (the PSP allows deriving at any
  TCB ≤ current), so platform firmware updates never orphan the disk.
- `owner_share` is what the unlock injects; the wire contract
  (`luks_passphrase` secret key, EIP-191 envelope, RA-TLS channel) is
  unchanged, only its meaning narrows from "the key" to "half the key".
- `vm_salt` separates two instances of the same unlock authority on the
  same chip; it is public (LUKS token) because HKDF salt need not be
  secret.

**Attack walk.** Operator with every snapshot and full power/disk/network
control: has neither the sealed key (PSP-held) nor the share — offline
decryption impossible. Former or rogue share holder with the snapshot
archive: same, the sealed key requires the physical chip and a genuine
guest. Share holder + colluding operator: can boot the genuine guest and
have it open the disk — which yields a running VM enforcing its own OS
authentication, not raw plaintext; this is the residual channel the
delegation rules (7ter) and the consumption-set rule (decision 5) gate.
Compromise of the chip's PSP alone yields half a key.

**Recovery keyslot.** The sealed key is chip-unique: if the CRN dies or
the instance must move, the derived keyslot is unopenable elsewhere. At
format time the init therefore adds a second LUKS2 keyslot wrapping the
same volume key to the **owner's** public key (ECIES over secp256k1, the
key the `owner=` address is derived from). The owner + the disk can always
recover offline; that is not a hole, it is what ownership means — and it
is strictly narrower than today, where *any* share holder + disk could.
The delegate share deliberately gets no recovery slot.

**Mode coverage.** Two-man keying requires the guest to perform the
format, so it applies to `rootfs_encryption: "guest"` only. The
pre-encrypted mode keeps passphrase-as-the-key and, with it, the offline
decryption exposure; this is recorded in section 7 and is a reason to
treat the pre-encrypted mode as the compatibility path once this ships.

## 6. Client contract (aleph-rs, summarized; details in the CLI design)

- `create` gains `--base-image <ref|preset>` (vm-images presets work as-is)
  implying `rootfs_encryption: "guest"`; measurements are computed with
  `base_sha256` = the STORE file hash, no image download needed.
- `unlock` sends `authorized_keys` alongside the share (same flags and
  defaults as create's SSH keys). Guard: the first unlock of a
  guest-encryption instance refuses to run without an SSH key unless
  explicitly overridden, because keys are installable at first boot only.
- Re-running unlock stays the recovery for reboots and wrong shares.
- Delegated unlock (once grants ship): `unlock --grant <file>` presents
  the owner-signed grant object alongside the delegate-signed request; the
  owner-side `delegation grant` verb produces the object (one wallet
  signature).

## 7. Trust model

- **What the CRN learns:** the public base image and everything it already
  learns in the pre-encrypted mode (ciphertext, access patterns, sizes).
  Nothing written after first boot.
- **What the CRN cannot do:** substitute the base (measured `base_sha256`,
  single-pass verify), inject SSH keys or secrets (owner-signed,
  channel-bound inject), fabricate an openable container (half a key at
  most), boot unverified bytes (mismatch wipes the header before
  poweroff), or — new with 5bis — **decrypt any snapshot offline, even in
  collusion with every current and former share holder**, because the
  volume key never exists outside a genuine guest on the original chip.
- **What the CRN can still do** (unchanged from the pre-encrypted mode):
  destroy or roll back the disk (a blank target re-triggers first boot; a
  snapshot rollback shows the owner stale state; both are state-loss
  events the owner observes, equivalent to the host's ever-present power
  to delete data), and tamper with ciphertext blocks (unauthenticated
  dm-crypt decrypts them to garbage). Rollback detection and
  `"guest-integrity"` (LUKS2 + dm-integrity AEAD, at real
  write-amplification cost) are the deferred upgrades for both modes.
- **Pre-encrypted mode delta:** without two-man keying it retains the
  "share holder + snapshots" offline exposure; documented, accepted, and
  an argument for migrating users to guest mode over time.

## 7bis. Threat model addendum: knowledge vs authority (added 2026-09-03)

The adversary is a malicious node operator giving it everything: full
control over the VM's power cycles, every historical disk version, and the
network the guest sees — plus possible collusion with compromised or
revoked delegates. Two observations structure everything above:

1. **The disk is protected by key knowledge, not by authorization
   checks.** Unlock is an *injection*: a party that does not know the
   share cannot inject it, however many grants it holds; a party that
   knows the share (under passphrase-as-the-key) needed no guest at all.
   In-guest authorization therefore gates the *channel*, and its security
   value is exactly the value of what the channel can do — which is why
   decision 5 pins the consumed-secret set and why 5bis moves the disk
   onto a key no one fully knows.
2. **Negative statements are unverifiable in-guest.** The guest cannot
   distinguish "no revocation exists" from "the revocation was withheld";
   any scheme that fetches authorization state dies to omission, and any
   guest-persisted state dies to rollback, and any RAM state dies to a
   power cycle (decision 8). Workable schemes use only affirmative,
   in-band, freshness-anchored statements.

## 7ter. Delegated unlock: grants and revocation (added 2026-09-03)

**Shipped baseline.** The unlock authority is the message sender
(PR #1190): the key that signed the deployment is the key the measured
cmdline binds. `--on-behalf-of` deployments are unlocked by the delegate
that created them; the CCN already enforced the owner's authorization of
that sender at message-acceptance time.

**v1: grants without revocation.** The injection envelope gains an
optional owner-signed grant object:

```
grant = { owner, delegate, scope: "unlock", vm?: <item hash>, sig_owner }
```

The measured init accepts a request when EITHER the EIP-191 signer equals
the cmdline authority (today's rule) OR the request carries a valid grant
from the cmdline authority to the signer. One wallet signature, once,
matching pyaleph's sign-once delegation UX. A dedicated minimal object is
preferred over presenting the owner's signed aggregate-update message:
same trust content, but parsing pyaleph aggregate semantics inside the
measured init would grow the TCB for nothing.

Ignoring revocation is a *measured* risk, acceptable because of 7bis(1).
A compromised delegate key (worst case: operator collusion) buys:

- **Not the disk**: no share, no injection; snapshots stay dead under
  5bis regardless.
- **Denial of service** on the injection channel — subsumed by the
  operator's day-one power to simply not run the VM.
- **Never data destruction**: failed opens are non-destructive by
  construction (section 5).
- **A fresh base copy at most**, if it wins a first-boot (or
  rollback-to-blank) race with its own share and SSH key: the target held
  no user data at that point, so nothing is exposed.
- **The real boundary**: any *future* secret consumed outside first boot
  (provisioning credentials, runtime-injected SSH keys) would escalate a
  compromised grant to live-VM takeover. Rule: **the consumed-secret set
  may not grow beyond `{share, first-boot authorized_keys}` until real
  revocation (below) ships.** Meanwhile, pyaleph-level revocation keeps
  its full force for everything the CCN mediates: a revoked delegate can
  no longer deploy, spend, or publish on the owner's behalf.

**v3: revocation via an authorization freshness oracle.** Rejected
designs, per 7bis(2) and decision 8: guest-fetched aggregate state
(omission), presented aggregate snapshots (staleness), generation floors
set through the attest agent (RAM, reset by reboot), owner-issued
short-expiry certs (imposes a renewal cadence on the party delegation
exists to keep offline; pre-signing batches is long expiry in disguise —
if the owner is the only issuer, revocation latency equals owner-online
cadence). The retained design keeps the owner's protocol exactly as
today (grant once, revoke in the security aggregate) and moves freshness
issuance to a small quorum of services with keys pinned in the measured
runtime image. Per unlock, the guest issues a nonce; quorum members answer
with `sig(nonce, time, "aggregate of O currently authorizes D for
unlock")`; the guest requires, say, 2-of-3 fresh statements. Nonce kills
replay, pinned keys kill forgery, and omission fails closed (no statement,
no unlock — an availability cost the operator already commands).
Revocation latency collapses to aggregate propagation. Trust accounting:
a fully compromised quorum degrades exactly to v1 (grants without
revocation), never below it — the oracle can only add. A Roughtime-style
nonce-signed time source falls out of the same mechanism, making grant
expiry fields (optional in v1's object) enforceable without SecureTSC.
Consciously deferred: it stands up new key-managed infrastructure and only
becomes load-bearing when the consumed-secret set needs to grow.

**Considered: direct on-chain verification (feasible, disproportionate).**
Managing grants in an Ethereum mainnet contract and having the guest
verify chain state directly was worked through and set aside. Forgery is
solvable (beacon light client: sync-committee signatures, then a
Merkle-Patricia proof of the contract storage slot against the verified
state root), and even the staleness attack — the operator serving a
perfectly valid *old* chain from before a revocation, which a host-fed
clock cannot detect — has a clockless fix: the guest issues a nonce, the
unlocking delegate lands it on-chain (calldata/event), and the guest
requires a proof of a nonce-bearing block, reading permission state at or
after it. A nonce cannot appear in a block minted before it existed, so
freshness comes from chain irreversibility, no trusted time anywhere.
Rejected on costs, not soundness: thousands of lines of
consensus-critical code (BLS12-381 pairings, light-client protocol, SSZ,
MPT proofs) inside the measured init versus a page of signature checks;
a weak-subjectivity checkpoint baked into the measured image — the
pinned-key problem in stricter clothing, with a harder refresh
obligation; a gas-paying transaction and inclusion latency on the
critical path of every post-reboot unlock; and owner grant/revoke UX
regressing from free aggregate updates to on-chain calls that split the
source of truth away from the security aggregate. All to harden a
channel whose total failure already degrades only to v1.

**Retained refinement: the oracle as an accountable notary.** The v3
quorum attests over a *public, append-only registry* (the security
aggregate as anchored by the message chain, or an on-chain mirror) rather
than over private state. Every statement it signs — `(nonce, time, "the
registry currently authorizes O→D")` — is then auditable after the fact
against registry history: an oracle that ever attests contrary to the
registry has produced portable, self-signed proof of its own
equivocation, verifiable by anyone. This converts the quorum from a
trusted party into an accountable one without adding a line to the guest:
the in-guest interface stays "verify k-of-n pinned signatures over my
nonce," fail closed, and governance reduces from "whom do we trust
blindly" to "whom do we remove on proof of equivocation."

## 8. Component changes and sequencing

1. **aleph-message**: `rootfs_encryption` field + validators (incl. the
   `authorized_keys` rejection). Should ride the same release window as
   the in-flight TDX schema work to avoid two ecosystem bumps.
2. **pyaleph**: aleph-message pin bump only (parse/price/store already
   generic); measurement cross-checking stays with the existing deferred
   CCN item.
3. **aleph-vm**: manifest placeholder-set widening, agent branch (disks +
   cmdline), nix first-boot init + derive-key helper + initrd additions,
   golden measurement re-seed, conformance fixtures for the two-disk argv.
   The grant check (7ter v1) lands in the same measured-init revision as
   two-man keying so instance measurements move once, not twice.
4. **Manifests**: publish the first-boot manifest (may share the bundle
   with the pre-encrypted one) once the image lands.
5. **aleph-rs**: types bump, `--base-image`, unlock `authorized_keys` +
   first-unlock guard, `delegation grant` verb + `unlock --grant` (small
   delta on the CLI-design work).
6. **Scheduler**: no change (instances are placed as before; v1 pins the
   node).
7. **Freshness oracle (v3)**: separate design + deployment effort, gated
   on an actual need to widen the consumed-secret set; nothing in v1/v2
   blocks on it, and shipping it later only requires a runtime image
   revision (pinned keys) plus the envelope field it already reserves.

Version gating is parse-level and fail-closed: a 2.0.1 CRN can parse
neither the new message field (pydantic forbids unknowns) nor the new
cmdline placeholder, so a guest-mode instance never half-launches on an
old node.

## 9. Testing

- Schema: validator matrix in aleph-message and aleph-rs (guest requires
  sev_snp, authorized_keys rejection, dump stability for absent field).
- Agent: unit tests for the disk layout and cmdline instantiation
  (mode/template pairing both ways), launch-spec goldens with two disks.
- Key derivation: the HKDF construction and token round-trip (salt,
  tcb_version) are pure and unit-testable host-side against fixed vectors;
  `SNP_GET_DERIVED_KEY` itself is Tier-2 (real hardware), covered by the
  E2E below plus a targeted reboot-rederive assertion.
- Grant objects: verification chain (owner sig, delegate sig, scope, vm
  binding, expiry-if-present) is pure; test vectors mirrored between
  aleph-rs (issuer) and the guest helper (verifier), like the owner-auth
  0x42 vectors.
- Guest: the nix build stays deterministic; golden-measurement CI covers
  the new init. First-boot logic (verify-while-copy, mismatch wipe, token,
  interrupted-copy recovery, key install, non-destructive failed open) is
  exercised by the testnet E2E scenario extension (first-boot create,
  unlock with keys, ssh, reboot, re-unlock, data persisted; negative:
  wrong base bytes must poweroff, wrong share must NOT destroy), blocked
  on the new SNP CRN like the rest of the E2E work.

## 10. Deferred

- Rollback detection and `"guest-integrity"` (authenticated encryption).
- The authorization freshness oracle (7ter v3) and, with it, any growth
  of the consumed-secret set beyond `{share, first-boot authorized_keys}`.
- Default base-image preset in vm-images for one-flag creates.
- Non-EVM unlock keys (inherited limit of the owner-auth scheme; the
  billing owner `content.address` may be non-EVM since PR #1190).
- TDX: `rootfs_encryption` is platform-neutral; a TDX runtime reuses the
  field, and TDX's equivalent sealing primitive slots into 5bis's
  `psp_sealed_key` role.
- Live re-keying / share rotation (the owner can rotate the LUKS keyslot
  over SSH today; protocol-level rotation of the *share* interacts with
  5bis and is designed with the oracle).
- Two-man keying for the pre-encrypted mode (would need a re-encryption
  pass on first boot; likely subsumed by migrating users to guest mode).
