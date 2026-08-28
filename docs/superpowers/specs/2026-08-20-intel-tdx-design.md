# Intel TDX support: design

**Date:** 2026-08-20, revised 2026-08-28
**Status:** Approved design, ready for implementation planning.
**Branch:** `od/tdx-design` off `main`.

**Driver:** roadmap / portability proof. There is no Intel TDX hardware in the
fleet today. The purpose of this work is to prove that the `aleph-tee`
abstraction generalizes beyond AMD, and to lock the protocol and schema seams
that would be expensive to change once they are in wide use. Hardware bring-up
is specified here but deliberately not built.

**Related:**

- [`2026-07-08-confidential-vm-protocol-design.md`](../../plans/2026-07-08-confidential-vm-protocol-design.md),
  section 7 ("An eventual TDX backend adds a platform tag with MRTD digests")
  and section 10 (IGVM direction).
- [`2026-08-18-snp-confidential-instances-design.md`](../../plans/2026-08-18-snp-confidential-instances-design.md).
- [`2026-08-12-snp-tcb-floor-design.md`](../../plans/2026-08-12-snp-tcb-floor-design.md)
  (G1), whose client-side floor architecture this design generalizes.

---

## 1. Goal and scope

Deliver two things:

1. **The schema and trait seams.** The first half already shipped:
   aleph-message 1.3.0 carries `LaunchMeasurement.registers` as an object
   rather than a scalar digest, and aleph-vm 2.0.0 and aleph-rs 0.17.0 consume
   it. What remains is the `tdx` platform value, `mode="tdx"`, and the
   register-map form of `VerificationResult` (section 4.4), which is now a
   breaking change to a released crate and should land before its cost grows
   further.
2. **A hardware-free TDX quote verifier** in `aleph-tee`. DCAP verification is
   pure computation: given one captured quote plus its Intel-signed collateral,
   the entire verifier can be implemented and fully tested with no TDX machine
   anywhere. Real quotes and full collateral are available from open-source
   projects (section 8.1), so nothing in this half waits on hardware.

Out of scope for the buildable increment, specified in section 7: the in-guest
backend, QEMU argument generation, the TDVF nix derivation, QGS/PCCS host
operations, and CRN capability advertisement.

---

## 2. Background: what already fits, and what does not

The existing split isolates TDX's differences well. Three files' worth of new
code plus two schema changes cover it.

| Layer | SEV-SNP today | TDX | Verdict |
|---|---|---|---|
| `TeeBackend` trait | report produce/parse only | same | unchanged |
| `AttestationReport{tee_type,data}` | AMD blob is sole truth | quote is self-certifying | unchanged |
| `report_data.rs` | domain-separated SHA-384 into 64 bytes | TDX `REPORTDATA` is also 64 bytes | unchanged |
| `LaunchMeasurement.registers` | `SevSnpRegisters{launch}` | `TdxRegisters{mrtd, rtmr1, rtmr2, mrconfigid}` | discriminated union |
| `VerificationResult.measurement` | one scalar | needs N registers | **changes**, breaking |
| `snp_min_tcb` aggregate key | numeric SPL ladder | status + advisories + module SVN | **generalizes** |
| verification chain | VCEK/ASK/ARK, pinned ARK | PCK chain, pinned Intel SGX Root CA | new module, same discipline |
| privilege gate | `MAX_ACCEPTED_VMPL = 1` | `TDATTRIBUTES.DEBUG == 0`, `MRSIGNERSEAM == 0` | new module, same discipline |
| launch argv | `sev-snp-guest` object | `tdx-guest` object | new function, spec only |
| evidence source | `/dev/sev-guest` ioctl | ConfigFS-TSM `outblob` | new function, spec only |
| expected-measurement tool | `sev-snp-measure` | `virtee/tdx-measure` | same org, same role |

Placeholders already in the tree: `aleph_tee::types::TeeType::Tdx` (serializes
as `"tdx"`, already tested), `HostInfo.tdx_supported = 6` and
`TeeBackend.TEE_BACKEND_TDX = 3` in `proto/supervisor.proto`, and a `TeeConfig`
that is already backend-agnostic. `TeeBackend` deliberately carries neither
launch nor verification, so a TDX backend owes only `get_report` and
`parse_report`.

### 2.1 Two properties better than expected

- **`vcpu_type` is not a TDX measurement input.** A TD's initial vCPU state is
  defined by the TDX module, not by the QEMU CPU model, so TDX
  `LaunchMeasurement` entries carry `vcpu_type: None`. The mixed-fleet problem
  SNP has (distinct digests for EPYC-v3 and EPYC-v4) does not exist on TDX.
  Section 6.6 checked the other machine-shape inputs and found none that reach
  the pinned registers.
- **Verification needs no Intel API key.** The PCK certificate chain is embedded
  in the quote itself (cert data type 5). Only TCB Info, QE Identity and CRLs
  are fetched; all three are free, unauthenticated, and Intel-signed, so they
  are verifiable from any mirror or a local PCCS. The trust path never depends
  on who served the collateral.

### 2.2 One property different

RTMR recomputation is practical but version-coupled. `virtee/tdx-measure`
reproduces MRTD and RTMR0 to RTMR2 for a direct-boot chain from the kernel,
initrd, cmdline and platform configuration, and section 6.6 validates it
against our own guest image. But it pins a QEMU source version per
distribution, because the ACPI tables and kernel setup-header patching it
models are QEMU's. That is the `sev-snp-measure` coupling the protocol design
already complains about, with a second dimension. This shapes the boot recipe
in section 6: the per-deployment binding goes somewhere the CCN can check with
one hash, and RTMR recomputation is kept as an optional strengthening rather
than the critical path.

---

## 3. Decisions

1. **`LaunchMeasurement` carries a register object, not a scalar digest**, with
   a **closed** key set per platform. An unknown register key is as
   schema-invalid as an unknown platform. Adding a register later is a schema
   release, which is the correct fail-closed stance. Shipped in 1.3.0 as a
   concrete SEV-SNP model; a second platform turns it into a discriminated
   union. See section 4.1.
2. **The `TeeBackend` trait is unchanged.** `get_report` stays synchronous and
   returns a quote; the TDX backend hides the host round trip inside a blocking
   ConfigFS-TSM `outblob` read. No async infection of `SevSnpBackend` or
   `NoneBackend`, no split report/quote methods that SNP would pay for and not use.
3. **The settings-aggregate TCB floor generalizes to `tee_min_tcb`**, keyed by
   TEE. The TDX block is an accepted-status list, an advisory-ID denylist, and a
   TDX-module SVN floor. G1's architecture is preserved intact: client-side
   enforcement, compiled-in baseline, aggregate raises only.
4. **The per-deployment binding moves from the measured cmdline into
   `MRCONFIGID`** for TDX. The CCN then checks the binding by recomputing one
   SHA-384, the guest enforces it at boot, and the cmdline stays fixed per
   runtime so `rtmr2` is publishable. See section 6.
5. **Pinned registers are `{mrtd, rtmr1, rtmr2, mrconfigid}`.** `rtmr0` is
   deliberately not pinned: TDVF extends the VMM-supplied memory layout and the
   variable store into it, which are deployment parameters, not code identity.
   `rtmr3` is not pinned either, but it is not free; see decision 8.
6. **We own the quote parsing and the policy.** Third-party DCAP crates are used
   as a differential-test oracle only, never in the trust path. Rationale in
   section 5.3.
7. **The CCN validates `rtmr1`/`rtmr2` by comparison against the runtime
   manifest**, not by derivation. An accepted, documented weakening relative to
   SNP that can be closed later with `tdx-measure`; see section 6.3.
8. **`rtmr3` is reserved for a launch-TCB commitment**, extended exactly once by
   the measured initrd. This is what recovers a cryptographic launch-TCB gate on
   a platform whose quotes otherwise report only the current TCB. The register
   is *derived*, not pinned: it appears in no message, and the client recomputes
   the expected value rather than comparing against a declared constant. Client
   enforcement starts as warn-on-mismatch and hardens once real hardware has
   exercised it. See section 6.5.
9. **Direct boot only, with two boot-path constraints.** The kernel is loaded
   by TDVF from fw_cfg, never through the UEFI boot manager off a GPT disk, and
   guest memory is at least 2.75 GB. Both keep deployment-varying inputs out of
   `rtmr1`; see section 6.6.

---

## 4. Schema changes

### 4.1 `LaunchMeasurement` (aleph-message)

Shipped in 1.3.0: `registers` is a concrete model, so the closed key set is a
property of the type rather than of a validator.

```python
class SevSnpRegisters(HashableModel):
    launch: RegisterValue          # 96 lowercase hex chars, pattern-constrained
    model_config = ConfigDict(extra="forbid")


class LaunchMeasurement(HashableModel):
    platform: TeePlatform          # sev_snp only for now
    registers: SevSnpRegisters
    vcpu_type: Optional[str] = None
```

This was chosen over a `Dict[str, str]` with per-platform required-key tables.
The generic version needed a `_REQUIRED_REGISTERS` map, a `MAX_REGISTERS` cap,
a register-name pattern and a `check_registers` validator, all to support a
platform that does not exist yet. The concrete model gets a sharper JSON schema
(`required: ["launch"]` plus `additionalProperties: false`) and located errors
(`missing`, `extra_forbidden`) instead of hand-assembled messages.

**Adding TDX** turns `registers` into a union discriminated on `platform`:

```python
class TdxRegisters(HashableModel):
    mrtd: RegisterValue
    rtmr1: RegisterValue
    rtmr2: RegisterValue
    mrconfigid: RegisterValue
    model_config = ConfigDict(extra="forbid")

registers: Annotated[Union[SevSnpRegisters, TdxRegisters], Field(discriminator=...)]
```

That is a schema release either way, since an unknown `platform` is already
schema-invalid (decision 1). The wire shape does not change for SEV-SNP.

`rtmr3` is deliberately absent from the TDX register set. It carries the
launch-TCB commitment (section 6.5), which the client *derives* rather than
compares against a declared constant, so it needs no message field. Keeping it
out of the schema is also what lets enforcement harden later without a protocol
change.

### 4.2 `TrustedExecutionEnvironment` (aleph-message)

`mode` grows `"tdx"`. `check_mode_consistency` generalizes from the `is_snp`
predicate to a measured-mode predicate (`mode in {"sev_snp", "tdx"}`): requires
`runtime` and `measurements`, forbids `firmware`, requires credit payment.

`policy` is the awkward field. It is typed `int` and carries either SEV bit
semantics or the SNP 64-bit guest policy. TDX has no host-chosen launch policy
at all: `TDATTRIBUTES` and `XFAM` are set by the TDX module and *measured*, not
selected by the host. **`policy` must therefore be absent or default in `tdx`
mode**, validated explicitly, rather than being given an invented meaning.

### 4.3 Settings aggregate

`snp_min_tcb` becomes `tee_min_tcb`, keyed by TEE:

```json
"tee_min_tcb": {
  "sev_snp": { "...": "existing per-generation SPL map, unchanged" },
  "tdx": {
    "accepted_statuses": ["UpToDate", "SWHardeningNeeded"],
    "denied_advisories": ["INTEL-SA-00837"],
    "min_tdx_module_svn": 5
  }
}
```

`snp_min_tcb` remains readable as an alias for one release cycle so
already-published floors keep working. In `aleph-rs`,
`aleph_sdk::attest::tcb` gains a `TdxTcbPolicy` beside `TcbFloor`, and
`TcbFloorPolicy::for_silicon` generalizes to dispatch on TEE type.

### 4.4 `VerificationResult` (aleph-tee and aleph-sdk, Rust)

Symmetric to 4.1, and shaped the same way: a concrete per-platform type, not a
`BTreeMap`. The scalar `measurement` becomes `registers`, an enum discriminated
on TEE type whose SEV-SNP arm carries `launch` and whose TDX arm carries the
four pinned registers. The existing doc-comment invariant ("derived from the
AMD-verified blob, NOT a caller-supplied copy") carries over verbatim and
applies per register.

The same scalar exists in two shipped places: `aleph_tee::types::VerificationResult`
(`measurement: Vec<u8>`) and, since aleph-rs 0.17.0, the public
`aleph_sdk::attest::VerificationResult` (`measurement: String`). Both move
together, in an aleph-rs 0.18.0 plus coordinated bumps in aleph-vm and
aleph-vm-scheduler. Neither `aleph-sdk` nor `aleph-types` is published to
crates.io, so consumers resolve through git tags and the blast radius is a
coordinated internal bump. The cost is a release, not a redesign, and it rises
with every further tag: this lands first, ahead of the TDX-specific increments,
even though nothing about it is TDX-specific.

---

## 5. `aleph-tee::tdx`

### 5.1 Module layout

Mirrors `sev_snp/` so the two read as siblings:

```
aleph-tee/src/tdx/
  mod.rs          pub use backend::TdxBackend;
  quote.rs        parse: header (48B) -> [v5 body descriptor] -> TD report body -> signature data -> cert data
  certs.rs        pinned Intel SGX Root CA; PCK chain; SGX extension OIDs
  collateral.rs   TCB Info / QE Identity / CRL fetch plus Intel-signature check
  verify.rs       verify_tdx_quote(): orchestration and policy gates
  backend.rs      TdxBackend (hardware-gated body, spec only for now)
  qemu.rs         tdx_qemu_args() (spec only)
```

`quote.rs` dispatches on quote version before touching the body. In v4 the TD
report body starts directly after the 48-byte header. In v5 a body descriptor
(`u16` type, `u32` size) intervenes, so the body starts at offset 54, and the
type distinguishes `TdReport10` (584 bytes: `tee_tcb_svn`, `mrseam`,
`mrsignerseam`, `seam_attributes`, `td_attributes`, `xfam`, `mrtd`,
`mrconfigid`, `mrowner`, `mrownerconfig`, `rtmr0..3`, `report_data`) from
`TdReport15` (648 bytes, adding `tee_tcb_svn2` and `mrservicetd`). Parsing a v5
quote at the v4 offset does not fail loudly, because everything is fixed-size
opaque bytes; it silently shifts every register by six and yields
plausible-looking digests. The parser tests include a v5 quote specifically to
catch this.

Extractors mirror the SNP ones: `extract_report_data(&body) -> [u8; 64]` and
`extract_registers(&body) -> TdxRegisters`.

### 5.2 `verify_tdx_quote()`

Signature: `verify_tdx_quote(quote, collateral, now: SystemTime, policy)`.

**The verifier takes the current time as a parameter and never reads the
clock.** Steps 3, 7 and 8 consult validity windows: CRLs carry `nextUpdate`,
and TCB Info and QE Identity carry `issueDate`/`nextUpdate`. A verifier that
calls `SystemTime::now()` internally cannot be tested against archived
collateral, because collateral expires; the fixtures in 8.1 already carry
`nextUpdate` values years in the past. Production callers pass the real clock,
tests pass a timestamp inside the fixture's window, and freshness stays
enforced in production. The shipped SEV-SNP verifier should be checked for the
same latent problem, since the remedy is identical.

Steps, with the SEV-SNP analogue in brackets:

1. Parse; assert `tee_type == TDX`. [`parse_sev_snp_report`]
2. Extract the PCK chain from cert data type 5; verify it to a **pinned Intel
   SGX Root CA public key**. [`pinned_amd_ark_der`: same discipline, same
   fail-closed direction, a wrong pin rejects genuine quotes rather than
   accepting forged ones]
3. Check CRLs (root CA and PCK CA). [no SNP analogue]
4. Verify the QE Report signature under the PCK key.
5. Assert `qe_report.report_data[0..32] == SHA-256(att_key || qe_auth_data)`.
   This is what binds the attestation key to the quoting enclave; skipping it is
   a total break.
6. Verify the quote signature over `header || td_report_body` under the
   attestation key. [report signature check]
7. Verify QE Identity against Intel's signed enclave identity.
8. Parse FMSPC, CPUSVN and PCESVN from the PCK certificate's SGX extension
   (OID `1.2.840.113741.1.13.1`); walk TCB levels to the highest satisfied one,
   yielding `(status, advisory_ids)`. For TDX, also match `tdxtcbcomponents`
   against `tee_tcb_svn`.
9. Platform gates (section 5.4). [`check_vmpl`]
10. Return `VerificationResult` with the registers and `report_data`.

As with SNP, a `valid: true` verdict is **not** sufficient to trust a guest. It
says only "this is a genuine Intel-attested TD on a platform at an acceptable
TCB". The caller must still pin the registers against the message's declared
`LaunchMeasurement`, bind freshness through `report_data`, and check the derived
`rtmr3` launch-TCB commitment (section 6.5). The existing `report_data.rs`
domain-separated schemes apply unchanged.

### 5.3 On third-party crates

`dcap-qvl` and `dcap-rs` are pure-Rust DCAP verifiers; Intel's own QVL is FFI to
the SGX SDK. We own the parsing and the policy, and use a third-party crate only
as a differential-test oracle.

The precedent is in `sev_snp/`. The aleph-cvm donor verifier was working code,
and porting it surfaced two real vulnerabilities: unsigned standalone
`measurement`/`report_data` copies that a verifier could be tricked into
trusting, and a shared `report_data` namespace that enabled attested-key
confusion and a full MITM. Both are documented in the rust-port-divergences
ledger. Putting an unaudited external verifier in the trust path reintroduces
exactly that class of risk in the place we have been most careful. The cost is
roughly the size of `sev_snp/verify.rs` (1015 lines), which is a cost already
paid once for AMD.

Crypto dependencies: `p256` (TDX signatures are ECDSA P-256, unlike SNP's
P-384), `x509-cert` / `der`, `sha2`.

### 5.4 Platform gates

The SNP verifier's VMPL gate has three TDX analogues. All must be enforced, or
the signature check is theatre:

- **`td_attributes.DEBUG == 0`.** A debuggable TD lets the host read guest
  memory. This is the single most important gate.
- **`mrsignerseam == [0u8; 48]`.** A non-zero MRSIGNERSEAM means the TD runs
  under a non-Intel-signed SEAM module. Fail closed.
- **`mrseam`** checked against the TDX-module identity in Intel's TCB Info, so a
  known-vulnerable module version is rejected.

### 5.5 TCB policy

```rust
pub struct TdxTcbPolicy {
    pub accepted_statuses: BTreeSet<TcbStatus>,
    pub denied_advisories: BTreeSet<String>,
    pub min_tdx_module_svn: u8,
}
```

Builtin baseline: accept `UpToDate` and `SWHardeningNeeded`; reject everything
else.

- `SWHardeningNeeded` is routine and pertains to QE software mitigations.
- `ConfigurationNeeded` is **rejected by default**. It typically flags BIOS
  state such as SMT, which is precisely the axis SNP's guest policy has a
  dedicated bit for. It stays reachable through the existing
  `--accept-outdated-tcb`-style override.
- `Revoked` is **never overridable**, unlike every other status. This is a
  deliberate asymmetry with the SNP override, which admits any concrete named
  TCB.

Intel's signed TCB Info carries the CVE-to-SVN ladder that the AMD side had to
hand-calibrate. Given that the rc8 floor audit found Milan's floor too low and
Zen4c's too strict, having Intel do that calibration is a real asset and not
merely a difference.

### 5.6 The launch-TCB gap

G1 decision 2 gates on `launch_tcb` and is deliberately relaunch-forcing: a host
firmware update alone does not clear a CVE bump, because a VM that already ran
under vulnerable firmware may already have been exposed.

**TDX cannot express this.** The quote's CPUSVN and PCESVN reflect the
platform's *current* TCB, not the TD's launch-time TCB. `tee_tcb_svn` gives the
SEAM module version, which is fixed for a TD's lifetime except that TDX 1.5
TD-preserving updates can advance it under a running TD. The strongest available
TDX statement is therefore "this platform is currently at an acceptable TCB",
which is strictly weaker than the SNP guarantee.

Worse than weaker, it is *silently* weaker: after an operator upgrades a
platform, a TD that ran for months under vulnerable firmware starts producing
quotes reporting the new, healthy TCB, and passes the client's floor check with
nothing anywhere recording that it was ever exposed.

Two mechanisms address this, and they are not alternatives:

- **Section 7.6** (node-side tracking) makes the transition visible to an honest
  operator, so exposed VMs become an actionable work list. It is not a trust
  boundary: the CRN is the party making the claim.
- **Section 6.5** (`rtmr3` launch-TCB commitment) makes it *verifiable by the
  client*, because only the TD can extend an RTMR and the extending initrd is
  itself covered by the pinned measurements. This is the real fix.

Until client enforcement of 6.5 hardens, treat the gap as open and rely on 7.6.

---

## 6. Boot recipe and CCN validation

### 6.1 The problem

Protocol decision 3 requires checked redundancy: messages carry measurements
*and* their inputs, and the CCN verifies consistency. For SNP the CCN recomputes
the launch digest with `sev-snp-measure`. For TDX:

- `mrtd` is cheaply recomputable: parse TDVF metadata, hash the TD pages. TDVF
  is the smallest artifact.
- `rtmr1` and `rtmr2` are recomputable with `tdx-measure`, but that tool models
  QEMU's kernel loading and ACPI generation and pins a QEMU version per
  distribution (section 2.2). Putting it on the CCN's critical path couples
  message validation to the CRN's QEMU version.

Publishing expected RTMRs in the runtime manifest (content-addressed,
publisher-measured at nix build time) and having the CCN compare rather than
recompute avoids that coupling for `rtmr1`. It **fails for `rtmr2`** as the SNP
recipe stands, because TDVF measures the kernel cmdline into `rtmr2` (section
6.6), and the cmdline is exactly where the SNP recipe puts the per-deployment
`workload_roothash`. A per-deployment cmdline means a per-deployment `rtmr2`,
which no manifest can publish.

### 6.2 The recipe: `tdx-mrconfigid-v1`

Move the per-deployment binding out of the cmdline and into `MRCONFIGID`.

`MRCONFIGID` is a 48-byte host-settable field that the TDX module measures into
the TD and echoes in every quote. Set it to the SHA-384 of a **deployment
descriptor**: a small host-delivered blob carrying the workload roothash, any
verified-volume roothashes, and whatever a later version adds. The measured
initrd reads the descriptor, hashes it, compares against `MRCONFIGID` from its
own local TDREPORT (cheap: no QGS round trip needed for a TDREPORT), and fails
closed on mismatch.

A lying CRN has no move. Either it sets `MRCONFIGID` honestly, in which case the
client's pin against the message catches any wrong value; or it sets it
dishonestly, in which case the guest refuses to boot; or it sets it malformed,
in which case QEMU refuses to start, since `tdx.c` base64-decodes the property
and rejects anything that is not exactly 48 bytes.

**The host-side path is confirmed**, every link checked: `mrconfigid` is a
settable `string` property on QEMU's `tdx-guest` object (QEMU 10.2.1, via QMP
`qom-list-properties`; note that `-object tdx-guest,help` reports "no options"
because the properties are registered with `object_property_add_str`), decoded
and length-checked in `target/i386/kvm/tdx.c`, copied into
`kvm_tdx_init_vm.mrconfigid[6]` for `KVM_TDX_INIT_VM`, and landing in the TDX
module's `td_params.mrconfigid` (Linux 6.18 uapi). What no fixture yet shows is
a populated value surviving into a quote: `MRCONFIGID` is all-zero in every
quote in section 8.1. That end-to-end confirmation is the first Tier 2 item.

**Descriptor delivery.** The descriptor must reach the guest over a channel that
does not perturb `rtmr1` or `rtmr2`, or the recipe defeats its own purpose. Its
integrity comes entirely from the `MRCONFIGID` comparison, so the channel needs
no integrity property of its own: any unmeasured host-to-guest path works. The
default is a small raw virtio-blk device (the same shape as the existing
cloud-init drive), read by the initrd before it derives the verity roothash.
Section 6.6 confirms this is safe: TDVF only measures a block device's partition
table when it *boots* from it, and the device count does not reach the pinned
registers.

Note that this is a genuine exception to protocol decision 11 ("every guest
input is measured or verity-bound"), and a deliberate one: the descriptor is
*bound* rather than measured, by a 48-byte field the TDX module measures for us.
The binding is strictly stronger than a measured cmdline token, because it is
enforced by the guest at boot as well as by the client at verification.

| | SNP recipe | TDX recipe |
|---|---|---|
| cmdline | per-deployment (roothash slots) | fixed per runtime |
| deployment binding | measured cmdline tokens | `MRCONFIGID` |
| CCN checks the binding by | recomputing the launch digest | recomputing one SHA-384 |
| CCN checks the runtime by | recomputing the launch digest | recomputing `mrtd`; comparing `rtmr1`/`rtmr2` to the manifest |
| extra volumes | cmdline grows | descriptor grows, cmdline does not |
| "CRN must not add, drop or reorder tokens" | prose discipline | mechanically enforced by the hash |

The cost is honest: TDX gets a *different* boot recipe from SNP rather than a
mirrored one, so two recipes are maintained. The mirrored alternative, a
per-deployment cmdline with the CCN recomputing `rtmr2` through `tdx-measure`,
is viable now that the tool exists, and was rejected on cost rather than
possibility: it puts a Rust tool pinned to QEMU versions on pyaleph's critical
path, in exchange for nothing the descriptor does not already give, and it
gives up the guest-side enforcement.

### 6.3 Runtime manifest

The manifest (section 11 of the protocol design) gains a per-recipe
`measurements` block publishing the expected `mrtd`, `rtmr1` and `rtmr2` for the
bundle, measured once at build time by the publisher with `tdx-measure`. In
this repo that means extending `nix/golden-measurements.json` and its weekly
drift check to a TDX runtime entry, rather than inventing a parallel mechanism.

CCN validation for a `mode="tdx"` message then becomes:

- recompute `mrtd` from the manifest-pinned TDVF artifact and compare (genuine
  checked redundancy on the firmware);
- compare `rtmr1` and `rtmr2` against the manifest;
- recompute `mrconfigid` from message fields alone (a pure hash, microseconds).

**Accepted weakening:** for `rtmr1` and `rtmr2` the CCN checks *consistency with
the manifest*, not *derivation from first principles*. The mitigation is that
the manifest is content-addressed and immutable, and its values are
independently reproducible by anyone who runs `tdx-measure` over the bundle, so
a lying publisher is caught by any single verifier. The weakening can be closed
later by having the CCN recompute with `tdx-measure` as a second check, at the
coupling cost described in 6.1; that is a strengthening, not a redesign.

### 6.4 Alternative considered and rejected

Pin `mrtd` only and let `MRCONFIGID` carry everything, ignoring RTMRs. Rejected:
`MRCONFIGID` alone is a host *claim* about configuration, and it only becomes
trustworthy if the measured guest independently enforces that what actually
booted matches the claim. That means the initrd reading its own RTMRs and
comparing, which is strictly more guest-side work than simply pinning the RTMRs
in the message. `MRCONFIGID` earns its place as a deployment binding (6.2), not
as a measurement substitute.

### 6.5 `rtmr3`: the launch-TCB commitment

This is what closes section 5.6 cryptographically rather than merely
operationally.

**Why it works.** A TD can read its own TDREPORT locally, with no QGS round trip
and therefore no host involvement: `CPUSVN` sits in `REPORTMACSTRUCT` and
`tee_tcb_svn` in `TEE_TCB_INFO`. So the guest can observe the platform TCB at
boot. RTMRs are extend-only, and **only the TD can extend them**: the host has no
interface to write one. Combining those two facts gives the guest a way to make
an unforgeable, unrewindable statement about what it saw at launch.

**The scheme.**

1. The measured initrd, before any untrusted code runs, extends `rtmr3` once:

   ```
   rtmr3 = extend(0, SHA-384(DOMAIN_LAUNCH_TCB || cpusvn || tee_tcb_svn))
   ```

   PCESVN is deliberately **not** in the commitment. It lives in the PCK
   certificate, which the guest only sees inside a quote, and a quote needs the
   host's QGS. Including it would make the boot-time commitment host-dependent,
   which is the property the scheme exists to avoid. PCESVN is still checked by
   the client at verification time from the quote's PCK chain; it is simply
   not part of the launch-time statement.

2. Every subsequent quote carries that `rtmr3` value.
3. The guest reports its observed launch TCB in band over the attested channel.
4. The client recomputes the expected `rtmr3` from the reported values and
   compares against the quote.

The in-band report is a claim, but `rtmr3` makes it unforgeable, and the initrd
doing the extending is covered by the `mrtd`/`rtmr1`/`rtmr2` pins we already
enforce. A TDX 1.5 TD-preserving update can advance `tee_tcb_svn` under a
running TD, but it cannot rewind `rtmr3`, so the launch-time statement survives
exactly the event that would otherwise erase it.

`DOMAIN_LAUNCH_TCB` belongs in `aleph_tee::report_data` beside `DOMAIN_KEY` and
`DOMAIN_FRESH`, for the same anti-drift reason that module already states: the
constructing side (the initrd) and the verifying side (the client) must not be
able to diverge, and a third domain tag keeps this namespace from colliding with
the two attested-TLS schemes.

**Register discipline.** `rtmr3` is reserved. It is extended **exactly once**,
by the initrd, and never again: because the client checks an exact value, any
later extension breaks verification. This binds the whole guest stack, not just
workload code. `rtmr3` is the conventional application register in the wider
ecosystem (dstack, for one, extends it with application identity), which is no
conflict here since we own the guest image, but it does mean the guest kernel's
own subsystems (IMA, the TSM driver) must be audited for `rtmr3` writes before
enforcement hardens. That audit is spike 3 in section 11. Adding the extend
later would change the initrd, therefore change `rtmr1`/`rtmr2`, therefore
force every published bundle to re-version, which is why the semantics are
reserved from v1 even though enforcement is not.

**Why `rtmr3` specifically.** `rtmr0` and `rtmr1` are firmware-owned. `rtmr2` is
already in the pinned set, so extending it would break the pin. `rtmr3` is the
only register both guest-extendable and free.

**Rollout.** Client enforcement is warn-on-mismatch in v1 and hard-fail once
real hardware has exercised the path and the kernel audit is clean. `rtmr3`
never appears in a message: it is derived, so no schema field is needed and
hardening later is not a protocol change.

### 6.6 What TDVF measures

Traced in EDK2 `edk2-stable202608` and confirmed with `virtee/tdx-measure`
against our own guest image (the nix-built `aleph-cvm-image` bzImage and
initrd). `tdx-measure --runtime-only` computes `rtmr1` and `rtmr2` from the
kernel, initrd and cmdline alone, so everything below except MRTD and `rtmr0`
is reproducible without a TDVF binary or a TDX machine.

**Register mapping**, from `TdxMeasurementCommon.c`: PCR 0 is MRTD; PCRs 1 and
7 are `rtmr0`; PCRs 2 to 6 are `rtmr1`; PCRs 8 to 15 are `rtmr2`.

**Where each input lands:**

| Input | Call site | Register |
|---|---|---|
| TD HOB (VMM memory layout) | `SecTdxHelper.c`, explicit index 0 | `rtmr0` |
| CFV (variable store) | `SecTdxHelper.c`, explicit index 0 | `rtmr0` |
| `BootOrder`, `Boot####` (boot device path) | `TdTcg2Dxe.c`, PCR 1 | `rtmr0` |
| Loaded PE image (the kernel) | `DxeTpm2MeasureBootLib`, PCR 4 | `rtmr1` |
| GPT partition table of the *boot* device | `DxeTpm2MeasureBootLib`, PCR 5 | `rtmr1` |
| Kernel cmdline (`+ " initrd=initrd"`) | direct-boot event log | `rtmr2` |
| Initrd content | direct-boot event log | `rtmr2` |

The cmdline placement was confirmed empirically: changing only the cmdline
leaves `rtmr1` byte-identical and moves `rtmr2`. Decision 5 is vindicated on
the same evidence: the deployment-varying firmware inputs all go to `rtmr0`.

**What `rtmr1` depends on.** From `tdx-measure`'s `patch_kernel`, which mirrors
QEMU's `x86_load_linux`: the kernel image, the initrd size, and the initrd load
address. That address is `below_4g_mem_size - acpi_data_size - 1` rounded, where
`acpi_data_size` is QEMU's `PC_FW_DATA`, a compile-time constant (`0x28000`),
and `below_4g_mem_size` follows the q35 memory split. Device count, device
order and vCPU count do **not** reach `rtmr1`; they shape `rtmr0` via the TD
HOB. This is what lets section 2.1 stand.

**Constraint 1: direct boot, never the UEFI boot manager off a GPT disk.** The
GPT measurement is gated on the boot device being a BlockIo device and runs at
most once. A kernel loaded from the fw_cfg-backed `QemuKernelLoaderFs` never
triggers it. A rootfs the *kernel* mounts later is fine, as is the descriptor
block device in 6.2. Direct boot is also the standard approach: Canonical's
reference stack uses it, and `tdx-measure` targets it.

**Constraint 2: guest memory at least 2.75 GB.** The q35 split pins
`below_4g_mem_size` to 2 GB once RAM reaches `0xb0000000`; below that it tracks
RAM, so the initrd address, and with it `rtmr1`, varies with memory size:

| Memory | `rtmr1` |
|---|---|
| 1 GB, 2.25 GB, 2.5 GB, 2.625 GB | four distinct values |
| 2.75 GB, 3 GB, 16 GB, 64 GB, 512 GB | identical |

(Exactly 2 GB coincides with the saturated value; do not rely on it.) This is
the threshold `tdx-measure` itself warns about. Below it `rtmr1` is
unpublishable in any manifest.

**Not available: IGVM.** QEMU's IGVM loader supports AMD SEV, SEV-ES and SEV-SNP
only. Section 10 keeps it as a direction; it is not an option for this design.

**Evidence caveat.** The register attribution above is `tdx-measure`'s model of
TDVF, corroborated by the EDK2 source everywhere both are checkable, but not
yet by a quote from a TDX machine. Confirming it against a real quote is a Tier
2 item alongside the `MRCONFIGID` end-to-end check.

---

## 7. Hardware-gated surface (specified, not built)

### 7.1 `TdxBackend::get_report`

ConfigFS-TSM: create `/sys/kernel/config/tsm/report/<uniq>/`, assert
`provider == "tdx_guest"` (so an SNP outblob can never be parsed as a TDX
quote), write the 64-byte `inblob`, read `outblob`, `rmdir`. The `generation`
counter guards against concurrent writes. Fallback is the `/dev/tdx_guest`
`GET_QUOTE` ioctl.

New failure mode with no SNP equivalent: **QGS unreachable means attestation
fails at request time, not launch time.** This needs a timeout and an error that
says "host quote service unreachable" rather than "attestation failed", or every
QGS outage will be misdiagnosed as a compromised guest.

### 7.2 `tdx_qemu_args()`

```
-cpu host
-machine q35,confidential-guest-support=tdx0,kernel-irqchip=split,hpet=off,vmport=off
-object tdx-guest,id=tdx0,mrconfigid=<base64 48B>,quote-generation-socket=vsock:2:4050
-bios /usr/local/share/ovmf-tdx/OVMF.fd
-kernel ... -initrd ... -append "<fixed per runtime>"
-m <at least 2.75G>
-nodefaults
```

Differences from the SNP argv, each with a consequence:

- No `memory-backend-memfd` object: TDX private memory is machine-managed
  `guest_memfd`.
- No `cbitpos` / `reduced-phys-bits`, so `supervisor-controller/src/cpuid.rs`
  and its host CPUID read stay SNP-only.
- No `kernel-hashes=on`: TDVF does its own measuring into RTMRs.
- No SMM.
- `-cpu host` rather than a pinned model, which is safe precisely because
  `vcpu_type` is not a TDX measurement input (section 2.1).

Two consequences worth acting on:

- **`mrconfigid` needs `canonical_policy`-grade handling.** It is base64 inside
  a comma-separated QEMU object argument, an identical smuggling surface to
  `policy`. Decode, assert exactly 48 bytes, re-encode. Unlike `policy`, it must
  **reject** rather than fall back to a default: there is no safe default
  deployment binding.
- **NUMA pinning and hugepages do not transfer.** Today both ride on the
  `memory-backend-memfd` object (`host-nodes=`, `hugetlb=`). TDX has no such
  object, so TDX needs a separate mechanism (controller-side cpuset, or
  `-numa`). This is a latent assumption in the multi-disk/NUMA placement work
  that TDX quietly breaks.

### 7.3 Rest of the stack

- **Controller:** `QemuConfig` gains `tdx: Option<bool>` and `mrconfigid`, an
  `is_tdx()` mirroring `is_snp()`, `build_tdx_argv`, and an
  `argv_parity_tdx.rs` conformance fixture set. The argv builder enforces
  decision 9: direct boot only, memory floor asserted.
- **Proto:** `ConfidentialMode.CONFIDENTIAL_MODE_TDX = 4`, and an `mrconfigid`
  field on `TeeConfig`. Additive only.
- **Nix:** a `tdvf.nix` building edk2 `OvmfPkg/IntelTdx/IntelTdxX64.dsc`,
  reproducible because `mrtd` is pinned; and a TDX guest kernel. The guest
  kernel is built from `allnoconfig` plus an explicit whitelist fragment, so
  TDX support is not free: `INTEL_TDX_GUEST`, `TDX_GUEST_DRIVER` and
  `TSM_REPORTS` must be named, and a TDX guest is its own measured runtime with
  its own golden-measurements entry, not a variant of the SNP image. The 6.18
  guest kernel is recent enough for all three.

### 7.4 Host operations

SNP needs a BIOS bit, after which `/dev/sev-guest` simply works. TDX needs, per
CRN:

- a `tdx-qgs` systemd unit listening on vsock port 4050;
- platform registration (PCK ID retrieval, and multi-package registration with
  Intel's provisioning service);
- a PCCS dependency plus `sgx_default_qcnl.conf`;
- BIOS with TDX **and** SGX enabled, since TDX attestation rides SGX.

This is a materially heavier operator story than SNP and belongs in the
node-operator runbook, not buried in a design document.

### 7.5 Capability advertisement

`check_intel_tdx_supported()` reading `/sys/module/kvm_intel/parameters/tdx` is
necessary but not sufficient. A host with TDX enabled and QGS unreachable will
happily launch instances that can never attest.

**Advertise `"tdx"` only when KVM reports TDX support and the QGS vsock
answers.** Advertise the capability, not the CPU bit. This applies to both
`MachineProperties.cpu.features` and `HostInfo.tdx_supported`.

### 7.6 Node-side launch-TCB tracking

This is the node-side operational hygiene that G1 section 8.1 deferred to a
separate spec. TDX promotes it from operator convenience to the only mechanism
that observes the section 5.6 gap at all.

**Trust caveat, stated first.** This is *not* a security boundary and must never
be presented as one. A recorded launch TCB is a CRN claim, and G1 decision 1
holds: the node is adversarial and the client's check inside RA-TLS remains the
authoritative gate. What this buys is that an **honest** operator can find and
repair exposed VMs, and that a fleet-wide floor raise produces a visible,
actionable work list instead of silence. For SEV-SNP the same tracking is pure
convenience, because the client reads `launch_tcb` out of the report directly.
For TDX the information exists nowhere else in the system.

**Recorded at launch, per VM, persisted** (it must survive a supervisor
restart): the platform CPUSVN and PCESVN, the TDX module version
(`tee_tcb_svn`), and the launch timestamp. The natural home is the existing
per-VM world state alongside the other persisted VM facts. Source of the
platform values is host-side: the platform PCK certificate held by the PCCS or
retrieved during registration. The exact read path is an implementation detail
worth a spike, not a design fork.

**The trigger is a two-phase state machine, not "the floor was raised".**
Relaunching before the operator upgrades merely relaunches under the same
vulnerable TCB, so a naive "floor raised means reboot" rule would churn VMs and
fix nothing:

| `launch_tcb` vs floor | current platform vs floor | State | Operator sees |
|---|---|---|---|
| meets | meets | `ok` | nothing |
| below | below | `blocked` | "upgrade this node's firmware or TDX module" |
| below | meets | `stale` | "N VMs need a relaunch to clear their exposure" |
| meets | below | `regressed` | should be impossible; TCB is monotonic. Log loudly. |

Only `stale` is actionable by relaunch. `blocked` is actionable by the operator
upgrading, after which those VMs transition to `stale`.

**Reading the floor.** The supervisor does not read the settings aggregate for
TCB purposes today, but the machinery exists: the authorized-allocation-signers
work already sources a settings-aggregate key CRN-side, and the same fetch,
cache and degrade-on-unreachable discipline applies here. Consistent with G1
decision 4, an unreachable aggregate degrades to the compiled-in baseline rather
than failing open or failing closed.

**Surface.** A per-VM status field plus a node-level count, exposed on the
existing node information endpoints and as a log line on transition. **Do not
auto-reboot.** Relaunching a user's confidential VM destroys guest-held state,
including anything sealed to the previous instance, and the operator may have
scheduling constraints we cannot see. The design position is: make the work list
correct and visible; leave the decision with the operator.

**Applies to both backends.** Nothing above is TDX-specific except the priority.
Implementing it for SEV-SNP at the same time costs little and gives operators
one consistent mechanism.

---

## 8. Testing

### 8.1 Fixture provenance

Real TDX quotes and complete DCAP collateral are available from open-source
projects under permissive licences. aleph-vm is MIT, so MIT and Apache-2.0
sources both vendor cleanly with attribution.

| Source | Licence | What it gives |
|---|---|---|
| [`Phala-Network/dcap-qvl`](https://github.com/Phala-Network/dcap-qvl) `sample/` | MIT | `tdx_quote` + `tdx_quote_collateral.json`, and a `tdx_quote_outdated` pair. The JSON carries the **entire** collateral set in one file: `pck_crl_issuer_chain`, `root_ca_crl`, `pck_crl`, `tcb_info_issuer_chain`, `tcb_info`, `tcb_info_signature`, `qe_identity_issuer_chain`, `qe_identity`, `qe_identity_signature`. |
| [`google/go-tdx-guest`](https://github.com/google/go-tdx-guest) `testing/testdata/` | Apache-2.0 | `tdx_prod_quote_SPR_E4.dat` (production Sapphire Rapids, v4), `quote_sample_v5.dat` (v5), separated PCS responses (`sample_tcbInfo_response`, `sample_qeIdentity_response`, `pckcrl`, `rootcrl.der`) shaped like the real endpoints, plus CCEL event-log data for RTMR replay. |
| [`automata-network/automata-dcap-attestation`](https://github.com/automata-network/automata-dcap-attestation) `rust-crates/samples/` | MIT | v3/v4/v5 quotes as an independent cross-check. |

Verified: all four quotes parse with `tee_type == 0x00000081` and Intel's QE
vendor ID `939a7233f79c4ca9940a0db3957f0607`, and each embeds a full
three-certificate PCK chain as cert data type 5. Coverage spans quote v4 **and**
v5 (both v5 fixtures are `TdReport15`), `UpToDate` **and** `OutOfDate` TCB
levels, and genuine production silicon, which is enough to exercise every step
of 5.2 and the whole 5.5 policy matrix. `MRCONFIGID` and `rtmr3` are all-zero
in all four, which is why 6.2 and 6.5 each carry a Tier 2 confirmation item.

`dcap-qvl` is both a fixture source and the differential oracle 5.3 nominates,
so the oracle agrees with those fixtures by construction. That makes the
differential test weaker than it looks: it catches our parsing and chain-walk
mistakes, not shared misinterpretations of the spec. Cross-checking against
`go-tdx-guest`'s independent implementation is what covers that gap.

### 8.2 Test matrix

Tier 1, all in CI, no hardware anywhere:

- **Quote parsing** against golden vectors, covering v4 and v5 framing and both
  `TdReport10` and `TdReport15` bodies.
- **Chain verification**: the pinned-root happy path plus one test per reject
  reason (forged root, broken chain, revoked certificate, wrong
  QE-report-to-attestation-key binding, tampered signature). This mirrors how
  `sev_snp/verify.rs` already exercises each reject path individually.
- **Collateral**: cached Intel-signed TCB Info and QE Identity as fixtures;
  assert signature verification and the TCB-level walk against hand-built
  ladders; assert the injected-clock freshness check rejects when `now` is
  past `nextUpdate`.
- **Policy**: table-driven over all seven statuses crossed with the override
  matrix; explicitly assert that `Revoked` is non-overridable.
- **Platform gates**: one test per gate, each asserting the reject.
- **Schema**: closed-key-set validation, the discriminated union, and
  `mrconfigid` injection rejection (mirroring `test_policy_injection_is_rejected`).
- **Differential**: our verifier against `dcap-qvl` over the same fixtures, as a
  dev-dependency only, never in the trust path.
- **Expected measurements**: `tdx-measure --runtime-only` over the TDX runtime
  bundle in the golden-measurements check, alongside `sev-snp-measure`.
- **Launch-TCB state machine (7.6)**: table-driven over the four states, plus a
  persistence round trip asserting a recorded launch TCB survives a supervisor
  restart, plus the degrade-to-baseline path when the settings aggregate is
  unreachable.
- **`rtmr3` commitment (6.5)**: assert the client's recomputation matches a
  fixture quote; assert a mismatched in-band launch TCB is rejected; assert a
  second extension breaks verification (the register-discipline constraint);
  assert `DOMAIN_LAUNCH_TCB` cannot collide with `DOMAIN_KEY` or `DOMAIN_FRESH`,
  mirroring the existing domain-separation tests in `report_data.rs`.

Tier 2 (`#[ignore]`, requires a Xeon): `get_report`, argv boot, end-to-end
RA-TLS, a populated `MRCONFIGID` surviving into a quote, and the 6.6 register
attribution against a real quote.

---

## 9. Increments and sequencing

In execution order:

| # | Increment | Repo | Note |
|---|---|---|---|
| 5 | `registers` on both `VerificationResult`s (4.4) | aleph-rs 0.18.0, aleph-vm, aleph-vm-scheduler | **First.** Breaking; cost rises per aleph-rs tag; hardware-free; SNP-facing |
| 1 | `TeePlatform.tdx`, `TdxRegisters`, the discriminated union, `mode="tdx"`, policy-absent validator | aleph-message, then pyaleph / aleph-rs / aleph-vm | schema release; SNP half already shipped in 1.3.0 |
| 2 | `tdx/quote.rs` parsing and extractors, v4 and v5 | aleph-vm | additive |
| 3 | DCAP chain verification (5.2 steps 2 to 6), injected clock | aleph-vm | additive |
| 4 | Collateral, TCB walk, platform gates (5.2 steps 7 to 9) | aleph-vm | additive |
| 6 | `tee_min_tcb` and `TdxTcbPolicy` | aleph-rs | generalizes G1 |
| 7 | Spec: `tdx-mrconfigid-v1` recipe, `tdx-measure` in the golden-measurements check, QGS runbook | aleph-vm docs, nix | spec plus one CI hook |
| 10 | TDX guest kernel in the whitelist fragment, `tdvf.nix`, as its own measured runtime | aleph-vm nix | needed before 7 can produce a real golden entry |
| 11 | Enforce decision 9 in the argv builder: direct boot only, memory floor | aleph-vm controller | small; rides with 7.3 |
| 8 | Node-side launch-TCB tracking (7.6) | aleph-vm | TEE-agnostic; buildable for SNP today |
| 9 | `DOMAIN_LAUNCH_TCB` + client-side `rtmr3` recomputation, warn-on-mismatch (6.5) | aleph-vm, aleph-rs | after 2 to 4; low value until the guest-side extend ships with 10 |

Increments 2 to 4 are pure addition and can proceed at any pace. Increment 5
is the only time-sensitive one.

Increment 8 is worth calling out separately: it is the only item here that
delivers value **before** any TDX hardware exists, because the same tracking
serves SEV-SNP operators today. It also discharges the spec G1 section 8.1
deferred. If TDX slips indefinitely, increment 8 should still ship.

---

## 10. Deferred and non-goals

- **CCN-side validation in pyaleph** (recompute `mrtd`, compare `rtmr1`/`rtmr2`
  to the manifest, recompute `mrconfigid`). Hardware-free, but it depends on the
  manifest `measurements` block from increment 7, so it is deferred rather than
  sequenced.
- **CCN-side `rtmr1`/`rtmr2` recomputation** with `tdx-measure`, as the optional
  strengthening in 6.3.
- **All hardware bring-up**: `TdxBackend`, argv, TDVF nix derivation, QGS/PCCS
  operations, capability detection. Specified in section 7, not built.
- **NVIDIA confidential computing composition.** TDX is a host TEE under
  confidential GPUs, but GPU attestation composition is its own design.
- **IGVM for TDX.** TDX is in the IGVM format but not in QEMU's IGVM loader
  (AMD only), and CRN hosts run QEMU well below the required version. Section
  10 of the protocol design already tags IGVM as a future recipe; nothing here
  changes that.
- **Hard-fail enforcement of the `rtmr3` commitment.** Reserved and implemented
  as warn-on-mismatch now (increment 9); hardening waits on the kernel audit
  (spike 3) and on real hardware exercising the path.
- **TD-preserving update semantics** beyond noting in 5.6 that they advance
  `tee_tcb_svn` under a running TD, which is precisely the event `rtmr3` is
  designed to survive.
- **TDX for the legacy SEV `mode="sev"` flow.** There is no TDX analogue of the
  CRN-mediated launch-secret handshake, and none is wanted.

---

## 11. Open questions (spikes, not design forks)

1. **Does our nix guest kernel's ConfigFS-TSM `outblob` yield a full quote or a
   bare TDREPORT?** Determines whether decision 2 holds as written or needs the
   `/dev/tdx_guest` `GET_QUOTE` ioctl fallback.
2. **Which TCB statuses do real Sapphire Rapids and Emerald Rapids platforms
   actually report?** The 5.5 baseline rejects `ConfigurationNeeded`; if that
   status is near-universal in practice, the baseline needs revisiting before
   any hardware lands.
3. **Does anything in the 6.18 guest kernel extend `rtmr3` on its own?** IMA
   and the TSM driver are the candidates. The 6.5 register discipline requires
   the answer to be no; if it is not, the extend must be disabled in the
   whitelist fragment before enforcement can harden.

**Resolved**, with the evidence folded into the sections above: whether
`mrconfigid` is settable on QEMU's `tdx-guest` object (yes, 6.2); whether
TDVF folds deployment-varying inputs into the pinned registers (only via two
avoidable boot-path choices, 6.6); whether a guest-side RTMR extend interface
exists on our kernel (yes, LTS 6.18 with ConfigFS-TSM, subject to the
whitelist fragment naming it).

---

## Revision history

- **2026-08-28.** Rebased onto `main` after the aleph-vm 2.0.0 and aleph-rs
  0.17.0 releases. Increment 0 resolved from open-source fixtures (8.1);
  spikes on `mrconfigid`, TDVF measurement and the kernel extend interface
  resolved (6.2, 6.6, 11). Increment 5 promoted to first, now a breaking
  change. Decision 9 and the memory floor added from the `tdx-measure`
  results. `VerificationResult.registers` reshaped from a map to a concrete
  per-platform type to match what 1.3.0 shipped. PCESVN dropped from the
  `rtmr3` commitment. Verifier takes `now` as a parameter.
- **2026-08-20.** Initial approved design.
