# Intel TDX support: design

**Date:** 2026-08-20
**Status:** Approved design, ready for implementation planning.
**Branch:** `od/tdx-design` off `dev`.

**Driver:** roadmap / portability proof. There is no Intel TDX hardware in the
fleet today. The purpose of this work is to prove that the `aleph-tee`
abstraction generalizes beyond AMD, and to lock the protocol and schema seams
that would be expensive to change once SEV-SNP ships. Hardware bring-up is
specified here but deliberately not built.

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

1. **The schema and trait seams**, landed now, so that adding TDX later is
   additive rather than a breaking protocol change. The window is open: the
   `aleph-message` TEE schema lives on the unmerged `od/vprogram-schema` branch
   and the latest release is 1.2.0, so `LaunchMeasurement` can still change
   shape for free.
2. **A hardware-free TDX quote verifier** in `aleph-tee`. DCAP verification is
   pure computation: given one captured quote plus its Intel-signed collateral,
   the entire verifier can be implemented and fully tested with no TDX machine
   anywhere. That is the bulk of the hard work, and it is the portability proof
   made concrete rather than asserted.

Out of scope for the buildable increment, specified in section 7: the in-guest
backend, QEMU argument generation, the TDVF nix derivation, QGS/PCCS host
operations, and CRN capability advertisement.

---

## 2. Background: what already fits, and what does not

The existing split isolates TDX's differences remarkably well. Three files'
worth of new code plus two schema changes cover it.

| Layer | SEV-SNP today | TDX | Verdict |
|---|---|---|---|
| `TeeBackend` trait | report produce/parse only | same | unchanged |
| `AttestationReport{tee_type,data}` | AMD blob is sole truth | quote is self-certifying | unchanged |
| `report_data.rs` | domain-separated SHA-384 into 64 bytes | TDX `REPORTDATA` is also 64 bytes | unchanged |
| `VerificationResult.measurement` | one `Vec<u8>` | needs N registers | **changes** |
| `LaunchMeasurement.digest` | one hex scalar | needs N registers | **changes** |
| `snp_min_tcb` aggregate key | numeric SPL ladder | status + advisories + module SVN | **generalizes** |
| verification chain | VCEK/ASK/ARK, pinned ARK | PCK chain, pinned Intel SGX Root CA | new module, same discipline |
| privilege gate | `MAX_ACCEPTED_VMPL = 1` | `TDATTRIBUTES.DEBUG == 0`, `MRSIGNERSEAM == 0` | new module, same discipline |
| launch argv | `sev-snp-guest` object | `tdx-guest` object | new function, spec only |
| evidence source | `/dev/sev-guest` ioctl | ConfigFS-TSM `outblob` | new function, spec only |

Placeholders already in the tree: `aleph_tee::types::TeeType::Tdx` (serializes
as `"tdx"`, already tested), `HostInfo.tdx_supported = 6` and
`TeeBackend.TEE_BACKEND_TDX = 3` in `proto/supervisor.proto`, and a `TeeConfig`
that is already backend-agnostic.

### 2.1 Two properties better than expected

- **`vcpu_type` is not a TDX measurement input.** A TD's initial vCPU state is
  defined by the TDX module, not by the QEMU CPU model, so TDX
  `LaunchMeasurement` entries carry `vcpu_type: None`: the same shape section 10
  of the protocol design predicted for IGVM. The mixed-fleet problem SNP has
  (distinct digests for EPYC-v3 and EPYC-v4) does not exist on TDX.
- **Verification needs no Intel API key.** The PCK certificate chain is embedded
  in the quote itself (cert data type 5). Only TCB Info, QE Identity and CRLs
  are fetched; all three are free, unauthenticated, and Intel-signed, so they
  are verifiable from any mirror or a local PCCS. The trust path never depends
  on who served the collateral.

### 2.2 One property worse than expected

The CCN cannot recompute RTMRs. This drives the boot-recipe decision in
section 6.

---

## 3. Decisions

1. **`LaunchMeasurement` carries a register map, not a scalar digest**, with a
   **closed** required-key set validated per platform. An unknown register key
   is as schema-invalid as an unknown platform. Adding a register later is a
   schema release, which is the correct fail-closed stance.
2. **The `TeeBackend` trait is unchanged.** `get_report` stays synchronous and
   returns a quote; the TDX backend hides the host round trip inside a blocking
   ConfigFS-TSM `outblob` read. No async infection of `SevSnpBackend` or
   `NoneBackend`, no split report/quote methods that SNP would pay for and not use.
3. **The settings-aggregate TCB floor generalizes to `tee_min_tcb`**, keyed by
   TEE. The TDX block is an accepted-status list, an advisory-ID denylist, and a
   TDX-module SVN floor. G1's architecture is preserved intact: client-side
   enforcement, compiled-in baseline, aggregate raises only.
4. **The per-deployment binding moves from the measured cmdline into
   `MRCONFIGID`** for TDX. This is what makes CCN validation tractable without
   emulating TDVF's measurement protocol. See section 6.
5. **Pinned registers are `{mrtd, rtmr1, rtmr2, mrconfigid}`.** `rtmr0` is
   deliberately not pinned: it varies with vCPU count and memory map, which are
   deployment parameters, not code identity. `rtmr3` is not pinned either, but
   it is not free; see decision 8.
6. **We own the quote parsing and the policy.** Third-party DCAP crates are used
   as a differential-test oracle only, never in the trust path. Rationale in
   section 5.3.
7. **The CCN validates `rtmr1`/`rtmr2` by comparison against the runtime
   manifest**, not by derivation from first principles. An accepted, documented
   weakening relative to SNP; see section 6.3.
8. **`rtmr3` is reserved for a launch-TCB commitment**, extended exactly once by
   the measured initrd. This is what recovers a cryptographic launch-TCB gate on
   a platform whose quotes otherwise report only the current TCB. The register
   is *derived*, not pinned: it appears in no message, and the client recomputes
   the expected value rather than comparing against a declared constant. The
   semantics are reserved from v1; client enforcement starts as warn-on-mismatch
   and hardens once real hardware has exercised it. See section 6.5.

---

## 4. Schema changes

### 4.1 `LaunchMeasurement` (aleph-message)

`digest: str` becomes `registers: Dict[str, str]`:

```python
class TeePlatform(str, Enum):
    sev_snp = "sev_snp"
    tdx = "tdx"


# Required register keys per platform. A message declaring a key outside this
# set, or omitting one inside it, is schema-invalid: the same fail-closed
# stance TeePlatform already takes for unknown platforms.
_REQUIRED_REGISTERS: Dict[TeePlatform, FrozenSet[str]] = {
    TeePlatform.sev_snp: frozenset({"launch"}),
    TeePlatform.tdx: frozenset({"mrtd", "rtmr1", "rtmr2", "mrconfigid"}),
}

# Every pinned register on every platform is 48 bytes.
_REGISTER_HEX_LENGTH = 96


class LaunchMeasurement(HashableModel):
    platform: TeePlatform
    registers: Dict[str, str]
    vcpu_type: Optional[str] = None   # direct-boot SNP only; None for tdx
```

The `check_digest_length` validator becomes `check_registers`: the key set must
equal `_REQUIRED_REGISTERS[platform]` exactly, and every value must be
`_REGISTER_HEX_LENGTH` lowercase hex characters.

SEV-SNP migrates from `digest: "<hex>"` to `registers: {"launch": "<hex>"}`.
Because `od/vprogram-schema` is unmerged and unreleased, there is no wire
compatibility burden.

`rtmr3` is deliberately absent from the TDX key set. It carries the launch-TCB
commitment (section 6.5), which the client *derives* rather than compares
against a declared constant, so it needs no message field. Keeping it out of the
schema is also what lets enforcement harden later without a protocol change.

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

### 4.4 `VerificationResult` (aleph-tee, Rust)

Symmetric to 4.1: `measurement: Vec<u8>` becomes
`registers: BTreeMap<String, Vec<u8>>`. SNP emits `{"launch": ...}`. The
existing doc-comment invariant ("derived from the AMD-verified blob, NOT a
caller-supplied copy") carries over verbatim and applies per register.

---

## 5. `aleph-tee::tdx`

### 5.1 Module layout

Mirrors `sev_snp/` so the two read as siblings:

```
aleph-tee/src/tdx/
  mod.rs          pub use backend::TdxBackend;
  quote.rs        parse: header (48B) -> TD report body -> signature data -> cert data
  certs.rs        pinned Intel SGX Root CA; PCK chain; SGX extension OIDs
  collateral.rs   TCB Info / QE Identity / CRL fetch plus Intel-signature check
  verify.rs       verify_tdx_quote(): orchestration and policy gates
  backend.rs      TdxBackend (hardware-gated body, spec only for now)
  qemu.rs         tdx_qemu_args() (spec only)
```

`quote.rs` handles both body shapes: `TdReport10` (584 bytes: `tee_tcb_svn`,
`mrseam`, `mrsignerseam`, `seam_attributes`, `td_attributes`, `xfam`, `mrtd`,
`mrconfigid`, `mrowner`, `mrownerconfig`, `rtmr0..3`, `report_data`) and TDX
1.5's `TdReport15` (648 bytes, adding `tee_tcb_svn2` and `mrservicetd`).

Extractors mirror the SNP ones: `extract_report_data(&body) -> [u8; 64]` and
`extract_registers(&body) -> BTreeMap<&'static str, [u8; 48]>`.

### 5.2 `verify_tdx_quote()`

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
10. Return `VerificationResult` with the register map and `report_data`.

As with SNP, a `valid: true` verdict is **not** sufficient to trust a guest. It
says only "this is a genuine Intel-attested TD on a platform at an acceptable
TCB". The caller must still pin the registers against the message's declared
`LaunchMeasurement`, bind freshness through `report_data`, and check the derived
`rtmr3` launch-TCB commitment (section 6.5). The existing `report_data.rs`
domain-separated schemes apply unchanged.

### 5.3 On third-party crates

`dcap-qvl` and `dcap-rs` are pure-Rust DCAP verifiers; Intel's own QVL is FFI to
the SGX SDK. The recommendation is to own the parsing and the policy, and to use
a third-party crate only as a differential-test oracle.

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

Proposed builtin baseline: accept `UpToDate` and `SWHardeningNeeded`; reject
everything else.

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

With 6.5 in place the residual risk is not "TDX cannot express the gate" but
"TDX expresses the gate through a guest-side mechanism whose kernel interface
needs confirming" (spike 5). Until that spike lands and client enforcement
hardens, treat the gap as open and rely on 7.6.

---

## 6. Boot recipe and CCN validation

### 6.1 The problem

Protocol decision 3 requires checked redundancy: messages carry measurements
*and* their inputs, and the CCN verifies consistency. For SNP the CCN recomputes
the launch digest with `sev-snp-measure`. For TDX:

- `mrtd` is recomputable: parse TDVF metadata, hash the TD pages. Cheap, and
  TDVF is the smallest artifact.
- `rtmr1` and `rtmr2` are **not** practically recomputable. They are extended by
  TDVF during boot, so reproducing them means emulating TDVF's measurement
  protocol and event ordering. That is the `sev-snp-measure` fragility section
  10 of the protocol design already complains about, but worse and more tightly
  version-coupled.

Publishing expected RTMRs in the runtime manifest (content-addressed,
publisher-measured at nix build time) and having the CCN compare rather than
recompute solves `rtmr1` (the kernel). It **fails for `rtmr2`**, because TDVF
measures the kernel cmdline there, and the cmdline is exactly where the SNP
recipe puts the per-deployment `workload_roothash`. A per-deployment cmdline
means a per-deployment `rtmr2`, which no manifest can publish.

### 6.2 The recipe: `tdx-mrconfigid-v1`

Move the per-deployment binding out of the cmdline and into `MRCONFIGID`.

`MRCONFIGID` is a 48-byte host-settable field that the TDX module measures into
the TD and echoes in every quote. Set it to the SHA-384 of a **deployment
descriptor**: a small host-delivered blob carrying the workload roothash, any
verified-volume roothashes, and whatever a later version adds. The measured
initrd reads the descriptor, hashes it, compares against `MRCONFIGID` from its
own local TDREPORT (cheap: no QGS round trip needed for a TDREPORT), and fails
closed on mismatch.

A lying CRN has no move: either it sets `MRCONFIGID` honestly, in which case the
client's pin against the message catches any wrong value, or it sets it
dishonestly, in which case the guest refuses to boot.

**Descriptor delivery.** The descriptor must reach the guest over a channel that
does not perturb `rtmr1` or `rtmr2`, or the recipe defeats its own purpose by
making those registers per-deployment again. The descriptor's integrity comes
entirely from the `MRCONFIGID` comparison, so the channel needs no integrity
property of its own: any unmeasured host-to-guest path works. The default is a
small raw virtio-blk device (the same shape as the existing cloud-init drive),
read by the initrd before it derives the verity roothash. Confirming that TDVF
does not fold attached block devices into `rtmr1`/`rtmr2` is spike 2 in
section 11.

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
mirrored one, so two recipes are maintained. The alternatives are worse: emulate
TDVF measurement in pyaleph indefinitely, or drop `rtmr2` from the pin set and
lose cmdline and initrd integrity entirely.

### 6.3 Runtime manifest

The manifest (section 11 of the protocol design) gains a per-recipe
`measurements` block publishing the expected `mrtd`, `rtmr1` and `rtmr2` for the
bundle, measured once at build time by the publisher.

CCN validation for a `mode="tdx"` message then becomes:

- recompute `mrtd` from the manifest-pinned TDVF artifact and compare (genuine
  checked redundancy on the firmware);
- compare `rtmr1` and `rtmr2` against the manifest;
- recompute `mrconfigid` from message fields alone (a pure hash, microseconds).

**Accepted weakening:** for `rtmr1` and `rtmr2` the CCN checks *consistency with
the manifest*, not *derivation from first principles*. The mitigation is that
the manifest is content-addressed and immutable, and its values are
independently reproducible by anyone who boots the bundle once, so a lying
publisher is caught by any single verifier.

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
   rtmr3 = extend(0, SHA-384(DOMAIN_LAUNCH_TCB || cpusvn || pcesvn || tee_tcb_svn))
   ```

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
later extension by workload code breaks verification. This is a constraint the
runtime bundle owns, and it is the reason the semantics are reserved from v1
even though enforcement is not. Adding the extend later would change the initrd,
therefore change `rtmr1`/`rtmr2`, therefore force every published bundle to
re-version.

**Why `rtmr3` specifically.** `rtmr0` and `rtmr1` are firmware-owned. `rtmr2` is
already in the pinned set, so extending it would break the pin. `rtmr3` is the
only register both guest-extendable and free.

**Rollout.** Client enforcement is warn-on-mismatch in v1 and hard-fail once
spike 5 confirms the kernel interface and real hardware has exercised the path.
`rtmr3` never appears in a message: it is derived, so no schema field is needed
and hardening later is not a protocol change.

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
  `argv_parity_tdx.rs` conformance fixture set.
- **Proto:** `ConfidentialMode.CONFIDENTIAL_MODE_TDX = 4`, and an `mrconfigid`
  field on `TeeConfig`. Additive only.
- **Nix:** a `tdvf.nix` building edk2 `OvmfPkg/IntelTdx/IntelTdxX64.dsc`,
  reproducible because `mrtd` is pinned; and a guest kernel configuration with
  `CONFIG_INTEL_TDX_GUEST`, `CONFIG_TDX_GUEST_DRIVER` and `CONFIG_TSM_REPORTS`.
  The current 6.18 guest kernel is recent enough.

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

Tier 1, all in CI, no hardware anywhere:

- **Quote parsing** against golden vectors, covering both `TdReport10` and
  `TdReport15` bodies.
- **Chain verification**: the pinned-root happy path plus one test per reject
  reason (forged root, broken chain, revoked certificate, wrong
  QE-report-to-attestation-key binding, tampered signature). This mirrors how
  `sev_snp/verify.rs` already exercises each reject path individually.
- **Collateral**: cached Intel-signed TCB Info and QE Identity as fixtures;
  assert signature verification and the TCB-level walk against hand-built
  ladders.
- **Policy**: table-driven over all seven statuses crossed with the override
  matrix; explicitly assert that `Revoked` is non-overridable.
- **Platform gates**: one test per gate, each asserting the reject.
- **Schema**: closed-key-set validation, the SNP `{"launch"}` migration, and
  `mrconfigid` injection rejection (mirroring `test_policy_injection_is_rejected`).
- **Differential**: our verifier against `dcap-qvl` over the same fixtures, as a
  dev-dependency only, never in the trust path.
- **Launch-TCB state machine (7.6)**: table-driven over the four states, plus a
  persistence round trip asserting a recorded launch TCB survives a supervisor
  restart, plus the degrade-to-baseline path when the settings aggregate is
  unreachable. All hardware-free.
- **`rtmr3` commitment (6.5)**: assert the client's recomputation matches a
  fixture quote; assert a mismatched in-band launch TCB is rejected; assert a
  second extension breaks verification (the register-discipline constraint);
  assert `DOMAIN_LAUNCH_TCB` cannot collide with `DOMAIN_KEY` or `DOMAIN_FRESH`,
  mirroring the existing domain-separation tests in `report_data.rs`.

Tier 2 (`#[ignore]`, requires a Xeon): `get_report`, argv boot, end-to-end
RA-TLS.

---

## 9. Increments and sequencing

| # | Increment | Repo | Note |
|---|---|---|---|
| 0 | Obtain a real TDX quote plus its collateral as test fixtures | n/a | **Everything is blocked on this.** Azure DCesv5 / GCP C3, or Intel DCAP samples. |
| 1 | `registers` map, `TeePlatform.tdx`, `mode="tdx"`, policy-absent validator | aleph-message | **Urgent**: must land before the 1.2.x release |
| 2 | `tdx/quote.rs` parsing and extractors | aleph-vm | additive |
| 3 | DCAP chain verification (steps 2 to 6) | aleph-vm | additive |
| 4 | Collateral, TCB walk, platform gates (steps 7 to 9) | aleph-vm | additive |
| 5 | `VerificationResult.registers` | aleph-vm | touches SNP; land before the SNP client ships |
| 6 | `tee_min_tcb` and `TdxTcbPolicy` | aleph-rs | generalizes G1 |
| 7 | Spec: `tdx-mrconfigid-v1` recipe, manifest `measurements` block, QGS runbook | aleph-vm docs | spec only |
| 8 | Node-side launch-TCB tracking (7.6): persisted launch TCB, aggregate floor read, four-state machine, operator surface | aleph-vm | TEE-agnostic; buildable for SNP today |
| 9 | `DOMAIN_LAUNCH_TCB` + client-side `rtmr3` recomputation, warn-on-mismatch (6.5) | aleph-vm, aleph-rs | hardware-free; the guest-side extend ships with 7 |

Increments 1 and 5 are the time-sensitive ones. Increments 2 to 4 are pure
addition and can proceed at any pace.

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
- **All hardware bring-up**: `TdxBackend`, argv, TDVF nix derivation, QGS/PCCS
  operations, capability detection. Specified in section 7, not built.
- **NVIDIA confidential computing composition.** TDX is a host TEE under
  confidential GPUs, but GPU attestation composition is its own design.
- **IGVM for TDX.** TDX is in the IGVM format but not in QEMU's IGVM loader, and
  CRN hosts run QEMU well below the required version. Section 10 of the protocol
  design already tags IGVM as a future recipe; nothing here changes that.
- **Hard-fail enforcement of the `rtmr3` commitment.** Reserved and implemented
  as warn-on-mismatch now (increment 9); hardening waits on spike 5 and on real
  hardware exercising the path.
- **TD-preserving update semantics** beyond noting in 5.6 that they advance
  `tee_tcb_svn` under a running TD, which is precisely the event `rtmr3` is
  designed to survive.
- **TDX for the legacy SEV `mode="sev"` flow.** There is no TDX analogue of the
  CRN-mediated launch-secret handshake, and none is wanted.

---

## 11. Open questions (spikes, not design forks)

1. **Does QEMU's `tdx-guest` object expose `mrconfigid` as a settable base64
   property?** Believed yes, alongside `mrowner` and `mrownerconfig`, but it
   needs confirming against the QEMU version we would target. Decision 4 depends
   on it; if it is not settable, the fallback is per-deployment `rtmr2` plus
   TDVF measurement emulation in the CCN, which is materially worse.
2. **Is anything deployment-varying folded into `rtmr1` or `rtmr2`?** Under the
   6.2 recipe the cmdline is fixed per runtime, so which of the two registers
   receives it no longer matters. What does matter is whether TDVF measures
   anything that differs between deployments of the same bundle: the descriptor
   block device, the VM UUID, ACPI tables, or boot order. Any such input makes
   the affected register unpublishable in the manifest and forces it out of the
   pinned set. This is the highest-risk spike in the list.
3. **Does our nix guest kernel's ConfigFS-TSM `outblob` yield a full quote or a
   bare TDREPORT?** Determines whether decision 2 holds as written or needs the
   `/dev/tdx_guest` `GET_QUOTE` ioctl fallback.
4. **Which TCB statuses do real Sapphire Rapids and Emerald Rapids platforms
   actually report?** The 5.5 baseline rejects `ConfigurationNeeded`; if that
   status is near-universal in practice, the baseline needs revisiting before
   any hardware lands.
5. **Is a guest-side RTMR extend interface available and stable on our kernel?**
   Decision 8 and section 6.5 rest on it. Mainline Linux exposure of RTMR
   extension has been contentious, and the usable path (a `tsm` interface, or
   the `/dev/tdx_guest` extend ioctl) needs confirming on the 6.18 guest kernel.
   This spike gates hardening client enforcement from warn to hard-fail; it does
   not gate reserving the register, which is why decision 8 is safe to take now.
   If the interface turns out unusable, section 5.6's residual risk is reinstated
   in full and section 7.6 becomes the only mitigation.
