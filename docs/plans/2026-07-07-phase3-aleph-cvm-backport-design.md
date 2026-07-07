# Phase 3: aleph-cvm feature backport onto the Rust supervisor

**Date:** 2026-07-07
**Status:** Design, approved for planning
**Author:** Olivier Desenfans
**Predecessor:** `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (Phases 0-2), `docs/plans/2026-07-04-rust-supervisor-daemon-design.md` (the completed Rust supervisor port)

## 1. Goal and scope

Graft aleph-cvm's confidential-computing (SEV-SNP) and NUMA capabilities onto the
now-complete Rust supervisor, without breaking three invariants:

- the frozen gRPC contract (`proto/supervisor.proto`),
- the public CRN HTTP API (including the existing SEV/SEV-ES confidential flow),
- the zero-downtime live-VM adoption path (decision 4 of the port).

This is a fresh Phase 3, deliberately wider than the original backport doc, which
scoped Phase 3 as "agent to Rust + real SEV-SNP" and listed NUMA and new TEE
backends as carve-out non-goals. We add NUMA here as a first-class stream. TDX and
NVIDIA-CC stay out: they are enum slots (`TeeBackend::TDX`, `TeeBackend::NVIDIA_CC`)
with zero donor code in either repository.

### 1.1 Donor and target, in one paragraph

The target is the Rust supervisor daemon (`rust/crates/supervisor-daemon`, worktree
branch `od/rust-daemon-inc56`). The donor is aleph-cvm
(`/home/olivier/git/aleph/aleph-cvm`), whose `aleph-compute-node` crate already owns the full Rust QEMU launch path, a NUMA
allocator, hugepage reservation, and SEV-SNP arg generation, and whose `aleph-tee`,
`aleph-attest-agent`, and `aleph-attest-cli` crates already implement the SEV-SNP
attestation stack (report generation/parsing, AMD-KDS cert-chain verification,
attestation-embedded TLS, client-side verifier).

## 2. The chokepoint that shapes everything

The Rust supervisor does **not** own the QEMU launch path today. For persistent
QEMU VMs it writes a controller-JSON slice (`{vm_hash}-controller.json`, built by
`build_written_config` at `lifecycle.rs:1522`) and starts the systemd template unit
`aleph-vm-controller@{vm_hash}.service`. The surviving **Python controller** reads
that JSON and builds/execs the actual `qemu-system` argv. This was decision 5 of the
port: daemon-first, controller ports deferred.

Both feature streams ultimately need to influence the QEMU argv:

- SEV-SNP needs `-object sev-snp-guest,...,policy=0x30000` plus a measured OVMF; the
  Python controller today emits SEV/SEV-ES (`-object sev-guest`), not SNP.
- NUMA memory binding needs `-object memory-backend-memfd,host-nodes=,policy=bind`
  plus hugetlb sizing in the argv.

So the two "big pieces" do not collide with each other (different argv fragments,
different subsystems), but they share one hidden prerequisite: something must own the
QEMU argv in Rust. That is Stream A, the foundation.

## 3. Decomposition into streams

### Stream A -- Rust owns the persistent-QEMU launch (foundation)

Faithfully port the Python QEMU controller into Rust: reproduce its exact argv and
its `aleph-vm-controller@` template-unit runtime model (Phase-2 parity philosophy).
The Python controller stays the parity oracle. Existing live VMs keep their Python
controllers until they cycle; only newly created VMs use the Rust launch path.

We take the *shape* from aleph-cvm's `qemu/args.rs` + `qemu/process.rs` as a
reference for how to structure a Rust argv builder and process supervisor, but we do
**not** adopt aleph-cvm's argv conventions or its `systemd-run` transient-unit model
wholesale, because that would change the argv running production VMs and break the
adoption seam. Feature-specific argv fragments (SNP, NUMA memory binding) are grafted
onto the faithful builder later, as fragments borrowed from aleph-cvm's generators,
not as a builder swap.

**Blocks:** B1, C2.

### Stream B -- SEV-SNP, added alongside the existing SEV/SEV-ES flow

SNP is a *second* confidential model selected by the `tee` backend. The existing
SEV/SEV-ES launch-secret handshake (`/control/machine/{ref}/confidential/{initialize,
measurement,inject_secret}`, backed by `confidential.rs` + `qmp.rs`) is left
untouched for backward compatibility.

- **B1 -- host launch (needs A).** Graft the `-object sev-snp-guest,policy=...` and
  measured-OVMF argv fragment onto the Stream-A builder. Extend the confidential
  create path (`lifecycle.rs:1635 confidential_config_slice`, `build_written_config`,
  `controller_config::ConfidentialConfig`) so an SNP `tee` backend selects the SNP
  launch path. No SEV/SEV-ES behavior changes.

- **B2 -- attestation stack (independent of A, starts immediately).** Port from
  aleph-cvm:
  - `aleph-tee`: SEV-SNP report generation (`/dev/sev-guest` GET_REPORT), report
    parsing, and full AMD-KDS cert-chain verification (VCEK/ASK/ARK, ECDSA-P384,
    VMPL <= 1).
  - `aleph-attest-agent`: in-guest HTTPS sidecar that terminates TLS with an
    attestation-embedded certificate (report_data = SHA-384(pubkey)), reverse-proxies
    to the app, and serves fresh-attestation + secret-injection endpoints.
  - `aleph-attest-cli`: client-side verifier that checks the embedded report during
    the TLS handshake, enforces measurement pinning, and injects secrets over the
    attested channel.
  - The measured-boot guest image: OVMF/kernel/initrd with precomputed
    `sev-snp-measure` values, using **dm-verity** for rootfs integrity as aleph-cvm
    does.

  For SNP, the attested-TLS channel is **direct client to guest**; the CRN is not in
  the attestation trust path. This differs from the SEV/SEV-ES flow (CRN-mediated
  over HTTP), which is exactly why the two models coexist rather than merge.

### Stream C -- NUMA, supervisor auto-places (pack-first)

The supervisor owns NUMA placement. This is a deliberate, scoped exception to
decision 10: decision 10 moved the memory/GPU *reservation buckets* agent-side
because those are client policy in client vocabulary, but NUMA/hugepage placement is
a physical-topology mechanism the agent cannot reason about without host state, so it
stays supervisor-side. The two ledgers are distinct and non-overlapping.

- **C1 -- topology reporting + CPU pinning (independent of A, starts immediately).**
  Populate `HostInfo.numa_nodes` from `/sys/devices/system/node/*` (currently rides
  empty, `service.rs:263-278`). Port aleph-cvm's `NumaAllocator` (`numa.rs`,
  pack-first placement, per-node vCPU/hugepage tracking) as a supervisor-side ledger.
  Enforce CPU pinning via the systemd `AllowedCPUs=` property on the unit the Rust
  daemon already starts, so this needs no QEMU argv change.

- **C2 -- memory NUMA binding + hugepages (needs A).** Graft the
  `memory-backend-memfd,host-nodes=,policy=bind` + hugetlb (`hugetlbsize=1G|2M`) argv
  fragments onto the Stream-A builder. Port aleph-cvm's `hugepages.rs` boot/runtime
  2M/1G reservation across NUMA nodes. Report effective placement in
  `VmInfo.numa_node` (currently always `None`, `service.rs:398`).

## 4. Sequencing: what is actually parallel

```
now, in parallel:  A (foundation)   B2 (attest stack + guest image)   C1 (topology + cpuset)
                        |                     |                              |
A lands ----------------+---------------------+------------------------------+
                        v                     v                              v
then:                  B1 (SNP argv) -- converges with -- B2      C2 (mem bind + hugepages)
```

The genuine parallel seam is **host-side (A / B1 / C1 / C2)** vs
**guest-and-client-side (B2)**, not SEV vs NUMA. Three streams start immediately: A,
B2, C1. The argv-dependent tails B1 and C2 converge after A.

## 5. Architecture decisions (locked 2026-07-07)

1. **Foundation-first.** Rust takes over the persistent-QEMU launch (Stream A) before
   any feature that touches the argv.
2. **Faithful port, then graft fragments.** Reproduce the Python controller's exact
   argv and template-unit model; add only the specific SNP/NUMA argv fragments from
   aleph-cvm. Do not adopt aleph-cvm's builder or transient-unit model wholesale. The
   parity oracle and adoption path stay valid.
3. **SNP alongside, not replacing.** Add the SNP attested-TLS model as a second,
   backend-selected confidential path; leave the SEV/SEV-ES launch-secret flow and
   its endpoints untouched. Zero breakage for existing confidential VMs or clients.
4. **Supervisor auto-places NUMA (pack-first).** Port aleph-cvm's `NumaAllocator`;
   supervisor holds the placement ledger. Reconciled with decision 10 as above
   (placement is mechanism; reservation buckets are policy).
5. **Measured-boot guest image via a backported Nix flake.** Bring aleph-cvm's
   `nix/flake.nix` measured-boot build (OVMF + kernel + initrd + `sev-snp-measure`
   precomputed measurement + dm-verity rootfs) into this repository, rather than
   bolting `sev-snp-measure` onto the existing `runtimes/` image build. It lands as
   its own PR along the way within the B2 stream, decoupled from any single feature
   increment.

## 6. Non-goals (YAGNI)

- TDX and NVIDIA-CC backends (enum slots only, no donor code).
- Any change to the public CRN HTTP API or the existing SEV/SEV-ES confidential flow.
- Encrypted rootfs (LUKS) and compose-rootfs from aleph-cvm: separate product
  features, not required for SNP measured boot.
- Retiring the Python controller for already-running VMs: they cycle out naturally;
  the Python controller entry point stays installed during the transition.
- Agent-to-Rust port: the original doc bundled this into Phase 3, but it is
  orthogonal to the two feature streams here and is tracked separately.
- **In-protocol / message-level confidential support:** wiring SNP so the Aleph
  network can schedule a confidential SNP VM from an `instance` message (agent-side
  allocation, auth, message plumbing). Deferred. For this phase, an SNP VM is created
  **directly via the supervisor gRPC `CreateVm`** with a `tee` config and the
  Nix-built image; the higher-level protocol path comes later.

## 7. Open sub-decisions (resolved in the implementation plan, not blocking this spec)

The guest-image build is now decided (§5.5: backport aleph-cvm's Nix flake). One
sub-decision remains open for the implementation plan:

- **dm-verity scope (B2).** Minimal rootfs-integrity for the measured-boot chain
  only, versus the fuller aleph-cvm verity/roothash machinery (workload volumes,
  encrypted mode). The Nix flake brings the machinery; the open question is how much
  of it we wire into the aleph-vm image path initially.

## 8. Risks

- **Stream A blast radius.** A is a substantial increment before any feature lands,
  and it touches the live-VM launch path. Mitigation: the Python controller stays the
  parity oracle; the existing conformance and real-KVM integration harness (which
  caught the sparse-tar bug that hermetic tests could not) gates every increment.
- **B2 measured-boot reproducibility.** If aleph-vm's images are not built for
  deterministic measurement, precomputed `sev-snp-measure` values will not match the
  running image and attestation will fail. This is the single most fragile point in
  SNP support and drives the §7 guest-image decision.
- **NUMA ledger consistency.** The supervisor-side placement ledger must survive
  daemon restarts and reconcile with adopted VMs (which have no recorded placement).
  Adopted VMs predate NUMA support, so reconcile must treat unknown placement as
  unpinned, not as node 0.

## 9. Validation

Each increment follows the same pipeline the port used (decision 11): subagent
implement, 3-lens adversarial review (parity / Rust robustness / CI-test quality),
consolidated fix batch with a regression test per finding, stacked PR, CI green
including the real-KVM integration leg. Confidential and NUMA paths have no droplet CI
coverage without the right hardware (SEV-SNP host, multi-node NUMA host), so those get
unit tests plus manual hardware checks, mirroring the GPU-flow approach from decision
10.

**Process.** Stacked PRs, each based on the previous branch, looping without pausing
for merges (decision 11). The loop runs until both SEV-SNP (B1 + B2) and NUMA (C1 +
C2) are included. aleph-testnets runs begin once SEV-SNP is implemented, not before.

**aleph-testnets SNP scenario.** Because in-protocol support is deferred (§6), the
testnets harness does not create the SNP VM from an Aleph `instance` message. It
instead calls the supervisor gRPC `CreateVm` **directly** with a `tee` config for the
SNP backend and the Nix-flake-built measured image, then verifies attestation
end-to-end with `aleph-attest-cli`: the embedded SEV-SNP report validates against the
AMD KDS cert chain during the TLS handshake, and the measurement matches the
precomputed `sev-snp-measure` value from the Nix build. This requires a **SEV-SNP
capable host** in the testnets path; provisioning that host is a prerequisite for the
first SNP testnets run and is called out as a dependency, not assumed to be the
default droplet.

## 10. Sources

- Rust supervisor current state: `rust/crates/supervisor-daemon/src/{lifecycle,
  confidential,qmp,controller_config,service,world}.rs`; `proto/supervisor.proto`.
- Donor: aleph-cvm crates `aleph-tee`, `aleph-compute-node` (`qemu/args.rs`,
  `numa.rs`, `hugepages.rs`, `verity.rs`), `aleph-attest-agent`, `aleph-attest-cli`;
  `nix/flake.nix`.
- Prior design: `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`
  (Phase 3 intent, confidential/NUMA seam), `docs/plans/2026-07-04-rust-supervisor-
  daemon-design.md` (port decisions 1-13).
- Existing Python confidential baseline: `src/aleph/vm/hypervisors/qemu_confidential/`,
  `src/aleph/vm/controllers/qemu_confidential/`, `src/aleph/vm/orchestrator/views/
  operator.py` (`/confidential/*` endpoints), `src/aleph/vm/sevclient.py`.
