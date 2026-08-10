# V-PROGRAM scheduler support: design

**Date:** 2026-07-11
**Status:** Approved design, implementation plan pending
**Repos:** aleph-vm (node side), aleph-vm-scheduler (follow-up stacked on PR #193)

## Goal

Let the Aleph Cloud scheduler command compatible aleph-vm nodes to run V-PROGRAM
messages (verifiable SEV-SNP programs), and replace the too-broad
"AuthenticAMD + sev_snp flag" node matching with advertising that reflects what
the node can actually launch.

Related documents:

- `docs/plans/2026-07-08-confidential-vm-protocol-design.md` (protocol design,
  message schema, runtime bundle)
- aleph-vm-scheduler PR #193 (`od/vprogram-scheduling`): scheduler-side
  V-PROGRAM scheduling, defines the wire contract this design implements
- aleph-message PR #158 (`od/vprogram-schema`): `VerifiableProgramContent`

## Scope

In scope:

1. Accept v-programs on the scheduler-controlled allocation endpoint and thread
   the new message type through the supervisor (parse, dispatch, lifecycle).
2. Structured TEE capability advertising (supported SNP guest vCPU models) plus
   the scheduler follow-up that consumes it.
3. Explicit rejection of v-programs on on-demand execution endpoints.
4. No payment checks for v-programs, including exclusion from the background
   payment sweep.

Out of scope:

- SEV-SNP guest launch. That is the Phase 3 backport (SNP-capable QEMU
  controller). On this stack, a v-program that reaches `start()` fails with a
  clear "SEV-SNP launch backend not available" error; the scheduler observes
  the failure through the executions list it already polls and reschedules.
- Measurement validation (CCN responsibility, pyaleph phase 2).
- Replication / redundancy (deferred in the protocol design).

## Dependencies and base

- `aleph-message` pinned to the git ref of PR #158 (branch `od/vprogram-schema`)
  for development, same pattern as pyaleph PR #1220. **Merge gate: swap the pin
  for a released aleph-message version first.** The pin provides the V-PROGRAM
  message type, `VerifiableProgramContent`, and the message class.
- Scheduler follow-up stacks on aleph-vm-scheduler PR #193, which is not merged
  yet, so wire-model renames there are still free.

## 1. Allocation endpoint (aleph-vm)

### Wire model

`Allocation` (`src/aleph/vm/orchestrator/resources.py`) gains:

```python
v_programs: set[ItemHash] = set()
```

Naming note: PR #193 currently calls this bucket `persistent_programs`, which
collides with the legacy notion of persistent (Firecracker) programs that ride
in `persistent_vms`. The scheduler follow-up renames the field to `v_programs`
everywhere it appears (CRN-bound `Allocation`, public `NodePlan`, dispatcher),
matching the `"v_program"` vm-type string. aleph-vm implements `v_programs`
only; it never accepts the transitional `persistent_programs` name.

### Reconciliation semantics

`update_allocations` merges `v_programs` into the scheduled set and starts each
hash through the existing `start_persistent_vm` path.

Stop semantics diverge deliberately from confidential instances: the current
stop-guard refuses to stop confidential VMs missing from an allocation because
user-paid confidential instances are not scheduler-owned. V-programs are the
opposite: the scheduler is the single source of truth, so **a v-program absent
from the allocation is stopped**, even though it is confidential. The guard
therefore keys on "is a v-program" before the confidential exemption.

`notify_allocation` keeps rejecting non-instance messages. V-programs are
scheduler-designated only and never arrive through notification.

## 2. Message-type threading (aleph-vm)

The gates that must learn the new type:

- `storage.get_message`: accept the v-program message class in the isinstance
  assert.
- `messages.update_message`: v-programs are immutable by schema (`allow_amend`
  is false, enforced at parse time), so no amend resolution: return the message
  unchanged.
- `VmType` (`src/aleph/vm/vm_type.py`): new member for v-programs. The node
  side IPv6 computation uses **type value 4**, mirroring
  `scheduler-events::VmType::ipv6_value()`. A test vector copied from the
  scheduler test suite locks the two implementations together.
- `VmExecution` (`src/aleph/vm/models.py`): new `is_vprogram` property.
  `is_confidential` currently keys on `environment.trusted_execution`, which
  v-programs do not have (they carry a `verification` block instead), so every
  confidential-related branch gets an explicit v-program check. The hypervisor
  for v-programs is unconditionally the QEMU confidential SNP controller; on
  this stack, reaching it raises the clean launch-unavailable error described
  in Scope.

## 3. On-demand rejection (aleph-vm)

`run_code_on_request` / `create_vm_execution` gain an explicit guard: HTTP 400
"V-PROGRAM executions are scheduler-controlled" on `/vm/{item_hash}` and the
hostname-based path. Today v-programs are rejected only by accident (the
storage assert), which section 2 removes, so the explicit gate is required.

## 4. Payment: none, by design

- `POST /control/allocations` performs no payment checks today; that stays
  true for v-programs.
- V-program executions are excluded from the `check_payment` background sweep
  (`src/aleph/vm/orchestrator/tasks.py`).
- The `notify_allocation` payment branches never see v-programs (type gate),
  no change needed there.

Rationale: credit-only enforcement already happens at the CCN (pyaleph
`check_balance`) and at the scheduler. Node-side duplication adds code and
complexity for no security benefit, and node-side payment checks are planned
for removal across all VM types anyway.

## 5. Capability advertising (aleph-vm)

### Wire shape

New platform-keyed block in `/about/usage/system`, mirrored in
`/about/capability`:

```json
"properties": {
  "cpu": { "...": "unchanged" },
  "tee": {
    "sev_snp": {
      "supported_vcpu_types": ["EPYC", "EPYC-v4"]
    }
  }
}
```

- Sibling of `properties.cpu`, not nested inside it: host-CPU facts and
  TEE-launch facts are different things, and this avoids touching the
  aleph-message `CpuProperties` schema (no release dependency).
- Platform-keyed (`sev_snp` today) so `tdx` or GPU-CC slot in later.
- Old schedulers ignore the unknown field; presence of the block doubles as
  the "this node speaks v-program" signal (see section 6).

### Detection: QEMU QMP probe

`supported_vcpu_types` comes from QEMU itself, not from a hardcoded CPUID
table, because only QEMU knows what this exact QEMU build + host kernel +
silicon combination can launch:

- At supervisor startup, spawn a short-lived
  `qemu-system-x86_64 -machine none -accel kvm` with a QMP socket, run
  `query-cpu-definitions`, keep EPYC-family models whose
  `unavailable-features` list is empty, cache for the process lifetime.
- The `tee` block is only emitted when SNP is actually supported. This also
  fixes `check_amd_sev_snp_supported`, which currently lacks the `/dev/sev`
  existence check that the SEV and SEV-ES probes have.
- Probe failure on an SNP host: no `tee` block, log a warning. We never
  advertise what we cannot prove. No static fallback table.

## 6. Scheduler follow-up (aleph-vm-scheduler, stacked on #193)

- Rename `persistent_programs` to `v_programs` (see section 1).
- `NodeSnapshot` gains `snp_vcpu_types: Vec<String>` parsed from
  `properties.tee.sev_snp.supported_vcpu_types` in the node watcher.
- `can_vm_run_on_node`, for v-programs:
  - A node without the `tee` block never receives v-programs (strict gate).
    This naturally excludes older aleph-vm versions that advertise the
    `sev_snp` feature flag but do not understand the `v_programs` allocation
    bucket.
  - At least one of the message's `LaunchMeasurement.vcpu_type` values must be
    in the node's `snp_vcpu_types` set (case-insensitive, consistent with the
    existing feature matching).
  - A measurement without `vcpu_type` matches against a documented default of
    `EPYC` (QEMU's baseline model). Documented in the schema so publishers
    know that omitting `vcpu_type` narrows compatibility rather than widening
    it.
- The existing gates (confidential enabled, `sev_snp` feature, IPv6, vendor,
  architecture) stay as base filters.

## 7. Error handling

- Launch failure (no SNP backend, manifest fetch error, malformed workload)
  surfaces in the execution record and in the executions list the scheduler
  already polls (`GET v2/about/executions/list`), so the scheduler reschedules.
  No new endpoint.
- Message fetch/parse failure at allocation time: reported per-VM in the
  `update_allocations` response, same as instances today.
- QMP probe failure: warning log, no `tee` block advertised (node simply does
  not receive v-programs).

## 8. Testing

aleph-vm:

- Allocation parsing: `v_programs` accepted, old payloads without the key
  still parse.
- Each type-threading gate (storage, update_message, VmType, VmExecution) with
  a canonical v-program fixture (reuse the cross-SDK fixture, item_hash
  `4c319b6bdf98f1e90f2bf8c69da175679fa21ca27d4547bbfa32f77dd3b49fe6`).
- On-demand rejection paths return 400.
- Payment sweep excludes v-program executions.
- `tee` block emission with a mocked QMP probe; absence when SNP unsupported
  or probe fails.
- IPv6 type value 4 against the vector from the scheduler test suite.

aleph-vm-scheduler:

- Extend PR #193's suite: vcpu_type matching, strict tee-block gating, the
  `EPYC` default for untagged measurements, `v_programs` rename round-trip.

Integration:

- Testnet loop with the real scheduler driving `POST /control/allocations`
  against a node running this branch (scheduler-in-the-loop is a stated goal
  for the v-program testnet work).

## Decisions log

| Decision | Choice |
|---|---|
| Launch scope | Wiring only; SNP launch comes from Phase 3. Clean failure at start until then. |
| Compatibility model | Node advertises supported SNP guest vCPU models; scheduler matches measurement `vcpu_type`. |
| Repo scope | Both repos: aleph-vm implementation + scheduler follow-up stacked on #193. |
| Wire shape | `properties.tee.sev_snp.supported_vcpu_types` in `/about/usage/system`. |
| Detection | QMP `query-cpu-definitions` probe, no static fallback. |
| Allocation bucket name | `v_programs` (renamed from #193's `persistent_programs`, which collided with legacy persistent programs). |
| Stop semantics | Scheduler is authoritative for v-programs: absent from allocation means stop, despite being confidential. |
| Payment | No node-side checks anywhere for v-programs; excluded from the payment sweep. |
| Untagged measurements | Scheduler matches them as `EPYC` (documented default). |
