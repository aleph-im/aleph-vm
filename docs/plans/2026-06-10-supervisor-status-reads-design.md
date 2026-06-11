# Agent reads VM status through the Supervisor (off the raw pool)

**Status:** design
**Date:** 2026-06-10
**Series:** message-free supervisor (Phase-0 residual cleanup, after #969 expiry, #970 update-watching, #971 owner-auth, #972 agent-record persistence)
**Stacks on:** `od/wire-supervisor-agent-records` (#972)

## 1. Goal

Remove the remaining agent-side reads of hypervisor **status** off the raw
`pool.executions` dict, routing them through `supervisor.list_vms()` with an
enriched `VmInfo`. After this PR, the allocation reconcile loop and the payment
monitoring tasks learn a VM's running / confidential / GPU state from the
Supervisor abstraction, not by reaching into the pool object. Persistence —
which is a scheduler/agent concept, not a hypervisor one — is sourced from the
agent registry. This closes the §7 "structural `pool.executions` iteration" and
`about_executions` residuals from the agent-record-persistence design.

This is the last of the "agent stops reading VM state off the raw pool" work.
It is *not* a capability migration (backup/restore/confidential/migration remain
stubs) and *not* the process carve-out (Phase 1 proper).

## 2. Background and guiding principle

The message-free-supervisor effort splits the `VmExecution` god-object into an
agent-side concept (message, owner, billing, expiry, update-watching — backed by
`AgentVmRegistry` + the agent DB) and a hypervisor-side `Vm` reached only through
the `Supervisor` abstraction (`supervisor/abc.py`, in-process impl in
`supervisor/inprocess.py`). Phase 0's exit criterion: *every call into hypervisor
functionality from agent code goes through the abstraction.*

Several agent-side paths still iterate the raw `pool.executions` dict to read a
VM's **status** (running? confidential? has GPUs?). This PR moves those reads
behind `list_vms()`/`get_vm()`.

**Guiding principle (decided 2026-06-10):** the Supervisor's description of a VM
stays **precise** — it reports the concrete hypervisor reality (exact TEE
generation, exact attached PCI devices). The **agent** performs any lossy
reduction needed for Aleph-facing APIs (e.g. collapsing "which SEV mode" down to
a boolean "is confidential"). Reductions and Aleph product concepts do **not**
belong in the proto contract.

Three corrollaries of that principle shape the contract change below:

- **`persistent` is not a supervisor fact.** From the hypervisor's point of view
  a VM runs until told to stop; idle-reaping of on-demand programs is an *agent*
  policy. The agent already records persistence in `AgentVmRecord.persistent`
  (`vm_registry.py:40`, persisted via `persist_record`). So persistence is read
  from the registry, and **no `persistent` field is added to `VmInfo`.**
- **Confidentiality is not a boolean.** The launch path knows the precise mode
  (the QEMU confidential controller builds a `sev-guest` object with an
  `AMDSEVPolicy`; SEV-SNP would be a distinct `sev-snp-guest` path). Collapsing
  that to `bool is_confidential` discards precision the supervisor holds. The
  contract carries an enum; the agent reduces it to a bool.
- **GPU presence is not a boolean.** The supervisor knows exactly which PCI
  devices are attached. The contract carries the device list; the agent reduces
  to "has any."

`is_instance` (`VmInfo` field 18) is the *same* category error (an Aleph
product split — `InstanceContent` vs `ProgramContent` — surfacing in the
contract), but it is **pre-existing** and load-bearing for the record-less
labeling fallback in `_vm_type_name` (`views/__init__.py:222`, see the
single-tenant ownership note at `views/__init__.py:265–277`). Redesigning it
(rename to an honest `VmKind`/execution-model signal, or delete and rework the
fallback) is identity/taxonomy work orthogonal to this PR. **Out of scope here;
tracked as a separate contract-cleanup follow-up.**

## 3. Contract change — `VmInfo` enrichment (proto + Python)

`proto/supervisor.proto`. `VmInfo`'s last field is `18` (`is_instance`); the new
fields take `19` and `20`. A new enum is added.

```proto
// The confidential-computing mode a VM is actually running under. Precise by
// design: the agent reduces this to a boolean for Aleph APIs, the contract does
// not pre-reduce it. SEV/SEV-ES are distinguished by the AMD SEV policy; SEV-SNP
// is a distinct launch path.
enum ConfidentialMode {
  CONFIDENTIAL_MODE_NONE    = 0;
  CONFIDENTIAL_MODE_SEV     = 1;   // base AMD SEV
  CONFIDENTIAL_MODE_SEV_ES  = 2;   // SEV with encrypted register state
  CONFIDENTIAL_MODE_SEV_SNP = 3;   // SEV-SNP (distinct sev-snp-guest launch; not yet emitted)
}

message VmInfo {
  // ... fields 1–18 unchanged, including bool is_instance = 18 ...
  ConfidentialMode confidential_mode = 19;     // precise TEE mode; NONE for non-confidential VMs
  repeated GpuDevice gpus = 20;                // exact PCI devices attached to this VM (mirrors HostInfo.gpus)
}
```

`GpuDevice` already exists (`{pci_host, device_id, model, supports_x_vga}`,
used by `HostInfo.gpus`); it is reused verbatim. **No `persistent` field is
added.**

Regenerate the Python stubs (`_pb/supervisor_pb2.py[i]`) using the repo's
existing proto-generation step. Mirror the two fields on the hand-written
`types.VmInfo` dataclass (`supervisor/types.py`):

```python
confidential_mode: ConfidentialMode = ConfidentialMode.NONE
gpus: list[GpuDevice] = field(default_factory=list)
```

(`ConfidentialMode` gets a Python mirror enum next to the existing `VmStatus` /
`Backend` mirrors; `GpuDevice` already has a Python dataclass mirror used by
`HostInfo`.)

## 4. `HostGPU` enrichment — make the GPU detail populatable

`VmExecution.gpus` is `list[HostGPU]`, and `HostGPU` (`resources.py:19`) today
retains only `pci_host` + `supports_x_vga`. The richer `GpuDevice`
(`resources.py:35` — `vendor`, `model`, `device_id`, `device_class`, …) is
matched in `VmExecution.prepare_gpus` (`models.py:469`) and then **discarded**.
To report a complete `GpuDevice` per attached GPU, `HostGPU` must retain two
more fields:

```python
class HostGPU(BaseModel):
    pci_host: str = Field(description="GPU PCI host address")
    supports_x_vga: bool = Field(default=True, description="...")
    device_id: str = Field(description="GPU vendor:device id, e.g. '10de:2504'")
    model: str | None = Field(default=None, description="GPU model name on the Aleph network")
```

`prepare_gpus` populates them from the matched `GpuDevice`
(`device_id=available_gpu.device_id`, `model=available_gpu.model`). Because
`HostGPU` is serialised onto the persisted execution and reloaded for persistent
VMs after a supervisor restart, the two new fields ride along automatically
(they are plain model fields); a test pins that they survive a
persist→reload round-trip.

## 5. In-process plumbing

`supervisor/inprocess.py` — `list_vms()` and `get_vm()` already build a `VmInfo`
from each `VmExecution`. Populate the two new fields:

**`confidential_mode`** — derived from the execution, honestly:

```python
def _confidential_mode(execution) -> ConfidentialMode:
    if not execution.is_confidential:
        return ConfidentialMode.NONE
    policy = getattr(execution.vm, "confidential_policy", 0) or 0
    if policy & AMDSEVPolicy.SEV_ES:        # 0x4
        return ConfidentialMode.SEV_ES
    return ConfidentialMode.SEV
    # SEV_SNP is emitted once a sev-snp-guest launch path exists.
```

`execution.is_confidential` reads `message.environment.trusted_execution`
(`models.py:337`); `confidential_policy` is the `AMDSEVPolicy` int on the
confidential QEMU instance (`qemu_confidential/instance.py:58`). For a
confidential VM whose `vm` object is not yet created (no policy available), fall
back to `SEV` (it is confidential by definition; the precise sub-mode refines
once launched).

**`gpus`** — map each `HostGPU` to a proto/`types` `GpuDevice`:

```python
gpus=[GpuDevice(pci_host=g.pci_host, device_id=g.device_id,
                model=g.model or "", supports_x_vga=g.supports_x_vga)
      for g in execution.gpus]
```

No change to any existing `VmInfo` field. This is a pure addition.

**Join key.** Agent code keys VMs by `vm_hash` (`ItemHash`); `VmInfo.vm_id` is
already `VmId(str(vm_hash))` (that is how `run.py` constructs it). Agent code
maps a `VmInfo` back to its hash via `ItemHash(info.vm_id)`. No new correlation
surface.

## 6. Consumer migrations

### 6a. `update_allocations` stop-loop (`views/__init__.py:582–607`)

Replace `for execution in list(pool.get_persistent_executions())` with a single
`await supervisor.list_vms()` snapshot. Persistence — the filter that
`get_persistent_executions()` provided — moves to the **registry**: iterate only
VMs whose `registry.get(vm_hash).persistent` is true. The stop predicate then
reads:

- running: `info.status is VmStatus.RUNNING` (was `execution.is_running`)
- no GPUs: `not info.gpus` (was `not execution.gpus`)
- not confidential: `info.confidential_mode is ConfidentialMode.NONE`
  (was `not execution.is_confidential`)
- payment tier: from `registry.get(vm_hash)` (already migrated in #972)

The action path (`supervisor.delete_vm`, `delete_port_mappings`,
`registry.forget`) is unchanged. The `vm_type` log label switches from
`execution.is_instance` to the registry record (the agent's own message), with
no pool access.

Result — a clean split: **registry = agent facts (persistent, payment, type);
`VmInfo` = hypervisor facts (status, gpus, confidential mode).** A VM with no
registry record is, as in #972, treated as non-persistent (not scheduler-managed)
and skipped by this loop.

### 6b. Payment grouping / monitoring (`tasks.py`)

`_group_executions_by_payment`, the hold-tier confidential filter
(`tasks.py:392`), the superfluid `started_at` read (`tasks.py:467`), and the
terminal forgotten-VM check (`tasks.py:351`, currently
`list(pool.executions.keys())`) all move to one `supervisor.list_vms()` snapshot
per cycle:

- running-ness from `info.status`
- confidential from `info.confidential_mode is not ConfidentialMode.NONE`
- `started_at` from `info.started_at_ns` (`_datetime_from_ns`)
- the set of live vm ids from the snapshot (`{ItemHash(i.vm_id) for i in infos}`)

Payment tier and address continue to come from the registry. The grouping helper
takes the snapshot (or the supervisor) instead of the pool.

### 6c. Delete `about_executions` (`views/__init__.py:197–209`)

Delete the `/about/executions/details` handler and its route registration. The
existing code comment already records it as a no-consumer residual that "dies in
Phase 1"; it dumps raw `VmExecution` internals that cannot cross the boundary.
The agent-owned `/about/executions` listing (`list_executions`) is already
`VmInfo`-backed and is unaffected.

### Behaviour preservation

The in-process `list_vms()` iterates the same `pool.executions.values()` the
loops do today, so the migrated population is identical — only the access path
changes. The one deliberate semantic shift is sourcing **persistence** from the
registry rather than `execution.persistent`; these agree at create time and the
registry is rehydrated for persistent VMs on restart, so the scheduler-managed
set is unchanged.

## 7. Testing

- **Proto / types:** `VmInfo` carries `confidential_mode` (default `NONE`) and
  `gpus` (default empty); `ConfidentialMode` round-trips through the generated
  stubs. No `persistent` field exists on `VmInfo`.
- **`HostGPU`:** `device_id` + `model` are retained by `prepare_gpus` and survive
  a persist→reload round-trip for a persistent VM.
- **`inprocess.list_vms`/`get_vm`:** fake executions exercise each branch —
  non-confidential → `NONE`; SEV-policy → `SEV`; SEV-ES-policy (`0x4`) → `SEV_ES`;
  a VM with two GPUs → two fully-populated `GpuDevice`s.
- **`update_allocations`:** a persistent VM that is GPU-bearing / confidential /
  on a payment stream is **not** stopped; a plain unscheduled running persistent
  VM **is** — now driven entirely by `VmInfo` + registry, with no
  `pool.get_persistent_executions()` / `execution.*` access. Adapt
  `test_views.py`.
- **Payment:** adapt `test_checkpayment.py` / `test_tasks_registry_reads.py` to
  drive status from a faked `list_vms()` snapshot rather than seeding
  `pool.executions` status.
- **`about_executions` removal:** the route is gone (request returns 404); its
  test is removed.
- **Source guard** (in the spirit of #972's `test_pool_has_no_message_reads`):
  assert the allocation loop and the payment tasks no longer reference
  `pool.executions`, `pool.get_persistent_executions`, `.is_running`,
  `.is_confidential`, or `.gpus` on pool executions.

## 8. Out of scope (explicit)

- **`is_instance` redesign** (rename to a `VmKind`/execution-model signal, or
  delete + rework the record-less fallback) — pre-existing identity/taxonomy,
  separate contract-cleanup follow-up.
- **Domain-mapping aggregate path** (`tasks.py` `on_domains_aggregate_update`
  iterating `pool.executions`, `pool.update_domain_mapping()`) and
  **`recreate_network`'s `execution.vm.tap_interface` reads** — the networking
  migration (bucket C), deferred together.
- **Confidential / backup / restore / migration capability impls** — the
  `Supervisor` ABC stubs (`NotImplementedSupervisorError`); each is its own PR
  (bucket B).
- **The legacy program / Firecracker create path** in `run.py` — deferred by the
  architecture design; it is Phase-1 carve-out #2.
