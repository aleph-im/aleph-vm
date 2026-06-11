# Agent reads VM status through the Supervisor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move the agent's remaining reads of hypervisor *status* off the raw `pool.executions` dict onto `supervisor.list_vms()` with an enriched, precise `VmInfo`.

**Architecture:** Add `ConfidentialMode` (enum) and `repeated GpuDevice gpus` to the `VmInfo` contract (proto + Python DTO) — the supervisor stays precise, the agent reduces to booleans. `persistent` is *not* added; the agent sources it from `AgentVmRegistry`. Enrich `HostGPU` so the GPU detail is populatable. Then migrate `update_allocations` and the payment-monitoring tasks to read status from `VmInfo` and identity/payment from the registry, and delete the dead `about_executions/details` endpoint.

**Tech Stack:** Python 3.14, aiohttp, pydantic v2, protobuf/grpc_tools, pytest. Design doc: `docs/plans/2026-06-10-supervisor-status-reads-design.md`. Stacks on `od/wire-supervisor-agent-records` (#972).

**Test runner (used throughout):**
```bash
VENV=/home/olivier/git/aleph/aleph-vm/.testvenv/bin/python
RUN="ALEPH_VM_CACHE_ROOT=$TMPDIR/c ALEPH_VM_EXECUTION_ROOT=$TMPDIR/e PYTHONPATH=src $VENV -m pytest -p no:warnings"
# e.g.  eval "$RUN tests/supervisor/test_supervisor_types.py -q"
```

**Key facts the engineer needs (verified against the tree):**
- `VmInfo`'s last proto field is `18` (`is_instance`); the Python DTO is `@dataclass(frozen=True)` at `src/aleph/vm/supervisor/types.py:184`. `is_instance` is **left untouched** (a separate follow-up handles it).
- Proto is regenerated with `python scripts/generate_proto.py`; CI runs `scripts/check_proto_clean.sh` (checks `supervisor_pb2.py` + `_grpc.py` + `proto/`, **not** the `.pyi`). Needs `grpc_tools` + `mypy-protobuf` (already in the venv).
- There is **no** proto↔`VmInfo` mapping layer yet; the in-process path constructs `types.VmInfo` directly in `inprocess.py:_to_vm_info` (`135`).
- `types.GpuDevice` (`types.py:274`) already has exactly `{pci_host, device_id, model, supports_x_vga}` — reuse it.
- `AMDSEVPolicy` (`aleph_message.models.execution.environment`) is an `IntEnum`; `SEV_ES = 4`.
- `HostGPU` (`resources.py:19`) is built in **two** places: `models.py:560` (message path, has the rich `GpuDevice`) and `controllers/qemu/instance.py:156` (spec path, only `pci_host`+`supports_x_vga`). New `HostGPU` fields **must** default, or the spec path breaks.
- `compute_required_balance/credit/flow` (`orchestrator/payment.py:162-185`) read **only** `execution.vm_hash` (`fetch_execution_price(execution.vm_hash, ...)`). Their only callers are in `tasks.py`.
- `is_after_community_wallet_start(dt: datetime | None)` (`orchestrator/utils.py:73`).

---

## File structure

| File | Responsibility | Change |
| --- | --- | --- |
| `proto/supervisor.proto` | the contract | add `ConfidentialMode` enum + 2 `VmInfo` fields |
| `src/aleph/vm/supervisor/_pb/*` | generated bindings | regenerate |
| `src/aleph/vm/supervisor/types.py` | Python DTO mirror | add `ConfidentialMode` enum + 2 `VmInfo` fields |
| `src/aleph/vm/resources.py` | `HostGPU` | add `device_id`, `model` (defaulted) |
| `src/aleph/vm/models.py` | `prepare_gpus` | populate the 2 new `HostGPU` fields |
| `src/aleph/vm/supervisor/inprocess.py` | `_to_vm_info` | populate `confidential_mode`, `gpus` |
| `src/aleph/vm/orchestrator/views/__init__.py` | `update_allocations`, delete `about_executions` | migrate stop-loop; remove endpoint |
| `src/aleph/vm/orchestrator/payment.py` | cost fns | take `vm_hash`es, not executions |
| `src/aleph/vm/orchestrator/tasks.py` | payment monitoring | grouping + `check_payment` off `list_vms` |
| `src/aleph/vm/orchestrator/supervisor.py` | routes | remove `about_executions` route+import |

---

## Task 1: Contract — `ConfidentialMode` enum + `VmInfo` fields (proto + Python)

**Files:**
- Modify: `proto/supervisor.proto` (VmInfo at lines 187-214; add enum near the other top-level enums)
- Regenerate: `src/aleph/vm/supervisor/_pb/supervisor_pb2.py`, `_grpc.py`, `.pyi`
- Modify: `src/aleph/vm/supervisor/types.py` (enums block ~25-37; `VmInfo` at 184-208)
- Test: `tests/supervisor/test_supervisor_types.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_types.py`:

```python
"""VmInfo contract carries precise TEE mode + attached GPUs; no agent-only fields."""

from dataclasses import fields

from aleph.vm.supervisor.types import (
    Backend,
    ConfidentialMode,
    GpuDevice,
    VmId,
    VmInfo,
    VmStatus,
)


def _minimal_vm_info(**overrides) -> VmInfo:
    base = dict(
        vm_id=VmId("vm-a"),
        status=VmStatus.RUNNING,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    base.update(overrides)
    return VmInfo(**base)


def test_vm_info_defaults_are_non_confidential_and_gpuless():
    info = _minimal_vm_info()
    assert info.confidential_mode is ConfidentialMode.NONE
    assert info.gpus == []


def test_vm_info_carries_precise_mode_and_devices():
    gpu = GpuDevice(pci_host="0000:01:00.0", device_id="10de:2504", model="RTX 3090", supports_x_vga=True)
    info = _minimal_vm_info(confidential_mode=ConfidentialMode.SEV_ES, gpus=[gpu])
    assert info.confidential_mode is ConfidentialMode.SEV_ES
    assert info.gpus[0].device_id == "10de:2504"


def test_vm_info_has_no_persistent_field():
    """persistent is an agent fact (registry), never on the supervisor contract."""
    assert "persistent" not in {f.name for f in fields(VmInfo)}


def test_confidential_mode_members():
    assert [m.name for m in ConfidentialMode] == ["NONE", "SEV", "SEV_ES", "SEV_SNP"]
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
eval "$RUN tests/supervisor/test_supervisor_types.py -q"
```
Expected: FAIL — `ImportError: cannot import name 'ConfidentialMode'`.

- [ ] **Step 3: Edit the proto**

In `proto/supervisor.proto`, add this enum immediately above `message VmInfo {` (line 187):

```proto
// The confidential-computing mode a VM is actually running under. Precise by
// design: the agent reduces this to a boolean for Aleph APIs; the contract does
// not pre-reduce it. SEV vs SEV-ES is distinguished by the AMD SEV policy;
// SEV-SNP is a distinct launch path (not yet emitted by the in-process backend).
enum ConfidentialMode {
  CONFIDENTIAL_MODE_NONE    = 0;
  CONFIDENTIAL_MODE_SEV     = 1;
  CONFIDENTIAL_MODE_SEV_ES  = 2;
  CONFIDENTIAL_MODE_SEV_SNP = 3;
}
```

Inside `message VmInfo`, after `bool is_instance = 18;` (line 213), add:

```proto
  ConfidentialMode confidential_mode = 19;   // precise TEE mode; NONE for non-confidential VMs
  repeated GpuDevice gpus = 20;              // exact PCI devices attached to this VM (mirrors HostInfo.gpus)
```

- [ ] **Step 4: Regenerate the bindings**

```bash
cd /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-expiry
$VENV scripts/generate_proto.py
```
Expected: prints the protoc command + "rewrote ... to use relative import", exit 0.

- [ ] **Step 5: Mirror in the Python DTO**

In `src/aleph/vm/supervisor/types.py`, add the enum next to `Backend`/`VmStatus` (after line 37):

```python
class ConfidentialMode(Enum):
    NONE = "none"
    SEV = "sev"
    SEV_ES = "sev_es"
    SEV_SNP = "sev_snp"
```

In the `VmInfo` dataclass, after `is_instance: bool = False` (line 208), add:

```python
    # Precise confidential-computing mode (the agent reduces to a bool for Aleph
    # APIs). NONE for non-confidential VMs.
    confidential_mode: ConfidentialMode = ConfidentialMode.NONE
    # Exact PCI devices attached to this VM; mirrors HostInfo.gpus.
    gpus: list[GpuDevice] = field(default_factory=list)
```

(`field` is already imported at `types.py:11`; `GpuDevice` is defined below `VmInfo` at line 274 — fine, the default factory is evaluated lazily.)

- [ ] **Step 6: Run the test + proto-clean check**

```bash
eval "$RUN tests/supervisor/test_supervisor_types.py -q"
bash scripts/check_proto_clean.sh
```
Expected: tests PASS; "proto bindings are up to date."

- [ ] **Step 7: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb/ src/aleph/vm/supervisor/types.py tests/supervisor/test_supervisor_types.py
git commit -m "feat(supervisor): VmInfo carries ConfidentialMode + attached GpuDevices"
```

---

## Task 2: Enrich `HostGPU` with `device_id` + `model`

**Files:**
- Modify: `src/aleph/vm/resources.py:19-25` (`HostGPU`)
- Modify: `src/aleph/vm/models.py:559-564` (`prepare_gpus` HostGPU construction)
- Test: `tests/supervisor/test_host_gpu_detail.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_host_gpu_detail.py`:

```python
"""HostGPU retains device_id + model so the supervisor can report full GpuDevices."""

from aleph.vm.resources import GpuDevice, GpuDeviceClass, HostGPU


def test_hostgpu_fields_default_for_spec_path():
    """The spec path (controllers/qemu/instance.py) builds HostGPU with only
    pci_host + supports_x_vga; the new fields must default, not break it."""
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True)
    assert gpu.device_id == ""
    assert gpu.model is None


def test_hostgpu_round_trips_detail():
    """device_id + model survive serialization (persist -> reload of a VM)."""
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True, device_id="10de:2504", model="RTX 3090")
    reloaded = HostGPU.model_validate(gpu.model_dump())
    assert reloaded.device_id == "10de:2504"
    assert reloaded.model == "RTX 3090"


def test_prepare_gpus_retains_detail():
    """prepare_gpus must copy device_id + model off the matched GpuDevice."""
    from types import SimpleNamespace

    from aleph.vm.models import VmExecution

    available = [
        GpuDevice(
            vendor="NVIDIA",
            model="RTX 3090",
            device_name="GA102",
            device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
            pci_host="0000:01:00.0",
            device_id="10de:2504",
            compatible=True,
        )
    ]
    # Minimal message stub: one GPU requirement matching device_id.
    message = SimpleNamespace(
        requirements=SimpleNamespace(gpu=[{"vendor": "NVIDIA", "device_id": "10de:2504", "device_name": "GA102"}])
    )
    execution = VmExecution.__new__(VmExecution)
    execution.spec = SimpleNamespace(message=message)
    execution.gpus = []

    # prepare_gpus is sync and reads only execution.spec (MessageSpec) + the arg.
    VmExecution.prepare_gpus(execution, available)

    assert execution.gpus[0].device_id == "10de:2504"
    assert execution.gpus[0].model == "RTX 3090"
```

> Note on the stub: `prepare_gpus` checks `isinstance(self.spec, MessageSpec)`. If the `SimpleNamespace` stub trips that guard at runtime, replace `execution.spec` with a real `MessageSpec` wrapping a loaded test instance message (the `examples/instance_message_from_aleph.json` fixture other supervisor tests use), or assert against the construction directly. The behavioral contract under test is: *the matched `GpuDevice`'s `device_id` and `model` reach the `HostGPU`.*

- [ ] **Step 2: Run it to make sure it fails**

```bash
eval "$RUN tests/supervisor/test_host_gpu_detail.py -q"
```
Expected: FAIL — `device_id`/`model` not on `HostGPU` (pydantic `extra='forbid'` rejects them) / `prepare_gpus` doesn't set them.

- [ ] **Step 3: Add the fields to `HostGPU`**

In `src/aleph/vm/resources.py`, replace the `HostGPU` body (lines 22-23):

```python
class HostGPU(BaseModel):
    """Host GPU properties detail."""

    pci_host: str = Field(description="GPU PCI host address")
    supports_x_vga: bool = Field(description="Whether the GPU supports x-vga QEMU parameter", default=True)
    device_id: str = Field(description="GPU vendor:device id, e.g. '10de:2504'", default="")
    model: str | None = Field(description="GPU model name on the Aleph network", default=None)

    model_config = ConfigDict(extra="forbid")
```

- [ ] **Step 4: Populate them in `prepare_gpus`**

In `src/aleph/vm/models.py`, the `HostGPU(...)` call (lines 560-563) becomes:

```python
                        gpus.append(
                            HostGPU(
                                pci_host=available_gpu.pci_host,
                                supports_x_vga=available_gpu.has_x_vga_support,
                                device_id=available_gpu.device_id,
                                model=available_gpu.model,
                            )
                        )
```

- [ ] **Step 5: Run the test + the existing GPU tests**

```bash
eval "$RUN tests/supervisor/test_host_gpu_detail.py -q"
eval "$RUN tests/ -k 'gpu or Gpu' -q"
```
Expected: new tests PASS; no regressions in existing GPU tests.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/resources.py src/aleph/vm/models.py tests/supervisor/test_host_gpu_detail.py
git commit -m "feat(resources): HostGPU retains device_id + model for supervisor reporting"
```

---

## Task 3: In-process supervisor populates `confidential_mode` + `gpus`

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py` (imports; `_to_vm_info` at 135-157; add `_confidential_mode` helper)
- Test: `tests/supervisor/test_inprocess_vm_info.py` (create)

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_inprocess_vm_info.py`:

```python
"""_to_vm_info reports the precise TEE mode and the attached GPUs."""

from types import SimpleNamespace

from aleph.vm.resources import HostGPU
from aleph.vm.supervisor.inprocess import _to_vm_info
from aleph.vm.supervisor.types import ConfidentialMode


def _execution(*, confidential=False, policy=0, gpus=()):
    times = SimpleNamespace(
        defined_at=None, preparing_at=None, prepared_at=None, starting_at=None,
        started_at=None, stopping_at=None, stopped_at=None,
    )
    vm = SimpleNamespace(tap_interface=None, confidential_policy=policy) if policy else None
    return SimpleNamespace(
        vm_hash="abc", vm=vm, times=times, is_instance=True,
        is_confidential=confidential, gpus=list(gpus), persistent=True,
    )


def test_non_confidential_reports_none():
    info = _to_vm_info(_execution(confidential=False), running=True)
    assert info.confidential_mode is ConfidentialMode.NONE


def test_sev_policy_reports_sev():
    info = _to_vm_info(_execution(confidential=True, policy=0x1), running=True)  # NO_DBG, no ES bit
    assert info.confidential_mode is ConfidentialMode.SEV


def test_sev_es_policy_reports_sev_es():
    info = _to_vm_info(_execution(confidential=True, policy=0x4), running=True)  # SEV_ES bit
    assert info.confidential_mode is ConfidentialMode.SEV_ES


def test_gpus_are_reported_as_devices():
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True, device_id="10de:2504", model="RTX 3090")
    info = _to_vm_info(_execution(gpus=[gpu]), running=True)
    assert [(g.pci_host, g.device_id, g.model, g.supports_x_vga) for g in info.gpus] == [
        ("0000:01:00.0", "10de:2504", "RTX 3090", True)
    ]


def test_gpu_model_none_becomes_empty_string():
    gpu = HostGPU(pci_host="0000:02:00.0", supports_x_vga=False, device_id="10de:1111", model=None)
    info = _to_vm_info(_execution(gpus=[gpu]), running=True)
    assert info.gpus[0].model == ""
```

- [ ] **Step 2: Run it to make sure it fails**

```bash
eval "$RUN tests/supervisor/test_inprocess_vm_info.py -q"
```
Expected: FAIL — `VmInfo` has no `confidential_mode`/`gpus` populated (helper missing).

- [ ] **Step 3: Add imports + the helper**

In `src/aleph/vm/supervisor/inprocess.py`, add to the imports:

```python
from aleph_message.models.execution.environment import AMDSEVPolicy

from aleph.vm.supervisor.types import ConfidentialMode, GpuDevice, PciAddress
```
(Add `ConfidentialMode`, `GpuDevice`, `PciAddress` to the existing `aleph.vm.supervisor.types` import line — do not duplicate the import.)

Above `_to_vm_info` (line 135), add:

```python
def _confidential_mode(execution) -> ConfidentialMode:
    """Precise TEE mode for a VM. The agent reduces this to a bool; the
    supervisor reports the generation it actually launched.

    SEV vs SEV-ES is read from the AMD SEV policy on the confidential QEMU
    object; SEV-SNP is a distinct launch path not yet emitted in-process. A
    confidential VM whose hypervisor object is not created yet reports SEV
    (it is confidential by definition; the sub-mode refines once launched).
    """
    if not execution.is_confidential:
        return ConfidentialMode.NONE
    policy = getattr(execution.vm, "confidential_policy", 0) or 0
    if policy & AMDSEVPolicy.SEV_ES.value:
        return ConfidentialMode.SEV_ES
    return ConfidentialMode.SEV
```

- [ ] **Step 4: Populate the two fields in `_to_vm_info`**

In `_to_vm_info`, after `is_instance=bool(execution.is_instance),` (line 156) add:

```python
        confidential_mode=_confidential_mode(execution),
        gpus=[
            GpuDevice(
                pci_host=PciAddress(g.pci_host),
                device_id=g.device_id,
                model=g.model or "",
                supports_x_vga=g.supports_x_vga,
            )
            for g in execution.gpus
        ],
```

- [ ] **Step 5: Run the test + the existing supervisor tests**

```bash
eval "$RUN tests/supervisor/test_inprocess_vm_info.py -q"
eval "$RUN tests/supervisor/ -k 'inprocess or supervisor_spec or list_vms' -q"
```
Expected: new tests PASS; no regressions.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_inprocess_vm_info.py
git commit -m "feat(supervisor): in-process VmInfo reports confidential mode + attached GPUs"
```

---

## Task 4: `update_allocations` reads status off `list_vms()`, persistence off the registry

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (stop-loop at 578-607)
- Test: `tests/supervisor/test_views.py` (extend)

**Context:** the stop-loop today iterates `pool.get_persistent_executions()` and reads `execution.is_running` / `execution.gpus` / `execution.is_confidential` / `execution.is_instance`. Payment tier already comes from `registry` (#972). After this task the loop reads status from `VmInfo` and persistence/type/payment from the registry; only the action path touches the supervisor (`delete_vm`) and DB (`delete_port_mappings`).

- [ ] **Step 1: Write the failing test**

Add to `tests/supervisor/test_views.py` (follow the file's existing fixtures for `update_allocations`; sketch shown — adapt to the harness already used there):

```python
@pytest.mark.asyncio
async def test_update_allocations_stops_unscheduled_via_vm_info(make_allocation_request):
    """A running, persistent, unscheduled VM with no GPU / not confidential / not
    paid-stream is stopped — driven by VmInfo + registry, not pool executions."""
    # registry: one persistent hold-tier VM; allocation request schedules nothing.
    # supervisor.list_vms() returns one RUNNING VmInfo for it, no gpus, NONE mode.
    ...
    assert supervisor.delete_vm.await_args_list == [call(VmId(str(VM_HASH)))]


@pytest.mark.asyncio
async def test_update_allocations_spares_gpu_confidential_and_stream(make_allocation_request):
    """GPU-bearing, confidential, or payment-stream VMs are never stopped here."""
    # Three persistent unscheduled RUNNING VMs:
    #   - one with gpus=[GpuDevice(...)]
    #   - one with confidential_mode=ConfidentialMode.SEV
    #   - one whose registry record uses_payment_stream
    ...
    supervisor.delete_vm.assert_not_awaited()
```

> Build these against a real `AgentVmRegistry()` seeded with `registry.record(VM_HASH, message=..., original=..., persistent=True)` and a `supervisor` mock whose `list_vms` returns the `VmInfo`s — mirroring how `test_checkpayment.py` seeds the registry. Reuse the existing `update_allocations` test scaffolding in `test_views.py`.

- [ ] **Step 2: Run to verify it fails**

```bash
eval "$RUN tests/supervisor/test_views.py -k update_allocations -q"
```
Expected: FAIL — current loop reads `pool.get_persistent_executions()`/`execution.*`, so the `VmInfo`-driven assertions don't hold.

- [ ] **Step 3: Migrate the stop-loop**

In `src/aleph/vm/orchestrator/views/__init__.py`, replace the loop body (lines 581-607, the `# Make a copy ...` comment through `stopped_vms.append(...)`) with:

```python
        # Status comes from the supervisor (VmInfo); persistence, payment tier
        # and owner come from the agent registry. A VM with no registry record is
        # not scheduler-managed and is left to the idle-expiry path.
        for info in await supervisor.list_vms():
            vm_hash = ItemHash(info.vm_id)
            record = registry.get(vm_hash)
            if (
                record is not None
                and record.persistent
                and vm_hash not in allocations
                and info.status is VmStatus.RUNNING
                and not record.uses_payment_stream
                and not record.uses_payment_credit
                and not info.gpus
                and info.confidential_mode is ConfidentialMode.NONE
            ):
                vm_type = VmType.from_message_content(record.message).name
                logger.info("Stopping %s %s", vm_type, vm_hash)
                try:
                    await supervisor.delete_vm(VmId(str(vm_hash)))
                except VmNotFoundError:
                    pass
                # Residual direct DB call: mapping persistence moves fully
                # hypervisor-side with the gRPC split.
                await delete_port_mappings(vm_hash)
                registry.forget(vm_hash)
                stopped_vms.append(vm_hash)
```

Ensure these names are imported at the top of the file (add any missing): `ItemHash`, `VmStatus`, `ConfidentialMode`, `VmId`, `VmType`, `VmNotFoundError`. (`VmStatus`/`ConfidentialMode`/`VmId` from `aleph.vm.supervisor.types`; `VmType` is already used by `_vm_type_name`.)

- [ ] **Step 4: Run the test + the whole views suite**

```bash
eval "$RUN tests/supervisor/test_views.py -q"
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/views/__init__.py tests/supervisor/test_views.py
git commit -m "refactor(allocations): stop-loop reads status from VmInfo, persistence from the registry"
```

---

## Task 5: Payment monitoring reads `list_vms()`; cost fns take `vm_hash`es

**Files:**
- Modify: `src/aleph/vm/orchestrator/payment.py:162-185` (3 cost fns)
- Modify: `src/aleph/vm/orchestrator/tasks.py` (`_group_executions_by_payment` 313-338; `check_payment` 341-499; `monitor_payments` 296-304; imports)
- Test: `tests/supervisor/test_tasks_registry_reads.py` (rewrite grouping tests), `tests/supervisor/test_checkpayment.py` (adapt)

**Context:** the grouping returns `VmExecution`s used only for `vm_hash` + three status reads (`is_running`, `is_confidential`, `started_at`). All are in `VmInfo`. The cost fns use only `execution.vm_hash`. So the grouping returns `VmInfo`, the cost fns take `ItemHash`es, and `check_payment` calls `list_vms()` once and drops `pool`.

- [ ] **Step 1: Write the failing tests (grouping)**

Rewrite the grouping tests in `tests/supervisor/test_tasks_registry_reads.py` to feed `VmInfo`s instead of a `pool`. Replace `_execution` and the four `test_grouping_*` tests with:

```python
from aleph.vm.supervisor.types import ConfidentialMode, VmId, VmInfo, VmStatus


def _info(vm_hash: ItemHash, *, running: bool = True, confidential=False) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=VmStatus.RUNNING if running else VmStatus.STOPPED,
        ipv4="", ipv6="", uptime_secs=0, backend=Backend.QEMU, numa_node=None, status_message="",
        confidential_mode=ConfidentialMode.SEV if confidential else ConfidentialMode.NONE,
    )


def test_grouping_sources_message_from_registry():
    payment = Payment(chain=Chain.ETH, type=PaymentType.superfluid)
    registry = _registry_with(_HASH, payment=payment)
    groups = _group_executions_by_payment([_info(_HASH)], registry, PaymentType.superfluid)
    assert list(groups) == ["0xabc"]
    assert groups["0xabc"][Chain.ETH][0].vm_id == str(_HASH)


def test_grouping_skips_unrecorded_executions():
    groups = _group_executions_by_payment([_info(_HASH)], AgentVmRegistry(), PaymentType.superfluid)
    assert groups == {}


def test_grouping_defaults_to_hold_and_filters_by_type():
    registry = _registry_with(_HASH, payment=None)
    assert _group_executions_by_payment([_info(_HASH)], registry, PaymentType.superfluid) == {}
    hold = _group_executions_by_payment([_info(_HASH)], registry, PaymentType.hold)
    assert hold["0xabc"][Chain.ETH][0].vm_id == str(_HASH)


def test_grouping_skips_stopped_and_diagnostic_executions():
    payment = Payment(chain=Chain.ETH, type=PaymentType.hold)
    registry = _registry_with(_HASH, payment=payment)
    for diag_id in (settings.CHECK_FASTAPI_VM_ID, settings.LEGACY_CHECK_FASTAPI_VM_ID):
        registry.record(ItemHash(diag_id), message=SimpleNamespace(payment=payment, address="0xabc"),
                        original=MagicMock(), persistent=True)
    infos = [
        _info(_HASH, running=False),  # stopped -> skipped
        _info(ItemHash(settings.CHECK_FASTAPI_VM_ID)),  # diagnostic -> skipped
        _info(ItemHash(settings.LEGACY_CHECK_FASTAPI_VM_ID)),  # legacy diagnostic -> skipped
    ]
    assert _group_executions_by_payment(infos, registry, PaymentType.hold) == {}
```

Add `from aleph.vm.supervisor.types import Backend` (and the others) to the test imports. Add a source-guard test:

```python
def test_payment_grouping_has_no_pool_status_reads():
    """check_payment / grouping must read VM status from VmInfo, not pool executions."""
    import inspect

    from aleph.vm.orchestrator import tasks

    for fn in (tasks._group_executions_by_payment, tasks.check_payment):
        source = inspect.getsource(fn)
        assert "pool.executions" not in source
        assert ".is_running" not in source
        assert ".is_confidential" not in source
```

- [ ] **Step 2: Run to verify failure**

```bash
eval "$RUN tests/supervisor/test_tasks_registry_reads.py -q"
```
Expected: FAIL — `_group_executions_by_payment` still takes `pool` and returns executions; source guard trips.

- [ ] **Step 3: Change the cost fns to take `vm_hash`es**

In `src/aleph/vm/orchestrator/payment.py`, replace the three functions (162-185):

```python
async def compute_required_balance(vm_hashes: Iterable[ItemHash]) -> Decimal:
    """Balance required for the resources of the given VMs (from messages + pricing aggregate)."""
    costs = await asyncio.gather(
        *(fetch_execution_price(vm_hash, [PaymentType.hold], payment_type_required=False) for vm_hash in vm_hashes)
    )
    return sum(costs, Decimal(0))


async def compute_required_credit_balance(vm_hashes: Iterable[ItemHash]) -> Decimal:
    """Credit balance required for the resources of the given VMs."""
    costs = await asyncio.gather(*(fetch_execution_price(vm_hash, [PaymentType.credit]) for vm_hash in vm_hashes))
    return sum(costs, Decimal(0))


async def compute_required_flow(vm_hashes: Iterable[ItemHash]) -> Decimal:
    """Stream flow required for a collection of VMs (typically all from one address)."""
    flows = await asyncio.gather(*(fetch_execution_price(vm_hash, [PaymentType.superfluid]) for vm_hash in vm_hashes))
    return sum(flows, Decimal(0))
```

Ensure `ItemHash` is imported in `payment.py` (it is used elsewhere there; add `from aleph_message.models import ItemHash` if absent). Remove the now-unused `VmExecution` import only if nothing else in the file uses it.

- [ ] **Step 4: Migrate the grouping + `check_payment` + `monitor_payments`**

In `src/aleph/vm/orchestrator/tasks.py`:

Add imports: `VmInfo` to the `aleph.vm.supervisor.types` line (now `from aleph.vm.supervisor.types import VmId, VmInfo, VmStatus`), `ConfidentialMode` too, and `from aleph_message.models import ItemHash` if not already imported. Add a small ns→datetime helper near the top:

```python
from datetime import datetime, timezone


def _dt_from_ns(ns: int) -> datetime | None:
    if not ns:
        return None
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).replace(microsecond=(ns // 1_000) % 1_000_000)
```

Replace `_group_executions_by_payment` (313-338):

```python
def _group_executions_by_payment(
    infos: list[VmInfo], registry: AgentVmRegistry, payment_type: PaymentType
) -> dict[str, dict[Chain, list[VmInfo]]]:
    """Group running VMs by sender address and chain for one payment type.

    Status comes from the supervisor (VmInfo); the message (payment tier, owner)
    comes from the agent registry. Spec-built and restart-restored VMs (which
    carry no hypervisor-side message) are grouped via their registry record.
    """
    by_address: dict[str, dict[Chain, list[VmInfo]]] = {}
    for info in infos:
        vm_hash = ItemHash(info.vm_id)
        record = registry.get(vm_hash)
        if record is None:
            continue
        if vm_hash in (settings.CHECK_FASTAPI_VM_ID, settings.LEGACY_CHECK_FASTAPI_VM_ID):
            continue
        if info.status is not VmStatus.RUNNING:
            continue
        payment = record.message.payment if record.message.payment else Payment(chain=Chain.ETH, type=PaymentType.hold)
        if payment.type == payment_type:
            by_address.setdefault(record.message.address, {}).setdefault(payment.chain, []).append(info)
    return by_address
```

Change `check_payment`'s signature and body. Signature (341):

```python
async def check_payment(supervisor: Supervisor, registry: AgentVmRegistry):
```

Take one snapshot at the top of the function body (replacing the `for vm_hash in list(pool.executions.keys()):` header at 351):

```python
    infos = await supervisor.list_vms()
    for info in infos:
        vm_hash = ItemHash(info.vm_id)
        if vm_hash == settings.FAKE_INSTANCE_ID:
            continue
        # ... unchanged terminal-status body, using `vm_hash` ...
```

In the three grouping loops (390, 417, 440) pass `infos`: `_group_executions_by_payment(infos, registry, PaymentType.hold)` etc. The grouped values are now `VmInfo`s; update the bodies:

- hold confidential filter (392): `executions = [i for i in executions if i.confidential_mode is not ConfidentialMode.NONE]`
- the `compute_required_*` calls take hashes: `await compute_required_balance([ItemHash(i.vm_id) for i in executions])` (and the credit/flow equivalents).
- `delete_vm` calls (407, 434, 497): `await supervisor.delete_vm(VmId(last_execution.vm_id))` where `last_execution` is now a `VmInfo`.
- the community-wallet split (467, 474): `if await is_after_community_wallet_start(_dt_from_ns(i.started_at_ns))`.
- rename the loop var `execution(s)`→`info(s)` where it now holds `VmInfo` for clarity (optional but recommended; keep `executions` as the list name to minimize churn if preferred).

In `monitor_payments` (291-304): drop the now-unused `pool` and update the call:

```python
async def monitor_payments(app: web.Application):
    supervisor: Supervisor = app["supervisor"]
    registry: AgentVmRegistry = app["vm_registry"]
    while True:
        await asyncio.sleep(settings.PAYMENT_MONITOR_INTERVAL)
        try:
            logger.debug("Monitoring balances task running")
            await check_payment(supervisor, registry)
            ...
```

(Leave `_handle_domains_aggregate` and its `pool.executions` use untouched — it is the deferred domain-mapping path.)

- [ ] **Step 5: Adapt `test_checkpayment.py`**

`test_checkpayment.py` (6 tests) currently seeds `pool.executions` and calls `check_payment(pool, supervisor, registry)`. Update each to: build a `supervisor` mock whose `list_vms()` returns the `VmInfo`s for the seeded hashes (running/confidential as the test needs), and call `check_payment(supervisor, registry)`. The registry seeding stays. Where a test patches `compute_required_flow` with a real impl, it still works (the new impl takes hashes). Where a test asserts a VM was/ wasn't stopped, assert on `supervisor.delete_vm`.

- [ ] **Step 6: Run the payment tests**

```bash
eval "$RUN tests/supervisor/test_tasks_registry_reads.py tests/supervisor/test_checkpayment.py -q"
```
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/orchestrator/payment.py src/aleph/vm/orchestrator/tasks.py tests/supervisor/test_tasks_registry_reads.py tests/supervisor/test_checkpayment.py
git commit -m "refactor(payment): monitoring reads status from VmInfo; cost fns take vm hashes"
```

---

## Task 6: Delete the `about_executions/details` debug endpoint

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (delete `about_executions` 197-209)
- Modify: `src/aleph/vm/orchestrator/supervisor.py` (remove import line 44; remove route line 196)
- Test: `tests/supervisor/test_supervisor_spec_pool_guards.py` or the relevant routing test (add a 404 assertion); plus the source guard from Task 5 covers tasks.py.

- [ ] **Step 1: Write the failing test**

Add (to an existing supervisor HTTP test module that builds the app, e.g. where other `/about/...` routes are exercised):

```python
@pytest.mark.asyncio
async def test_about_executions_details_route_removed(aiohttp_client):
    """The raw-pool debug dump is gone (no consumers; cannot cross the boundary)."""
    app = await build_app_under_test()  # the harness used by sibling route tests
    client = await aiohttp_client(app)
    resp = await client.get("/about/executions/details")
    assert resp.status == 404
```

> If no such app-building harness exists in the suite, instead assert the route is not registered: import the route table builder and assert no route path equals `/about/executions/details`.

- [ ] **Step 2: Run to verify failure**

```bash
eval "$RUN tests/supervisor/ -k about_executions_details -q"
```
Expected: FAIL — route still returns 200.

- [ ] **Step 3: Delete the handler**

In `src/aleph/vm/orchestrator/views/__init__.py`, delete the entire `about_executions` function (lines 197-209, including the `@cors_allow_all` decorator).

- [ ] **Step 4: Delete the route + import**

In `src/aleph/vm/orchestrator/supervisor.py`: remove `about_executions,` from the import block (line 44) and delete the route line `web.get("/about/executions/details", about_executions),` (line 196).

- [ ] **Step 5: Run the test + a broad import/smoke check**

```bash
eval "$RUN tests/supervisor/ -k about_executions_details -q"
eval "$RUN tests/supervisor/test_tasks_registry_reads.py -k no_pool_status_reads -q"
$VENV -c "import aleph.vm.orchestrator.supervisor"  # import-time check: no dangling name
```
Expected: PASS; import succeeds (no `NameError` for `about_executions`).

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/orchestrator/supervisor.py tests/supervisor/
git commit -m "refactor(views): delete the raw-pool about_executions/details debug endpoint"
```

---

## Final verification (after all tasks)

```bash
# Whole supervisor suite + the run/expiry siblings touched by the stack
eval "$RUN tests/supervisor/ -q"
# Proto bindings clean
bash scripts/check_proto_clean.sh
# Style gates (match the repo's configured linters)
$VENV -m ruff check src/aleph/vm/supervisor src/aleph/vm/orchestrator src/aleph/vm/resources.py src/aleph/vm/models.py
```
Expected: green suite; "proto bindings are up to date"; no lint errors on touched files.

Then use **superpowers:finishing-a-development-branch** to push and open the PR (base `od/wire-supervisor-agent-records`, #972).

---

## Self-review notes

- **Spec coverage:** §3 → Task 1; §4 (HostGPU) → Task 2; §5 (in-process) → Task 3; §6a → Task 4; §6b → Task 5; §6c → Task 6. `is_instance` left untouched per §2/§8. ✓
- **Persistence shift** (§6a): sourced from `registry.record.persistent`; record-less VMs skipped. Covered by Task 4 tests. ✓
- **Type consistency:** `ConfidentialMode` (Task 1) used in Tasks 3/4/5; `GpuDevice`/`HostGPU` fields (Tasks 1/2) consumed in Task 3; cost-fn signature change (Task 5) matches its only callers. ✓
- **Out of scope (untouched):** `_handle_domains_aggregate`, `recreate_network`, the capability stubs, the legacy program create path.
