# Message-free VmExecution and controller layer: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `aleph_message` from `VmExecution` and the controller layer completely: replace the `MachineResources` value type with a message-free `HardwareResources` DTO, delete the dead message-driven half of `VmExecution`, and delete the dead message-path program controller `AlephFirecrackerProgram`.

**Architecture:** `VmExecution` becomes spec-only (`spec: CreateVmSpec`, no `MessageSpec`). Live controllers take a `HardwareResources(vcpus, memory)` DTO. `AlephFirecrackerProgram` (+ `ProgramVmConfiguration` and the dead `ConfigurationPayload*` classes) are removed; the agent-shared symbols in `program.py` stay. The agent and the resource-download classes keep `aleph_message` (the documented boundary). See `docs/plans/2026-06-17-execution-message-free-design.md`.

**Tech stack:** Python 3.12+, aiohttp, frozen dataclasses, pytest. Canonical test command (worktree `just`/hatch are broken):

```bash
PY=/home/olivier/git/aleph/aleph-vm/venv/bin/python
export PYTHONPATH="$PWD/src:$PWD/.test-roots/stubs"
export ALEPH_VM_CACHE_ROOT=/tmp/emf-cache ALEPH_VM_EXECUTION_ROOT=/tmp/emf-exec
mkdir -p $ALEPH_VM_CACHE_ROOT $ALEPH_VM_EXECUTION_ROOT
$PY -m pytest <targets> -q
```

Known environment-baseline failures (present on base, not regressions): `tests/supervisor/test_execution.py` (jailman `chown` subprocess) and `tests/supervisor/test_interfaces.py` (pyroute2 netlink).

**Task order rationale:** DTO first; then strip `VmExecution` (removes the only `AlephFirecrackerProgram` construction and the message branches); then delete `AlephFirecrackerProgram`; then swap the live controllers to `HardwareResources`; then migrate tests; then gates. Between the models strip and the controller swap, `mypy` is transiently red (models passes `HardwareResources` where controllers still annotate `MachineResources`) while tests stay green (runtime is duck-typed on `.vcpus`/`.memory`). `mypy` is a final gate.

---

### Task 1: Add the `HardwareResources` DTO

**Files:**
- Modify: `src/aleph/vm/supervisor/types.py`
- Test: `tests/supervisor/test_types_hardware_resources.py` (create)

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_types_hardware_resources.py
from dataclasses import FrozenInstanceError

import pytest

from aleph.vm.supervisor.types import HardwareResources


def test_defaults_match_machineresources():
    hw = HardwareResources()
    assert (hw.vcpus, hw.memory) == (1, 128)


def test_explicit_values():
    hw = HardwareResources(vcpus=4, memory=2048)
    assert (hw.vcpus, hw.memory) == (4, 2048)


def test_is_frozen():
    hw = HardwareResources()
    with pytest.raises(FrozenInstanceError):
        hw.vcpus = 2  # type: ignore[misc]


def test_has_no_seconds_field():
    # seconds is agent-side policy; the daemon must not carry it.
    assert "seconds" not in HardwareResources().__dataclass_fields__
```

- [ ] **Step 2: Run it, verify it fails**

Run: `$PY -m pytest tests/supervisor/test_types_hardware_resources.py -q`
Expected: FAIL with `ImportError: cannot import name 'HardwareResources'`.

- [ ] **Step 3: Add the DTO**

In `src/aleph/vm/supervisor/types.py`, near the other DTOs, add:

```python
@dataclass(frozen=True)
class HardwareResources:
    """Message-free hardware sizing handed to controllers.

    Mirrors the fields the controllers read from aleph_message's
    MachineResources (vcpus, memory in MiB) so the daemon never imports a
    message type. The `seconds` run-timeout field is intentionally absent: it
    is agent-side policy (the agent passes the timeout over the gRPC run call).
    Field names match MachineResources so controller field access is unchanged.
    """

    vcpus: int = 1
    memory: int = 128  # MiB
```

(`dataclass` is already imported in this module.)

- [ ] **Step 4: Run the test, verify it passes**

Run: `$PY -m pytest tests/supervisor/test_types_hardware_resources.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/types.py tests/supervisor/test_types_hardware_resources.py
git commit -m "feat(supervisor): add message-free HardwareResources DTO"
```

---

### Task 2: Strip `VmExecution` to spec-only

**Files:**
- Modify: `src/aleph/vm/models.py`
- Modify: `src/aleph/vm/pool.py` (remove the `execution.save()` call)

- [ ] **Step 1: Confirm `save()` and `run_code` are removable**

```bash
grep -rn --include=*.py "\.save()" src/aleph/vm/ | grep -v "def save\|save_record\|port_mappings\|save_controller\|save_execution"
# expect exactly: pool.py (restart_persistent_vm) and models.py (start)
grep -rn --include=*.py "execution.run_code\|self.run_code\|\.run_code(scope" src/aleph/vm/ | grep -v "vm.run_code\|program_client\|guest"
# expect: nothing (VmExecution.run_code has no production caller)
```
If either grep shows an unexpected caller, STOP and reassess.

- [ ] **Step 2: Remove the message imports from `models.py`**

Delete:
```python
from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ProgramContent,
)
from aleph_message.models.execution.environment import (
    GpuProperties,
    HypervisorType,
    MachineResources,
)
```
Also remove `AlephFirecrackerProgram` from the `controllers.firecracker.program` import (keep `AlephProgramResources`). Add `HardwareResources` to the existing `from aleph.vm.supervisor.types import ...` line.

- [ ] **Step 3: Delete `MessageSpec`, collapse the `spec` union, rewrite `__init__`**

- Delete the `MessageSpec` dataclass.
- `spec: MessageSpec | CreateVmSpec` -> `spec: CreateVmSpec`.
- Rewrite `__init__` to the spec-only signature:

```python
def __init__(
    self,
    vm_hash: VmId,
    vm_spec: CreateVmSpec,
    snapshot_manager: SnapshotManager | None = None,
    systemd_manager: SystemDManager | None = None,
    persistent: bool = False,
):
    self.init_task = None
    self.uuid = uuid.uuid1()
    self.vm_hash = vm_hash
    self.spec = vm_spec
    self.times = VmExecutionTimes(defined_at=datetime.now(tz=timezone.utc))
    self.ready_event = asyncio.Event()
    self.concurrent_runs = 0
    self.runs_done_event = asyncio.Event()
    self.runs_done_event.set()
    self.stop_event = asyncio.Event()
    self.preparation_pending_lock = asyncio.Lock()
    self.stop_pending_lock = asyncio.Lock()
    self.snapshot_manager = snapshot_manager
    self.systemd_manager = systemd_manager
    self.persistent = persistent
    self.mapped_ports = {}
    self.gpus = []
```

`from_spec` stays:
```python
return cls(
    vm_hash=spec.vm_id,
    vm_spec=spec,
    snapshot_manager=snapshot_manager,
    systemd_manager=systemd_manager,
    persistent=spec.persistent,
)
```

- [ ] **Step 4: Delete the message-only members**

Delete: `message` property, `original` property, `prepare_gpus`,
`fetch_port_redirect_config_and_setup`, the `hypervisor` property, `run_code`, and
the `assert isinstance(self.vm, AlephFirecrackerProgram)` it contained. For
`vm_spec`, check callers:
```bash
grep -rn --include=*.py "\.vm_spec\b" src/aleph/vm/
```
If live callers exist, keep `vm_spec` returning `self.spec`; else delete it.

- [ ] **Step 5: Simplify the branching accessors**

```python
@property
def is_program(self) -> bool:
    return self.spec.backend is Backend.FIRECRACKER

@property
def is_instance(self) -> bool:
    return self.spec.backend is Backend.QEMU

@property
def is_confidential(self) -> bool:
    return self.spec.tee is not None

@property
def allocated_memory_mib(self) -> int:
    return self.spec.memory_mib

@property
def allocated_vcpus(self) -> int:
    return self.spec.vcpus
```

- [ ] **Step 6: Simplify `prepare()` to the spec path only**

```python
async def prepare(self) -> None:
    """Build VM resources from the spec. No download (paths are resolved)."""
    async with self.preparation_pending_lock:
        if self.resources:
            return
        self.times.preparing_at = datetime.now(tz=timezone.utc)
        if self.spec.backend is Backend.FIRECRACKER:
            self.resources = SpecProgramResources.from_spec(self.spec)
        elif self.spec.tee is not None:
            self.resources = AlephQemuConfidentialResources.from_spec(self.spec, namespace=str(self.vm_hash))
        else:
            self.resources = AlephQemuResources.from_spec(self.spec, namespace=str(self.vm_hash))
        self.times.prepared_at = datetime.now(tz=timezone.utc)
```

- [ ] **Step 7: Simplify `create()` to the spec path only**

Remove the entire `message = self.spec.message ... else: raise Exception("Unknown VM")` block. In the kept spec branch, change the `MachineResources(...)` build to:
```python
hardware_resources = HardwareResources(vcpus=self.spec.vcpus, memory=self.spec.memory_mib)
```

- [ ] **Step 8: Remove `save()` and its callers**

- Delete the `save()` method from `models.py`.
- In `models.py` `start()`, remove the `await self.save()` line.
- In `pool.py` `restart_persistent_vm`, remove `await execution.save()` and its now-stale "Re-save so the record survives" comment.
- Remove orphaned imports in `models.py`:
```bash
grep -n "ExecutionRecord\|save_record\|pydantic_encoder\|^import json\|json\." src/aleph/vm/models.py
```
Drop any with no remaining use.

- [ ] **Step 9: Verify models.py is message-free**

```bash
grep -n "aleph_message\|MachineResources\|HypervisorType\|MessageSpec\|InstanceContent\|ProgramContent\|ExecutableContent\|GpuProperties\|AlephFirecrackerProgram" src/aleph/vm/models.py
# expect: no output
```

- [ ] **Step 10: Run the daemon-path tests (expect Task 5 test breakage)**

```bash
$PY -m pytest tests/supervisor/ -q
```
Expected: source imports cleanly; failures confined to tests constructing message-built `VmExecution` or calling removed members. Record the failing set for Task 5; do not edit tests here.

- [ ] **Step 11: Commit**

```bash
git add src/aleph/vm/models.py src/aleph/vm/pool.py
git commit -m "refactor(supervisor): make VmExecution spec-only, drop aleph_message"
```

---

### Task 3: Delete the dead `AlephFirecrackerProgram` controller

**Files:**
- Modify: `src/aleph/vm/controllers/firecracker/program.py`
- Modify: `src/aleph/vm/controllers/firecracker/__init__.py`
- Modify: `src/aleph/vm/orchestrator/vm/__init__.py`

- [ ] **Step 1: Re-confirm zero production construction**

```bash
grep -rn --include=*.py "AlephFirecrackerProgram" src/aleph/vm/ | grep -v "tests/"
# expect only: the two __init__.py re-exports and program.py's own class def
```
If anything else references it, STOP.

- [ ] **Step 2: Confirm the payload classes are internal-only before deleting them**

```bash
for sym in ProgramVmConfiguration ConfigurationPayload ConfigurationPayloadV1 ConfigurationPayloadV2; do
  echo "$sym:"; grep -rn --include=*.py "\b$sym\b" src/aleph/vm/ | grep -v "controllers/firecracker/program.py"
done
# expect: no output for each (no external references)
```
For each payload class, also check it is not referenced by a KEPT symbol inside `program.py` (e.g. `ProgramConfiguration`). Delete only those with no remaining references after `AlephFirecrackerProgram` is gone.

- [ ] **Step 3: Delete the class and its exclusive config types**

In `program.py` delete `class AlephFirecrackerProgram` (line ~285 to end of class), `class ProgramVmConfiguration`, and the confirmed-dead `ConfigurationPayload` / `ConfigurationPayloadV1` / `ConfigurationPayloadV2`. Keep `AlephProgramResources`, `get_volumes_for_program`, `ProgramConfiguration`, `ConfigurationResponse`, `RunCodePayload`, `Interface`, `read_input_data`, `FileTooLargeError`. Remove now-unused imports in `program.py` (e.g. `MachineResources`, `AlephFirecrackerExecutable` if unused after deletion — verify each).

- [ ] **Step 4: Remove the re-exports**

- `src/aleph/vm/controllers/firecracker/__init__.py`: remove the `AlephFirecrackerProgram` import and its `__all__` entry (delete the file if it becomes empty, and check nothing imports the package expecting that name).
- `src/aleph/vm/orchestrator/vm/__init__.py`: same.

```bash
grep -rn --include=*.py "from aleph.vm.controllers.firecracker import\|from aleph.vm.orchestrator.vm import" src/aleph/vm/ tests/
```
Fix any importer that pulled `AlephFirecrackerProgram` from the package (there should be none in `src/`).

- [ ] **Step 5: Verify the module still imports and the agent path is intact**

```bash
$PY -c "import aleph.vm.controllers.firecracker.program; import aleph.vm.orchestrator.vm.program_client"
$PY -m pytest tests/supervisor/test_program_client.py -q 2>/dev/null || $PY -m pytest tests/ -k program_client -q
```
Expected: imports succeed; agent program-client tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/controllers/firecracker/ src/aleph/vm/orchestrator/vm/__init__.py
git commit -m "refactor(controllers): delete dead message-path AlephFirecrackerProgram"
```

---

### Task 4: Swap the live controllers to `HardwareResources`

Pure type swap on the surviving controllers. Field reads (`.vcpus`/`.memory`) unchanged. No serialization change.

**Files:**
- Modify: `src/aleph/vm/controllers/interface.py` (base attr)
- Modify: `src/aleph/vm/controllers/firecracker/executable.py` (attr + param + default)
- Modify: `src/aleph/vm/controllers/firecracker/spec_program.py` (the `MachineResources(vcpus=..., memory=...)` build)
- Modify: `src/aleph/vm/controllers/qemu/instance.py` (attr + default)
- Modify: `src/aleph/vm/controllers/qemu_confidential/instance.py` (attr + default)

- [ ] **Step 1: Replace imports and tokens in each file**

Remove `from aleph_message.models.execution.environment import MachineResources`; add `from aleph.vm.supervisor.types import HardwareResources`. Replace every `MachineResources` with `HardwareResources` (annotations, `MachineResources()` defaults, and the `MachineResources(vcpus=..., memory=...)` build in `spec_program.py`).

```bash
grep -rn "MachineResources" src/aleph/vm/   # expect: no output anywhere
```

- [ ] **Step 2: Type check**

```bash
$PY -m mypy src/aleph/vm/models.py src/aleph/vm/controllers/
```
Expected: clean on our symbols (the transient `HardwareResources` vs `MachineResources` mismatch from Task 2 is now resolved). The two former `trusted_execution`/`policy` errors are gone.

- [ ] **Step 3: Run controller tests (Task 5 migrates remaining breakage)**

```bash
$PY -m pytest tests/supervisor/test_qemu_instance.py tests/supervisor/test_wait_for_controller.py -q
```
Record failures from message-built constructions for Task 5; do not edit tests here.

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/controllers/
git commit -m "refactor(controllers): take HardwareResources instead of MachineResources"
```

---

### Task 5: Migrate the test suite onto the spec path

Sites (verify current set first):
```bash
grep -rln --include=*.py "VmExecution(" tests/ | xargs grep -ln "message=\|original="
grep -rln --include=*.py "AlephFirecrackerProgram\|MachineResources\|\.run_code(\|prepare_gpus\|fetch_port_redirect" tests/
```

**Triage rule per construction/usage (apply individually):**

1. Behavior still has a live spec path (lifecycle, ports, drain, wait-for-controller, GPU detail) -> **convert**: build a `CreateVmSpec` (template: the factory from Task 5 Step 1) and use `VmExecution.from_spec(...)`.
2. Test exercises only removed surface (`prepare_gpus`, `fetch_port_redirect_config_and_setup`, `run_code`, message-built `prepare`/`create`, `save()` record-writing, `.message`/`.original`, `AlephFirecrackerProgram`) -> **delete**, noting the reason in the commit body.
3. A behavior is genuinely lost with no spec-path equivalent -> STOP and escalate.

- [ ] **Step 1: Add a shared `CreateVmSpec` test factory**

If `tests/supervisor/conftest.py` lacks one, add a factory mirroring `_spec` from `tests/supervisor/test_supervisor_spec_admission.py`, parameterized for backend, tee, gpus, persistent, memory_mib, vcpus. Reuse it across migrated tests (DRY).

- [ ] **Step 2: Migrate file-by-file**

Apply the triage rule to each of: `test_execution.py`, `test_views.py`, `test_qemu_instance.py`, `test_drain.py`, `test_run.py`, `test_firewall.py`, `test_wait_for_controller.py`, `test_host_gpu_detail.py`. After each:
```bash
$PY -m pytest tests/supervisor/<file>.py -q
```
Expected PASS (except the `test_execution.py` jailman `chown` baseline).

- [ ] **Step 3: Full suite**

```bash
$PY -m pytest tests/ -q
```
Expected: green except the documented environment baseline (jailman `chown`, pyroute2 netlink).

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "test(supervisor): migrate VmExecution tests to spec path; drop message-path-only tests"
```

---

### Task 6: Final gates, boundary verification, review, PR

- [ ] **Step 1: Format + import order**

```bash
$PY -m ruff format --check src/aleph/vm/ tests/supervisor/
$PY -m isort --profile black --check-only src/aleph/vm/ tests/supervisor/
```
Fix with the non-`--check` forms if needed; re-run.

- [ ] **Step 2: Type check**

```bash
$PY -m mypy src/aleph/vm/models.py src/aleph/vm/pool.py src/aleph/vm/controllers/ src/aleph/vm/supervisor/
```
Expected: the two pre-existing `models.py` `trusted_execution`/`policy` errors are gone; no new errors on our symbols.

- [ ] **Step 3: Boundary assertions**

```bash
grep -rn "MachineResources\|HypervisorType" src/aleph/vm/ ; echo "^ expect: no output"
grep -n "aleph_message" src/aleph/vm/models.py ; echo "^ expect: no output"
grep -rn "AlephFirecrackerProgram" src/aleph/vm/ ; echo "^ expect: no output"
grep -rn "aleph_message" src/aleph/vm/controllers/
# ^ remaining hits MUST be only the resource-download classes (AlephProgramResources /
#   AlephQemuResources / bases) and message-content used by the agent-shared download
#   path. Confirm each is the documented boundary, not a missed daemon coupling.
```

- [ ] **Step 4: Code-quality review** (per subagent-driven-development) over the full branch diff vs `od/supervisor-vmid-identity`. Address findings, re-review.

- [ ] **Step 5: Push and open PR**

```bash
git push -u origin od/execution-message-free
gh pr create --base od/supervisor-vmid-identity --head od/execution-message-free \
  --title "refactor(supervisor): make VmExecution and controllers message-free" \
  --body "<summary + boundary note + verification, per the design doc>"
```

---

## Self-review (plan vs design)

- **Spec coverage:** DTO without `seconds` (Task 1); `VmExecution` strip incl. `save`/`run_code` removal (Task 2); `AlephFirecrackerProgram` deletion (Task 3); live-controller swap (Task 4); test migration (Task 5); gates + boundary (Task 6). All design sections covered.
- **`seconds` removed:** justified by its sole reader (`AlephFirecrackerProgram.run_code`) being deleted; run timeout stays agent-side via the gRPC run call.
- **Boundary preserved:** the resource-download classes and the agent-shared `program.py` serialization symbols (`ProgramConfiguration`, `ConfigurationResponse`, `RunCodePayload`, `Interface`, `read_input_data`, `FileTooLargeError`, `get_volumes_for_program`) are explicitly kept.
- **Type consistency:** `HardwareResources` fields (`vcpus`/`memory`) match the `MachineResources` fields the surviving controllers read; defaults match so `HardwareResources()` is a drop-in.
- **Ordering:** strip models -> delete `AlephFirecrackerProgram` -> swap controllers keeps each step's tests green; `mypy` is red only transiently and is enforced as a final gate.
- **Verification-dependent steps** (payload-class liveness, orphaned imports, `vm_spec`/`save` callers, re-export importers) are written as grep-then-decide, not assumed.
