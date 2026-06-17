# Message-free VmExecution and controller layer: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove `aleph_message` from `VmExecution` and the controller layer completely, replacing the `MachineResources` value type with a message-free `HardwareResources` DTO and deleting the dead message-driven half of `VmExecution`.

**Architecture:** `VmExecution` becomes spec-only (`spec: CreateVmSpec`, no `MessageSpec`). Controllers take a `HardwareResources` DTO instead of `aleph_message`'s `MachineResources`. The agent and the shared resource-download classes keep `aleph_message` (the documented boundary). See `docs/plans/2026-06-17-execution-message-free-design.md`.

**Tech stack:** Python 3.12+, aiohttp, frozen dataclasses, pytest. Canonical test command (worktree `just`/hatch are broken):

```bash
PY=/home/olivier/git/aleph/aleph-vm/venv/bin/python
export PYTHONPATH="$PWD/src:$PWD/.test-roots/stubs"
export ALEPH_VM_CACHE_ROOT=/tmp/emf-cache ALEPH_VM_EXECUTION_ROOT=/tmp/emf-exec
mkdir -p $ALEPH_VM_CACHE_ROOT $ALEPH_VM_EXECUTION_ROOT
$PY -m pytest <targets> -q
```

Known environment-baseline failures (present on base, not regressions): `tests/supervisor/test_execution.py` (jailman `chown` subprocess) and `tests/supervisor/test_interfaces.py` (pyroute2 netlink).

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
    assert (hw.vcpus, hw.memory, hw.seconds) == (1, 128, 1)


def test_explicit_values():
    hw = HardwareResources(vcpus=4, memory=2048, seconds=30)
    assert (hw.vcpus, hw.memory, hw.seconds) == (4, 2048, 30)


def test_is_frozen():
    hw = HardwareResources()
    with pytest.raises(FrozenInstanceError):
        hw.vcpus = 2  # type: ignore[misc]
```

- [ ] **Step 2: Run it, verify it fails**

Run: `$PY -m pytest tests/supervisor/test_types_hardware_resources.py -q`
Expected: FAIL with `ImportError: cannot import name 'HardwareResources'`.

- [ ] **Step 3: Add the DTO**

In `src/aleph/vm/supervisor/types.py`, after the existing `NewType` aliases / near the other DTOs, add:

```python
@dataclass(frozen=True)
class HardwareResources:
    """Message-free hardware sizing handed to controllers.

    Mirrors the three fields the controllers read from aleph_message's
    MachineResources (vcpus, memory in MiB, seconds for the program run
    timeout) so the daemon never imports a message type. Field names match
    MachineResources so controller field access is unchanged.
    """

    vcpus: int = 1
    memory: int = 128  # MiB
    seconds: int = 1
```

(`dataclass` is already imported in this module.)

- [ ] **Step 4: Run the test, verify it passes**

Run: `$PY -m pytest tests/supervisor/test_types_hardware_resources.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/types.py tests/supervisor/test_types_hardware_resources.py
git commit -m "feat(supervisor): add message-free HardwareResources DTO"
```

---

### Task 2: Swap controllers from `MachineResources` to `HardwareResources`

Pure type swap. Field reads (`.vcpus`/`.memory`/`.seconds`) are unchanged. No serialization change (the on-disk `Configuration` uses `vcpu_count: int`, not `MachineResources`).

**Files (each: replace the import and every `MachineResources` annotation/default):**
- Modify: `src/aleph/vm/controllers/interface.py` (line ~9 import, ~31 attr)
- Modify: `src/aleph/vm/controllers/firecracker/executable.py` (~15 import, ~134 attr, ~156 param, ~168 default)
- Modify: `src/aleph/vm/controllers/firecracker/program.py` (~16 import, ~298 default)
- Modify: `src/aleph/vm/controllers/firecracker/spec_program.py` (~23 import, ~? `MachineResources(vcpus=..., memory=...)`)
- Modify: `src/aleph/vm/controllers/qemu/instance.py` (~11 import, ~170 attr, ~191 default)
- Modify: `src/aleph/vm/controllers/qemu_confidential/instance.py` (~10 import, ~78 attr, ~102 default)

- [ ] **Step 1: Replace the import in each file**

Remove:
```python
from aleph_message.models.execution.environment import MachineResources
```
Add (grouped with the other `aleph.vm.supervisor.types` imports if present, else as a new import):
```python
from aleph.vm.supervisor.types import HardwareResources
```

- [ ] **Step 2: Replace every `MachineResources` token with `HardwareResources`**

In each file, replace:
- `hardware_resources: MachineResources` -> `hardware_resources: HardwareResources`
- `hardware_resources: MachineResources | None = None` -> `hardware_resources: HardwareResources | None = None`
- `= MachineResources()` -> `= HardwareResources()`
- `MachineResources(vcpus=..., memory=...)` (in `spec_program.py`) -> `HardwareResources(vcpus=..., memory=...)`

Verify none remain:
```bash
grep -rn "MachineResources" src/aleph/vm/controllers/   # expect: no output
```

- [ ] **Step 3: Run the controller-facing tests**

Run:
```bash
$PY -m pytest tests/supervisor/test_qemu_instance.py tests/supervisor/test_wait_for_controller.py -q
```
Expected: any failures are import/type only and are fixed by completing this task; tests that construct controllers with `MachineResources(...)` will be migrated in Task 4. Note which tests fail for later triage; do not fix tests here.

- [ ] **Step 4: Type-check the controllers**

Run: `$PY -m mypy src/aleph/vm/controllers/`
Expected: no `MachineResources`/`HardwareResources` name or attr errors introduced by this task (pre-existing env-noise unrelated to this swap is acceptable; compare against base if unsure).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/controllers/
git commit -m "refactor(controllers): take message-free HardwareResources instead of MachineResources"
```

---

### Task 3: Strip `VmExecution` to spec-only

**Files:**
- Modify: `src/aleph/vm/models.py`
- Modify: `src/aleph/vm/pool.py` (remove the `execution.save()` call)
- Test: existing `tests/supervisor/test_execution.py` etc. are migrated in Task 4.

Sub-steps (one commit at the end; run the relevant tests after the edits):

- [ ] **Step 1: Confirm `save()` and `run_code` are removable**

```bash
grep -rn --include=*.py "\.save()" src/aleph/vm/ | grep -v "def save\|save_record\|port_mappings\|save_controller\|save_execution"
# expect exactly: pool.py (restart_persistent_vm) and models.py (start)
grep -rn --include=*.py "execution.run_code\|self.run_code\|\.run_code(scope" src/aleph/vm/ | grep -v "vm.run_code\|program_client\|guest"
# expect: nothing (VmExecution.run_code has no production caller)
```
If either grep shows an unexpected caller, STOP and reassess before removing.

- [ ] **Step 2: Remove the message imports from `models.py`**

Delete the import block:
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
Add `HardwareResources` to the existing `from aleph.vm.supervisor.types import ...` line (currently `Backend, CreateVmSpec, VmId`).

- [ ] **Step 3: Delete `MessageSpec` and collapse the `spec` union**

- Delete the `MessageSpec` dataclass.
- `spec: MessageSpec | CreateVmSpec` -> `spec: CreateVmSpec`.
- In `__init__`, drop the `message`/`original` parameters and the `if vm_spec is not None / else MessageSpec(...)` branch; require `vm_spec` and assign `self.spec = vm_spec`. Keep `vm_hash`, `snapshot_manager`, `systemd_manager`, `persistent`.

New `__init__` body (sizing the signature to the spec-only world):
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

`from_spec` stays but drops the now-redundant `vm_spec=` keyword position only if needed; keep it explicit:
```python
return cls(
    vm_hash=spec.vm_id,
    vm_spec=spec,
    snapshot_manager=snapshot_manager,
    systemd_manager=systemd_manager,
    persistent=spec.persistent,
)
```

- [ ] **Step 4: Delete the message-only properties and methods**

Delete: `message` property, `original` property, `prepare_gpus`, `fetch_port_redirect_config_and_setup`, the `hypervisor` property, and `run_code` (dead). Keep `vm_spec` property (now always returns `self.spec`) — or delete it and have callers read `self.spec` directly; verify callers first:
```bash
grep -rn --include=*.py "\.vm_spec\b" src/aleph/vm/
```
If `vm_spec` has live callers, keep it returning `self.spec`; otherwise delete it.

- [ ] **Step 5: Simplify the spec/message-branching accessors**

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

Remove the `message = self.spec.message` branch entirely; keep the existing `isinstance(self.spec, CreateVmSpec)` body (which becomes unconditional):

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

Remove the `message = self.spec.message` branch (the `AlephFirecrackerProgram` / message-built `AlephQemuInstance` / message-built `AlephQemuConfidentialInstance` constructions). Keep the existing spec branch, which already builds `MachineResources(...)` — change that to `HardwareResources(...)`:

```python
hardware_resources = HardwareResources(vcpus=self.spec.vcpus, memory=self.spec.memory_mib)
```

The spec branch already covers FIRECRACKER (`SpecFirecrackerProgram`), confidential (`AlephQemuConfidentialInstance`), and plain QEMU (`AlephQemuInstance`). After removing the message branch the method ends after the QEMU `return vm`; delete the trailing `message = self.spec.message ... else: raise Exception("Unknown VM")` block.

- [ ] **Step 8: Remove `save()` and its callers**

- Delete the `save()` method from `models.py`.
- In `models.py` `start()`, remove the `await self.save()` line (line ~720).
- In `pool.py` `restart_persistent_vm`, remove the `await execution.save()` line (line ~561) and its now-stale "Re-save so the record survives" comment.
- Remove now-unused imports in `models.py` if they become orphaned (`ExecutionRecord`, `save_record`, `pydantic_encoder`, `json` if unused elsewhere). Verify with:
```bash
grep -n "ExecutionRecord\|save_record\|pydantic_encoder\|json\." src/aleph/vm/models.py
```
Keep any that still have a live use.

- [ ] **Step 9: Verify models.py is message-free**

```bash
grep -n "aleph_message\|MachineResources\|HypervisorType\|MessageSpec\|InstanceContent\|ProgramContent\|ExecutableContent\|GpuProperties" src/aleph/vm/models.py
# expect: no output
```

- [ ] **Step 10: Run the daemon-path tests (expect Task 4 test breakage)**

Run:
```bash
$PY -m pytest tests/supervisor/ -q
```
Expected: source imports cleanly; failures are confined to tests that construct message-built `VmExecution` or call removed methods. Record the failing set for Task 4. Do not edit tests here.

- [ ] **Step 11: Commit**

```bash
git add src/aleph/vm/models.py src/aleph/vm/pool.py
git commit -m "refactor(supervisor): make VmExecution spec-only, drop aleph_message"
```

---

### Task 4: Migrate the test suite onto the spec path

~20 message-built `VmExecution` constructions across these files (verify the current set first):

```bash
grep -rln --include=*.py "VmExecution(" tests/ | xargs grep -ln "message=\|original="
```

Known sites: `tests/supervisor/test_execution.py`, `test_views.py`, `test_qemu_instance.py`, `test_drain.py`, `test_run.py`, `test_firewall.py`, `test_wait_for_controller.py`, `test_host_gpu_detail.py`.

**Triage rule per construction (apply, do not batch-edit blindly):**

1. If the test asserts behavior that still has a live spec path (lifecycle, ports, drain, wait-for-controller, GPU detail via spec), **convert** it: build a `CreateVmSpec` (use the helper from `tests/supervisor/test_supervisor_spec_admission.py::_spec` as a template, extended with the fields the test needs) and construct `VmExecution.from_spec(...)` or `VmExecution(vm_hash=..., vm_spec=...)`.
2. If the test exercises only the removed message path (`prepare_gpus`, `fetch_port_redirect_config_and_setup`, `run_code`, message-built `prepare`/`create`, `save()` writing a record, `.message`/`.original`), and that behavior is intentionally gone, **delete** the test. Note each deletion in the commit body with the reason.
3. If a behavior is genuinely lost with no spec-path equivalent, STOP and escalate — that means the purge dropped a live behavior and the design needs revisiting.

- [ ] **Step 1: Build/confirm a shared spec factory for tests**

If `tests/supervisor/conftest.py` lacks a reusable `CreateVmSpec` factory, add one (mirror `_spec` from `test_supervisor_spec_admission.py`, parameterized for backend, tee, gpus, persistent, memory, vcpus). Reuse across the migrated tests (DRY).

- [ ] **Step 2: Migrate file-by-file**

For each file in the known set, apply the triage rule. Run that file's tests after editing:
```bash
$PY -m pytest tests/supervisor/<file>.py -q
```
Expected: PASS (except the environment baseline in `test_execution.py`: the jailman `chown` subprocess failures are pre-existing and unrelated).

- [ ] **Step 3: Full suite**

```bash
$PY -m pytest tests/ -q
```
Expected: green except the documented environment baseline (jailman `chown`, pyroute2 netlink).

- [ ] **Step 4: Commit**

```bash
git add tests/
git commit -m "test(supervisor): migrate VmExecution tests to the spec path; drop message-path-only tests"
```

---

### Task 5: Final gates and boundary verification

- [ ] **Step 1: Format and import order**

```bash
$PY -m ruff format --check src/aleph/vm/ tests/supervisor/
$PY -m isort --profile black --check-only src/aleph/vm/ tests/supervisor/
```
Fix with the non-`--check` forms if needed; re-run.

- [ ] **Step 2: Type check**

```bash
$PY -m mypy src/aleph/vm/models.py src/aleph/vm/pool.py src/aleph/vm/controllers/ src/aleph/vm/supervisor/
```
Expected: the two pre-existing `models.py` `trusted_execution`/`policy` union-attr errors are GONE (their branch was deleted). No new errors on our symbols.

- [ ] **Step 3: Boundary assertions**

```bash
# Daemon execution object and controllers carry no message value types:
grep -rn "MachineResources\|HypervisorType" src/aleph/vm/ ; echo "^ expect: no output"
grep -n "aleph_message" src/aleph/vm/models.py ; echo "^ expect: no output"
# The documented edge: resources classes keep their message constructors only:
grep -rn "aleph_message" src/aleph/vm/controllers/ | grep -v "# boundary"
```
The last grep should show `aleph_message` only in the resource-download classes (`AlephQemuResources`/`AlephProgramResources` and their bases) and any controller still legitimately reading message content for the agent-shared download path. Confirm each remaining hit is the documented boundary, not a missed daemon coupling.

- [ ] **Step 4: Dispatch a code-quality reviewer** (per subagent-driven-development) over the full branch diff vs `od/supervisor-vmid-identity`. Address findings, re-review.

- [ ] **Step 5: Push and open PR**

```bash
git push -u origin od/execution-message-free
gh pr create --base od/supervisor-vmid-identity --head od/execution-message-free \
  --title "refactor(supervisor): make VmExecution and controllers message-free" \
  --body "<summary + boundary note + verification, per the design doc>"
```

---

## Self-review (plan vs design)

- **Spec coverage:** DTO (Task 1), controller swap (Task 2), VmExecution strip incl. save/run_code removal (Task 3), test migration (Task 4), gates + boundary checks (Task 5). All design sections covered.
- **Out of scope (documented):** deletion of the now-dead `AlephFirecrackerProgram` class is deferred to a follow-up; the resources classes keep their message constructors (the boundary).
- **Type consistency:** `HardwareResources` fields (`vcpus`/`memory`/`seconds`) match the `MachineResources` fields the controllers read, so field access is unchanged; defaults match so `HardwareResources()` is a drop-in.
- **Verification-dependent steps** (controller liveness, orphaned imports, `vm_spec`/`save` callers) are written as explicit grep-then-decide steps rather than assumed, because the exact set can shift with the lower PRs in the stack.
