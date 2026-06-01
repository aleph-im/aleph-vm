# Message-free supervisor create + reboot-recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the supervisor *create* a VM from a message-free `CreateVmSpec` (paths only, no Aleph message, no download), wire it into `pool.executions`, route the production creation path through the spec translator, and reattach surviving VMs after a reboot from on-disk controller configs — all without the supervisor's machinery ever reading an Aleph message.

**Architecture:** `VmExecution` gains a spec-driven construction path alongside the existing message path (no behavior change to the message path). `pool.create_a_vm_from_spec(spec)` mirrors `create_a_vm` but sources everything from the spec and writes the controller config via Phase 0.C's `build_qemu_configuration`, skipping the message-coupled `vm.configure()`. `InProcessSupervisor.create_vm` delegates to it. `orchestrator/run.py` (agent territory) translates eligible QEMU instances to a spec, then re-attaches the message to the created execution purely for its own consumers (operator API owner-auth, port forwarding) — the supervisor's machinery never reads it. Reboot-recovery (`pool.load_persistent_executions`) scans `*-controller.json` + systemd and reattaches via `spec_from_controller_configuration(config)` → `VmExecution.from_spec`, dropping the DB-message read entirely.

**Tech Stack:** Python 3.11, asyncio, pydantic v2, pytest / pytest-asyncio. Test conventions per `tests/supervisor/`: sibling imports (no `tests/supervisor/__init__.py`), `monkeypatch`, ruff/isort/mypy green.

**Scope:** PRs 1–4, stacked, each independently deployable. **Ownership is out of scope and intentionally so:** the supervisor never tracks who owns a VM. The agent API gates HTTP calls against its own ownership store; the agent's operator API may be unavailable during a reboot, which is acceptable — separating the API lifecycle from the supervisor lifecycle is the point. PR 4 therefore does not preserve any message for the agent across a reboot.

**Design doc:** `docs/plans/2026-05-29-message-free-supervisor-create-reboot-design.md`

**Two resolved design decisions** (called out by the controller before planning):
1. **PR sequencing:** PR 3 (route production through the spec) lands before any reboot-recovery work, so the create path is fully wired and routed first.
2. **Resources holder:** a `from_spec` classmethod on the existing `AlephQemuResources` (not a parallel dataclass). The `create()` path already does `assert isinstance(self.resources, AlephQemuResources)` and `pool.calculate_available_disk` reads `resources.get_disk_usage_delta()`; keeping one type avoids duck-typing and a widened annotation.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/aleph/vm/controllers/firecracker/executable.py` | Resources holder base | Make `message_content` nullable so a spec holder carries no message |
| `src/aleph/vm/controllers/qemu/instance.py` | QEMU resources holder | Add `AlephQemuResources.from_spec` (no download) |
| `src/aleph/vm/models.py` | `VmExecution` | Optional `message`/`original` + `spec`; `from_spec`; spec-aware properties; spec branches in `prepare()`/`create()`; `start(write_config=...)`; `save()` skip; `allocated_*` props |
| `src/aleph/vm/pool.py` | Pool / lifecycle | `create_a_vm_from_spec`; nullability guards in `check_admission` + `get_executions_by_address` |
| `src/aleph/vm/orchestrator/views/__init__.py` | Monitoring views | Guard `VmType.from_message_content` against message-less executions |
| `src/aleph/vm/orchestrator/tasks.py` | Payment/notify tasks | Guard `execution.message.address` comprehensions |
| `src/aleph/vm/supervisor/inprocess.py` | Supervisor boundary | Implement `create_vm` (delegate to pool) |
| `src/aleph/vm/orchestrator/run.py` | Agent creation path | Route eligible QEMU instances through the spec; re-attach message for agent consumers |
| `src/aleph/vm/supervisor/qemu_build.py` | Spec ⇄ config | Add `spec_from_controller_configuration` (inverse of `build_qemu_configuration`) |
| `src/aleph/vm/pool.py` | Reboot-recovery | Rewrite `load_persistent_executions` to scan configs; config-driven `_restore_running_execution_from_config` / `_restore_network` / `_handle_dead_controller`; drop DB-message reads |

---

## PR 1 — `VmExecution` spec-constructible (message-free internals)

### Task 1: `AlephQemuResources.from_spec` (no download)

**Files:**
- Modify: `src/aleph/vm/controllers/firecracker/executable.py:94-138` (make `message_content` nullable)
- Modify: `src/aleph/vm/controllers/qemu/instance.py:40-96` (add `from_spec`)
- Test: `tests/supervisor/test_supervisor_spec_resources.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_spec_resources.py`:

```python
"""Tests for AlephQemuResources.from_spec — the message-free resources holder."""

from __future__ import annotations

from pathlib import Path

from aleph.vm.controllers.qemu.instance import AlephQemuResources
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    VmId,
)


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId("deadbeef" * 8),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS),
            DiskSpec(
                path=Path("/data/extra.img"),
                readonly=True,
                format=DiskFormat.RAW,
                role=DiskRole.EXTRA,
                mount="/mnt/data",
            ),
        ],
        vcpus=4,
        memory_mib=2048,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True)],
        numa_node=None,
        persistent=True,
    )


def test_from_spec_populates_paths_without_download():
    resources = AlephQemuResources.from_spec(_spec(), namespace="ns")

    assert resources.message_content is None
    assert resources.namespace == "ns"
    assert resources.rootfs_path == Path("/data/rootfs.qcow2")
    assert len(resources.volumes) == 1
    assert resources.volumes[0].path_on_host == Path("/data/extra.img")
    assert resources.volumes[0].mount == "/mnt/data"
    assert resources.volumes[0].read_only is True
    assert len(resources.gpus) == 1
    assert resources.gpus[0].pci_host == "0000:01:00.0"
    assert resources.gpus[0].supports_x_vga is True


def test_from_spec_disk_usage_delta_is_zero():
    # The supervisor does not do admission; the spec holder reports no reservation.
    resources = AlephQemuResources.from_spec(_spec(), namespace="ns")
    assert resources.get_disk_usage_delta() == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_resources.py -v`
Expected: FAIL with `AttributeError: type object 'AlephQemuResources' has no attribute 'from_spec'`

- [ ] **Step 3: Make `message_content` nullable**

In `src/aleph/vm/controllers/firecracker/executable.py`, change the class attribute annotation and `__init__` signature so a spec holder can carry no message:

```python
class AlephFirecrackerResources:
    """Resources required to start a Firecracker VM"""

    message_content: ExecutableContent | None
```

```python
    def __init__(self, message_content: ExecutableContent | None, namespace: str):
        self.message_content = message_content
        self.namespace = namespace
```

`get_disk_usage_delta()` already guards via `if hasattr(self.message_content, "rootfs")` — `hasattr(None, "rootfs")` is `False`, so no rootfs is counted; spec volumes carry `size_mib=None` (next step) so the volume loop adds `0`. No change to that method.

- [ ] **Step 4: Add `from_spec` to `AlephQemuResources`**

In `src/aleph/vm/controllers/qemu/instance.py`, add the classmethod to `AlephQemuResources` (after `make_writable_volume`, before `ConfigurationType = TypeVar(...)`):

```python
    @classmethod
    def from_spec(cls, spec, namespace: str) -> "AlephQemuResources":
        """Build a message-free resources holder from a CreateVmSpec.

        No download is performed: every path comes from the spec, which the
        agent already resolved on disk. The holder satisfies the attribute
        surface the QEMU controller and pool read (rootfs_path, volumes,
        gpus, kernel_image_path), with message_content left None.
        """
        from aleph.vm.controllers.firecracker.executable import HostVolume
        from aleph.vm.resources import HostGPU
        from aleph.vm.supervisor.errors import InvalidBackendError
        from aleph.vm.supervisor.types import DiskRole

        resources = cls(None, namespace)
        resources.kernel_image_path = Path(settings.LINUX_PATH)

        rootfs_disks = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
        if not rootfs_disks:
            raise InvalidBackendError("CreateVmSpec has no ROOTFS disk")
        resources.rootfs_path = rootfs_disks[0].path

        resources.volumes = [
            HostVolume(mount=d.mount, path_on_host=d.path, read_only=d.readonly, size_mib=None)
            for d in spec.disks
            if d.role in {DiskRole.EXTRA, DiskRole.DATA}
        ]
        resources.gpus = [HostGPU(pci_host=g.pci_host, supports_x_vga=g.supports_x_vga) for g in spec.gpus]
        return resources
```

(`Path` and `settings` are already imported in this module.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_resources.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/controllers/firecracker/executable.py src/aleph/vm/controllers/qemu/instance.py tests/supervisor/test_supervisor_spec_resources.py
git commit -m "feat(supervisor): AlephQemuResources.from_spec (message-free, no download)"
```

---

### Task 2: `VmExecution` optional message + `from_spec`

**Files:**
- Modify: `src/aleph/vm/models.py:97-113` (annotations), `:381-407` (`__init__`)
- Test: `tests/supervisor/test_supervisor_spec_execution.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_spec_execution.py`:

```python
"""Tests for VmExecution spec-constructible path (message-free)."""

from __future__ import annotations

from pathlib import Path

import pytest
from aleph_message.models import ItemHash

from aleph.vm.models import VmExecution
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def make_spec(*, internet: bool = True, vcpus: int = 4, memory_mib: int = 2048) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def test_from_spec_sets_spec_and_no_message():
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    assert execution.spec is not None
    assert execution.message is None
    assert execution.original is None
    assert execution.vm_hash == ItemHash(_HASH)
    assert execution.persistent is True
    assert execution.resources is None
    assert execution.vm is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py::test_from_spec_sets_spec_and_no_message -v`
Expected: FAIL with `AttributeError: type object 'VmExecution' has no attribute 'from_spec'`

- [ ] **Step 3: Make message/original optional, add `spec`, add `from_spec`**

In `src/aleph/vm/models.py`, update imports — add `MachineResources` and the supervisor types. Change the existing environment import (line 18) and add the supervisor import after it:

```python
from aleph_message.models.execution.environment import GpuProperties, HypervisorType, MachineResources
```

```python
from aleph.vm.supervisor.types import Backend, CreateVmSpec
```

Update the class attribute annotations (around lines 106-107):

```python
    vm_hash: ItemHash
    original: ExecutableContent | None
    message: ExecutableContent | None
    spec: CreateVmSpec | None = None
```

Update `__init__` (lines 381-407) so `message`/`original` default to `None` and a `spec` kwarg exists. Keep every parameter keyword-compatible (all three call sites in `pool.py` pass keywords):

```python
    def __init__(
        self,
        vm_hash: ItemHash,
        message: ExecutableContent | None = None,
        original: ExecutableContent | None = None,
        snapshot_manager: SnapshotManager | None = None,
        systemd_manager: SystemDManager | None = None,
        persistent: bool = False,
        spec: CreateVmSpec | None = None,
    ):
        self.init_task = None
        self.uuid = uuid.uuid1()  # uuid1() includes the hardware address and timestamp
        self.vm_hash = vm_hash
        self.message = message
        self.original = original
        self.spec = spec
        self.times = VmExecutionTimes(defined_at=datetime.now(tz=timezone.utc))
        self.ready_event = asyncio.Event()
        self.concurrent_runs = 0
        self.runs_done_event = asyncio.Event()
        self.runs_done_event.set()  # 0 runs = all done
        self.stop_event = asyncio.Event()  # triggered when the VM is stopped
        self.preparation_pending_lock = asyncio.Lock()
        self.stop_pending_lock = asyncio.Lock()
        self.snapshot_manager = snapshot_manager
        self.systemd_manager = systemd_manager
        self.persistent = persistent
        self.mapped_ports = {}
        self.gpus = []
```

Add the classmethod immediately after `__init__`:

```python
    @classmethod
    def from_spec(
        cls,
        spec: CreateVmSpec,
        *,
        snapshot_manager: SnapshotManager | None,
        systemd_manager: SystemDManager | None,
    ) -> "VmExecution":
        """Construct a message-free execution from a CreateVmSpec.

        The supervisor's machinery (prepare/create/start/save) reads only the
        spec. message/original stay None; an agent may attach them afterwards
        for its own consumers (operator API, billing) — see orchestrator/run.py.
        """
        return cls(
            vm_hash=ItemHash(spec.vm_id),
            spec=spec,
            snapshot_manager=snapshot_manager,
            systemd_manager=systemd_manager,
            persistent=spec.persistent,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py::test_from_spec_sets_spec_and_no_message -v`
Expected: PASS

- [ ] **Step 5: Run the existing execution + pool tests to confirm no regression**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_inprocess_query.py tests/supervisor/test_supervisor_inprocess_lifecycle.py -v`
Expected: PASS (the `__init__` change keeps all keyword call sites working)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/models.py tests/supervisor/test_supervisor_spec_execution.py
git commit -m "feat(supervisor): VmExecution.from_spec with optional message/original"
```

---

### Task 3: Spec-aware properties

**Files:**
- Modify: `src/aleph/vm/models.py:328-367` (the `is_program`/`is_instance`/`is_confidential`/`hypervisor`/payment properties)
- Test: `tests/supervisor/test_supervisor_spec_execution.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/supervisor/test_supervisor_spec_execution.py`:

```python
from aleph_message.models.execution.environment import HypervisorType


def test_spec_properties_for_qemu_instance():
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    assert execution.is_instance is True
    assert execution.is_program is False
    assert execution.is_confidential is False
    assert execution.hypervisor is HypervisorType.qemu
    # Payment flags are agent-side; absent without a message.
    assert execution.uses_payment_stream is False
    assert execution.uses_payment_credit is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py::test_spec_properties_for_qemu_instance -v`
Expected: FAIL — `is_program` calls `isinstance(self.message, ProgramContent)` with `self.message is None` → returns False, but `is_confidential` accesses `self.message.environment` → `AttributeError`

- [ ] **Step 3: Re-back the properties**

In `src/aleph/vm/models.py`, replace the five properties (lines 328-367) with spec-aware versions. When a spec is present it is authoritative for the supervisor's machinery; otherwise behaviour is exactly as before:

```python
    @property
    def is_program(self) -> bool:
        if self.spec is not None:
            return self.spec.backend is Backend.FIRECRACKER
        return isinstance(self.message, ProgramContent)

    @property
    def is_instance(self) -> bool:
        if self.spec is not None:
            return self.spec.backend in {Backend.QEMU, Backend.QEMU_SEV}
        return isinstance(self.message, InstanceContent)

    @property
    def is_confidential(self) -> bool:
        if self.spec is not None:
            return self.spec.backend is Backend.QEMU_SEV
        # FunctionEnvironment has no trusted_execution
        return True if getattr(self.message.environment, "trusted_execution", None) else False

    @property
    def hypervisor(self) -> HypervisorType:
        if self.spec is not None:
            if self.spec.backend is Backend.FIRECRACKER:
                return HypervisorType.firecracker
            return HypervisorType.qemu
        if self.is_program:
            return HypervisorType.firecracker

        # Hypervisor setting is only used for instances
        return self.message.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
```

And guard the two payment properties (lines 361-367) against a missing message:

```python
    @property
    def uses_payment_stream(self) -> bool:
        return bool(self.message and self.message.payment and self.message.payment.is_stream)

    @property
    def uses_payment_credit(self) -> bool:
        return bool(self.message and self.message.payment and self.message.payment.is_credit)
```

> Note: for the spec path `is_program`/`is_instance` only distinguish QEMU (instance) from Firecracker (program). Firecracker is not yet spec-constructible (out of scope), so the rare Firecracker-instance case is not represented here.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Confirm message-path behaviour unchanged**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_instance.py tests/supervisor/test_qemu_instance.py -v`
Expected: PASS (no behaviour change on the message path)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/models.py tests/supervisor/test_supervisor_spec_execution.py
git commit -m "feat(supervisor): spec-aware VmExecution backend properties"
```

---

### Task 4: spec branches in `prepare()` and `create()`

**Files:**
- Modify: `src/aleph/vm/models.py:418-452` (`prepare`), `:480-540` (`create`)
- Test: `tests/supervisor/test_supervisor_spec_execution.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/supervisor/test_supervisor_spec_execution.py`:

```python
from aleph.vm.controllers.qemu.instance import AlephQemuInstance, AlephQemuResources


@pytest.mark.asyncio
async def test_prepare_builds_resources_without_download(monkeypatch):
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    # download_all must never be called on the spec path.
    called = {"download": False}

    async def fail_download(self):  # type: ignore[no-untyped-def]
        called["download"] = True

    monkeypatch.setattr(AlephQemuResources, "download_all", fail_download)

    await execution.prepare()

    assert called["download"] is False
    assert isinstance(execution.resources, AlephQemuResources)
    assert execution.resources.rootfs_path == Path("/data/rootfs.qcow2")
    assert execution.times.prepared_at is not None


@pytest.mark.asyncio
async def test_create_builds_qemu_instance_from_spec():
    execution = VmExecution.from_spec(
        make_spec(internet=False, vcpus=3, memory_mib=1024),
        snapshot_manager=None,
        systemd_manager=None,
    )
    await execution.prepare()

    vm = execution.create(vm_id=7, tap_interface=None)

    assert isinstance(vm, AlephQemuInstance)
    assert vm.vm_id == 7
    assert vm.hardware_resources.vcpus == 3
    assert vm.hardware_resources.memory == 1024
    assert vm.enable_networking is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py -k "prepare or create" -v`
Expected: FAIL — `prepare()` falls into the message branch and hits `self.is_program`→`isinstance(None,...)`/`AlephQemuResources(self.message, ...)` with a `None` message, then `download_all()` on real paths

- [ ] **Step 3: Add the spec branch to `prepare()`**

In `src/aleph/vm/models.py`, inside `prepare()`, after `self.times.preparing_at = datetime.now(tz=timezone.utc)` (line 425) and before the `resources: (...)` type declaration, insert:

```python
            if self.spec is not None:
                # Spec path: every path is already resolved on disk; no download.
                self.resources = AlephQemuResources.from_spec(self.spec, namespace=str(self.vm_hash))
                self.times.prepared_at = datetime.now(tz=timezone.utc)
                return
```

- [ ] **Step 4: Add the spec branch to `create()`**

In `src/aleph/vm/models.py`, inside `create()`, after the `if not self.resources: raise` block (lines 483-485) and before `vm: AlephVmControllerInterface`, insert:

```python
        if self.spec is not None:
            assert isinstance(self.resources, AlephQemuResources)
            hardware_resources = MachineResources(vcpus=self.spec.vcpus, memory=self.spec.memory_mib)
            self.vm = vm = AlephQemuInstance(
                vm_id=vm_id,
                vm_hash=self.vm_hash,
                resources=self.resources,
                enable_networking=self.spec.network.internet_access,
                hardware_resources=hardware_resources,
                tap_interface=tap_interface,
            )
            return vm
```

(Confidential `QEMU_SEV` is out of scope; `create_a_vm_from_spec` rejects it before reaching here, so the non-confidential `AlephQemuInstance` is always correct on the spec path.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/models.py tests/supervisor/test_supervisor_spec_execution.py
git commit -m "feat(supervisor): spec-driven prepare() and create() in VmExecution"
```

---

### Task 5: `start(write_config=...)` and `save()` skip for the spec path

**Files:**
- Modify: `src/aleph/vm/models.py:542-587` (`start`), `:752-795` (`save`)
- Test: `tests/supervisor/test_supervisor_spec_execution.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/supervisor/test_supervisor_spec_execution.py`:

```python
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_start_skips_configure_and_save_for_spec(monkeypatch):
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    execution = VmExecution.from_spec(
        make_spec(internet=False), snapshot_manager=None, systemd_manager=systemd
    )
    await execution.prepare()
    execution.create(vm_id=7, tap_interface=None)

    # configure() is message-coupled (cloud-init reads resources.message_content)
    # and must NOT be called on the spec path.
    execution.vm.configure = AsyncMock()
    execution.vm.setup = AsyncMock()
    execution.vm.start_guest_api = AsyncMock()
    # Controller comes up immediately.
    monkeypatch.setattr(
        VmExecution, "non_blocking_wait_for_boot", AsyncMock(return_value=True)
    )
    save_record = AsyncMock()
    monkeypatch.setattr("aleph.vm.models.save_record", save_record)

    await execution.start(write_config=False)

    execution.vm.configure.assert_not_awaited()
    systemd.enable_and_start.assert_awaited_once_with(execution.controller_service)
    save_record.assert_not_awaited()  # spec path keeps no DB record
    assert execution.ready_event.is_set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py::test_start_skips_configure_and_save_for_spec -v`
Expected: FAIL — `start()` has no `write_config` parameter (`TypeError`)

- [ ] **Step 3: Add `write_config` to `start()`**

In `src/aleph/vm/models.py`, change the `start` signature (line 542) and guard the `configure()` call (line 554):

```python
    async def start(self, write_config: bool = True):
```

```python
            if write_config:
                await self.vm.configure()
```

- [ ] **Step 4: Skip `save()` for the spec path**

In `src/aleph/vm/models.py`, at the top of `save()` (after the `assert self.vm` on line 754), insert:

```python
        if self.message is None:
            # Spec-built executions keep no DB record. The durable description
            # of a running VM is its on-disk controller config; the supervisor
            # reattaches from that, not from a stored message.
            return
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_execution.py -v`
Expected: PASS (all tests)

- [ ] **Step 6: Run the lint/type gate for PR 1**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m mypy src/aleph/vm/models.py src/aleph/vm/controllers/qemu/instance.py src/aleph/vm/controllers/firecracker/executable.py`
Expected: `Success: no issues found`
Run: `cd .worktrees/supervisor-create && .testvenv/bin/ruff check src/aleph/vm/models.py src/aleph/vm/controllers/qemu/instance.py tests/supervisor/test_supervisor_spec_execution.py tests/supervisor/test_supervisor_spec_resources.py`
Expected: no new errors versus baseline

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/models.py tests/supervisor/test_supervisor_spec_execution.py
git commit -m "feat(supervisor): start(write_config) and message-free save() skip"
```

---

## PR 2 — `pool.create_a_vm_from_spec` + `InProcessSupervisor.create_vm`

### Task 6: nullability guards for message-less executions in the pool

A spec-built execution (`message is None`) can sit in `pool.executions`. Three call sites iterate **all** executions and read `execution.message`; they must tolerate `None`.

**Files:**
- Modify: `src/aleph/vm/models.py` (add `allocated_memory_mib` / `allocated_vcpus` properties)
- Modify: `src/aleph/vm/pool.py:203-213` (`check_admission` loop), `:819-843` (`get_executions_by_address`)
- Modify: `src/aleph/vm/orchestrator/views/__init__.py:238,272` (vm_type), `src/aleph/vm/orchestrator/tasks.py:195,229`
- Test: `tests/supervisor/test_supervisor_spec_pool_guards.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_spec_pool_guards.py`:

```python
"""A message-less (spec-built) execution must not break pool-wide iterations."""

from __future__ import annotations

from pathlib import Path

from aleph_message.models import PaymentType

from aleph.vm.models import VmExecution
from aleph.vm.pool import VmPool
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def test_allocated_properties_from_spec():
    execution = VmExecution.from_spec(_spec(), snapshot_manager=None, systemd_manager=None)
    assert execution.allocated_memory_mib == 1024
    assert execution.allocated_vcpus == 2


def test_get_executions_by_address_skips_message_less(monkeypatch):
    monkeypatch.setattr("aleph.vm.pool.settings", VmPool.__init__.__globals__["settings"])
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    spec_exec = VmExecution.from_spec(_spec(), snapshot_manager=None, systemd_manager=None)
    spec_exec.times.started_at = spec_exec.times.starting_at = spec_exec.times.defined_at
    pool.executions[_HASH] = spec_exec

    # Must not raise even though execution.message is None.
    result = pool.get_executions_by_address(PaymentType.hold)
    assert result == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_pool_guards.py -v`
Expected: FAIL — `AttributeError: 'VmExecution' object has no attribute 'allocated_memory_mib'`

- [ ] **Step 3: Add `allocated_*` properties to `VmExecution`**

In `src/aleph/vm/models.py`, after the `uses_payment_credit` property, add:

```python
    @property
    def allocated_memory_mib(self) -> int:
        """Requested memory in MiB, from the spec or the message."""
        if self.spec is not None:
            return self.spec.memory_mib
        if self.message and self.message.resources:
            return self.message.resources.memory
        return 0

    @property
    def allocated_vcpus(self) -> int:
        """Requested vCPUs, from the spec or the message."""
        if self.spec is not None:
            return self.spec.vcpus
        if self.message and self.message.resources:
            return self.message.resources.vcpus
        return 0
```

- [ ] **Step 4: Use the properties in `check_admission`**

In `src/aleph/vm/pool.py`, replace the admission loop body (lines 203-213) so it reads the source-agnostic properties and skips executions with no requested resources:

```python
        for execution in tuple(self.executions.values()):
            if current_vm_hash is not None and execution.vm_hash == current_vm_hash:
                continue
            memory = execution.allocated_memory_mib
            vcpus = execution.allocated_vcpus
            if not memory and not vcpus:
                continue
            if execution.is_instance:
                committed_instance_memory_mib += memory
            else:
                committed_program_memory_mib += memory
            committed_vcpus += vcpus
```

- [ ] **Step 5: Guard `get_executions_by_address`**

In `src/aleph/vm/pool.py`, at the top of the loop in `get_executions_by_address` (after line 822 `for vm_hash, execution in self.executions.items():`), add:

```python
            if execution.message is None:
                # Spec-built (supervisor-owned) executions carry no message;
                # payment grouping is an agent concern.
                continue
```

- [ ] **Step 6: Guard the monitoring views and payment tasks**

In `src/aleph/vm/orchestrator/views/__init__.py`, at both sites (lines 238 and 272) replace
`"vm_type": VmType.from_message_content(execution.message).name,` with a message-less fallback:

```python
                "vm_type": (
                    VmType.from_message_content(execution.message).name
                    if execution.message is not None
                    else (VmType.instance.name if execution.is_instance else VmType.microvm.name)
                ),
```

In `src/aleph/vm/orchestrator/tasks.py`, guard the two comprehensions (lines 195 and 229) by adding `execution.message and` before `execution.message.address == address`:

```python
        if execution.is_instance and execution.vm and execution.message and execution.message.address == address
```

(Apply the same edit to the second occurrence around line 229.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_pool_guards.py -v`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add src/aleph/vm/models.py src/aleph/vm/pool.py src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/orchestrator/tasks.py tests/supervisor/test_supervisor_spec_pool_guards.py
git commit -m "fix(supervisor): tolerate message-less executions in pool-wide iterations"
```

---

### Task 7: `pool.create_a_vm_from_spec(spec)`

**Files:**
- Modify: `src/aleph/vm/pool.py` (imports + new method after `create_a_vm`, ~line 398)
- Test: `tests/supervisor/test_supervisor_spec_pool_create.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_spec_pool_create.py`:

```python
"""pool.create_a_vm_from_spec — message-free, no-download create wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec(backend: Backend = Backend.QEMU) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=backend,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    import asyncio

    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.network = None  # exercise the no-network branch
    pool.snapshot_manager = None
    pool.creation_lock = asyncio.Lock()
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    pool.systemd_manager = systemd
    return pool


@pytest.mark.asyncio
async def test_create_a_vm_from_spec_wires_into_pool(monkeypatch):
    pool = _bare_pool()

    build_cfg = AsyncMock(return_value="fake-config")
    save_cfg = MagicMock()
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", save_cfg)
    # Controller reports active immediately.
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    execution = await pool.create_a_vm_from_spec(_spec())

    assert pool.executions[execution.vm_hash] is execution
    assert execution.message is None
    assert execution.vm is not None
    build_cfg.assert_awaited_once()
    save_cfg.assert_called_once_with(_HASH, "fake-config")
    pool.systemd_manager.enable_and_start.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_a_vm_from_spec_rejects_non_qemu(monkeypatch):
    pool = _bare_pool()
    with pytest.raises(InvalidBackendError):
        await pool.create_a_vm_from_spec(_spec(backend=Backend.QEMU_SEV))
    assert pool.executions == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_pool_create.py -v`
Expected: FAIL — `AttributeError: 'VmPool' object has no attribute 'create_a_vm_from_spec'`

- [ ] **Step 3: Add imports to `pool.py`**

In `src/aleph/vm/pool.py`, add to the imports near the top (after the existing `from aleph.vm.controllers...` / `from aleph.vm.systemd import SystemDManager` block):

```python
from aleph.vm.controllers.configuration import save_controller_configuration
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.qemu_build import build_qemu_configuration
from aleph.vm.supervisor.types import Backend, CreateVmSpec
```

(No import cycle: `supervisor.qemu_build` imports controllers + `supervisor.types`/`errors`; none import `pool`.)

- [ ] **Step 4: Add the method**

In `src/aleph/vm/pool.py`, add immediately after `create_a_vm` (after line 398):

```python
    async def create_a_vm_from_spec(self, spec: CreateVmSpec) -> VmExecution:
        """Create a VM from a message-free CreateVmSpec.

        The supervisor's creation path: no Aleph message, no download. The
        spec carries resolved on-disk paths. The controller config is written
        by build_qemu_configuration (0.C), so the message-coupled
        vm.configure() is skipped (start(write_config=False)).
        """
        if spec.backend is not Backend.QEMU:
            raise InvalidBackendError(f"create_a_vm_from_spec supports QEMU only, got {spec.backend}")

        vm_hash = ItemHash(spec.vm_id)
        async with self.creation_lock:
            current_execution = self.executions.get(vm_hash)
            if current_execution and current_execution.is_running and not current_execution.is_stopping:
                current_execution.cancel_expiration()
                return current_execution

            execution = VmExecution.from_spec(
                spec,
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
            )
            self.executions[vm_hash] = execution

            tap_interface = None
            vm_id = None
            try:
                await execution.prepare()  # builds resources from the spec; no download

                vm_id = self.get_unique_vm_id()

                if self.network:
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, VmType.instance)
                    if self.network.interface_exists(vm_id):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_id, tap_interface)

                config = await build_qemu_configuration(spec, vm_id, tap_interface)
                save_controller_configuration(spec.vm_id, config)

                execution.create(vm_id=vm_id, tap_interface=tap_interface)
                await execution.start(write_config=False)
                # NOTE: port forwarding is not fetched here. It depends on the
                # owner address + user-settings aggregate (agent concerns); the
                # agent drives it through the supervisor's add_port_forward.
            except Exception:
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_id is not None:
                    teardown_nftables_for_vm(vm_id)
                    await tap_interface.delete()
                self.forget_vm(vm_hash)
                raise

            self._schedule_forget_on_stop(execution)
            return execution
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_pool_create.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/pool.py tests/supervisor/test_supervisor_spec_pool_create.py
git commit -m "feat(supervisor): pool.create_a_vm_from_spec (message-free create)"
```

---

### Task 8: `InProcessSupervisor.create_vm` delegates to the pool

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py:136-137`
- Modify/replace: `tests/supervisor/test_supervisor_inprocess_stubs.py::test_create_vm_is_stubbed`
- Test: `tests/supervisor/test_supervisor_inprocess_create.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_inprocess_create.py`:

```python
"""InProcessSupervisor.create_vm delegates to pool.create_a_vm_from_spec."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
    VmStatus,
)

_HASH = "itemhash123"


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


@pytest.mark.asyncio
async def test_create_vm_delegates_and_returns_info():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={_HASH: execution},
        systemd=FakeSystemd({f"aleph-vm-controller@{_HASH}.service": True}),
    )
    pool.create_a_vm_from_spec = AsyncMock(return_value=execution)
    sup = InProcessSupervisor(pool=pool)

    spec = _spec()
    info = await sup.create_vm(spec)

    pool.create_a_vm_from_spec.assert_awaited_once_with(spec)
    assert info.vm_id == _HASH
    assert info.status is VmStatus.RUNNING
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_inprocess_create.py -v`
Expected: FAIL — `create_vm` still raises `NotImplementedSupervisorError`

- [ ] **Step 3: Implement `create_vm`**

In `src/aleph/vm/supervisor/inprocess.py`, replace the stub (lines 136-137):

```python
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        with translating_errors():
            execution = await self.pool.create_a_vm_from_spec(spec)
            return _to_vm_info(execution, _is_running(execution, self.pool))
```

- [ ] **Step 4: Update the stub test**

In `tests/supervisor/test_supervisor_inprocess_stubs.py`, remove `test_create_vm_is_stubbed` (and the now-unused `NotImplementedSupervisorError`/`make_spec`/`CreateVmSpec`/`Backend`/`NetworkConfig`/`VmId` imports if they are no longer referenced by other tests in the file — keep any still used by `test_backup_migration_confidential_are_stubbed`).

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_inprocess_create.py tests/supervisor/test_supervisor_inprocess_stubs.py -v`
Expected: PASS

- [ ] **Step 6: Run the supervisor conformance + lint/type gate for PR 2**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_conformance_inprocess.py -v`
Expected: PASS
Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m mypy src/aleph/vm/pool.py src/aleph/vm/supervisor/inprocess.py`
Expected: `Success: no issues found`

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_create.py tests/supervisor/test_supervisor_inprocess_stubs.py
git commit -m "feat(supervisor): implement InProcessSupervisor.create_vm via spec"
```

---

## PR 3 — route production creation through the spec

### Task 9: `create_vm_execution` routes eligible QEMU instances through the spec

The agent translates an eligible message to a spec, creates the VM message-free, then **re-attaches the message** to the created execution for its own consumers (operator-API owner-auth, port forwarding, billing). The supervisor's machinery never read it. Ineligible messages (programs, Firecracker, confidential, GPU instances) keep the legacy `create_a_vm` path unchanged.

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py:30-31` (imports), `:57-70` (`create_vm_execution`)
- Test: `tests/supervisor/test_supervisor_run_routing.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_run_routing.py`:

```python
"""run.create_vm_execution routes eligible QEMU instances through the spec."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator import run as run_module
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = ItemHash("deadbeef" * 8)


def _eligible_content():
    # Minimal InstanceContent-like duck for _is_spec_eligible.
    from aleph_message.models import InstanceContent

    return SimpleNamespace(__class__=InstanceContent)  # replaced below


@pytest.mark.asyncio
async def test_eligible_instance_routed_through_spec(monkeypatch):
    from aleph_message.models import InstanceContent

    content = object.__new__(InstanceContent)
    # _is_spec_eligible checks environment + requirements.
    content.environment = SimpleNamespace(hypervisor=None, trusted_execution=None)
    content.requirements = None

    original_content = object()
    message = SimpleNamespace(content=content)
    original_message = SimpleNamespace(content=original_content)

    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, original_message))
    )

    spec = CreateVmSpec(
        vm_id=VmId(str(_HASH)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/x"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=1,
        memory_mib=512,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )
    build_spec = AsyncMock(return_value=spec)
    monkeypatch.setattr(run_module, "build_create_vm_spec", build_spec)

    created = SimpleNamespace(message=None, original=None, is_instance=True)
    created.fetch_port_redirect_config_and_setup = AsyncMock()
    pool = SimpleNamespace(
        message_cache={},
        create_a_vm_from_spec=AsyncMock(return_value=created),
        create_a_vm=AsyncMock(),
    )

    execution = await run_module.create_vm_execution(_HASH, pool, persistent=True)

    pool.create_a_vm_from_spec.assert_awaited_once_with(spec)
    pool.create_a_vm.assert_not_awaited()
    # Agent re-attached the message for its own consumers.
    assert execution.message is content
    assert execution.original is original_content
    created.fetch_port_redirect_config_and_setup.assert_awaited_once()


@pytest.mark.asyncio
async def test_program_falls_back_to_legacy(monkeypatch):
    from aleph_message.models import ProgramContent

    content = object.__new__(ProgramContent)
    message = SimpleNamespace(content=content)
    original_message = SimpleNamespace(content=object())
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, original_message))
    )

    legacy = SimpleNamespace()
    pool = SimpleNamespace(
        message_cache={},
        create_a_vm_from_spec=AsyncMock(),
        create_a_vm=AsyncMock(return_value=legacy),
    )

    execution = await run_module.create_vm_execution(_HASH, pool, persistent=False)

    pool.create_a_vm.assert_awaited_once()
    pool.create_a_vm_from_spec.assert_not_awaited()
    assert execution is legacy
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py -v`
Expected: FAIL — `create_vm_execution` always calls `create_a_vm`; `build_create_vm_spec`/`_is_spec_eligible` not referenced in `run.py`

- [ ] **Step 3: Add imports + eligibility helper to `run.py`**

In `src/aleph/vm/orchestrator/run.py`, add to the imports:

```python
from aleph_message.models import InstanceContent, ItemHash
from aleph_message.models.execution.environment import HypervisorType
```

(extend the existing `from aleph_message.models import ItemHash` line to include `InstanceContent`, and add the `HypervisorType` import), and add:

```python
from aleph.vm.supervisor.translate import build_create_vm_spec
```

Add the eligibility helper above `create_vm_execution`:

```python
def _is_spec_eligible(content) -> bool:
    """True when the supervisor's message-free create path can handle this message.

    Mirrors build_create_vm_spec's own validation: a non-confidential QEMU
    instance with no GPU requirement. Everything else keeps the legacy path.
    """
    if not isinstance(content, InstanceContent):
        return False
    hypervisor = content.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
    if hypervisor != HypervisorType.qemu:
        return False
    if getattr(content.environment, "trusted_execution", None) is not None:
        return False
    if content.requirements and content.requirements.gpu:
        return False
    return True
```

- [ ] **Step 4: Route through the spec in `create_vm_execution`**

Replace the body of `create_vm_execution` (lines 57-70):

```python
async def create_vm_execution(vm_hash: ItemHash, pool: VmPool, persistent: bool = False) -> VmExecution:
    message, original_message = await load_updated_message(vm_hash)
    pool.message_cache[vm_hash] = message

    logger.debug(f"Message: {json.dumps(message.model_dump(exclude_none=True), indent=4, sort_keys=True, default=str)}")

    content = message.content
    if _is_spec_eligible(content):
        spec = await build_create_vm_spec(vm_hash, content)
        execution = await pool.create_a_vm_from_spec(spec)
        # Agent territory: attach the message so the operator API (owner auth),
        # port forwarding and billing keep working. The supervisor machinery
        # that just created the VM never read these.
        execution.message = content
        execution.original = original_message.content
        if execution.is_instance:
            await execution.fetch_port_redirect_config_and_setup()
        return execution

    execution = await pool.create_a_vm(
        vm_hash=vm_hash,
        message=content,
        original=original_message.content,
        persistent=persistent,
    )

    return execution
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py -v`
Expected: PASS (2 passed)

- [ ] **Step 6: Full supervisor lint/type/test gate for PR 3**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m mypy src/aleph/vm/orchestrator/run.py`
Expected: `Success: no issues found`
Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_translate.py tests/supervisor/test_supervisor_qemu_build.py tests/supervisor/test_supervisor_spec_execution.py tests/supervisor/test_supervisor_spec_pool_create.py tests/supervisor/test_supervisor_inprocess_create.py tests/supervisor/test_supervisor_run_routing.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_routing.py
git commit -m "feat(supervisor): route eligible QEMU instances through the spec create path"
```

---

## PR 4 — reboot-recovery from on-disk configs (message-free)

The supervisor reattaches surviving VMs from `*-controller.json` + active systemd units, not from the DB. No message is read or preserved. The agent's operator API may be briefly unavailable during the reboot; that is acceptable and by design (the API lifecycle is separate from the supervisor lifecycle).

### Task 10: `spec_from_controller_configuration` (config → spec)

**Files:**
- Modify: `src/aleph/vm/supervisor/qemu_build.py` (imports + new function)
- Test: `tests/supervisor/test_supervisor_spec_from_config.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_spec_from_config.py`:

```python
"""spec_from_controller_configuration — reverse of build_qemu_configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.conf import settings as real_settings
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.sizes import MiB
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.qemu_build import spec_from_controller_configuration
from aleph.vm.supervisor.types import Backend, DiskRole

_HASH = "deadbeef" * 8


def _config(*, interface_name: str | None = "tap7") -> Configuration:
    vm_cfg = QemuVMConfiguration(
        qemu_bin_path="/usr/bin/qemu-system-x86_64",
        image_path="/data/rootfs.qcow2",
        monitor_socket_path=Path("/run/m.socket"),
        qmp_socket_path=Path("/run/q.socket"),
        vcpu_count=4,
        mem_size_mb=MiB(2048),
        interface_name=interface_name,
        host_volumes=[QemuVMHostVolume(mount="/mnt/data", path_on_host=Path("/data/extra.img"), read_only=True)],
        gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
    )
    return Configuration(
        vm_id=7,
        vm_hash=_HASH,
        settings=real_settings,
        vm_configuration=vm_cfg,
        hypervisor=HypervisorType.qemu,
    )


def test_spec_from_config_roundtrips_core_fields():
    spec = spec_from_controller_configuration(_config())

    assert spec.vm_id == _HASH
    assert spec.backend is Backend.QEMU
    assert spec.vcpus == 4
    assert spec.memory_mib == 2048
    assert spec.network.internet_access is True  # interface_name present

    rootfs = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
    extra = [d for d in spec.disks if d.role is DiskRole.EXTRA]
    assert rootfs[0].path == Path("/data/rootfs.qcow2")
    assert extra[0].path == Path("/data/extra.img")
    assert extra[0].mount == "/mnt/data"
    assert extra[0].readonly is True
    assert len(spec.gpus) == 1
    assert spec.gpus[0].pci_host == "0000:01:00.0"


def test_spec_from_config_no_interface_means_no_internet():
    spec = spec_from_controller_configuration(_config(interface_name=None))
    assert spec.network.internet_access is False


def test_spec_from_config_rejects_non_qemu():
    from aleph.vm.controllers.configuration import VMConfiguration

    cfg = Configuration(
        vm_id=1,
        vm_hash=_HASH,
        settings=real_settings,
        vm_configuration=VMConfiguration(
            use_jailer=True,
            firecracker_bin_path=Path("/x"),
            jailer_bin_path=Path("/y"),
            config_file_path=Path("/z"),
            init_timeout=5.0,
        ),
        hypervisor=HypervisorType.firecracker,
    )
    with pytest.raises(InvalidBackendError):
        spec_from_controller_configuration(cfg)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_from_config.py -v`
Expected: FAIL — `ImportError: cannot import name 'spec_from_controller_configuration'`

- [ ] **Step 3: Extend the qemu_build imports**

In `src/aleph/vm/supervisor/qemu_build.py`, extend the existing imports. Add `QemuVMConfiguration` to the `aleph.vm.controllers.configuration` import, and widen the `supervisor.types` import:

```python
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
```

```python
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    VmId,
)
```

- [ ] **Step 4: Add the function**

In `src/aleph/vm/supervisor/qemu_build.py`, add at the end of the module:

```python
def spec_from_controller_configuration(config: Configuration) -> CreateVmSpec:
    """Reconstruct a CreateVmSpec from an on-disk controller Configuration.

    The inverse of build_qemu_configuration, used by reboot-recovery to
    reattach a running VM message-free. Only non-confidential QEMU configs
    are supported (QemuConfidentialVMConfiguration is a separate type).
    """
    vm_cfg = config.vm_configuration
    if not isinstance(vm_cfg, QemuVMConfiguration):
        raise InvalidBackendError(
            f"Reattach supports QemuVMConfiguration only, got {type(vm_cfg).__name__}"
        )

    disks: list[DiskSpec] = [
        DiskSpec(
            path=Path(vm_cfg.image_path),
            readonly=False,
            format=DiskFormat.QCOW2,
            role=DiskRole.ROOTFS,
            mount="",
        )
    ] + [
        DiskSpec(
            path=v.path_on_host,
            readonly=v.read_only,
            format=DiskFormat.RAW,
            role=DiskRole.EXTRA,
            mount=v.mount,
        )
        for v in vm_cfg.host_volumes
    ]

    gpus = [GpuSpec(pci_host=PciAddress(g.pci_host), supports_x_vga=g.supports_x_vga) for g in vm_cfg.gpus]

    return CreateVmSpec(
        vm_id=VmId(str(config.vm_hash)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=vm_cfg.vcpu_count,
        memory_mib=vm_cfg.mem_size_mb.count,
        tee=None,
        network=NetworkConfig(
            internet_access=bool(vm_cfg.interface_name),
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=gpus,
        numa_node=None,
        persistent=True,
    )
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_spec_from_config.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/supervisor/qemu_build.py tests/supervisor/test_supervisor_spec_from_config.py
git commit -m "feat(supervisor): spec_from_controller_configuration (config -> spec)"
```

---

### Task 11: config-driven reattach helpers

**Files:**
- Modify: `src/aleph/vm/pool.py` — replace `_restore_running_execution` with `_restore_running_execution_from_config`, make `_restore_network` message-free, replace `_handle_dead_execution` with `_handle_dead_controller`
- Test: `tests/supervisor/test_supervisor_reattach.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_reattach.py`:

```python
"""Config-driven, message-free reattach helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    return pool


@pytest.mark.asyncio
async def test_handle_dead_controller_stops_service():
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH)

    await pool._handle_dead_controller(config)

    pool.systemd_manager.stop_and_disable.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_restore_running_execution_from_config_registers_execution(monkeypatch):
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH, vm_id=7)

    monkeypatch.setattr("aleph.vm.pool.spec_from_controller_configuration", lambda c: _spec())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))

    from aleph.vm.models import VmExecution

    monkeypatch.setattr(VmExecution, "prepare", AsyncMock())
    fake_vm = SimpleNamespace(support_snapshot=False, start_guest_api=AsyncMock())
    monkeypatch.setattr(VmExecution, "create", MagicMock(return_value=fake_vm))

    await pool._restore_running_execution_from_config(config, vm_id=7, vm_hash=_HASH)

    assert _HASH in pool.executions
    execution = pool.executions[_HASH]
    assert execution.spec is not None
    assert execution.message is None
    fake_vm.start_guest_api.assert_awaited_once()
    assert execution.ready_event.is_set()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_reattach.py -v`
Expected: FAIL — `AttributeError: 'VmPool' object has no attribute '_handle_dead_controller'`

- [ ] **Step 3: Make `_restore_network` message-free**

In `src/aleph/vm/pool.py`, in `_restore_network` (line 583), replace the message-derived vm_type with the QEMU-instance value:

```python
        # Reattach is QEMU-instance only; the message is gone by design.
        vm_type = VmType.instance
        tap_interface = await self.network.prepare_tap(vm_id, vm_hash, vm_type)
```

- [ ] **Step 4: Replace `_restore_running_execution` with the config-driven version**

In `src/aleph/vm/pool.py`, replace the whole `_restore_running_execution` method (lines 545-576) with:

```python
    async def _restore_running_execution_from_config(
        self, config: Configuration, vm_id: int, vm_hash: ItemHash
    ) -> None:
        """Rebuild in-memory state for a VM whose controller is still active.

        Sourced entirely from the on-disk controller config — message-free.
        """
        spec = spec_from_controller_configuration(config)
        execution = VmExecution.from_spec(
            spec,
            snapshot_manager=self.snapshot_manager,
            systemd_manager=self.systemd_manager,
        )

        execution.mapped_ports = await get_port_mappings(vm_hash)
        logger.info("Loading existing mapped_ports %s", execution.mapped_ports)

        await execution.prepare()  # builds resources from the spec; no download
        tap_interface = await self._restore_network(execution, vm_id, vm_hash)

        vm = execution.create(vm_id=vm_id, tap_interface=tap_interface, prepare=False)
        await vm.start_guest_api()
        execution.ready_event.set()
        execution.times.started_at = datetime.now(tz=timezone.utc)

        self._schedule_forget_on_stop(execution)

        if vm.support_snapshot and self.snapshot_manager:
            await self.snapshot_manager.start_for(vm=execution.vm)

        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()

        self.executions[vm_hash] = execution
```

> Note: `fetch_port_redirect_config_and_setup` is intentionally dropped from reattach — it reads `message.address` and the user-settings aggregate (agent concerns). Port redirects are re-created from the persisted `port_mappings` table via `recreate_port_redirect_rules`.

- [ ] **Step 5: Replace `_handle_dead_execution` with `_handle_dead_controller`**

In `src/aleph/vm/pool.py`, replace `_handle_dead_execution` (lines 600-611) with:

```python
    async def _handle_dead_controller(self, config: Configuration) -> None:
        """Stop the stale controller service for a VM that is no longer active.

        The orphan controller config is removed by _cleanup_orphan_resources
        once the VM is absent from self.executions.
        """
        service_name = f"aleph-vm-controller@{config.vm_hash}.service"
        try:
            self.systemd_manager.stop_and_disable(service_name)
            logger.info("Stopped and disabled stale controller service %s", service_name)
        except Exception:
            logger.warning("Failed to stop/disable stale controller %s", service_name, exc_info=True)
```

- [ ] **Step 6: Add the imports the helpers need**

In `src/aleph/vm/pool.py`, add to the imports:

```python
from aleph.vm.controllers.configuration import (
    Configuration,
    load_controller_configuration,
    save_controller_configuration,
)
from aleph.vm.supervisor.qemu_build import (
    build_qemu_configuration,
    spec_from_controller_configuration,
)
```

(Merge `save_controller_configuration`, added in Task 7, into this single import block; `build_qemu_configuration` likewise.)

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_reattach.py -v`
Expected: PASS (2 passed)

- [ ] **Step 8: Commit**

```bash
git add src/aleph/vm/pool.py tests/supervisor/test_supervisor_reattach.py
git commit -m "feat(supervisor): config-driven message-free reattach helpers"
```

---

### Task 12: rewrite `load_persistent_executions` to scan configs

**Files:**
- Modify: `src/aleph/vm/pool.py` — `load_persistent_executions` (lines 466-543); remove DB-only imports (`get_execution_records`, `ExecutionRecord`, `get_message_executable_content`) if ruff flags them unused
- Rewrite: `tests/supervisor/test_vm_id_collision.py`

- [ ] **Step 1: Rewrite the collision test to the config-scan path**

Replace `tests/supervisor/test_vm_id_collision.py` entirely:

```python
"""Tests for vm_id collision between persistent instances on reboot-recovery.

After a reboot the supervisor reattaches VMs from on-disk controller configs.
Two configs that claim the same vm_id (a stale config left behind) must not
both restore — they would share a tap interface and clobber each other's
networking. Only the first active one is restored; the rest are treated as
dead controllers.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.pool import VmPool

HASH_A = "a" * 64
HASH_B = "b" * 64


def _make_pool(tmp_path: Path) -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    pool.systemd_manager.get_services_active_states = MagicMock(return_value={})
    return pool


def _write_configs(tmp_path: Path, *vm_hashes: str) -> None:
    for vm_hash in vm_hashes:
        (tmp_path / f"{vm_hash}-controller.json").write_text("{}")


def _config_for(vm_hash: str, vm_id: int) -> SimpleNamespace:
    return SimpleNamespace(vm_hash=vm_hash, vm_id=vm_id)


@pytest.mark.asyncio
class TestDuplicateVmIdLoading:
    async def _run(self, pool, tmp_path, configs, active):
        def fake_load(vm_hash):
            return configs[vm_hash]

        with (
            patch("aleph.vm.pool.settings", SimpleNamespace(EXECUTION_ROOT=tmp_path)),
            patch("aleph.vm.pool.load_controller_configuration", side_effect=fake_load),
            patch.object(pool, "_restore_running_execution_from_config", new_callable=AsyncMock) as restore,
            patch.object(pool, "_handle_dead_controller", new_callable=AsyncMock) as dead,
            patch.object(pool, "_cleanup_orphan_resources"),
            patch.object(pool, "update_domain_mapping", new_callable=AsyncMock),
        ):
            pool.systemd_manager.get_services_active_states.return_value = active
            await pool.load_persistent_executions()
        return restore, dead

    async def test_duplicate_vm_id_only_first_active_restored(self, tmp_path):
        pool = _make_pool(tmp_path)
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 7)}
        active = {
            f"aleph-vm-controller@{HASH_A}.service": True,
            f"aleph-vm-controller@{HASH_B}.service": True,
        }
        restore, dead = await self._run(pool, tmp_path, configs, active)
        assert restore.call_count == 1
        assert dead.call_count == 1

    async def test_duplicate_vm_id_dead_both_cleaned(self, tmp_path):
        pool = _make_pool(tmp_path)
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 7)}
        restore, dead = await self._run(pool, tmp_path, configs, active={})
        assert restore.call_count == 0
        assert dead.call_count == 2

    async def test_unique_vm_ids_all_restored(self, tmp_path):
        pool = _make_pool(tmp_path)
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 8)}
        active = {
            f"aleph-vm-controller@{HASH_A}.service": True,
            f"aleph-vm-controller@{HASH_B}.service": True,
        }
        restore, dead = await self._run(pool, tmp_path, configs, active)
        assert restore.call_count == 2
        assert dead.call_count == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_vm_id_collision.py -v`
Expected: FAIL — `load_persistent_executions` still calls `get_execution_records()` and the patched names (`load_controller_configuration`, `_restore_running_execution_from_config`, `_handle_dead_controller`) are not used yet

- [ ] **Step 3: Rewrite `load_persistent_executions`**

In `src/aleph/vm/pool.py`, replace the body of `load_persistent_executions` (lines 466-543) with the config-scan version:

```python
    async def load_persistent_executions(self):
        """Reattach VMs whose controllers survived a supervisor restart.

        Scans EXECUTION_ROOT for <hash>-controller.json files, checks which
        aleph-vm-controller@<hash>.service units are active (one batch D-Bus
        call), and rebuilds in-memory state from each active config. Dead
        controllers are stopped; their orphan configs are removed by
        _cleanup_orphan_resources. Entirely message-free: nothing is read
        from the database.
        """
        try:
            config_paths = sorted(settings.EXECUTION_ROOT.glob("*-controller.json"))
        except Exception:
            logger.warning("Failed to enumerate controller configs", exc_info=True)
            config_paths = []

        configs: list[Configuration] = []
        for config_path in config_paths:
            vm_hash = config_path.name[: -len("-controller.json")]
            if ItemHash(vm_hash) in self.executions:
                continue
            config = load_controller_configuration(vm_hash)
            if config is None:
                continue
            configs.append(config)

        # Batch-fetch active states: 1 D-Bus ListUnits() call for all VMs.
        all_services = [f"aleph-vm-controller@{config.vm_hash}.service" for config in configs]
        service_active_states = self.systemd_manager.get_services_active_states(all_services)

        # Track claimed vm_ids to detect duplicates across configs. A stale
        # config can reuse a vm_id; only the first active one is restored to
        # avoid two VMs sharing a tap interface.
        claimed_vm_ids: set[int] = set()

        for config in configs:
            vm_hash = ItemHash(str(config.vm_hash))
            vm_id = config.vm_id
            service_name = f"aleph-vm-controller@{config.vm_hash}.service"
            is_active = service_active_states.get(service_name, False)

            if not is_active:
                await self._handle_dead_controller(config)
                continue

            if vm_id in claimed_vm_ids:
                logger.warning(
                    "Skipping reattach of %s: vm_id %d already claimed by another config",
                    vm_hash,
                    vm_id,
                )
                await self._handle_dead_controller(config)
                continue

            logger.info("Reattaching execution %s for VM %d", vm_hash, vm_id)
            claimed_vm_ids.add(vm_id)
            await self._restore_running_execution_from_config(config, vm_id, vm_hash)

        self._cleanup_orphan_resources()

        if self.executions:
            await self.update_domain_mapping(force_update=True)
        logger.info("Loaded %d executions", len(self.executions))
```

- [ ] **Step 4: Remove the now-unused DB imports**

In `src/aleph/vm/pool.py`, the metrics import (lines 27-31) should keep only `get_port_mappings`. Remove `ExecutionRecord` and `get_execution_records`:

```python
from aleph.vm.orchestrator.metrics import get_port_mappings
```

Also remove the `get_message_executable_content` import (line 40) and the `TypeAdapter` / `HostGPU` / `json` imports if ruff reports them unused after this change. Run ruff to confirm which are now unused:

Run: `cd .worktrees/supervisor-create && .testvenv/bin/ruff check src/aleph/vm/pool.py`
Then delete exactly the imports ruff flags as `F401` and re-run until clean.

- [ ] **Step 5: Run the collision test to verify it passes**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_vm_id_collision.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Full PR 4 lint/type/test gate**

Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m mypy src/aleph/vm/pool.py src/aleph/vm/supervisor/qemu_build.py`
Expected: `Success: no issues found`
Run: `cd .worktrees/supervisor-create && .testvenv/bin/python -m pytest tests/supervisor/test_vm_id_collision.py tests/supervisor/test_supervisor_reattach.py tests/supervisor/test_supervisor_spec_from_config.py tests/supervisor/test_orphan_cleanup.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/pool.py tests/supervisor/test_vm_id_collision.py
git commit -m "feat(supervisor): message-free reboot-recovery from on-disk configs"
```

---

## Self-Review

**Spec coverage (design §3 in-scope items):**
- "VmExecution constructible/operable from CreateVmSpec, no message/download" → Tasks 1–5. ✅
- "InProcessSupervisor.create_vm wires a spec-built VmExecution into the pool and launches its controller" → Tasks 7–8. ✅
- "Production creation path routes through build_create_vm_spec → create_vm" → Task 9. ✅
- "Reboot-recovery message-free (on-disk configs + systemd)" → Tasks 10–12. ✅
- Ownership / operator-API survival across reboot → out of scope by decision (agent concern; API may be down during reboot). ✅

**Placeholder scan:** no TBD/TODO; every code step shows complete code; commands have expected output. The one judgment step (Task 12 Step 4, "delete exactly the imports ruff flags as F401") is mechanical and gated by a command, not a vague instruction. ✅

**Type consistency:** `from_spec` (both `AlephQemuResources` and `VmExecution`), `create_a_vm_from_spec`, `allocated_memory_mib`/`allocated_vcpus`, `start(write_config=...)`, `_is_spec_eligible`, `spec_from_controller_configuration`, `_restore_running_execution_from_config`, `_handle_dead_controller` are named identically across the tasks that define and call them. `build_qemu_configuration(spec, vm_id, tap_interface)` matches its 0.C signature. `VmType.instance` matches `vm_type.py`. `save_controller_configuration(vm_hash, configuration)` / `load_controller_configuration(vm_hash)` match `controllers/configuration.py`. ✅

**Risk notes for the implementer:**
- The `tests/supervisor/` suite imports siblings directly (`from test_supervisor_inprocess_query import ...`); run pytest from the worktree root so `tests/supervisor` is on the path, matching existing tests.
- Some daemon-dependent supervisor tests fail to *collect* locally (missing `pytest_mock`, `solathon`, `superfluid`); that is pre-existing and unrelated. Run the targeted test files listed in each step rather than the whole suite locally; CI runs the full suite.
- Pre-existing ruff debt in `qemu_build.py` (FBT/EM) is #953's concern; keep PR commits lint-neutral (no *new* errors).
