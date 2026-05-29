# Phase 0.B: Supervisor ABC + DTOs + In-Process Implementation: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Python `Supervisor` abstraction inside aleph-vm (the single agent-to-VM-management call path), with hand-written DTOs, a closed error hierarchy, and an in-process implementation that wraps today's `VmPool` / `VmExecution` for the 12 query/control/port-forward/log/host methods. VM creation, backups, migration, and confidential ops are explicit `NotImplementedSupervisorError` stubs (deferred to later phases).

**Architecture:** A new `aleph.vm.supervisor` package (distinct from the existing `aleph.vm.hypervisors` backend launchers). `types.py` holds frozen-dataclass DTOs and local enums mirroring `supervisor.proto`. `errors.py` holds the `SupervisorError` hierarchy and a `translate_exception` table that maps internal backend exceptions to the closed wire vocabulary. `abc.py` holds seven capability ABCs aggregated into `Supervisor`. `inprocess.py` holds `InProcessSupervisor(Supervisor)`, holding a `VmPool`. No agent call site changes; no proto types leak past the package.

**Tech Stack:** Python 3.10+, dataclasses, `abc`, `enum`, pytest (+ pytest-asyncio), `aleph_message` types. Reference design: `docs/plans/2026-05-29-phase-0b-supervisor-abc-design.md`.

**Working directory:** the worktree `/home/olivier/git/aleph/aleph-vm/.worktrees/supervisor-abc`, branch `od/supervisor-abc`.

**Test command:** `pytest tests/supervisor/<file>.py -v` (run in the project's testing environment; e.g. `hatch run testing:pytest ...` if hatch is configured).

**Identity convention:** at the boundary a VM is identified by `vm_id: str` (the `ItemHash` rendered with `str(...)`). The in-process implementation converts back with `ItemHash(vm_id)`.

---

### Task 1: DTOs and enums (`types.py`)

**Files:**
- Create: `src/aleph/vm/supervisor/types.py`
- Test: `tests/supervisor/test_supervisor_types.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_types.py
from dataclasses import FrozenInstanceError

import pytest

from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    ErrorCode,
    GpuSpec,
    HealthInfo,
    HostInfo,
    LogChunk,
    LogSource,
    NetworkConfig,
    Protocol,
    TeeConfig,
    VmInfo,
    VmStatus,
)


def test_enums_have_expected_members():
    assert {b.name for b in Backend} == {"FIRECRACKER", "QEMU", "QEMU_SEV"}
    assert {s.name for s in VmStatus} == {
        "DEFINED",
        "BOOTING",
        "RUNNING",
        "STOPPING",
        "STOPPED",
        "FAILED",
    }
    assert {f.name for f in DiskFormat} == {"RAW", "QCOW2", "SQUASHFS"}
    assert {r.name for r in DiskRole} == {"ROOTFS", "CODE", "RUNTIME", "DATA", "EXTRA"}
    assert {p.name for p in Protocol} == {"TCP", "UDP"}
    assert {s.name for s in LogSource} == {"SERIAL", "STDOUT", "SYSTEMD"}
    assert "INTERNAL" in {c.name for c in ErrorCode}
    assert "VM_NOT_FOUND" in {c.name for c in ErrorCode}


def test_vm_info_is_frozen_dataclass():
    info = VmInfo(
        vm_id="abc",
        status=VmStatus.RUNNING,
        ipv4="10.0.0.2",
        ipv6="",
        uptime_secs=42,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    assert info.vm_id == "abc"
    with pytest.raises(FrozenInstanceError):
        info.vm_id = "other"  # type: ignore[misc]


def test_create_vm_spec_constructs_with_nested_dtos():
    spec = CreateVmSpec(
        vm_id="abc",
        backend=Backend.QEMU,
        kernel_path="",
        initrd_path="",
        disks=[DiskSpec(path="/var/lib/x.qcow2", readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=2048,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )
    assert spec.disks[0].role is DiskRole.ROOTFS
    assert spec.network.internet_access is True


def test_supporting_dtos_construct():
    assert TeeConfig(backend="sev-snp", policy="", session_dir="/x").backend == "sev-snp"
    assert GpuSpec(pci_host="0000:01:00.0", supports_x_vga=True).supports_x_vga is True
    assert LogChunk(timestamp_ns=1, line="hello", source=LogSource.SERIAL).line == "hello"
    assert HealthInfo(status="ok", vm_count=3).vm_count == 3
    assert HostInfo(cpu_count=8, memory_mib=16000).cpu_count == 8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_types.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.supervisor.types'`

- [ ] **Step 3: Write `types.py`**

```python
# src/aleph/vm/supervisor/types.py
"""Agnostic DTOs and enums for the Supervisor boundary.

Frozen dataclasses mirroring proto/supervisor.proto messages. No Aleph or
protobuf types appear here: this is the vocabulary the agent and any future
remote supervisor share. Proto<->dataclass mapping lives only in the gRPC
implementation (Phase 0.D).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Backend(Enum):
    FIRECRACKER = "firecracker"
    QEMU = "qemu"
    QEMU_SEV = "qemu_sev"


class VmStatus(Enum):
    DEFINED = "defined"
    BOOTING = "booting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class DiskFormat(Enum):
    RAW = "raw"
    QCOW2 = "qcow2"
    SQUASHFS = "squashfs"


class DiskRole(Enum):
    ROOTFS = "rootfs"
    CODE = "code"
    RUNTIME = "runtime"
    DATA = "data"
    EXTRA = "extra"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"


class LogSource(Enum):
    SERIAL = "serial"
    STDOUT = "stdout"
    SYSTEMD = "systemd"


class BackupStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class MigrationPhase(Enum):
    PREPARING = "preparing"
    EXPORTING = "exporting"
    IMPORTING = "importing"
    COMPLETE = "complete"
    FAILED = "failed"


class ErrorCode(Enum):
    """Mirror of proto ErrorCode. Carried by SupervisorError."""

    VM_NOT_FOUND = "vm_not_found"
    VM_ALREADY_EXISTS = "vm_already_exists"
    INSUFFICIENT_RESOURCES = "insufficient_resources"
    RESOURCE_DOWNLOAD_FAILED = "resource_download_failed"
    FILE_TOO_LARGE = "file_too_large"
    VM_SETUP_FAILED = "vm_setup_failed"
    MICROVM_INIT_FAILED = "microvm_init_failed"
    INVALID_BACKEND = "invalid_backend"
    TEE_UNAVAILABLE = "tee_unavailable"
    PORT_UNAVAILABLE = "port_unavailable"
    HOST_NOT_FOUND = "host_not_found"
    BACKUP_NOT_FOUND = "backup_not_found"
    MIGRATION_IN_PROGRESS = "migration_in_progress"
    INTERNAL = "internal"


@dataclass(frozen=True)
class DiskSpec:
    path: str
    readonly: bool
    format: DiskFormat
    role: DiskRole


@dataclass(frozen=True)
class TeeConfig:
    backend: str
    policy: str
    session_dir: str


@dataclass(frozen=True)
class NetworkConfig:
    internet_access: bool
    requested_ipv6: str
    ipv6_prefix_len: int


@dataclass(frozen=True)
class GpuSpec:
    pci_host: str
    supports_x_vga: bool


@dataclass(frozen=True)
class CreateVmSpec:
    vm_id: str
    backend: Backend
    kernel_path: str
    initrd_path: str
    disks: list[DiskSpec]
    vcpus: int
    memory_mib: int
    tee: TeeConfig | None
    network: NetworkConfig
    gpus: list[GpuSpec]
    numa_node: int | None
    persistent: bool


@dataclass(frozen=True)
class VmInfo:
    vm_id: str
    status: VmStatus
    ipv4: str
    ipv6: str
    uptime_secs: int
    backend: Backend
    numa_node: int | None
    status_message: str


@dataclass(frozen=True)
class PortForwardSpec:
    vm_id: str
    host_port: int
    vm_port: int
    protocol: Protocol


@dataclass(frozen=True)
class PortForwardInfo:
    vm_id: str
    host_port: int
    vm_port: int
    protocol: Protocol


@dataclass(frozen=True)
class LogChunk:
    timestamp_ns: int
    line: str
    source: LogSource


@dataclass(frozen=True)
class BackupInfo:
    vm_id: str
    backup_id: str
    status: BackupStatus
    size_bytes: int
    created_at_unix_secs: int
    error_message: str


@dataclass(frozen=True)
class BackupChunk:
    data: bytes
    offset: int


@dataclass(frozen=True)
class MigrationInfo:
    vm_id: str
    migration_id: str
    phase: MigrationPhase
    bytes_transferred: int
    bytes_total: int
    error_message: str


@dataclass(frozen=True)
class Measurement:
    vm_id: str
    measurement_bytes: bytes
    tee_backend: str


@dataclass(frozen=True)
class NumaNodeInfo:
    index: int
    cpu_count: int
    memory_mib: int


@dataclass(frozen=True)
class GpuDevice:
    pci_host: str
    device_id: str
    model: str
    supports_x_vga: bool


@dataclass(frozen=True)
class HealthInfo:
    status: str
    vm_count: int


@dataclass(frozen=True)
class HostInfo:
    cpu_count: int = 0
    memory_mib: int = 0
    cpu_architecture: str = ""
    cpu_vendor: str = ""
    cpu_model: str = ""
    kernel_version: str = ""
    hostname: str = ""
    sev_supported: bool = False
    sev_es_supported: bool = False
    sev_snp_supported: bool = False
    tdx_supported: bool = False
    numa_nodes: list[NumaNodeInfo] = field(default_factory=list)
    gpus: list[GpuDevice] = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_types.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/types.py tests/supervisor/test_supervisor_types.py
git commit -m "feat(supervisor): DTOs and enums for the Supervisor boundary"
```

---

### Task 2: Error hierarchy and exception translation (`errors.py`)

**Files:**
- Create: `src/aleph/vm/supervisor/errors.py`
- Test: `tests/supervisor/test_supervisor_errors.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_errors.py
import pytest
from aiohttp import ClientResponseError
from aiohttp.client_reqrep import RequestInfo
from yarl import URL

from aleph.vm.supervisor.errors import (
    FileTooLargeError as SupFileTooLargeError,
)
from aleph.vm.supervisor.errors import (
    HostNotFoundError as SupHostNotFoundError,
)
from aleph.vm.supervisor.errors import (
    InsufficientResourcesError as SupInsufficientResourcesError,
)
from aleph.vm.supervisor.errors import (
    InternalSupervisorError,
    NotImplementedSupervisorError,
    SupervisorError,
    translate_exception,
    translating_errors,
)
from aleph.vm.supervisor.types import ErrorCode


def test_supervisor_error_carries_code():
    err = SupervisorError("boom", code=ErrorCode.INTERNAL)
    assert err.code is ErrorCode.INTERNAL
    assert str(err) == "boom"


def test_not_implemented_maps_to_internal_code():
    assert NotImplementedSupervisorError("x").code is ErrorCode.INTERNAL


def test_translate_known_internal_exceptions():
    from aleph.vm.resources import InsufficientResourcesError

    translated = translate_exception(
        InsufficientResourcesError("no ram", required={"mem": 1}, available={"mem": 0})
    )
    assert isinstance(translated, SupInsufficientResourcesError)
    assert translated.code is ErrorCode.INSUFFICIENT_RESOURCES


def test_translate_file_too_large():
    from aleph.vm.controllers.firecracker.program import FileTooLargeError

    translated = translate_exception(FileTooLargeError("too big"))
    assert isinstance(translated, SupFileTooLargeError)
    assert translated.code is ErrorCode.FILE_TOO_LARGE


def test_translate_host_not_found():
    from aleph.vm.utils import HostNotFoundError

    translated = translate_exception(HostNotFoundError("no host"))
    assert isinstance(translated, SupHostNotFoundError)
    assert translated.code is ErrorCode.HOST_NOT_FOUND


def test_translate_unknown_exception_maps_to_internal():
    translated = translate_exception(ValueError("surprise"))
    assert isinstance(translated, InternalSupervisorError)
    assert translated.code is ErrorCode.INTERNAL


def test_translating_errors_passes_supervisor_errors_through():
    with pytest.raises(SupHostNotFoundError):
        with translating_errors():
            raise SupHostNotFoundError("already a supervisor error")


def test_translating_errors_converts_internal():
    with pytest.raises(InternalSupervisorError):
        with translating_errors():
            raise ValueError("surprise")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.supervisor.errors'`

- [ ] **Step 3: Write `errors.py`**

```python
# src/aleph/vm/supervisor/errors.py
"""Closed error vocabulary for the Supervisor boundary.

SupervisorError subclasses map one-to-one to proto ErrorCode values. The
in-process implementation catches the scattered internal backend exceptions
and re-raises them as this closed set; the gRPC server (0.D) reuses the same
table to fill ErrorDetail trailers; views (0.E) catch SupervisorError instead
of backend internals.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from aleph.vm.supervisor.types import ErrorCode


class SupervisorError(Exception):
    """Base for every error crossing the Supervisor boundary."""

    code: ErrorCode = ErrorCode.INTERNAL

    def __init__(self, message: str = "", *, code: ErrorCode | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class VmNotFoundError(SupervisorError):
    code = ErrorCode.VM_NOT_FOUND


class VmAlreadyExistsError(SupervisorError):
    code = ErrorCode.VM_ALREADY_EXISTS


class InsufficientResourcesError(SupervisorError):
    code = ErrorCode.INSUFFICIENT_RESOURCES


class ResourceDownloadError(SupervisorError):
    code = ErrorCode.RESOURCE_DOWNLOAD_FAILED


class FileTooLargeError(SupervisorError):
    code = ErrorCode.FILE_TOO_LARGE


class VmSetupError(SupervisorError):
    code = ErrorCode.VM_SETUP_FAILED


class MicroVMInitError(SupervisorError):
    code = ErrorCode.MICROVM_INIT_FAILED


class InvalidBackendError(SupervisorError):
    code = ErrorCode.INVALID_BACKEND


class TeeUnavailableError(SupervisorError):
    code = ErrorCode.TEE_UNAVAILABLE


class PortUnavailableError(SupervisorError):
    code = ErrorCode.PORT_UNAVAILABLE


class HostNotFoundError(SupervisorError):
    code = ErrorCode.HOST_NOT_FOUND


class BackupNotFoundError(SupervisorError):
    code = ErrorCode.BACKUP_NOT_FOUND


class MigrationInProgressError(SupervisorError):
    code = ErrorCode.MIGRATION_IN_PROGRESS


class NotImplementedSupervisorError(SupervisorError):
    """A boundary method that is intentionally not implemented yet."""

    code = ErrorCode.INTERNAL


class InternalSupervisorError(SupervisorError):
    code = ErrorCode.INTERNAL


def translate_exception(exc: BaseException) -> SupervisorError:
    """Map an internal backend exception to the closed Supervisor vocabulary.

    Imports are local so this module stays importable even if a backend
    module fails to import in a stripped-down environment.
    """
    if isinstance(exc, SupervisorError):
        return exc

    from aleph.vm.controllers.firecracker.executable import ResourceDownloadError as _ResourceDownloadError
    from aleph.vm.controllers.firecracker.executable import VmSetupError as _VmSetupError
    from aleph.vm.controllers.firecracker.program import FileTooLargeError as _FileTooLargeError
    from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError as _MicroVMFailedInitError
    from aleph.vm.resources import InsufficientResourcesError as _InsufficientResourcesError
    from aleph.vm.utils import HostNotFoundError as _HostNotFoundError

    message = str(exc)
    if isinstance(exc, _InsufficientResourcesError):
        return InsufficientResourcesError(message)
    if isinstance(exc, _ResourceDownloadError):
        return ResourceDownloadError(message)
    if isinstance(exc, _FileTooLargeError):
        return FileTooLargeError(message)
    if isinstance(exc, _VmSetupError):
        return VmSetupError(message)
    if isinstance(exc, _MicroVMFailedInitError):
        return MicroVMInitError(message)
    if isinstance(exc, _HostNotFoundError):
        return HostNotFoundError(message)
    return InternalSupervisorError(message)


@contextlib.contextmanager
def translating_errors() -> Iterator[None]:
    """Re-raise any non-SupervisorError as the translated SupervisorError."""
    try:
        yield
    except SupervisorError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate boundary catch-all
        raise translate_exception(exc) from exc
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_errors.py -v`
Expected: PASS (8 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/errors.py tests/supervisor/test_supervisor_errors.py
git commit -m "feat(supervisor): closed error hierarchy and exception translation table"
```

---

### Task 3: Capability ABCs and aggregate `Supervisor` (`abc.py`)

**Files:**
- Create: `src/aleph/vm/supervisor/abc.py`
- Test: `tests/supervisor/test_supervisor_abc.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_abc.py
import inspect

import pytest

from aleph.vm.supervisor.abc import (
    BackupOps,
    ConfidentialOps,
    HostOps,
    LifecycleOps,
    LogsOps,
    MigrationOps,
    PortForwardingOps,
    Supervisor,
)

EXPECTED_METHODS = {
    "health",
    "get_host_info",
    "create_vm",
    "get_vm",
    "list_vms",
    "delete_vm",
    "reboot_vm",
    "reinstall_vm",
    "add_port_forward",
    "remove_port_forward",
    "list_port_forwards",
    "get_logs",
    "stream_logs",
    "start_backup",
    "get_backup_status",
    "list_backups",
    "download_backup",
    "delete_backup",
    "restore_backup",
    "export_vm",
    "import_vm",
    "get_migration_status",
    "initialize_confidential",
    "get_measurement",
    "inject_secret",
}


def test_supervisor_aggregates_all_25_methods():
    abstract = Supervisor.__abstractmethods__
    assert abstract == EXPECTED_METHODS
    assert len(EXPECTED_METHODS) == 25


def test_supervisor_cannot_be_instantiated():
    with pytest.raises(TypeError):
        Supervisor()  # type: ignore[abstract]


def test_all_boundary_methods_are_coroutines():
    for name in EXPECTED_METHODS:
        method = getattr(Supervisor, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be async"


def test_capability_abcs_partition_the_surface():
    by_abc = {
        HostOps: {"health", "get_host_info"},
        LifecycleOps: {"create_vm", "get_vm", "list_vms", "delete_vm", "reboot_vm", "reinstall_vm"},
        PortForwardingOps: {"add_port_forward", "remove_port_forward", "list_port_forwards"},
        LogsOps: {"get_logs", "stream_logs"},
        BackupOps: {
            "start_backup",
            "get_backup_status",
            "list_backups",
            "download_backup",
            "delete_backup",
            "restore_backup",
        },
        MigrationOps: {"export_vm", "import_vm", "get_migration_status"},
        ConfidentialOps: {"initialize_confidential", "get_measurement", "inject_secret"},
    }
    for abc_cls, names in by_abc.items():
        assert names <= abc_cls.__abstractmethods__
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_abc.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.supervisor.abc'`

- [ ] **Step 3: Write `abc.py`**

```python
# src/aleph/vm/supervisor/abc.py
"""The Supervisor abstraction: capability ABCs aggregated into one interface.

Seven capability ABCs, all async, one method per proto RPC. A concrete
supervisor (in-process today, gRPC client in 0.D) implements all 25 methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from aleph.vm.supervisor.types import (
    BackupInfo,
    BackupChunk,
    CreateVmSpec,
    HealthInfo,
    HostInfo,
    LogChunk,
    Measurement,
    MigrationInfo,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmInfo,
)


class HostOps(ABC):
    @abstractmethod
    async def health(self) -> HealthInfo: ...

    @abstractmethod
    async def get_host_info(self) -> HostInfo: ...


class LifecycleOps(ABC):
    @abstractmethod
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo: ...

    @abstractmethod
    async def get_vm(self, vm_id: str) -> VmInfo: ...

    @abstractmethod
    async def list_vms(self) -> list[VmInfo]: ...

    @abstractmethod
    async def delete_vm(self, vm_id: str) -> None: ...

    @abstractmethod
    async def reboot_vm(self, vm_id: str) -> VmInfo: ...

    @abstractmethod
    async def reinstall_vm(self, vm_id: str) -> VmInfo: ...


class PortForwardingOps(ABC):
    @abstractmethod
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo: ...

    @abstractmethod
    async def remove_port_forward(self, vm_id: str, host_port: int, protocol: Protocol) -> None: ...

    @abstractmethod
    async def list_port_forwards(self, vm_id: str | None = None) -> list[PortForwardInfo]: ...


class LogsOps(ABC):
    @abstractmethod
    async def get_logs(self, vm_id: str, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]: ...

    @abstractmethod
    def stream_logs(self, vm_id: str, include_history: bool = False) -> AsyncIterator[LogChunk]: ...


class BackupOps(ABC):
    @abstractmethod
    async def start_backup(self, vm_id: str, quiesce_guest: bool = False) -> BackupInfo: ...

    @abstractmethod
    async def get_backup_status(self, vm_id: str, backup_id: str) -> BackupInfo: ...

    @abstractmethod
    async def list_backups(self, vm_id: str | None = None) -> list[BackupInfo]: ...

    @abstractmethod
    def download_backup(self, vm_id: str, backup_id: str) -> AsyncIterator[BackupChunk]: ...

    @abstractmethod
    async def delete_backup(self, vm_id: str, backup_id: str) -> None: ...

    @abstractmethod
    async def restore_backup(self, vm_id: str, backup_id: str) -> VmInfo: ...


class MigrationOps(ABC):
    @abstractmethod
    async def export_vm(self, vm_id: str, destination_dir: str) -> MigrationInfo: ...

    @abstractmethod
    async def import_vm(self, vm_id: str, source_dir: str) -> VmInfo: ...

    @abstractmethod
    async def get_migration_status(self, vm_id: str, migration_id: str) -> MigrationInfo: ...


class ConfidentialOps(ABC):
    @abstractmethod
    async def initialize_confidential(self, vm_id: str, session_bytes: bytes, godh_bytes: bytes) -> None: ...

    @abstractmethod
    async def get_measurement(self, vm_id: str) -> Measurement: ...

    @abstractmethod
    async def inject_secret(self, vm_id: str, secret_header_bytes: bytes, secret_bytes: bytes) -> None: ...


class Supervisor(
    HostOps,
    LifecycleOps,
    PortForwardingOps,
    LogsOps,
    BackupOps,
    MigrationOps,
    ConfidentialOps,
    ABC,
):
    """The single agent-to-VM-management interface."""
```

Note on the two streaming methods (`stream_logs`, `download_backup`): they are declared as plain `def` returning `AsyncIterator[...]` (not `async def`). The test in this task asserts the OTHER 23 are coroutine functions; update the test to exclude these two. Apply this correction now:

In `tests/supervisor/test_supervisor_abc.py`, change `test_all_boundary_methods_are_coroutines` to:

```python
STREAMING_METHODS = {"stream_logs", "download_backup"}


def test_all_boundary_methods_are_coroutines():
    for name in EXPECTED_METHODS - STREAMING_METHODS:
        method = getattr(Supervisor, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be async"
    for name in STREAMING_METHODS:
        method = getattr(Supervisor, name)
        assert not inspect.iscoroutinefunction(method), f"{name} returns an async iterator, not a coroutine"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_abc.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/abc.py tests/supervisor/test_supervisor_abc.py
git commit -m "feat(supervisor): capability ABCs and aggregate Supervisor interface"
```

---

### Task 4: `InProcessSupervisor` scaffold (all methods stubbed)

**Files:**
- Create: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_stubs.py`

This task makes every method exist and raise `NotImplementedSupervisorError`. Later tasks replace the real ones. A tiny fake pool stands in for `VmPool`.

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_stubs.py
import pytest

from aleph.vm.supervisor.errors import NotImplementedSupervisorError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import Backend, CreateVmSpec, NetworkConfig


class FakePool:
    def __init__(self):
        self.executions = {}


def make_spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id="abc",
        backend=Backend.QEMU,
        kernel_path="",
        initrd_path="",
        disks=[],
        vcpus=1,
        memory_mib=512,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


@pytest.fixture
def supervisor():
    return InProcessSupervisor(pool=FakePool())


def test_can_instantiate(supervisor):
    assert isinstance(supervisor, InProcessSupervisor)


@pytest.mark.asyncio
async def test_create_vm_is_stubbed(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.create_vm(make_spec())


@pytest.mark.asyncio
async def test_backup_migration_confidential_are_stubbed(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.start_backup("abc")
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.export_vm("abc", "/tmp/x")
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.get_measurement("abc")


@pytest.mark.asyncio
async def test_streaming_stubs_raise_on_iteration(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        async for _ in supervisor.download_backup("abc", "b1"):
            pass
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_stubs.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.supervisor.inprocess'`

- [ ] **Step 3: Write `inprocess.py` scaffold**

```python
# src/aleph/vm/supervisor/inprocess.py
"""In-process Supervisor: wraps today's VmPool / VmExecution.

This is the throwaway implementation that runs in the same process as the
agent during the strangler period. It validates the contract under real pool
behavior before any gRPC exists. Methods not yet implemented raise
NotImplementedSupervisorError.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import NotImplementedSupervisorError
from aleph.vm.supervisor.types import (
    BackupChunk,
    BackupInfo,
    CreateVmSpec,
    HealthInfo,
    HostInfo,
    LogChunk,
    Measurement,
    MigrationInfo,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmInfo,
)

if TYPE_CHECKING:
    from aleph.vm.pool import VmPool


class InProcessSupervisor(Supervisor):
    def __init__(self, pool: VmPool):
        self.pool = pool

    # ── Host ──
    async def health(self) -> HealthInfo:
        raise NotImplementedSupervisorError("health")

    async def get_host_info(self) -> HostInfo:
        raise NotImplementedSupervisorError("get_host_info")

    # ── Lifecycle ──
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        raise NotImplementedSupervisorError("create_vm is deferred to a later phase")

    async def get_vm(self, vm_id: str) -> VmInfo:
        raise NotImplementedSupervisorError("get_vm")

    async def list_vms(self) -> list[VmInfo]:
        raise NotImplementedSupervisorError("list_vms")

    async def delete_vm(self, vm_id: str) -> None:
        raise NotImplementedSupervisorError("delete_vm")

    async def reboot_vm(self, vm_id: str) -> VmInfo:
        raise NotImplementedSupervisorError("reboot_vm")

    async def reinstall_vm(self, vm_id: str) -> VmInfo:
        raise NotImplementedSupervisorError("reinstall_vm")

    # ── Port forwarding ──
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        raise NotImplementedSupervisorError("add_port_forward")

    async def remove_port_forward(self, vm_id: str, host_port: int, protocol: Protocol) -> None:
        raise NotImplementedSupervisorError("remove_port_forward")

    async def list_port_forwards(self, vm_id: str | None = None) -> list[PortForwardInfo]:
        raise NotImplementedSupervisorError("list_port_forwards")

    # ── Logs ──
    async def get_logs(self, vm_id: str, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        raise NotImplementedSupervisorError("get_logs")

    async def stream_logs(self, vm_id: str, include_history: bool = False) -> AsyncIterator[LogChunk]:
        raise NotImplementedSupervisorError("stream_logs")
        yield  # pragma: no cover - makes this an async generator

    # ── Backups ──
    async def start_backup(self, vm_id: str, quiesce_guest: bool = False) -> BackupInfo:
        raise NotImplementedSupervisorError("start_backup")

    async def get_backup_status(self, vm_id: str, backup_id: str) -> BackupInfo:
        raise NotImplementedSupervisorError("get_backup_status")

    async def list_backups(self, vm_id: str | None = None) -> list[BackupInfo]:
        raise NotImplementedSupervisorError("list_backups")

    async def download_backup(self, vm_id: str, backup_id: str) -> AsyncIterator[BackupChunk]:
        raise NotImplementedSupervisorError("download_backup")
        yield  # pragma: no cover - makes this an async generator

    async def delete_backup(self, vm_id: str, backup_id: str) -> None:
        raise NotImplementedSupervisorError("delete_backup")

    async def restore_backup(self, vm_id: str, backup_id: str) -> VmInfo:
        raise NotImplementedSupervisorError("restore_backup")

    # ── Migration ──
    async def export_vm(self, vm_id: str, destination_dir: str) -> MigrationInfo:
        raise NotImplementedSupervisorError("export_vm")

    async def import_vm(self, vm_id: str, source_dir: str) -> VmInfo:
        raise NotImplementedSupervisorError("import_vm")

    async def get_migration_status(self, vm_id: str, migration_id: str) -> MigrationInfo:
        raise NotImplementedSupervisorError("get_migration_status")

    # ── Confidential ──
    async def initialize_confidential(self, vm_id: str, session_bytes: bytes, godh_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("initialize_confidential")

    async def get_measurement(self, vm_id: str) -> Measurement:
        raise NotImplementedSupervisorError("get_measurement")

    async def inject_secret(self, vm_id: str, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("inject_secret")
```

Note: `stream_logs` and `download_backup` are written as `async def` with a trailing unreachable `yield`, which makes them async-generator functions (so the abstract `def ... -> AsyncIterator` is satisfied at runtime and `async for` works). Calling them returns an async generator; iteration raises. This matches the test in Step 1.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_stubs.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_stubs.py
git commit -m "feat(supervisor): InProcessSupervisor scaffold with stubbed methods"
```

---

### Task 5: Conformance test suite

**Files:**
- Create: `tests/supervisor/conformance.py` (reusable abstract test base, importable without being collected as tests itself)
- Create: `tests/supervisor/test_supervisor_conformance_inprocess.py`

- [ ] **Step 1: Write the conformance base and the in-process binding**

```python
# tests/supervisor/conformance.py
"""Reusable conformance checks any Supervisor implementation must pass.

Subclass SupervisorContractTests in a test module and implement the
`supervisor` fixture. Reused for the gRPC client in 0.D. This module is not
collected directly (its class name does not start with Test).
"""

import inspect

import pytest

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import NotImplementedSupervisorError

STUB_METHODS = {
    "create_vm",
    "start_backup",
    "get_backup_status",
    "list_backups",
    "download_backup",
    "delete_backup",
    "restore_backup",
    "export_vm",
    "import_vm",
    "get_migration_status",
    "initialize_confidential",
    "get_measurement",
    "inject_secret",
}


class SupervisorContractTests:
    """Mix in and provide a `supervisor` fixture returning a Supervisor."""

    @pytest.fixture
    def supervisor(self) -> Supervisor:
        raise NotImplementedError

    def test_is_a_supervisor(self, supervisor):
        assert isinstance(supervisor, Supervisor)

    def test_implements_all_abstract_methods(self, supervisor):
        # A concrete instance exists, so abstractmethods are all overridden.
        assert type(supervisor).__abstractmethods__ == frozenset()

    @pytest.mark.asyncio
    async def test_stub_methods_raise_not_implemented(self, supervisor):
        if "create_vm" in STUB_METHODS:
            from aleph.vm.supervisor.types import Backend, CreateVmSpec, NetworkConfig

            spec = CreateVmSpec(
                vm_id="x",
                backend=Backend.QEMU,
                kernel_path="",
                initrd_path="",
                disks=[],
                vcpus=1,
                memory_mib=512,
                tee=None,
                network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
                gpus=[],
                numa_node=None,
                persistent=True,
            )
            with pytest.raises(NotImplementedSupervisorError):
                await supervisor.create_vm(spec)

    def test_streaming_methods_return_async_iterators(self, supervisor):
        for name in ("stream_logs", "download_backup"):
            method = getattr(supervisor, name)
            # async generator function, not a coroutine
            assert not inspect.iscoroutinefunction(method) or inspect.isasyncgenfunction(method)
```

```python
# tests/supervisor/test_supervisor_conformance_inprocess.py
import pytest

from aleph.vm.supervisor.inprocess import InProcessSupervisor

from .conformance import SupervisorContractTests  # noqa: TID252


class FakePool:
    def __init__(self):
        self.executions = {}


class TestInProcessSupervisorConformance(SupervisorContractTests):
    @pytest.fixture
    def supervisor(self):
        return InProcessSupervisor(pool=FakePool())
```

Note: the relative import `from .conformance import ...` requires `tests/supervisor/` to be a package. Add an empty `tests/supervisor/__init__.py` if it does not exist (Step 2 covers this).

- [ ] **Step 2: Ensure the test package marker exists**

Run: `test -f tests/supervisor/__init__.py && echo exists || echo missing`

If `missing`, create it:

```bash
touch tests/supervisor/__init__.py
```

Note: adding `tests/supervisor/__init__.py` makes the directory a package so the relative import works. If other test files in `tests/supervisor/` then fail collection due to duplicate basenames elsewhere in the suite, switch the import to absolute (`from tests.supervisor.conformance import SupervisorContractTests`) instead and remove the `__init__.py`. Verify with the full `pytest tests/supervisor -q` run in Task 12.

- [ ] **Step 3: Run to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_conformance_inprocess.py -v`
Expected: PASS (4 tests)

- [ ] **Step 4: Commit**

```bash
git add tests/supervisor/conformance.py tests/supervisor/test_supervisor_conformance_inprocess.py tests/supervisor/__init__.py
git commit -m "test(supervisor): reusable conformance suite bound to InProcessSupervisor"
```

---

### Task 6: Implement `get_vm` and `list_vms` (the `VmInfo` mapping)

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_query.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_query.py
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import Backend, VmStatus


def make_execution(*, running=True, confidential=False, hypervisor=HypervisorType.qemu, with_ip=True):
    started = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
    times = SimpleNamespace(
        defined_at=started,
        starting_at=started,
        started_at=started if running else None,
        stopping_at=None,
        stopped_at=None,
    )
    tap = SimpleNamespace(
        guest_ip=SimpleNamespace(ip="10.0.0.2"),
        guest_ipv6=SimpleNamespace(ip="fd00::2"),
    )
    vm = SimpleNamespace(tap_interface=tap if with_ip else None)
    return SimpleNamespace(
        vm_hash="itemhash123",
        times=times,
        persistent=True,
        controller_service="aleph-vm-controller@itemhash123.service",
        is_program=False,
        is_instance=True,
        is_confidential=confidential,
        hypervisor=hypervisor,
        vm=vm,
    )


class FakeSystemd:
    def __init__(self, active: dict[str, bool] | None = None):
        self._active = active or {}

    def get_services_active_states(self, services):
        return {s: self._active.get(s, False) for s in services}


class FakePool:
    def __init__(self, executions=None, systemd=None):
        self.executions = executions or {}
        self.systemd_manager = systemd or FakeSystemd()


@pytest.mark.asyncio
async def test_get_vm_maps_a_running_qemu_instance():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm("itemhash123")

    assert info.vm_id == "itemhash123"
    assert info.status is VmStatus.RUNNING
    assert info.backend is Backend.QEMU
    assert info.ipv4 == "10.0.0.2"
    assert info.ipv6 == "fd00::2"
    assert info.uptime_secs >= 100


@pytest.mark.asyncio
async def test_get_vm_unknown_raises_vm_not_found():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_vm("nope")


@pytest.mark.asyncio
async def test_confidential_instance_reports_qemu_sev_backend():
    execution = make_execution(confidential=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)
    info = await sup.get_vm("itemhash123")
    assert info.backend is Backend.QEMU_SEV


@pytest.mark.asyncio
async def test_list_vms_returns_one_info_per_execution():
    pool = FakePool(
        executions={"a": make_execution(), "b": make_execution(running=False)},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": False}),
    )
    sup = InProcessSupervisor(pool=pool)
    infos = await sup.list_vms()
    assert {i.vm_id for i in infos} == {"itemhash123"}  # both fakes share vm_hash
    assert len(infos) == 2
```

Note: both fakes share `vm_hash="itemhash123"`; the test asserts the count is 2 (one info per execution) while the id set collapses. This is fine for the mapping check.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_query.py -v`
Expected: FAIL (`get_vm` raises `NotImplementedSupervisorError`, not `VmNotFoundError` / a `VmInfo`)

- [ ] **Step 3: Implement the mapping in `inprocess.py`**

Add these imports near the top of `inprocess.py`:

```python
from datetime import datetime, timezone

from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.supervisor.errors import VmNotFoundError, translating_errors
from aleph.vm.supervisor.types import Backend, VmStatus
```

Add module-level helpers and replace the `get_vm` / `list_vms` stub bodies:

```python
def _backend_of(execution) -> Backend:
    if execution.is_program or execution.hypervisor == HypervisorType.firecracker:
        return Backend.FIRECRACKER
    if execution.is_confidential:
        return Backend.QEMU_SEV
    return Backend.QEMU


def _is_running(execution, pool) -> bool:
    if execution.persistent and getattr(pool, "systemd_manager", None):
        states = pool.systemd_manager.get_services_active_states([execution.controller_service])
        return states.get(execution.controller_service, False)
    times = execution.times
    return bool(times.starting_at and not times.stopping_at)


def _status_of(execution, running: bool) -> VmStatus:
    times = execution.times
    if times.stopped_at:
        return VmStatus.STOPPED
    if times.stopping_at:
        return VmStatus.STOPPING
    if running:
        return VmStatus.RUNNING
    if times.started_at:
        return VmStatus.RUNNING
    if times.starting_at:
        return VmStatus.BOOTING
    return VmStatus.DEFINED


def _uptime_secs(execution, running: bool) -> int:
    started = execution.times.started_at
    if running and started:
        return int((datetime.now(tz=timezone.utc) - started).total_seconds())
    return 0


def _to_vm_info(execution, running: bool) -> "VmInfo":
    tap = execution.vm.tap_interface if execution.vm else None
    ipv4 = str(tap.guest_ip.ip) if tap else ""
    ipv6 = str(tap.guest_ipv6.ip) if tap else ""
    return VmInfo(
        vm_id=str(execution.vm_hash),
        status=_status_of(execution, running),
        ipv4=ipv4,
        ipv6=ipv6,
        uptime_secs=_uptime_secs(execution, running),
        backend=_backend_of(execution),
        numa_node=None,
        status_message="",
    )
```

```python
    async def get_vm(self, vm_id: str) -> VmInfo:
        with translating_errors():
            execution = self.pool.executions.get(vm_id)
            if execution is None:
                raise VmNotFoundError(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def list_vms(self) -> list[VmInfo]:
        with translating_errors():
            return [
                _to_vm_info(execution, _is_running(execution, self.pool))
                for execution in self.pool.executions.values()
            ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_query.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_query.py
git commit -m "feat(supervisor): implement get_vm and list_vms VmInfo mapping"
```

---

### Task 7: Implement `delete_vm`, `reboot_vm`, `reinstall_vm`

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_lifecycle.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_lifecycle.py
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor

from .test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution


@pytest.mark.asyncio
async def test_delete_vm_stops_and_forgets():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    await sup.delete_vm("itemhash123")

    pool.stop_vm.assert_awaited_once_with("itemhash123")
    pool.forget_vm.assert_called_once_with("itemhash123")


@pytest.mark.asyncio
async def test_delete_unknown_vm_raises():
    pool = FakePool()
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)
    with pytest.raises(VmNotFoundError):
        await sup.delete_vm("nope")
    pool.stop_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_reboot_persistent_vm_restarts_systemd_and_returns_info():
    execution = make_execution(running=True)
    systemd = FakeSystemd({"aleph-vm-controller@itemhash123.service": True})
    systemd.restart = MagicMock()
    pool = FakePool(executions={"itemhash123": execution}, systemd=systemd)
    sup = InProcessSupervisor(pool=pool)

    info = await sup.reboot_vm("itemhash123")

    systemd.restart.assert_called_once_with("aleph-vm-controller@itemhash123.service")
    assert info.vm_id == "itemhash123"


@pytest.mark.asyncio
async def test_reboot_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.reboot_vm("nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_lifecycle.py -v`
Expected: FAIL (`delete_vm` raises `NotImplementedSupervisorError`)

- [ ] **Step 3: Implement in `inprocess.py`**

Replace the `delete_vm`, `reboot_vm`, and `reinstall_vm` stub bodies. Add a small private lookup helper to the class:

```python
    def _require(self, vm_id: str):
        execution = self.pool.executions.get(vm_id)
        if execution is None:
            raise VmNotFoundError(vm_id)
        return execution

    async def delete_vm(self, vm_id: str) -> None:
        with translating_errors():
            self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            self.pool.forget_vm(vm_id)

    async def reboot_vm(self, vm_id: str) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            if execution.persistent and getattr(self.pool, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
            else:
                await self.pool.stop_vm(vm_id)
                self.pool.forget_vm(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def reinstall_vm(self, vm_id: str) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.persistent and getattr(self.pool, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
            else:
                self.pool.forget_vm(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))
```

Note: `reboot_vm` / `reinstall_vm` here keep today's systemd-level mechanics (design §11 Q2). Their full semantics align with `views/operator.py` and converge when those views migrate in 0.E.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_lifecycle.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_lifecycle.py
git commit -m "feat(supervisor): implement delete_vm, reboot_vm, reinstall_vm"
```

---

### Task 8: Implement port forwarding (`add` / `remove` / `list`)

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_ports.py`

The in-process port methods adapt to `VmExecution.update_port_redirects(requested_ports)` and the `mapped_ports` dict (`{vm_port: {"host": host_port, "tcp": bool, "udp": bool}}`).

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_ports.py
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import PortForwardSpec, Protocol

from .test_supervisor_inprocess_query import FakePool


def make_execution_with_ports(mapped_ports=None):
    execution = SimpleNamespace(
        vm_hash="vm1",
        mapped_ports=mapped_ports if mapped_ports is not None else {},
    )
    execution.update_port_redirects = AsyncMock()
    return execution


@pytest.mark.asyncio
async def test_add_port_forward_calls_update_and_returns_info():
    execution = make_execution_with_ports()

    async def fake_update(requested):
        # mimic VmExecution: record the mapping with an allocated host port
        for vm_port, proto in requested.items():
            execution.mapped_ports[vm_port] = {"host": 34000, **proto}

    execution.update_port_redirects.side_effect = fake_update
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    info = await sup.add_port_forward(PortForwardSpec(vm_id="vm1", host_port=0, vm_port=8080, protocol=Protocol.TCP))

    execution.update_port_redirects.assert_awaited_once()
    assert info.vm_id == "vm1"
    assert info.vm_port == 8080
    assert info.host_port == 34000
    assert info.protocol is Protocol.TCP


@pytest.mark.asyncio
async def test_list_port_forwards_for_one_vm():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    forwards = await sup.list_port_forwards("vm1")

    assert len(forwards) == 1
    assert forwards[0].host_port == 34000
    assert forwards[0].vm_port == 8080
    assert forwards[0].protocol is Protocol.TCP


@pytest.mark.asyncio
async def test_list_port_forwards_all_vms():
    e1 = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    e1.vm_hash = "vm1"
    e2 = make_execution_with_ports({53: {"host": 34001, "tcp": False, "udp": True}})
    e2.vm_hash = "vm2"
    pool = FakePool(executions={"vm1": e1, "vm2": e2})
    sup = InProcessSupervisor(pool=pool)

    forwards = await sup.list_port_forwards(None)

    assert {f.host_port for f in forwards} == {34000, 34001}


@pytest.mark.asyncio
async def test_remove_port_forward_updates_redirects():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    await sup.remove_port_forward("vm1", host_port=34000, protocol=Protocol.TCP)

    execution.update_port_redirects.assert_awaited_once()


@pytest.mark.asyncio
async def test_port_forward_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.add_port_forward(PortForwardSpec(vm_id="nope", host_port=0, vm_port=80, protocol=Protocol.TCP))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_ports.py -v`
Expected: FAIL (methods raise `NotImplementedSupervisorError`)

- [ ] **Step 3: Implement in `inprocess.py`**

Add `PortForwardInfo` and `Protocol` are already imported. Replace the three port stub bodies:

```python
    def _mapped_to_infos(self, execution) -> list[PortForwardInfo]:
        infos: list[PortForwardInfo] = []
        for vm_port, mapping in execution.mapped_ports.items():
            host_port = int(mapping["host"])
            for proto in (Protocol.TCP, Protocol.UDP):
                if mapping.get(proto.value):
                    infos.append(
                        PortForwardInfo(
                            vm_id=str(execution.vm_hash),
                            host_port=host_port,
                            vm_port=int(vm_port),
                            protocol=proto,
                        )
                    )
        return infos

    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        with translating_errors():
            execution = self._require(spec.vm_id)
            requested: dict[int, dict[str, bool]] = {}
            for vm_port, mapping in execution.mapped_ports.items():
                requested[int(vm_port)] = {"tcp": bool(mapping.get("tcp")), "udp": bool(mapping.get("udp"))}
            entry = requested.setdefault(spec.vm_port, {"tcp": False, "udp": False})
            entry[spec.protocol.value] = True
            await execution.update_port_redirects(requested)
            mapping = execution.mapped_ports[spec.vm_port]
            return PortForwardInfo(
                vm_id=spec.vm_id,
                host_port=int(mapping["host"]),
                vm_port=spec.vm_port,
                protocol=spec.protocol,
            )

    async def remove_port_forward(self, vm_id: str, host_port: int, protocol: Protocol) -> None:
        with translating_errors():
            execution = self._require(vm_id)
            requested: dict[int, dict[str, bool]] = {}
            for vm_port, mapping in execution.mapped_ports.items():
                requested[int(vm_port)] = {"tcp": bool(mapping.get("tcp")), "udp": bool(mapping.get("udp"))}
                if int(mapping["host"]) == host_port:
                    requested[int(vm_port)][protocol.value] = False
            await execution.update_port_redirects(requested)

    async def list_port_forwards(self, vm_id: str | None = None) -> list[PortForwardInfo]:
        with translating_errors():
            if vm_id is not None:
                return self._mapped_to_infos(self._require(vm_id))
            infos: list[PortForwardInfo] = []
            for execution in self.pool.executions.values():
                infos.extend(self._mapped_to_infos(execution))
            return infos
```

Note: `mapped_ports` keys may be stored as `int`; the helpers coerce with `int(...)`. The protocol boolean keys in the dict are `"tcp"` / `"udp"`, matching `Protocol.value`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_ports.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_ports.py
git commit -m "feat(supervisor): implement port forwarding add/remove/list"
```

---

### Task 9: Implement logs (`get_logs`, `stream_logs`)

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_logs.py`

The controller log queue (`vm.get_log_queue()`) yields `(log_type, message)` tuples where `log_type` is `"stdout"` or `"stderr"`. `stream_logs` wraps the queue and yields `LogChunk`; `unregister_queue` is called on exit. `get_logs` drains currently-available lines without blocking.

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_logs.py
import asyncio
from types import SimpleNamespace

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import LogChunk, LogSource

from .test_supervisor_inprocess_query import FakePool


def make_execution_with_logs(lines):
    queue = asyncio.Queue()
    for entry in lines:
        queue.put_nowait(entry)
    unregistered = {"called": False}

    def unregister(q):
        unregistered["called"] = True

    vm = SimpleNamespace(get_log_queue=lambda: queue, unregister_queue=unregister)
    execution = SimpleNamespace(vm_hash="vm1", vm=vm)
    return execution, unregistered


@pytest.mark.asyncio
async def test_stream_logs_yields_logchunks_then_unregisters():
    execution, unregistered = make_execution_with_logs([("stdout", "hello"), ("stderr", "oops")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    received = []
    async for chunk in sup.stream_logs("vm1"):
        received.append(chunk)
        if len(received) == 2:
            break

    assert isinstance(received[0], LogChunk)
    assert received[0].line == "hello"
    assert received[0].source is LogSource.STDOUT
    assert received[1].source is LogSource.STDOUT or received[1].source is LogSource.SERIAL
    assert unregistered["called"] is True


@pytest.mark.asyncio
async def test_get_logs_drains_available_lines():
    execution, _ = make_execution_with_logs([("stdout", "a"), ("stdout", "b")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    chunks = await sup.get_logs("vm1")

    assert [c.line for c in chunks] == ["a", "b"]


@pytest.mark.asyncio
async def test_logs_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_logs("nope")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_logs.py -v`
Expected: FAIL (methods raise `NotImplementedSupervisorError`)

- [ ] **Step 3: Implement in `inprocess.py`**

Add `LogChunk` and `LogSource` to the `types` import. Replace `get_logs` and `stream_logs`:

```python
    async def get_logs(self, vm_id: str, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        with translating_errors():
            execution = self._require(vm_id)
            if not execution.vm:
                return []
            queue = execution.vm.get_log_queue()
            chunks: list[LogChunk] = []
            try:
                while not queue.empty():
                    log_type, message = queue.get_nowait()
                    chunks.append(LogChunk(timestamp_ns=0, line=message, source=_log_source(log_type)))
                    queue.task_done()
                    if max_lines and len(chunks) >= max_lines:
                        break
            finally:
                execution.vm.unregister_queue(queue)
            if from_tail and max_lines:
                chunks = chunks[-max_lines:]
            return chunks

    async def stream_logs(self, vm_id: str, include_history: bool = False) -> AsyncIterator[LogChunk]:
        execution = self._require(vm_id)
        if not execution.vm:
            return
        queue = execution.vm.get_log_queue()
        try:
            while True:
                log_type, message = await queue.get()
                yield LogChunk(timestamp_ns=0, line=message, source=_log_source(log_type))
                queue.task_done()
        finally:
            execution.vm.unregister_queue(queue)
```

Add the module-level helper:

```python
def _log_source(log_type: str) -> "LogSource":
    if log_type == "stdout":
        return LogSource.STDOUT
    if log_type == "stderr":
        # stderr is delivered on the same journal path; map to STDOUT for now.
        return LogSource.STDOUT
    return LogSource.SERIAL
```

Note: `_require` raising `VmNotFoundError` inside the async generator `stream_logs` propagates when iteration begins, which is the desired behavior. `timestamp_ns` is 0 in 0.B because the queue tuples carry no timestamp; enriching it is a follow-up when the log view migrates.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_logs.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_logs.py
git commit -m "feat(supervisor): implement get_logs and stream_logs"
```

---

### Task 10: Implement host methods (`health`, `get_host_info`)

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py`
- Test: `tests/supervisor/test_supervisor_inprocess_host.py`

Per design §11 Q1, populate what is trivially available: `health` reports VM count; `get_host_info` reports CPU count and total memory; topology/TEE/GPU detail is left at defaults until the host-status view migrates.

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_host.py
import pytest

from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import HealthInfo, HostInfo

from .test_supervisor_inprocess_query import FakePool, make_execution


@pytest.mark.asyncio
async def test_health_reports_ok_and_vm_count():
    pool = FakePool(executions={"a": make_execution(), "b": make_execution()})
    sup = InProcessSupervisor(pool=pool)

    health = await sup.health()

    assert isinstance(health, HealthInfo)
    assert health.status == "ok"
    assert health.vm_count == 2


@pytest.mark.asyncio
async def test_get_host_info_reports_cpu_and_memory():
    sup = InProcessSupervisor(pool=FakePool())

    info = await sup.get_host_info()

    assert isinstance(info, HostInfo)
    assert info.cpu_count >= 1
    assert info.memory_mib > 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/supervisor/test_supervisor_inprocess_host.py -v`
Expected: FAIL (methods raise `NotImplementedSupervisorError`)

- [ ] **Step 3: Implement in `inprocess.py`**

Add imports near the top:

```python
import os

import psutil
```

Add `HealthInfo`, `HostInfo` to the `types` import. Replace the two host stub bodies:

```python
    async def health(self) -> HealthInfo:
        with translating_errors():
            return HealthInfo(status="ok", vm_count=len(self.pool.executions))

    async def get_host_info(self) -> HostInfo:
        with translating_errors():
            return HostInfo(
                cpu_count=os.cpu_count() or 0,
                memory_mib=int(psutil.virtual_memory().total / (1024 * 1024)),
                kernel_version=os.uname().release,
                hostname=os.uname().nodename,
            )
```

Note: `psutil` is already a project dependency (used elsewhere in aleph-vm). Topology, TEE flags, and GPUs stay at their dataclass defaults in 0.B.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/supervisor/test_supervisor_inprocess_host.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_host.py
git commit -m "feat(supervisor): implement health and get_host_info"
```

---

### Task 11: End-to-end error translation in a real method

**Files:**
- Test: `tests/supervisor/test_supervisor_inprocess_error_translation.py`

This verifies that an internal backend exception raised deep in a pool call surfaces as the correct `SupervisorError` through the `translating_errors()` wrapper already applied in the methods.

- [ ] **Step 1: Write the failing test**

```python
# tests/supervisor/test_supervisor_inprocess_error_translation.py
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.resources import InsufficientResourcesError as InternalInsufficientResources
from aleph.vm.supervisor.errors import InsufficientResourcesError as SupInsufficientResources
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import ErrorCode

from .test_supervisor_inprocess_query import FakePool, make_execution


@pytest.mark.asyncio
async def test_internal_exception_in_delete_is_translated():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock(
        side_effect=InternalInsufficientResources("no", required={"a": 1}, available={"a": 0})
    )
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    with pytest.raises(SupInsufficientResources) as excinfo:
        await sup.delete_vm("itemhash123")

    assert excinfo.value.code is ErrorCode.INSUFFICIENT_RESOURCES
```

- [ ] **Step 2: Run test to verify it passes (translation is already wired)**

Run: `pytest tests/supervisor/test_supervisor_inprocess_error_translation.py -v`
Expected: PASS (1 test). If it FAILS because `delete_vm` does not wrap the call in `translating_errors()`, fix `delete_vm` to do so (it already does per Task 7); the test pins this behavior.

- [ ] **Step 3: Commit**

```bash
git add tests/supervisor/test_supervisor_inprocess_error_translation.py
git commit -m "test(supervisor): pin internal-exception translation through delete_vm"
```

---

### Task 12: Full suite, style, typing, and final verification

**Files:**
- None (verification only)

- [ ] **Step 1: Run the full supervisor test suite**

Run: `pytest tests/supervisor -q`
Expected: all supervisor tests pass (including the pre-existing `tests/supervisor/*` daemon tests and the new files). If the relative import in Task 5 caused a collection error, apply the absolute-import fallback noted there and re-run.

- [ ] **Step 2: Run style checks**

Run: `hatch run linting:style`
Expected: PASS. If ruff/black/isort report issues in the new files, apply their autofixes (`hatch run linting:style` may format in place depending on config) and re-run until clean.

- [ ] **Step 3: Run type checks**

Run: `hatch run linting:typing`
Expected: PASS for the new `aleph.vm.supervisor` modules. Resolve any mypy errors (e.g. add precise types) without weakening signatures.

- [ ] **Step 4: Verify proto drift check still clean (sanity, no proto changed)**

Run: `hatch run testing:bash scripts/check_proto_clean.sh`
Expected: "proto bindings are up to date."

- [ ] **Step 5: Final commit if any fixups were made**

```bash
git add -A
git commit -m "chore(supervisor): style and typing fixups for Phase 0.B"
```

- [ ] **Step 6: Push and open the PR (base = the rename branch or dev)**

```bash
git push -u origin od/supervisor-abc
```

If PR #951 (the rename) has merged to `dev`, rebase onto `dev` first so the PR diff shows only 0.B:

```bash
git fetch origin dev
git rebase --onto origin/dev origin/od/supervisor-rename od/supervisor-abc
git push --force-with-lease
```

Then open the PR with `gh pr create --base dev` (or `--base od/supervisor-rename` if the rename has not merged yet).

---

## Self-Review notes

- Spec coverage: §4 ABCs → Task 3; §5 DTOs → Task 1; §6 `CreateVmSpec` type → Task 1 (the create vertical is explicitly deferred, no task); §7 errors + translation → Task 2 + Task 11; §8 in-process real methods → Tasks 6-10; §2.1 stub set → Task 4 + conformance Task 5; §9 testing (conformance, error translation, clean-method units) → Tasks 5, 11, 6-10.
- The 12 real methods (Tasks 6-10) plus 13 stubs (Task 4) = 25, matching the proto surface pinned in Task 3.
- Identity is `str(vm_hash)` on output and `pool.executions.get(vm_id)` on input throughout; no `ItemHash` import is needed because `pool.executions` is keyed by the same hash and lookups use the string form via the fakes. In production `pool.executions` is keyed by `ItemHash`; `ItemHash` subclasses `str`, so `pool.executions.get(vm_id)` with a `str` key resolves correctly. This is verified by the fakes using plain string keys and confirmed against `ItemHash`'s `str` subclassing.
