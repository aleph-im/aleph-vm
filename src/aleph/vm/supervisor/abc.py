"""The Supervisor abstraction: capability ABCs aggregated into one interface.

Seven capability ABCs, all async, one method per proto RPC. A concrete
supervisor (in-process today, gRPC client in 0.D) implements all 25 methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

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
