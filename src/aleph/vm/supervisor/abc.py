"""The Supervisor abstraction: capability ABCs aggregated into one interface.

Seven capability ABCs, all async, one method per proto RPC. A concrete
supervisor (in-process today, gRPC client in 0.D) implements all 25 methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from aleph.vm.supervisor.types import (
    BackupChunk,
    BackupId,
    BackupInfo,
    CreateVmSpec,
    DirectoryPath,
    HealthInfo,
    HostInfo,
    HostPort,
    LogChunk,
    Measurement,
    MigrationId,
    MigrationInfo,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmId,
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
    async def get_vm(self, vm_id: VmId) -> VmInfo: ...

    @abstractmethod
    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        """The spec a live VM was created from. Raises
        NotImplementedSupervisorError for VMs created outside the spec path."""

    @abstractmethod
    async def list_vms(self) -> list[VmInfo]: ...

    @abstractmethod
    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None: ...

    @abstractmethod
    async def reboot_vm(self, vm_id: VmId) -> VmInfo: ...

    @abstractmethod
    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo: ...


class PortForwardingOps(ABC):
    @abstractmethod
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo: ...

    @abstractmethod
    async def remove_port_forward(self, vm_id: VmId, host_port: HostPort, protocol: Protocol) -> None: ...

    @abstractmethod
    async def list_port_forwards(self, vm_id: VmId | None = None) -> list[PortForwardInfo]: ...


class LogsOps(ABC):
    @abstractmethod
    async def get_logs(self, vm_id: VmId, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]: ...

    @abstractmethod
    def stream_logs(self, vm_id: VmId, include_history: bool = False) -> AsyncIterator[LogChunk]: ...


class BackupOps(ABC):
    @abstractmethod
    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False) -> BackupInfo: ...

    @abstractmethod
    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo: ...

    @abstractmethod
    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]: ...

    @abstractmethod
    def download_backup(self, vm_id: VmId, backup_id: BackupId) -> AsyncIterator[BackupChunk]: ...

    @abstractmethod
    async def delete_backup(self, vm_id: VmId, backup_id: BackupId) -> None: ...

    @abstractmethod
    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo: ...


class MigrationOps(ABC):
    @abstractmethod
    async def export_vm(self, vm_id: VmId, destination_dir: DirectoryPath) -> MigrationInfo: ...

    @abstractmethod
    async def import_vm(self, vm_id: VmId, source_dir: DirectoryPath) -> VmInfo: ...

    @abstractmethod
    async def get_migration_status(self, vm_id: VmId, migration_id: MigrationId) -> MigrationInfo: ...


class ConfidentialOps(ABC):
    @abstractmethod
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None: ...

    @abstractmethod
    async def get_measurement(self, vm_id: VmId) -> Measurement: ...

    @abstractmethod
    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None: ...


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
