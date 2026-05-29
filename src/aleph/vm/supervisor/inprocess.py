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

    # Host
    async def health(self) -> HealthInfo:
        raise NotImplementedSupervisorError("health")

    async def get_host_info(self) -> HostInfo:
        raise NotImplementedSupervisorError("get_host_info")

    # Lifecycle
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

    # Port forwarding
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        raise NotImplementedSupervisorError("add_port_forward")

    async def remove_port_forward(self, vm_id: str, host_port: int, protocol: Protocol) -> None:
        raise NotImplementedSupervisorError("remove_port_forward")

    async def list_port_forwards(self, vm_id: str | None = None) -> list[PortForwardInfo]:
        raise NotImplementedSupervisorError("list_port_forwards")

    # Logs
    async def get_logs(self, vm_id: str, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        raise NotImplementedSupervisorError("get_logs")

    async def stream_logs(self, vm_id: str, include_history: bool = False) -> AsyncIterator[LogChunk]:
        raise NotImplementedSupervisorError("stream_logs")
        yield  # pragma: no cover - makes this an async generator

    # Backups
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

    # Migration
    async def export_vm(self, vm_id: str, destination_dir: str) -> MigrationInfo:
        raise NotImplementedSupervisorError("export_vm")

    async def import_vm(self, vm_id: str, source_dir: str) -> VmInfo:
        raise NotImplementedSupervisorError("import_vm")

    async def get_migration_status(self, vm_id: str, migration_id: str) -> MigrationInfo:
        raise NotImplementedSupervisorError("get_migration_status")

    # Confidential
    async def initialize_confidential(self, vm_id: str, session_bytes: bytes, godh_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("initialize_confidential")

    async def get_measurement(self, vm_id: str) -> Measurement:
        raise NotImplementedSupervisorError("get_measurement")

    async def inject_secret(self, vm_id: str, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("inject_secret")
