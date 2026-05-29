"""In-process Supervisor: wraps today's VmPool / VmExecution.

This is the throwaway implementation that runs in the same process as the
agent during the strangler period. It validates the contract under real pool
behavior before any gRPC exists. Methods not yet implemented raise
NotImplementedSupervisorError.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import NotImplementedSupervisorError, VmNotFoundError, translating_errors
from aleph.vm.supervisor.types import (
    Backend,
    BackupChunk,
    BackupInfo,
    CreateVmSpec,
    HealthInfo,
    HostInfo,
    LogChunk,
    LogSource,
    Measurement,
    MigrationInfo,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmInfo,
    VmStatus,
)

if TYPE_CHECKING:
    from aleph.vm.pool import VmPool


def _backend_of(execution) -> Backend:
    if execution.is_program:
        return Backend.FIRECRACKER
    if execution.is_confidential:
        return Backend.QEMU_SEV
    if execution.hypervisor == HypervisorType.firecracker:
        return Backend.FIRECRACKER
    return Backend.QEMU


def _is_running(execution, pool) -> bool:
    if execution.persistent and getattr(execution, "systemd_manager", None) and getattr(pool, "systemd_manager", None):
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
    if times.starting_at:
        return VmStatus.BOOTING
    return VmStatus.DEFINED


def _uptime_secs(execution, running: bool) -> int:
    started = execution.times.started_at
    if running and started:
        return int((datetime.now(tz=timezone.utc) - started).total_seconds())
    return 0


def _to_vm_info(execution, running: bool) -> VmInfo:
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


def _log_source(log_type: str) -> LogSource:
    if log_type == "stdout":
        return LogSource.STDOUT
    if log_type == "stderr":
        # stderr is delivered on the same journal path; map to STDOUT for now.
        return LogSource.STDOUT
    return LogSource.SERIAL


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
            if execution.persistent and getattr(execution, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
            else:
                await self.pool.stop_vm(vm_id)
                self.pool.forget_vm(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def reinstall_vm(self, vm_id: str) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.persistent and getattr(execution, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
            else:
                self.pool.forget_vm(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    # Port forwarding
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

    # Logs
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
            finally:
                execution.vm.unregister_queue(queue)
            if max_lines:
                chunks = chunks[-max_lines:] if from_tail else chunks[:max_lines]
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
