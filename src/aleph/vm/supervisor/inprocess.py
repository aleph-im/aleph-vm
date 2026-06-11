"""In-process Supervisor: wraps today's VmPool / VmExecution.

This is the throwaway implementation that runs in the same process as the
agent during the strangler period. It validates the contract under real pool
behavior before any gRPC exists. Methods not yet implemented raise
NotImplementedSupervisorError.
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import psutil
from aleph_message.models.execution.environment import AMDSEVPolicy, HypervisorType

from aleph.vm.orchestrator.metrics import delete_port_mappings
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    NotImplementedSupervisorError,
    VmNotFoundError,
    translating_errors,
)
from aleph.vm.supervisor.types import (
    Backend,
    BackupChunk,
    BackupId,
    BackupInfo,
    ConfidentialMode,
    CreateVmSpec,
    DirectoryPath,
    GpuDevice,
    GuestPort,
    HealthInfo,
    HealthStatus,
    HostInfo,
    HostPort,
    IpAssignment,
    LogChunk,
    LogSource,
    Measurement,
    MigrationId,
    MigrationInfo,
    PciAddress,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils.logs import get_past_vm_logs

if TYPE_CHECKING:
    from aleph.vm.pool import VmPool

logger = logging.getLogger(__name__)


def _backend_of(execution) -> Backend:
    """The VMM only; confidential computing is reported via confidential_mode."""
    if execution.is_program or execution.hypervisor == HypervisorType.firecracker:
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


def _ns(dt: datetime | None) -> int:
    """Unix nanoseconds for an aware datetime; 0 for None.

    Same lossless composition as the log timestamps: whole seconds plus the
    integer microsecond field (datetimes carry µs precision, so this
    roundtrips exactly; float multiplication would not).
    """
    if dt is None:
        return 0
    return int(dt.timestamp()) * 1_000_000_000 + dt.microsecond * 1_000


def _running_states(pool) -> dict[str, bool]:
    """Running flag for every execution with one batched systemd query.

    Same semantics as _is_running, but a single D-Bus call covers all
    persistent VMs instead of one call each.
    """
    persistent_services: dict[str, str] = {}
    for vm_hash, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            persistent_services[execution.controller_service] = str(vm_hash)

    service_states: dict[str, bool] = {}
    if persistent_services and getattr(pool, "systemd_manager", None):
        service_states = pool.systemd_manager.get_services_active_states(list(persistent_services.keys()))

    states: dict[str, bool] = {}
    for vm_hash, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            states[str(vm_hash)] = service_states.get(execution.controller_service, False)
        else:
            times = execution.times
            states[str(vm_hash)] = bool(times.starting_at and not times.stopping_at)
    return states


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


def _guest_channel_path(execution) -> str:
    """Host UDS endpoint of the guest channel (Firecracker vsock); empty for
    VMs without one."""
    fvm = getattr(execution.vm, "fvm", None) if execution.vm else None
    if execution.is_program and fvm is not None:
        return str(fvm.vsock_path)
    return ""


def _guest_ready_payload(execution) -> bytes:
    """Raw bytes from the guest's ready signal, passed through opaquely."""
    fvm = getattr(execution.vm, "fvm", None) if execution.vm else None
    return getattr(fvm, "init_payload", b"") if fvm is not None else b""


def _to_vm_info(execution, running: bool) -> VmInfo:
    tap = execution.vm.tap_interface if execution.vm else None
    times = execution.times
    ipv4 = IpAssignment(
        address=str(tap.guest_ip.ip) if tap else "",
        network_cidr=str(tap.ip_network) if tap else "",
        gateway=str(tap.host_ip.ip) if tap and getattr(tap, "host_ip", None) else "",
    )
    ipv6 = IpAssignment(
        address=str(tap.guest_ipv6.ip) if tap else "",
        network_cidr=str(tap.ipv6_network) if tap else "",
        gateway=str(tap.host_ipv6.ip) if tap and getattr(tap, "host_ipv6", None) else "",
    )
    return VmInfo(
        vm_id=VmId(str(execution.vm_hash)),
        status=_status_of(execution, running),
        ipv4=ipv4,
        ipv6=ipv6,
        uptime_secs=_uptime_secs(execution, running),
        backend=_backend_of(execution),
        numa_node=None,
        status_message="",
        defined_at_ns=_ns(times.defined_at),
        preparing_at_ns=_ns(times.preparing_at),
        prepared_at_ns=_ns(times.prepared_at),
        starting_at_ns=_ns(times.starting_at),
        started_at_ns=_ns(times.started_at),
        stopping_at_ns=_ns(times.stopping_at),
        stopped_at_ns=_ns(times.stopped_at),
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
        guest_channel_path=_guest_channel_path(execution),
        guest_ready_payload=_guest_ready_payload(execution),
    )


def _log_source(log_type: str) -> LogSource:
    if log_type == "stdout":
        return LogSource.STDOUT
    if log_type == "stderr":
        return LogSource.STDERR
    return LogSource.SERIAL


def _history_chunks(vm_id: VmId) -> list[LogChunk]:
    """Journald history for a VM, mapped to LogChunks.

    Blocking sd-journal read; same behavior as the old views (the agent
    endpoints already read journald inline on the event loop).
    """
    stdout_id = f"vm-{vm_id}-stdout"
    stderr_id = f"vm-{vm_id}-stderr"
    chunks: list[LogChunk] = []
    for entry in get_past_vm_logs(stdout_id, stderr_id):
        source = LogSource.STDOUT if entry["SYSLOG_IDENTIFIER"] == stdout_id else LogSource.STDERR
        message = entry["MESSAGE"]
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        ts = entry["__REALTIME_TIMESTAMP"]
        # Exact for post-epoch times: whole seconds + the integer microsecond
        # field. int(ts.timestamp() * 1e9) would carry ~256ns of float64 error.
        timestamp_ns = int(ts.timestamp()) * 1_000_000_000 + ts.microsecond * 1_000
        chunks.append(LogChunk(timestamp_ns=timestamp_ns, line=message, source=source))
    return chunks


class InProcessSupervisor(Supervisor):
    def __init__(self, pool: VmPool):
        self.pool = pool

    # Host
    async def health(self) -> HealthInfo:
        with translating_errors():
            return HealthInfo(status=HealthStatus.OK, vm_count=len(self.pool.executions))

    async def get_host_info(self) -> HostInfo:
        with translating_errors():
            network = getattr(self.pool, "network", None)
            return HostInfo(
                cpu_count=os.cpu_count() or 0,
                memory_mib=int(psutil.virtual_memory().total / (1024 * 1024)),
                kernel_version=os.uname().release,
                hostname=os.uname().nodename,
                host_ipv4=network.host_ipv4 if network else "",
            )

    # Lifecycle
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        with translating_errors():
            execution = await self.pool.create_vm_from_spec(spec)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def get_vm(self, vm_id: VmId) -> VmInfo:
        with translating_errors():
            execution = self.pool.executions.get(vm_id)
            if execution is None:
                raise VmNotFoundError(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def list_vms(self) -> list[VmInfo]:
        with translating_errors():
            running = _running_states(self.pool)
            return [
                _to_vm_info(execution, running[str(vm_hash)]) for vm_hash, execution in self.pool.executions.items()
            ]

    def _require(self, vm_id: VmId):
        execution = self.pool.executions.get(vm_id)
        if execution is None:
            raise VmNotFoundError(vm_id)
        return execution

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.vm_hash in self.pool.executions:
                # Routine: the pool's _schedule_forget_on_stop task has usually
                # not run yet by the time stop_vm returns, so delete_vm wins
                # this race on most reaps.
                logger.debug("VM %s was not removed from pool after stop; forgetting it now", vm_id)
                self.pool.forget_vm(vm_id)
            if wipe:
                # Mirrors the old operate_erase semantics exactly: persisted
                # port mappings (persistent VMs keep them across stops) and
                # writable data volumes go; the rootfs stays.
                if execution.persistent:
                    await delete_port_mappings(execution.vm_hash)
                execution.erase_volumes()

    async def reboot_vm(self, vm_id: VmId) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            if execution.persistent and getattr(execution, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
            else:
                await self.pool.stop_vm(vm_id)
                self.pool.forget_vm(vm_id)
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.persistent:
                # Keep the execution registered so the allocation loop cannot
                # create a duplicate while we re-prepare (mirrors the old
                # operate_reinstall persistent branch). Note: restart_persistent_vm
                # re-registers the execution again after prepare() — the duplicate
                # write is intentional.
                execution.stop_event = asyncio.Event()
                self.pool.executions[execution.vm_hash] = execution
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                execution.resources = None
                await execution.prepare()
                await self.pool.restart_persistent_vm(execution)
            else:
                if execution.vm_hash in self.pool.executions:
                    self.pool.forget_vm(execution.vm_hash)
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                # The agent re-creates non-persistent VMs through the create
                # path (it owns the message); we return the stopped state.
            return _to_vm_info(execution, _is_running(execution, self.pool))

    # Port forwarding
    def _mapped_to_infos(self, execution) -> list[PortForwardInfo]:
        infos: list[PortForwardInfo] = []
        for vm_port, mapping in execution.mapped_ports.items():
            for proto in (Protocol.TCP, Protocol.UDP):
                if mapping.get(proto.value):
                    infos.append(
                        PortForwardInfo(
                            vm_id=VmId(str(execution.vm_hash)),
                            host_port=HostPort(int(mapping["host"])),
                            vm_port=GuestPort(int(vm_port)),
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
            entry = requested.setdefault(int(spec.vm_port), {"tcp": False, "udp": False})
            entry[spec.protocol.value] = True
            await execution.update_port_redirects(requested)
            mapping = execution.mapped_ports[int(spec.vm_port)]
            return PortForwardInfo(
                vm_id=spec.vm_id,
                host_port=HostPort(int(mapping["host"])),
                vm_port=spec.vm_port,
                protocol=spec.protocol,
            )

    async def remove_port_forward(self, vm_id: VmId, host_port: HostPort, protocol: Protocol) -> None:
        with translating_errors():
            execution = self._require(vm_id)
            requested: dict[int, dict[str, bool]] = {}
            for vm_port, mapping in execution.mapped_ports.items():
                requested[int(vm_port)] = {"tcp": bool(mapping.get("tcp")), "udp": bool(mapping.get("udp"))}
                if int(mapping["host"]) == host_port:
                    requested[int(vm_port)][protocol.value] = False
            # A port whose last active protocol was just cleared must be
            # dropped from the request entirely: update_port_redirects only
            # deletes mappings for absent keys (all-False keys are kept as
            # ghost entries).
            requested = {vm_port: flags for vm_port, flags in requested.items() if flags["tcp"] or flags["udp"]}
            await execution.update_port_redirects(requested)

    async def list_port_forwards(self, vm_id: VmId | None = None) -> list[PortForwardInfo]:
        with translating_errors():
            if vm_id is not None:
                return self._mapped_to_infos(self._require(vm_id))
            infos: list[PortForwardInfo] = []
            for execution in self.pool.executions.values():
                infos.extend(self._mapped_to_infos(execution))
            return infos

    # Logs
    async def get_logs(self, vm_id: VmId, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        """Journald history for the VM (works for stopped VMs too)."""
        with translating_errors():
            chunks = _history_chunks(vm_id)
            if max_lines:
                chunks = chunks[-max_lines:] if from_tail else chunks[:max_lines]
            return chunks

    async def stream_logs(self, vm_id: VmId, include_history: bool = False) -> AsyncIterator[LogChunk]:
        if include_history:
            with translating_errors():
                history = _history_chunks(vm_id)
            for chunk in history:
                yield chunk
        execution = self.pool.executions.get(vm_id)
        if not execution or not execution.vm:
            return
        queue = execution.vm.get_log_queue()
        try:
            while True:
                log_type, message = await queue.get()
                # Live queue items carry no timestamp; 0 is the "live" sentinel.
                yield LogChunk(timestamp_ns=0, line=message, source=_log_source(log_type))
                queue.task_done()
        finally:
            execution.vm.unregister_queue(queue)

    # Backups
    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False) -> BackupInfo:
        raise NotImplementedSupervisorError("start_backup")

    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo:
        raise NotImplementedSupervisorError("get_backup_status")

    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]:
        raise NotImplementedSupervisorError("list_backups")

    async def download_backup(self, vm_id: VmId, backup_id: BackupId) -> AsyncIterator[BackupChunk]:
        raise NotImplementedSupervisorError("download_backup")
        yield  # pragma: no cover - makes this an async generator

    async def delete_backup(self, vm_id: VmId, backup_id: BackupId) -> None:
        raise NotImplementedSupervisorError("delete_backup")

    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo:
        raise NotImplementedSupervisorError("restore_backup")

    # Migration
    async def export_vm(self, vm_id: VmId, destination_dir: DirectoryPath) -> MigrationInfo:
        raise NotImplementedSupervisorError("export_vm")

    async def import_vm(self, vm_id: VmId, source_dir: DirectoryPath) -> VmInfo:
        raise NotImplementedSupervisorError("import_vm")

    async def get_migration_status(self, vm_id: VmId, migration_id: MigrationId) -> MigrationInfo:
        raise NotImplementedSupervisorError("get_migration_status")

    # Confidential
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("initialize_confidential")

    async def get_measurement(self, vm_id: VmId) -> Measurement:
        raise NotImplementedSupervisorError("get_measurement")

    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        raise NotImplementedSupervisorError("inject_secret")
