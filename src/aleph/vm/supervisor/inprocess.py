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
import shutil
import tarfile
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import psutil
from aleph_message.models.execution.environment import AMDSEVPolicy, HypervisorType

from aleph.vm.controllers.qemu.backup import (
    InsufficientDiskSpaceError,
    check_disk_space_for_multiple,
    cleanup_expired_backups,
    create_backup_archive,
    create_qemu_disk_backup,
    find_existing_backup,
    get_backup_directory,
    restore_rootfs,
    verify_qemu_disk,
)
from aleph.vm.orchestrator.metrics import delete_port_mappings
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    BackupNotFoundError,
    InsufficientResourcesError,
    InternalSupervisorError,
    InvalidBackendError,
    NotImplementedSupervisorError,
    VmNotFoundError,
    translating_errors,
)
from aleph.vm.supervisor.types import (
    Backend,
    BackupChunk,
    BackupId,
    BackupInfo,
    BackupStatus,
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
    VmEvent,
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


# The single archive member a supervisor backup carries today: the rootfs
# disk. Extra data disks are not backed up (restore replaces the rootfs only,
# and an asymmetric archive would be a trap).
_BACKUP_ROOTFS_MEMBER = "rootfs.qcow2"
_BACKUP_DOWNLOAD_CHUNK_BYTES = 1024 * 1024


def _validate_backup_id(vm_id: VmId, backup_id: BackupId) -> None:
    """Reject ids that are not of this VM or that could escape the backup
    directory (the id becomes a file name)."""
    malformed = not backup_id or "/" in backup_id or "\\" in backup_id or ".." in backup_id
    if malformed or not backup_id.startswith(f"{vm_id}-"):
        raise BackupNotFoundError(backup_id)


def _backup_info_from_tar(tar_path: Path, vm_id: VmId) -> BackupInfo:
    stat = tar_path.stat()
    return BackupInfo(
        vm_id=vm_id,
        backup_id=BackupId(tar_path.stem),
        status=BackupStatus.COMPLETE,
        size_bytes=stat.st_size,
        created_at_unix_secs=int(stat.st_mtime),
        error_message="",
    )


def _extract_rootfs_member(tar_path: Path, destination: Path) -> None:
    """Stream the rootfs member of a backup archive to *destination*.

    Member-streamed on purpose (no extractall): archive member names never
    touch the filesystem, so a crafted archive cannot escape the backup
    directory.
    """
    with tarfile.open(tar_path, "r") as tar:
        try:
            member = tar.getmember(_BACKUP_ROOTFS_MEMBER)
        except KeyError:
            msg = f"Backup archive {tar_path.name} has no {_BACKUP_ROOTFS_MEMBER} member"
            raise InternalSupervisorError(msg) from None
        source = tar.extractfile(member)
        if source is None:
            msg = f"Backup member {_BACKUP_ROOTFS_MEMBER} in {tar_path.name} is not a regular file"
            raise InternalSupervisorError(msg)
        with source, destination.open("wb") as dst:
            shutil.copyfileobj(source, dst)


class InProcessSupervisor(Supervisor):
    def __init__(self, pool: VmPool):
        self.pool = pool
        # Live watch_events subscribers; events are fan-out, no replay.
        self._event_queues: set[asyncio.Queue[VmEvent]] = set()
        # Backup bookkeeping. Completed archives live on disk (the source of
        # truth); _backup_jobs only holds in-flight and failed runs.
        self._backup_jobs: dict[BackupId, BackupInfo] = {}
        self._backup_tasks: dict[VmId, asyncio.Task] = {}
        # Serializes backup and restore per VM: a restore must not swap the
        # rootfs out from under a running qemu-img convert.
        self._backup_locks: dict[VmId, asyncio.Lock] = {}

    # ── Events ──
    def _emit_event(self, vm_id: VmId, old_status: VmStatus, new_status: VmStatus) -> None:
        """Fan a lifecycle transition out to every watcher. Emission points
        are the supervisor's own lifecycle methods: every transition crossing
        the boundary is covered (spontaneous guest death is not detected
        anywhere today; see the proto note on WatchEvents)."""
        if not self._event_queues:
            return
        event = VmEvent(vm_id=vm_id, old_status=old_status, new_status=new_status, timestamp_ns=time.time_ns())
        for queue in self._event_queues:
            queue.put_nowait(event)

    async def watch_events(self) -> AsyncIterator[VmEvent]:
        queue: asyncio.Queue[VmEvent] = asyncio.Queue()
        self._event_queues.add(queue)
        try:
            while True:
                yield await queue.get()
        finally:
            self._event_queues.discard(queue)

    def _status_snapshot(self, execution) -> VmStatus:
        return _status_of(execution, _is_running(execution, self.pool))

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
            info = _to_vm_info(execution, _is_running(execution, self.pool))
            self._emit_event(spec.vm_id, VmStatus.DEFINED, info.status)
            return info

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

    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        with translating_errors():
            execution = self._require(vm_id)
            spec = execution.vm_spec
            if spec is None:
                msg = f"VM {vm_id} was created outside the spec path (message-built); no spec is held"
                raise NotImplementedSupervisorError(msg)
            return spec

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        with translating_errors():
            execution = self._require(vm_id)
            old_status = self._status_snapshot(execution)
            await self.pool.stop_vm(vm_id)
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
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

    async def stop_vm(self, vm_id: VmId) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            if not (execution.persistent and getattr(execution, "systemd_manager", None)):
                msg = "Stopping an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                raise NotImplementedSupervisorError(msg)
            old_status = self._status_snapshot(execution)
            await self.pool.stop_vm(vm_id)
            # Keep the execution registered so the VM stays observable
            # (STOPPED) and start_vm has a handle. A fresh stop_event defuses
            # the pool's forget-on-stop task (same trick as reinstall).
            execution.stop_event = asyncio.Event()
            self.pool.executions[execution.vm_hash] = execution
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
            return _to_vm_info(execution, running=False)

    async def start_vm(self, vm_id: VmId) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            if not (execution.persistent and getattr(execution, "systemd_manager", None)):
                msg = "Starting an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                raise NotImplementedSupervisorError(msg)
            if _is_running(execution, self.pool):
                return _to_vm_info(execution, running=True)
            old_status = self._status_snapshot(execution)
            await self.pool.restart_persistent_vm(execution)
            info = _to_vm_info(execution, _is_running(execution, self.pool))
            self._emit_event(vm_id, old_status, info.status)
            return info

    async def reboot_vm(self, vm_id: VmId) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            old_status = self._status_snapshot(execution)
            if execution.persistent and getattr(execution, "systemd_manager", None):
                self.pool.systemd_manager.restart(execution.controller_service)
                info = _to_vm_info(execution, _is_running(execution, self.pool))
                # A reboot is a down-then-up pair; watchers that drop per-VM
                # state on "down" must see the down.
                self._emit_event(vm_id, old_status, VmStatus.STOPPED)
                self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info
            spec = execution.vm_spec
            await self.pool.stop_vm(vm_id)
            if execution.vm_hash in self.pool.executions:
                self.pool.forget_vm(vm_id)
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
            if spec is not None:
                # A real reboot: the supervisor holds the spec, so it can
                # recreate the VM itself instead of returning a stopped husk
                # and expecting the client to know it must re-create.
                new_execution = await self.pool.create_vm_from_spec(spec)
                info = _to_vm_info(new_execution, _is_running(new_execution, self.pool))
                self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info
            # Message-built (legacy) ephemeral VMs: the agent owns the
            # message and re-creates through its own path.
            return _to_vm_info(execution, _is_running(execution, self.pool))

    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            old_status = self._status_snapshot(execution)
            await self.pool.stop_vm(vm_id)
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
            if execution.persistent:
                # Keep the execution registered so the allocation loop cannot
                # create a duplicate while we re-prepare (mirrors the old
                # operate_reinstall persistent branch). Note: restart_persistent_vm
                # re-registers the execution again after prepare(); the duplicate
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
            info = _to_vm_info(execution, _is_running(execution, self.pool))
            if info.status is not VmStatus.STOPPED:
                self._emit_event(vm_id, VmStatus.STOPPED, info.status)
            return info

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
                # Live queue items carry no timestamp; stamp at capture so
                # the wire never carries a magic 0 (which clients rendered
                # as the 1970 epoch).
                yield LogChunk(timestamp_ns=time.time_ns(), line=message, source=_log_source(log_type))
                queue.task_done()
        finally:
            execution.vm.unregister_queue(queue)

    # Backups
    def _qemu_rootfs_path(self, execution) -> Path:
        """The on-disk rootfs of a QEMU VM; backups and restores operate on it."""
        if _backend_of(execution) is not Backend.QEMU:
            msg = "Backups operate on the rootfs disk image; only QEMU VMs have one"
            raise InvalidBackendError(msg)
        resources = getattr(execution.vm, "resources", None) if execution.vm else None
        rootfs_path = getattr(resources, "rootfs_path", None)
        if not rootfs_path:
            msg = f"VM {execution.vm_hash} has no rootfs disk image"
            raise InternalSupervisorError(msg)
        return Path(rootfs_path)

    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False) -> BackupInfo:
        with translating_errors():
            execution = self._require(vm_id)
            rootfs_path = self._qemu_rootfs_path(execution)
            backup_dir = get_backup_directory()
            cleanup_expired_backups(backup_dir)

            # Idempotent: a backup already running for this VM is the answer
            # to a second StartBackup, not a conflict.
            running_task = self._backup_tasks.get(vm_id)
            if running_task is not None and not running_task.done():
                for job in self._backup_jobs.values():
                    if job.vm_id == vm_id and job.status is BackupStatus.RUNNING:
                        return job

            # A non-expired archive is also the answer; expiry (24h TTL)
            # defines backup freshness, mirroring the old operator endpoint.
            existing = find_existing_backup(backup_dir, str(vm_id))
            if existing is not None:
                return _backup_info_from_tar(existing, vm_id)

            try:
                await check_disk_space_for_multiple([rootfs_path], backup_dir)
            except InsufficientDiskSpaceError as exc:
                raise InsufficientResourcesError(str(exc)) from exc

            # Microsecond precision: a retry right after a failed run must get
            # a fresh id (the id is also the tar stem, which keeps the format
            # dash-free for list_backups' rsplit).
            timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            backup_id = BackupId(f"{vm_id}-{timestamp}")
            job = BackupInfo(
                vm_id=vm_id,
                backup_id=backup_id,
                status=BackupStatus.RUNNING,
                size_bytes=0,
                created_at_unix_secs=int(time.time()),
                error_message="",
            )
            # This run supersedes earlier failed attempts for the VM.
            for old_id, old_job in list(self._backup_jobs.items()):
                if old_job.vm_id == vm_id and old_job.status is BackupStatus.FAILED:
                    del self._backup_jobs[old_id]
            self._backup_jobs[backup_id] = job
            self._backup_tasks[vm_id] = asyncio.create_task(
                self._run_backup(execution, vm_id, backup_id, timestamp, rootfs_path, backup_dir, quiesce_guest)
            )
            return job

    async def _run_backup(
        self,
        execution,
        vm_id: VmId,
        backup_id: BackupId,
        timestamp: str,
        rootfs_path: Path,
        backup_dir: Path,
        quiesce_guest: bool,
    ) -> None:
        lock = self._backup_locks.setdefault(vm_id, asyncio.Lock())
        disk_backup: Path | None = None
        try:
            async with lock:
                client = None
                frozen = False
                if quiesce_guest and _is_running(execution, self.pool):
                    client, frozen = await self._try_fsfreeze(execution)
                try:
                    disk_backup = await create_qemu_disk_backup(str(vm_id), rootfs_path, backup_dir)
                finally:
                    if frozen and client is not None:
                        await self._try_fsthaw(client, vm_id)
                await verify_qemu_disk(disk_backup)
                await create_backup_archive(
                    vm_hash=str(vm_id),
                    backup_files={_BACKUP_ROOTFS_MEMBER: disk_backup},
                    destination_dir=backup_dir,
                    source_sizes={_BACKUP_ROOTFS_MEMBER: rootfs_path.stat().st_size},
                    timestamp=timestamp,
                )
                # The archive on disk is now the record; drop the live job.
                self._backup_jobs.pop(backup_id, None)
        except Exception as exc:
            logger.exception("Backup %s failed", backup_id)
            self._backup_jobs[backup_id] = BackupInfo(
                vm_id=vm_id,
                backup_id=backup_id,
                status=BackupStatus.FAILED,
                size_bytes=0,
                created_at_unix_secs=int(time.time()),
                error_message=str(exc),
            )
        finally:
            if disk_backup is not None:
                disk_backup.unlink(missing_ok=True)
            self._backup_tasks.pop(vm_id, None)

    async def _try_fsfreeze(self, execution):
        """Best-effort guest fs-freeze through the QEMU guest agent; the
        backup proceeds unfrozen when the agent is unavailable."""
        from aleph.vm.controllers.qemu.client import QemuVmClient

        try:
            client = QemuVmClient(execution.vm)
            frozen = await asyncio.wait_for(client.guest_fsfreeze_freeze(), timeout=30)
            logger.info("Froze %s filesystem(s) for %s", frozen, execution.vm_hash)
            return client, True
        except Exception as exc:
            logger.warning("fsfreeze unavailable for %s, proceeding without: %s", execution.vm_hash, exc)
            return None, False

    async def _try_fsthaw(self, client, vm_id: VmId) -> None:
        try:
            await client.guest_fsfreeze_thaw()
        except Exception:
            logger.exception("Failed to thaw filesystems for %s", vm_id)

    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo:
        with translating_errors():
            _validate_backup_id(vm_id, backup_id)
            tar_path = get_backup_directory() / f"{backup_id}.tar"
            if tar_path.exists():
                return _backup_info_from_tar(tar_path, vm_id)
            job = self._backup_jobs.get(backup_id)
            if job is not None:
                return job
            raise BackupNotFoundError(backup_id)

    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]:
        with translating_errors():
            backup_dir = get_backup_directory()
            pattern = f"{vm_id}-*.tar" if vm_id else "*.tar"
            # The archive stem is "<vm_id>-<timestamp>"; neither part contains
            # a dash (hex item hash, %Y%m%dT%H%M%SZ), so rsplit is exact.
            infos = [
                _backup_info_from_tar(tar_path, VmId(tar_path.stem.rsplit("-", 1)[0]))
                for tar_path in sorted(backup_dir.glob(pattern))
            ]
            infos += [job for job in self._backup_jobs.values() if vm_id is None or job.vm_id == vm_id]
            return infos

    async def download_backup(self, vm_id: VmId, backup_id: BackupId) -> AsyncIterator[BackupChunk]:
        with translating_errors():
            _validate_backup_id(vm_id, backup_id)
            tar_path = get_backup_directory() / f"{backup_id}.tar"
            if not tar_path.exists():
                raise BackupNotFoundError(backup_id)
        offset = 0
        with tar_path.open("rb") as tar_file:
            while True:
                data = await asyncio.to_thread(tar_file.read, _BACKUP_DOWNLOAD_CHUNK_BYTES)
                if not data:
                    return
                yield BackupChunk(data=data, offset=offset)
                offset += len(data)

    async def delete_backup(self, vm_id: VmId, backup_id: BackupId) -> None:
        with translating_errors():
            _validate_backup_id(vm_id, backup_id)
            job = self._backup_jobs.get(backup_id)
            if job is not None and job.status is BackupStatus.RUNNING:
                msg = f"Backup {backup_id} is still running"
                raise InternalSupervisorError(msg)
            tar_path = get_backup_directory() / f"{backup_id}.tar"
            existed = tar_path.exists()
            tar_path.unlink(missing_ok=True)
            tar_path.with_suffix(".tar.sha256").unlink(missing_ok=True)
            tar_path.with_suffix(".tar.meta.json").unlink(missing_ok=True)
            # Deleting a FAILED record is also a valid delete.
            if self._backup_jobs.pop(backup_id, None) is None and not existed:
                raise BackupNotFoundError(backup_id)

    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            rootfs_path = self._qemu_rootfs_path(execution)
            if not (execution.persistent and getattr(execution, "systemd_manager", None)):
                msg = "Restoring an ephemeral VM is not supported; only persistent QEMU VMs can be restored"
                raise NotImplementedSupervisorError(msg)
            _validate_backup_id(vm_id, backup_id)
            backup_dir = get_backup_directory()
            tar_path = backup_dir / f"{backup_id}.tar"
            if not tar_path.exists():
                raise BackupNotFoundError(backup_id)

            lock = self._backup_locks.setdefault(vm_id, asyncio.Lock())
            async with lock:
                staging = backup_dir / f"{backup_id}.restore.qcow2"
                try:
                    await asyncio.to_thread(_extract_rootfs_member, tar_path, staging)
                    await verify_qemu_disk(staging)
                    old_status = self._status_snapshot(execution)
                    if _is_running(execution, self.pool):
                        await self.pool.stop_vm(vm_id)
                        # Fresh stop_event defuses the pool's forget-on-stop
                        # task; the VM stays registered through the swap (same
                        # trick as stop_vm and reinstall_vm).
                        execution.stop_event = asyncio.Event()
                        self.pool.executions[execution.vm_hash] = execution
                        self._emit_event(vm_id, old_status, VmStatus.STOPPED)
                    await restore_rootfs(staging, rootfs_path)
                    await self.pool.restart_persistent_vm(execution)
                finally:
                    staging.unlink(missing_ok=True)
                info = _to_vm_info(execution, _is_running(execution, self.pool))
                if info.status is not VmStatus.STOPPED:
                    self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info

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
