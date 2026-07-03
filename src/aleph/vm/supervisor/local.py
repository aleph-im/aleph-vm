"""Local Supervisor: the pool-backed engine that wraps today's VmPool / VmExecution.

This is the embedded engine that runs in the same process as the agent
(dev/tests and Phase 1 production). It does all the real VM work behind the
`Supervisor` interface, driving the local `VmPool` directly. Methods not yet
implemented raise NotImplementedSupervisorError.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import tarfile
import time
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import psutil
from aleph_message.models.execution.environment import AMDSEVPolicy

from aleph.vm.conf import settings
from aleph.vm.network.firewall import (
    initialize_nftables,
    recreate_network_for_vms,
    remove_all_aleph_chains,
)
from aleph.vm.supervisor.controllers.qemu.backup import (
    InsufficientDiskSpaceError,
    backup_metadata,
    check_disk_space_for_multiple,
    cleanup_expired_backups,
    create_backup_archive,
    create_qemu_disk_backup,
    find_existing_backup,
    get_backup_directory,
    get_qemu_disk_virtual_size,
    restore_rootfs,
    verify_qemu_disk,
)
from aleph.vm.supervisor.controllers.qemu.client import QemuVmClient
from aleph.vm.supervisor.error_mapping import translating_errors
from aleph.vm.supervisor.networking_db import delete_port_mappings, get_port_mappings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.configuration import remove_controller_configuration
from aleph.vm.supervisor_interface.errors import (
    BackupNotFoundError,
    InsufficientResourcesError,
    InternalSupervisorError,
    InvalidBackendError,
    NotImplementedSupervisorError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
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
    PciAddress,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    ReservationRequest,
    SevInfo,
    TeeBackend,
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
    if execution.is_program:
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
    for vm_id, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            persistent_services[execution.controller_service] = str(vm_id)

    service_states: dict[str, bool] = {}
    if persistent_services and getattr(pool, "systemd_manager", None):
        service_states = pool.systemd_manager.get_services_active_states(list(persistent_services.keys()))

    states: dict[str, bool] = {}
    for vm_id, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            states[str(vm_id)] = service_states.get(execution.controller_service, False)
        else:
            times = execution.times
            states[str(vm_id)] = bool(times.starting_at and not times.stopping_at)
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


async def _run_code_over_channel(channel_path: str, scope: dict, *, timeout: float) -> bytes:
    """Run one request over a program VM's guest channel and return the raw reply.

    The engine half of program serving: the same CONNECT <RUNTIME_CONTROL_PORT>
    wire exchange the agent's ProgramGuestClient.run_code performs, but driven
    from the supervisor process which owns the VM's guest channel UDS. Used by
    persistent programs (the agent cannot reach the channel across the boundary).
    """
    from aleph.vm.program_config import RunCodePayload, VmInitNotConnectedError
    from aleph.vm.utils.runtime_channel import RUNTIME_CONTROL_PORT

    async def communicate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
        payload = RunCodePayload(scope=scope)
        writer.write(f"CONNECT {RUNTIME_CONTROL_PORT}\n".encode() + payload.as_msgpack())
        await writer.drain()
        await reader.readline()  # ack
        return await reader.read()

    try:
        reader, writer = await asyncio.open_unix_connection(path=channel_path)
    except (ConnectionRefusedError, FileNotFoundError) as error:
        raise VmInitNotConnectedError("MicroVM may have crashed") from error
    try:
        return await asyncio.wait_for(communicate(reader, writer), timeout=timeout)
    finally:
        writer.close()
        await writer.wait_closed()


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
        vm_id=VmId(str(execution.vm_id)),
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
        awaiting_confidential_init=bool(execution.is_awaiting_confidential_init),
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


# The rootfs archive member, always present in a backup. With include_volumes
# the VM's non-read-only persistent volumes are added alongside it (named by
# their on-disk basename). restore_backup replaces only the rootfs member; the
# extra volumes are carried for the operator's own use (download/restore).
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
    try:
        # checksum/source_sizes come from the sidecars; volumes is read from
        # the archive index. A corrupt or non-tar file (e.g. a partial write)
        # still yields a usable BackupInfo, just without the archive metadata.
        meta = backup_metadata(tar_path)
    except (tarfile.TarError, OSError):
        logger.warning("Could not read backup metadata for %s", tar_path.name)
        meta = {}
    return BackupInfo(
        vm_id=vm_id,
        backup_id=BackupId(tar_path.stem),
        status=BackupStatus.COMPLETE,
        size_bytes=stat.st_size,
        created_at_unix_secs=int(stat.st_mtime),
        error_message="",
        checksum=meta.get("checksum", ""),
        volumes=list(meta.get("volumes", [])),
        source_sizes=dict(meta.get("source_sizes", {})),
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


class LocalSupervisor(Supervisor):
    def __init__(self, pool: VmPool):
        self.pool = pool
        # Live watch_events subscribers; events are fan-out, no replay.
        self._event_queues: set[asyncio.Queue[VmEvent]] = set()
        # Backup bookkeeping. Completed archives live on disk (the source of
        # truth); _backup_jobs only holds in-flight and failed runs.
        self._backup_jobs: dict[BackupId, BackupInfo] = {}
        self._backup_tasks: dict[VmId, asyncio.Task] = {}
        # Serializes backup and restore per VM: neither may touch the disks
        # while the other one converts or swaps them.
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
            # Rich GPU inventory (vendor / device_name / device_class) the
            # public usage endpoint exposes. Raw hardware only: the agent
            # annotates model / compatible from the settings aggregate.
            # Carried as plain dicts so the boundary stays GpuDevice-agnostic.
            inventory = [gpu.model_dump() for gpu in getattr(self.pool, "gpus", None) or []]
            get_available = getattr(self.pool, "get_available_gpus", None)
            available_gpus = [gpu.model_dump() for gpu in get_available()] if get_available else []
            calc_disk = getattr(self.pool, "calculate_available_disk", None)
            available_disk_bytes = calc_disk() if calc_disk else 0
            return HostInfo(
                cpu_count=os.cpu_count() or 0,
                memory_mib=int(psutil.virtual_memory().total / (1024 * 1024)),
                kernel_version=os.uname().release,
                hostname=os.uname().nodename,
                host_ipv4=network.host_ipv4 if network else "",
                available_disk_bytes=available_disk_bytes,
                gpu_inventory=inventory,
                available_gpus=available_gpus,
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
            # Off the event loop: _running_states issues a single batched D-Bus
            # ListUnits() call. Keeping it on the loop would stall every caller
            # (the payment sweep and every /about/executions/list request) for
            # the duration of that call. Mirrors main's monitor_payments fix
            # (aleph-vm#963), and applies it to the list endpoints too.
            running = await asyncio.to_thread(_running_states, self.pool)
            return [_to_vm_info(execution, running[str(vm_id)]) for vm_id, execution in self.pool.executions.items()]

    def _require(self, vm_id: VmId):
        execution = self.pool.executions.get(vm_id)
        if execution is None:
            raise VmNotFoundError(vm_id)
        return execution

    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        with translating_errors():
            execution = self._require(vm_id)
            return execution.vm_spec

    async def delete_vm(self, vm_id: VmId, wipe: bool = False, keep_port_mappings: bool = False) -> None:
        with translating_errors():
            execution = self.pool.executions.get(vm_id)
            if execution is None:
                # Not tracked, but possibly queued (or given up) for reattach
                # retry: its controller is still running. Honor the delete by
                # stopping that controller and dequeuing it; raising
                # VmNotFoundError here would make the agent forget the VM
                # while the retry loop resurrects it as an unmanageable,
                # still-billed instance.
                if await self.pool.discard_failed_reattach(vm_id):
                    logger.info("Deleted queued failed-reattach VM %s (untracked controller stopped)", vm_id)
                    return
                raise VmNotFoundError(vm_id)
            old_status = self._status_snapshot(execution)
            await self.pool.stop_vm(vm_id)
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
            if execution.vm_id in self.pool.executions:
                # Routine: the pool's _schedule_forget_on_stop task has usually
                # not run yet by the time stop_vm returns, so delete_vm wins
                # this race on most reaps.
                logger.debug("VM %s was not removed from pool after stop; forgetting it now", vm_id)
                self.pool.forget_vm(vm_id)
            # Delete releases the definition: the controller config and the
            # cloud-init seed go too (stop_vm keeps them for reattach).
            remove_controller_configuration(str(vm_id))
            # The VM is gone, so its persisted port mappings normally go too:
            # a delete is final unless the caller says otherwise. Delete+recreate
            # cycles (crash recovery, message updates) pass keep_port_mappings=True
            # so the recreated VM reloads the same host ports; wipe overrides it
            # (an erase is always final). Port mappings are hypervisor-owned state,
            # so this lives here rather than as a residual direct DB call
            # agent-side. Note: VmExecution.record_usage (models.py) also deletes
            # the mappings of non-persistent VMs on stop; keep both sites in sync.
            if wipe or not keep_port_mappings:
                await delete_port_mappings(execution.vm_id)
            if wipe:
                # Mirrors the old operate_erase semantics: writable data volumes
                # go, the rootfs stays.
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
            self.pool.executions[execution.vm_id] = execution
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
                # RestartUnit only queues a job: wait until the unit is
                # confirmed active so the reported status is truthful.
                await execution.wait_for_controller_ready()
                execution.times.started_at = datetime.now(tz=timezone.utc)
                info = _to_vm_info(execution, _is_running(execution, self.pool))
                # A reboot is a down-then-up pair; watchers that drop per-VM
                # state on "down" must see the down.
                self._emit_event(vm_id, old_status, VmStatus.STOPPED)
                self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info
            spec = execution.vm_spec
            await self.pool.stop_vm(vm_id)
            if execution.vm_id in self.pool.executions:
                self.pool.forget_vm(vm_id)
            self._emit_event(vm_id, old_status, VmStatus.STOPPED)
            # A real reboot: the supervisor holds the spec, so it can
            # recreate the VM itself instead of returning a stopped husk
            # and expecting the client to know it must re-create.
            new_execution = await self.pool.create_vm_from_spec(spec)
            info = _to_vm_info(new_execution, _is_running(new_execution, self.pool))
            self._emit_event(vm_id, VmStatus.STOPPED, info.status)
            return info

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
                self.pool.executions[execution.vm_id] = execution
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                execution.resources = None
                await execution.prepare()
                await self.pool.restart_persistent_vm(execution)
            else:
                if execution.vm_id in self.pool.executions:
                    self.pool.forget_vm(execution.vm_id)
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                # The agent re-creates non-persistent VMs through the create
                # path (it owns the message); we return the stopped state.
            info = _to_vm_info(execution, _is_running(execution, self.pool))
            if info.status is not VmStatus.STOPPED:
                self._emit_event(vm_id, VmStatus.STOPPED, info.status)
            return info

    async def run_program_code(self, vm_id: VmId, scope: dict, *, timeout: float) -> bytes:
        """Serve one request inside a persistent program VM over its guest channel.

        Blocks until the execution reports ready, then runs the code over the
        VM's guest channel UDS. The pool-backed VmExecution for a spec program is
        a SpecFirecrackerProgram (no message-coupled run_code of its own), so the
        engine drives the runtime channel directly here.
        """
        with translating_errors():
            execution = self._require(vm_id)
            if not execution.is_program:
                msg = f"VM {vm_id} is not a program; code can only be run on programs"
                raise InvalidBackendError(msg)
            await execution.becomes_ready()
            channel_path = _guest_channel_path(execution)
            if not channel_path:
                msg = f"VM {vm_id} exposes no guest channel; cannot run program code"
                raise InternalSupervisorError(msg)
            return await _run_code_over_channel(channel_path, scope, timeout=timeout)

    # Port forwarding
    def _mapped_to_infos(self, execution) -> list[PortForwardInfo]:
        infos: list[PortForwardInfo] = []
        for vm_port, mapping in execution.mapped_ports.items():
            for proto in (Protocol.TCP, Protocol.UDP):
                if mapping.get(proto.value):
                    infos.append(
                        PortForwardInfo(
                            vm_id=VmId(str(execution.vm_id)),
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
            msg = f"VM {execution.vm_id} has no rootfs disk image"
            raise InternalSupervisorError(msg)
        return Path(rootfs_path)

    def _backup_disk_paths(self, execution, include_volumes: bool) -> dict[str, Path]:
        """The archive members for a backup: the rootfs, plus the VM's
        non-read-only persistent volumes when include_volumes is set. The
        member name is the disk's basename stem with a .qcow2 suffix; the
        rootfs is always 'rootfs.qcow2'."""
        disk_paths: dict[str, Path] = {_BACKUP_ROOTFS_MEMBER: self._qemu_rootfs_path(execution)}
        if not include_volumes:
            return disk_paths
        resources = getattr(execution, "resources", None)
        volumes = getattr(resources, "volumes", None) or []
        for vol in volumes:
            if getattr(vol, "read_only", False):
                continue
            vol_path = Path(vol.path_on_host)
            disk_paths[vol_path.stem + ".qcow2"] = vol_path
        return disk_paths

    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False, include_volumes: bool = False) -> BackupInfo:
        with translating_errors():
            execution = self._require(vm_id)
            disk_paths = self._backup_disk_paths(execution, include_volumes)
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
                await check_disk_space_for_multiple(list(disk_paths.values()), backup_dir)
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
                self._run_backup(execution, vm_id, backup_id, timestamp, disk_paths, backup_dir, quiesce_guest)
            )
            return job

    async def _run_backup(
        self,
        execution,
        vm_id: VmId,
        backup_id: BackupId,
        timestamp: str,
        disk_paths: dict[str, Path],
        backup_dir: Path,
        quiesce_guest: bool,
    ) -> None:
        lock = self._backup_locks.setdefault(vm_id, asyncio.Lock())
        disk_backups: list[Path] = []
        try:
            async with lock:
                client = None
                frozen = False
                if quiesce_guest and _is_running(execution, self.pool):
                    client, frozen = await self._try_fsfreeze(execution)
                backup_files: dict[str, Path] = {}
                try:
                    for member_name, source_path in disk_paths.items():
                        disk_backup = await create_qemu_disk_backup(str(vm_id), source_path, backup_dir)
                        disk_backups.append(disk_backup)
                        backup_files[member_name] = disk_backup
                finally:
                    if frozen and client is not None:
                        await self._try_fsthaw(client, vm_id)
                for disk_backup in disk_backups:
                    await verify_qemu_disk(disk_backup)
                await create_backup_archive(
                    vm_hash=str(vm_id),
                    backup_files=backup_files,
                    destination_dir=backup_dir,
                    source_sizes={name: src.stat().st_size for name, src in disk_paths.items()},
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
            for disk_backup in disk_backups:
                disk_backup.unlink(missing_ok=True)
            self._backup_tasks.pop(vm_id, None)

    async def _try_fsfreeze(self, execution):
        """Best-effort guest fs-freeze through the QEMU guest agent; the
        backup proceeds unfrozen when the agent is unavailable."""
        from aleph.vm.supervisor.controllers.qemu.client import QemuVmClient

        try:
            client = QemuVmClient(execution.vm)
            frozen = await asyncio.wait_for(client.guest_fsfreeze_freeze(), timeout=30)
            logger.info("Froze %s filesystem(s) for %s", frozen, execution.vm_id)
            return client, True
        except Exception as exc:
            logger.warning("fsfreeze unavailable for %s, proceeding without: %s", execution.vm_id, exc)
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
                        self.pool.executions[execution.vm_id] = execution
                        self._emit_event(vm_id, old_status, VmStatus.STOPPED)
                    await restore_rootfs(staging, rootfs_path)
                    await self.pool.restart_persistent_vm(execution)
                finally:
                    staging.unlink(missing_ok=True)
                info = _to_vm_info(execution, _is_running(execution, self.pool))
                if info.status is not VmStatus.STOPPED:
                    self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info

    async def restore_from_image(
        self, vm_id: VmId, image_path: DirectoryPath, max_virtual_size_bytes: int = 0
    ) -> VmInfo:
        """Restore the rootfs from a QCOW2 image already staged on a host path.

        The agent stages the uploaded image (or the downloaded volume) to
        image_path, then hands the disk/VM work here: validate the image,
        reject one larger than max_virtual_size_bytes (a restore must not grow
        the disk), swap it in for the current rootfs and restart the VM.
        """
        with translating_errors():
            execution = self._require(vm_id)
            rootfs_path = self._qemu_rootfs_path(execution)
            if not (execution.persistent and getattr(execution, "systemd_manager", None)):
                msg = "Restoring an ephemeral VM is not supported; only persistent QEMU VMs can be restored"
                raise NotImplementedSupervisorError(msg)

            image = Path(image_path)
            if not image.exists():
                raise InternalSupervisorError(f"staged restore image {image} does not exist")

            # qemu-img rejects anything that is not a valid QCOW2 image with a
            # non-zero exit code. That is a client error (a bad upload), so map
            # it to InvalidBackendError; the agent turns that into a 400. A bare
            # CalledProcessError would translate to InternalSupervisorError -> 500.
            try:
                await verify_qemu_disk(image)
            except subprocess.CalledProcessError as exc:
                raise InvalidBackendError(f"Restore image {image.name} is not a valid QCOW2 disk") from exc
            if max_virtual_size_bytes:
                new_size = await get_qemu_disk_virtual_size(image)
                if new_size > max_virtual_size_bytes:
                    msg = (
                        f"New rootfs virtual size ({new_size} bytes) exceeds the declared rootfs size "
                        f"({max_virtual_size_bytes} bytes). Restore cannot increase disk size."
                    )
                    raise InvalidBackendError(msg)

            lock = self._backup_locks.setdefault(vm_id, asyncio.Lock())
            async with lock:
                old_status = self._status_snapshot(execution)
                if _is_running(execution, self.pool):
                    await self.pool.stop_vm(vm_id)
                    # Fresh stop_event defuses the pool's forget-on-stop task;
                    # the VM stays registered through the swap.
                    execution.stop_event = asyncio.Event()
                    self.pool.executions[execution.vm_id] = execution
                    self._emit_event(vm_id, old_status, VmStatus.STOPPED)
                await restore_rootfs(image, rootfs_path)
                await self.pool.restart_persistent_vm(execution)
                info = _to_vm_info(execution, _is_running(execution, self.pool))
                if info.status is not VmStatus.STOPPED:
                    self._emit_event(vm_id, VmStatus.STOPPED, info.status)
                return info

    # ── Migration ──
    #
    # Migration rides the standard lifecycle RPCs entirely: the agent stages and
    # rebases the disks, then drives create_vm / stop_vm / start_vm / delete_vm.
    # The export-time stop is a plain stop_vm: it stops the controller unit and
    # blocks until the guest has ACPI-powered down and QEMU has flushed its disk
    # caches, so the exported overlay is consistent with no extra step.

    # Confidential
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None:
        """Persist the owner's SEV session certificates and start the VM.

        Writes vm_session.b64 / vm_godh.b64 under the per-VM confidential
        session directory, then enables and starts the controller service so
        the guest reaches the launch-secret state (same steps the old
        operate_confidential_initialize endpoint performed)."""
        with translating_errors():
            execution = self._require(vm_id)
            session_dir = settings.CONFIDENTIAL_SESSION_DIRECTORY / str(vm_id)
            session_dir.mkdir(parents=True, exist_ok=True)
            (session_dir / "vm_session.b64").write_bytes(session_bytes)
            (session_dir / "vm_godh.b64").write_bytes(godh_bytes)
            await self.pool.systemd_manager.enable_and_start(execution.controller_service)

    async def get_measurement(self, vm_id: VmId) -> Measurement:
        """The SEV launch measurement plus the platform state the owner needs
        to verify it before injecting the secret."""
        with translating_errors():
            execution = self._require(vm_id)
            client = QemuVmClient(execution.vm)
            try:
                sev_info = client.query_sev_info()
                launch_measure = client.query_launch_measure()
            finally:
                client.close()
            # The TEE generation comes from the VM's confidential config (an
            # input the supervisor holds), not a hardcoded value. TeeBackend.SEV
            # covers SEV and SEV-ES (the client refines via sev_info.policy);
            # SEV-SNP is a distinct launch path.
            mode = _confidential_mode(execution)
            tee_backend = TeeBackend.SEV_SNP if mode is ConfidentialMode.SEV_SNP else TeeBackend.SEV
            return Measurement(
                vm_id=vm_id,
                measurement_bytes=b"",
                tee_backend=tee_backend,
                sev_info=SevInfo(
                    enabled=sev_info.enabled,
                    api_major=sev_info.api_major,
                    api_minor=sev_info.api_minor,
                    build_id=sev_info.build_id,
                    policy=sev_info.policy,
                    state=sev_info.state,
                    handle=sev_info.handle,
                ),
                launch_measure=launch_measure,
            )

    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        """Inject the encrypted secret into the SEV secret area and resume the
        guest. The header and secret cross the boundary as bytes; QEMU's
        QMP command takes the base64 strings."""
        with translating_errors():
            execution = self._require(vm_id)
            client = QemuVmClient(execution.vm)
            try:
                client.inject_secret(secret_header_bytes.decode(), secret_bytes.decode())
                client.continue_execution()
            finally:
                client.close()

    # Network
    async def recreate_network(self) -> dict:
        """Flush and rebuild the host firewall for the running local VMs.

        Removes every aleph-related nftables chain, re-initializes the base
        ruleset, recreates the per-VM chains for the currently running VMs and
        reapplies their persisted port-redirect rules. Returns a summary dict.
        """
        logger.info("Starting network recreation process")

        # Step 1: Collect all running VMs and their network configuration
        running_vms = []
        for vm_id, execution in self.pool.executions.items():
            if execution.is_running and execution.vm and execution.vm.tap_interface:
                running_vms.append(
                    {
                        "vm_hash": vm_id,
                        "vm_index": execution.vm.vm_index,
                        "tap_interface": execution.vm.tap_interface,
                        "execution": execution,
                    }
                )
                logger.debug(f"Found running VM {vm_id} with vm_index={execution.vm.vm_index}")

        logger.info(f"Found {len(running_vms)} running VMs to recreate network rules for")

        # Step 2: Remove all aleph-related chains (VM-specific and supervisor chains)
        try:
            removed_chains, failed_removals = remove_all_aleph_chains()
            if failed_removals:
                logger.warning(f"Failed to remove {len(failed_removals)} chains")
                for chain_name, error in failed_removals:
                    logger.warning(f"  - {chain_name}: {error}")
        except Exception as e:
            raise InternalSupervisorError(f"Failed to remove existing chains: {e!s}") from e

        # Step 3: Re-initialize the base network setup
        logger.info("Re-initializing nftables")
        try:
            initialize_nftables()
        except Exception as e:
            raise InternalSupervisorError(f"Failed to initialize network: {e!s}") from e

        # Step 4: Recreate VM-specific chains and rules
        try:
            recreated_vms, failed_vms = recreate_network_for_vms(running_vms)
        except Exception as e:
            raise InternalSupervisorError(f"Failed to recreate VM networks: {e!s}") from e

        # Step 5: Recreate port forwarding rules for instances
        logger.info("Recreating port forwarding rules for instances")
        for vm_info in running_vms:
            execution = vm_info["execution"]
            if execution.is_instance and str(vm_info["vm_hash"]) in recreated_vms:
                try:
                    # All rules were flushed: reapply from the persisted
                    # mappings, then re-sync message-driven VMs against the
                    # aggregate. Spec-built (reattached) executions have no
                    # message; their persisted mappings are authoritative.
                    execution.mapped_ports = await get_port_mappings(str(vm_info["vm_hash"]))
                    if execution.mapped_ports:
                        await execution.recreate_port_redirect_rules()
                    logger.debug(f"Recreated port redirects for instance {vm_info['vm_hash']}")
                except Exception as e:
                    logger.error(f"Error recreating port redirects for VM {vm_info['vm_hash']}: {e}")
                    # Don't add to failed_vms as the VM network itself was created successfully

        logger.info(
            f"Network recreation complete. Removed chains: {len(removed_chains)}, "
            f"Recreated VMs: {len(recreated_vms)}, Failed: {len(failed_vms)}"
        )

        return {
            "success": len(failed_vms) == 0,
            "removed_chains_count": len(removed_chains),
            "removed_chains": removed_chains,
            "recreated_count": len(recreated_vms),
            "failed_count": len(failed_vms),
            "recreated_vms": recreated_vms,
            "failed_vms": failed_vms,
        }

    # ── Reservation ──
    async def reserve_resources(self, request: ReservationRequest) -> datetime:
        """Run capacity admission, then hold the requested resources for the user.

        ``request`` is a message-free resources DTO the agent built from the
        Aleph message: check_capacity keeps the dry-run honest (refuse here
        rather than let the client pay and be rejected by notify_allocation),
        then reserve_gpus holds the GPUs and returns the reservation expiry.
        """
        with translating_errors():
            self.pool.check_capacity(
                memory_mib=request.memory_mib,
                vcpus=request.vcpus,
                disk_mib=request.disk_mib,
                is_instance=request.is_instance,
            )
            return await self.pool.reserve_gpus(request.gpus, request.owner_id)
