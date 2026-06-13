"""gRPC client Supervisor: the agent's remote supervisor implementation.

`GrpcSupervisor` implements the `Supervisor` ABC over a Unix-domain-socket
gRPC channel. Errors come back as the closed `SupervisorError` vocabulary:
the precise exception class is rebuilt from the `ErrorDetail` trailer the
server attaches; the gRPC status code is the coarse fallback (a server that
aborted without a trailer still maps to a sensible class).

The channel is created lazily on first use so the object can be constructed
before an event loop exists (e.g. at app wiring time).

Every unary call carries a deadline: gRPC's default is no deadline at all,
so a wedged supervisor would otherwise hang the agent's HTTP handler
forever. Streams (logs, events, backup download) are long-lived by design
and carry none.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import grpc
from google.protobuf.message import Message

from aleph.vm.supervisor import proto_convert as conv
from aleph.vm.supervisor._pb import supervisor_pb2 as pb
from aleph.vm.supervisor._pb import supervisor_pb2_grpc
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    BackupNotFoundError,
    FileTooLargeError,
    HostNotFoundError,
    InsufficientResourcesError,
    InternalSupervisorError,
    InvalidBackendError,
    MicroVMInitError,
    MigrationInProgressError,
    MigrationNotFoundError,
    NotImplementedSupervisorError,
    PortUnavailableError,
    ResourceDownloadError,
    SupervisorError,
    TeeUnavailableError,
    VmAlreadyExistsError,
    VmNotFoundError,
    VmSetupError,
)
from aleph.vm.supervisor.grpc_server import ERROR_TRAILER_KEY
from aleph.vm.supervisor.types import (
    BackupChunk,
    BackupId,
    BackupInfo,
    CreateVmSpec,
    DirectoryPath,
    ErrorCode,
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
    VmEvent,
    VmId,
    VmInfo,
)

logger = logging.getLogger(__name__)

# Deadlines, in seconds. QUERY covers reads and quick host-side mutations
# (port forwarding, journald reads); LIFECYCLE covers operations that boot or
# tear down VMs — bounded by the spec's ready timeout plus VMM overhead, and
# by in-flight run draining on the way down.
QUERY_TIMEOUT_SECS = 30.0
LIFECYCLE_TIMEOUT_SECS = 300.0

ERROR_CLASS_BY_CODE: dict[ErrorCode, type[SupervisorError]] = {
    ErrorCode.VM_NOT_FOUND: VmNotFoundError,
    ErrorCode.VM_ALREADY_EXISTS: VmAlreadyExistsError,
    ErrorCode.INSUFFICIENT_RESOURCES: InsufficientResourcesError,
    ErrorCode.RESOURCE_DOWNLOAD_FAILED: ResourceDownloadError,
    ErrorCode.FILE_TOO_LARGE: FileTooLargeError,
    ErrorCode.VM_SETUP_FAILED: VmSetupError,
    ErrorCode.MICROVM_INIT_FAILED: MicroVMInitError,
    ErrorCode.INVALID_BACKEND: InvalidBackendError,
    ErrorCode.TEE_UNAVAILABLE: TeeUnavailableError,
    ErrorCode.PORT_UNAVAILABLE: PortUnavailableError,
    ErrorCode.HOST_NOT_FOUND: HostNotFoundError,
    ErrorCode.BACKUP_NOT_FOUND: BackupNotFoundError,
    ErrorCode.MIGRATION_IN_PROGRESS: MigrationInProgressError,
    ErrorCode.MIGRATION_NOT_FOUND: MigrationNotFoundError,
    ErrorCode.INTERNAL: InternalSupervisorError,
}

# Coarse fallback when the server attached no ErrorDetail trailer.
ERROR_CLASS_BY_STATUS: dict[grpc.StatusCode, type[SupervisorError]] = {
    grpc.StatusCode.NOT_FOUND: VmNotFoundError,
    grpc.StatusCode.ALREADY_EXISTS: VmAlreadyExistsError,
    grpc.StatusCode.RESOURCE_EXHAUSTED: InsufficientResourcesError,
    grpc.StatusCode.INVALID_ARGUMENT: InvalidBackendError,
    grpc.StatusCode.UNIMPLEMENTED: NotImplementedSupervisorError,
}


def translate_rpc_error(error: grpc.aio.AioRpcError) -> SupervisorError:
    """Rebuild the SupervisorError a server-side abort carried."""
    # UNIMPLEMENTED wins over the trailer: NotImplementedSupervisorError shares
    # the INTERNAL wire code, so only the status code distinguishes it.
    if error.code() == grpc.StatusCode.UNIMPLEMENTED:
        return NotImplementedSupervisorError(error.details() or "")

    metadata = error.trailing_metadata()
    if metadata:
        for key, value in metadata:
            if key == ERROR_TRAILER_KEY:
                detail = pb.ErrorDetail.FromString(value)
                code = conv.ERROR_CODE_FROM_PB.get(detail.code, ErrorCode.INTERNAL)
                return ERROR_CLASS_BY_CODE[code](detail.message)

    error_class = ERROR_CLASS_BY_STATUS.get(error.code(), InternalSupervisorError)
    return error_class(error.details() or "")


class GrpcSupervisor(Supervisor):
    """Supervisor over a UDS gRPC channel (the agent side of the split)."""

    def __init__(self, socket_path: Path | str):
        self._socket_path = str(socket_path)
        self._channel: grpc.aio.Channel | None = None
        self._stub: supervisor_pb2_grpc.SupervisorStub | None = None

    @property
    def socket_path(self) -> str:
        return self._socket_path

    def _ensure_stub(self) -> supervisor_pb2_grpc.SupervisorStub:
        if self._stub is None:
            self._channel = grpc.aio.insecure_channel(f"unix:{self._socket_path}")
            self._stub = supervisor_pb2_grpc.SupervisorStub(self._channel)
        return self._stub

    async def close(self) -> None:
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
            self._stub = None

    async def _unary(self, method: str, request: Message, timeout: float):
        """One unary RPC with a deadline, errors rebuilt class-exact."""
        try:
            return await getattr(self._ensure_stub(), method)(request, timeout=timeout)
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error

    # ── Host ──
    async def health(self) -> HealthInfo:
        return conv.health_info_from_pb(await self._unary("Health", pb.HealthRequest(), QUERY_TIMEOUT_SECS))

    async def get_host_info(self) -> HostInfo:
        return conv.host_info_from_pb(await self._unary("GetHostInfo", pb.GetHostInfoRequest(), QUERY_TIMEOUT_SECS))

    # ── Lifecycle ──
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        reply = await self._unary("CreateVm", conv.create_vm_spec_to_pb(spec), LIFECYCLE_TIMEOUT_SECS)
        return conv.vm_info_from_pb(reply)

    async def get_vm(self, vm_id: VmId) -> VmInfo:
        reply = await self._unary("GetVm", pb.GetVmRequest(vm_id=str(vm_id)), QUERY_TIMEOUT_SECS)
        return conv.vm_info_from_pb(reply)

    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        reply = await self._unary("GetVmSpec", pb.GetVmSpecRequest(vm_id=str(vm_id)), QUERY_TIMEOUT_SECS)
        return conv.create_vm_spec_from_pb(reply)

    async def list_vms(self) -> list[VmInfo]:
        reply = await self._unary("ListVms", pb.ListVmsRequest(), QUERY_TIMEOUT_SECS)
        return [conv.vm_info_from_pb(info) for info in reply.vms]

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        await self._unary("DeleteVm", pb.DeleteVmRequest(vm_id=str(vm_id), wipe=wipe), LIFECYCLE_TIMEOUT_SECS)

    async def stop_vm(self, vm_id: VmId) -> VmInfo:
        reply = await self._unary("StopVm", pb.StopVmRequest(vm_id=str(vm_id)), LIFECYCLE_TIMEOUT_SECS)
        return conv.vm_info_from_pb(reply)

    async def start_vm(self, vm_id: VmId) -> VmInfo:
        reply = await self._unary("StartVm", pb.StartVmRequest(vm_id=str(vm_id)), LIFECYCLE_TIMEOUT_SECS)
        return conv.vm_info_from_pb(reply)

    async def reboot_vm(self, vm_id: VmId) -> VmInfo:
        reply = await self._unary("RebootVm", pb.RebootVmRequest(vm_id=str(vm_id)), LIFECYCLE_TIMEOUT_SECS)
        return conv.vm_info_from_pb(reply)

    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo:
        reply = await self._unary(
            "ReinstallVm",
            pb.ReinstallVmRequest(vm_id=str(vm_id), wipe_volumes=wipe_volumes),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.vm_info_from_pb(reply)

    # ── Port forwarding ──
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        reply = await self._unary("AddPortForward", conv.port_forward_spec_to_pb(spec), QUERY_TIMEOUT_SECS)
        return conv.port_forward_info_from_pb(reply)

    async def remove_port_forward(self, vm_id: VmId, host_port: HostPort, protocol: Protocol) -> None:
        await self._unary(
            "RemovePortForward",
            pb.RemovePortForwardRequest(
                vm_id=str(vm_id), host_port=int(host_port), protocol=conv.PROTOCOL_TO_PB[protocol]
            ),
            QUERY_TIMEOUT_SECS,
        )

    async def list_port_forwards(self, vm_id: VmId | None = None) -> list[PortForwardInfo]:
        reply = await self._unary(
            "ListPortForwards",
            pb.ListPortForwardsRequest(vm_id=str(vm_id) if vm_id is not None else ""),
            QUERY_TIMEOUT_SECS,
        )
        return [conv.port_forward_info_from_pb(info) for info in reply.forwards]

    # ── Events ──
    async def watch_events(self) -> AsyncIterator[VmEvent]:
        call = self._ensure_stub().WatchEvents(pb.WatchEventsRequest())
        try:
            async for msg in call:
                yield conv.vm_event_from_pb(msg)
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        finally:
            call.cancel()

    # ── Logs ──
    async def get_logs(self, vm_id: VmId, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        reply = await self._unary(
            "GetLogs",
            pb.GetLogsRequest(vm_id=str(vm_id), max_lines=max_lines, from_tail=from_tail),
            QUERY_TIMEOUT_SECS,
        )
        return [conv.log_chunk_from_pb(chunk) for chunk in reply.lines]

    async def stream_logs(self, vm_id: VmId, include_history: bool = False) -> AsyncIterator[LogChunk]:
        call = self._ensure_stub().StreamLogs(pb.StreamLogsRequest(vm_id=str(vm_id), include_history=include_history))
        try:
            async for chunk in call:
                yield conv.log_chunk_from_pb(chunk)
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        finally:
            call.cancel()

    # ── Backups ──
    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False) -> BackupInfo:
        reply = await self._unary(
            "StartBackup",
            pb.StartBackupRequest(vm_id=str(vm_id), quiesce_guest=quiesce_guest),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.backup_info_from_pb(reply)

    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo:
        reply = await self._unary(
            "GetBackupStatus",
            pb.GetBackupStatusRequest(vm_id=str(vm_id), backup_id=str(backup_id)),
            QUERY_TIMEOUT_SECS,
        )
        return conv.backup_info_from_pb(reply)

    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]:
        reply = await self._unary(
            "ListBackups",
            pb.ListBackupsRequest(vm_id=str(vm_id) if vm_id is not None else ""),
            QUERY_TIMEOUT_SECS,
        )
        return [conv.backup_info_from_pb(info) for info in reply.backups]

    async def download_backup(self, vm_id: VmId, backup_id: BackupId) -> AsyncIterator[BackupChunk]:
        call = self._ensure_stub().DownloadBackup(pb.DownloadBackupRequest(vm_id=str(vm_id), backup_id=str(backup_id)))
        try:
            async for chunk in call:
                yield conv.backup_chunk_from_pb(chunk)
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        finally:
            call.cancel()

    async def delete_backup(self, vm_id: VmId, backup_id: BackupId) -> None:
        await self._unary(
            "DeleteBackup",
            pb.DeleteBackupRequest(vm_id=str(vm_id), backup_id=str(backup_id)),
            QUERY_TIMEOUT_SECS,
        )

    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo:
        reply = await self._unary(
            "RestoreBackup",
            pb.RestoreBackupRequest(vm_id=str(vm_id), backup_id=str(backup_id)),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.vm_info_from_pb(reply)

    # ── Migration ──
    async def export_vm(self, vm_id: VmId, destination_dir: DirectoryPath) -> MigrationInfo:
        reply = await self._unary(
            "ExportVm",
            pb.ExportVmRequest(vm_id=str(vm_id), destination_dir=str(destination_dir)),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.migration_info_from_pb(reply)

    async def import_vm(self, vm_id: VmId, source_dir: DirectoryPath) -> VmInfo:
        reply = await self._unary(
            "ImportVm",
            pb.ImportVmRequest(vm_id=str(vm_id), source_dir=str(source_dir)),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.vm_info_from_pb(reply)

    async def get_migration_status(self, vm_id: VmId, migration_id: MigrationId) -> MigrationInfo:
        reply = await self._unary(
            "GetMigrationStatus",
            pb.GetMigrationStatusRequest(vm_id=str(vm_id), migration_id=str(migration_id)),
            QUERY_TIMEOUT_SECS,
        )
        return conv.migration_info_from_pb(reply)

    # ── Confidential ──
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None:
        await self._unary(
            "InitializeConfidential",
            pb.InitializeConfidentialRequest(vm_id=str(vm_id), session_bytes=session_bytes, godh_bytes=godh_bytes),
            LIFECYCLE_TIMEOUT_SECS,
        )

    async def get_measurement(self, vm_id: VmId) -> Measurement:
        reply = await self._unary("GetMeasurement", pb.GetMeasurementRequest(vm_id=str(vm_id)), LIFECYCLE_TIMEOUT_SECS)
        return conv.measurement_from_pb(reply)

    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        await self._unary(
            "InjectSecret",
            pb.InjectSecretRequest(
                vm_id=str(vm_id), secret_header_bytes=secret_header_bytes, secret_bytes=secret_bytes
            ),
            LIFECYCLE_TIMEOUT_SECS,
        )
