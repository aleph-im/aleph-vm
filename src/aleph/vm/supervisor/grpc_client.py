"""gRPC client Supervisor: the agent's remote supervisor implementation.

`GrpcSupervisor` implements the `Supervisor` ABC over a Unix-domain-socket
gRPC channel. Errors come back as the closed `SupervisorError` vocabulary:
the precise exception class is rebuilt from the `ErrorDetail` trailer the
server attaches; the gRPC status code is the coarse fallback (a server that
aborted without a trailer still maps to a sensible class).

The channel is created lazily on first use so the object can be constructed
before an event loop exists (e.g. at app wiring time).
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path

import grpc

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

    # ── Host ──
    async def health(self) -> HealthInfo:
        try:
            reply = await self._ensure_stub().Health(pb.HealthRequest())
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.health_info_from_pb(reply)

    async def get_host_info(self) -> HostInfo:
        try:
            reply = await self._ensure_stub().GetHostInfo(pb.GetHostInfoRequest())
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.host_info_from_pb(reply)

    # ── Lifecycle ──
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        try:
            reply = await self._ensure_stub().CreateVm(conv.create_vm_spec_to_pb(spec))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def get_vm(self, vm_id: VmId) -> VmInfo:
        try:
            reply = await self._ensure_stub().GetVm(pb.GetVmRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        try:
            reply = await self._ensure_stub().GetVmSpec(pb.GetVmSpecRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.create_vm_spec_from_pb(reply)

    async def list_vms(self) -> list[VmInfo]:
        try:
            reply = await self._ensure_stub().ListVms(pb.ListVmsRequest())
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return [conv.vm_info_from_pb(info) for info in reply.vms]

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        try:
            await self._ensure_stub().DeleteVm(pb.DeleteVmRequest(vm_id=str(vm_id), wipe=wipe))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error

    async def stop_vm(self, vm_id: VmId) -> VmInfo:
        try:
            reply = await self._ensure_stub().StopVm(pb.StopVmRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def start_vm(self, vm_id: VmId) -> VmInfo:
        try:
            reply = await self._ensure_stub().StartVm(pb.StartVmRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def reboot_vm(self, vm_id: VmId) -> VmInfo:
        try:
            reply = await self._ensure_stub().RebootVm(pb.RebootVmRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo:
        try:
            reply = await self._ensure_stub().ReinstallVm(
                pb.ReinstallVmRequest(vm_id=str(vm_id), wipe_volumes=wipe_volumes)
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    # ── Port forwarding ──
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        try:
            reply = await self._ensure_stub().AddPortForward(conv.port_forward_spec_to_pb(spec))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.port_forward_info_from_pb(reply)

    async def remove_port_forward(self, vm_id: VmId, host_port: HostPort, protocol: Protocol) -> None:
        try:
            await self._ensure_stub().RemovePortForward(
                pb.RemovePortForwardRequest(
                    vm_id=str(vm_id), host_port=int(host_port), protocol=conv.PROTOCOL_TO_PB[protocol]
                )
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error

    async def list_port_forwards(self, vm_id: VmId | None = None) -> list[PortForwardInfo]:
        try:
            reply = await self._ensure_stub().ListPortForwards(
                pb.ListPortForwardsRequest(vm_id=str(vm_id) if vm_id is not None else "")
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
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
        try:
            reply = await self._ensure_stub().GetLogs(
                pb.GetLogsRequest(vm_id=str(vm_id), max_lines=max_lines, from_tail=from_tail)
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
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
        try:
            reply = await self._ensure_stub().StartBackup(
                pb.StartBackupRequest(vm_id=str(vm_id), quiesce_guest=quiesce_guest)
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.backup_info_from_pb(reply)

    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo:
        try:
            reply = await self._ensure_stub().GetBackupStatus(
                pb.GetBackupStatusRequest(vm_id=str(vm_id), backup_id=str(backup_id))
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.backup_info_from_pb(reply)

    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]:
        try:
            reply = await self._ensure_stub().ListBackups(
                pb.ListBackupsRequest(vm_id=str(vm_id) if vm_id is not None else "")
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
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
        try:
            await self._ensure_stub().DeleteBackup(pb.DeleteBackupRequest(vm_id=str(vm_id), backup_id=str(backup_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error

    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo:
        try:
            reply = await self._ensure_stub().RestoreBackup(
                pb.RestoreBackupRequest(vm_id=str(vm_id), backup_id=str(backup_id))
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    # ── Migration ──
    async def export_vm(self, vm_id: VmId, destination_dir: DirectoryPath) -> MigrationInfo:
        try:
            reply = await self._ensure_stub().ExportVm(
                pb.ExportVmRequest(vm_id=str(vm_id), destination_dir=str(destination_dir))
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.migration_info_from_pb(reply)

    async def import_vm(self, vm_id: VmId, source_dir: DirectoryPath) -> VmInfo:
        try:
            reply = await self._ensure_stub().ImportVm(pb.ImportVmRequest(vm_id=str(vm_id), source_dir=str(source_dir)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.vm_info_from_pb(reply)

    async def get_migration_status(self, vm_id: VmId, migration_id: MigrationId) -> MigrationInfo:
        try:
            reply = await self._ensure_stub().GetMigrationStatus(
                pb.GetMigrationStatusRequest(vm_id=str(vm_id), migration_id=str(migration_id))
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.migration_info_from_pb(reply)

    # ── Confidential ──
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None:
        try:
            await self._ensure_stub().InitializeConfidential(
                pb.InitializeConfidentialRequest(vm_id=str(vm_id), session_bytes=session_bytes, godh_bytes=godh_bytes)
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error

    async def get_measurement(self, vm_id: VmId) -> Measurement:
        try:
            reply = await self._ensure_stub().GetMeasurement(pb.GetMeasurementRequest(vm_id=str(vm_id)))
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
        return conv.measurement_from_pb(reply)

    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None:
        try:
            await self._ensure_stub().InjectSecret(
                pb.InjectSecretRequest(
                    vm_id=str(vm_id), secret_header_bytes=secret_header_bytes, secret_bytes=secret_bytes
                )
            )
        except grpc.aio.AioRpcError as error:
            raise translate_rpc_error(error) from error
