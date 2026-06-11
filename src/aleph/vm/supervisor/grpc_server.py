"""gRPC server exposing a Supervisor over the wire contract.

Wraps any `Supervisor` implementation (the `InProcessSupervisor` in the
daemon) behind `proto/supervisor.proto`. Errors cross the boundary as the
closed `ErrorCode` vocabulary: every `SupervisorError` aborts the RPC with a
mapped `grpc.StatusCode` and a serialized `ErrorDetail` in the
`aleph-supervisor-error-bin` trailing metadata; the client reconstructs the
exact exception class from the trailer.
"""

from __future__ import annotations

import functools
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from pathlib import Path
from typing import TypeVar

import grpc

from aleph.vm.supervisor import proto_convert as conv
from aleph.vm.supervisor._pb import supervisor_pb2 as pb
from aleph.vm.supervisor._pb import supervisor_pb2_grpc
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    NotImplementedSupervisorError,
    SupervisorError,
    translate_exception,
)
from aleph.vm.supervisor.types import (
    BackupId,
    DirectoryPath,
    ErrorCode,
    HostPort,
    MigrationId,
    VmId,
)

logger = logging.getLogger(__name__)

ERROR_TRAILER_KEY = "aleph-supervisor-error-bin"

# Wire status for each error code. The trailer carries the precise code; the
# status code is the coarse fallback for clients that do not read the trailer.
STATUS_CODE_BY_ERROR = {
    ErrorCode.VM_NOT_FOUND: grpc.StatusCode.NOT_FOUND,
    ErrorCode.BACKUP_NOT_FOUND: grpc.StatusCode.NOT_FOUND,
    ErrorCode.HOST_NOT_FOUND: grpc.StatusCode.NOT_FOUND,
    ErrorCode.VM_ALREADY_EXISTS: grpc.StatusCode.ALREADY_EXISTS,
    ErrorCode.INSUFFICIENT_RESOURCES: grpc.StatusCode.RESOURCE_EXHAUSTED,
    ErrorCode.INVALID_BACKEND: grpc.StatusCode.INVALID_ARGUMENT,
    ErrorCode.FILE_TOO_LARGE: grpc.StatusCode.INVALID_ARGUMENT,
    ErrorCode.PORT_UNAVAILABLE: grpc.StatusCode.FAILED_PRECONDITION,
    ErrorCode.TEE_UNAVAILABLE: grpc.StatusCode.FAILED_PRECONDITION,
    ErrorCode.MIGRATION_IN_PROGRESS: grpc.StatusCode.FAILED_PRECONDITION,
    ErrorCode.RESOURCE_DOWNLOAD_FAILED: grpc.StatusCode.INTERNAL,
    ErrorCode.VM_SETUP_FAILED: grpc.StatusCode.INTERNAL,
    ErrorCode.MICROVM_INIT_FAILED: grpc.StatusCode.INTERNAL,
    ErrorCode.INTERNAL: grpc.StatusCode.INTERNAL,
}

T = TypeVar("T")


async def _abort(context: grpc.aio.ServicerContext, error: SupervisorError) -> None:
    """Abort the RPC carrying the closed error vocabulary. Never returns."""
    if isinstance(error, NotImplementedSupervisorError):
        status = grpc.StatusCode.UNIMPLEMENTED
    else:
        status = STATUS_CODE_BY_ERROR.get(error.code, grpc.StatusCode.INTERNAL)
        if error.code is ErrorCode.INTERNAL:
            # INTERNAL means "not a vocabulary case" — keep the server-side
            # cause (with the original traceback chained by translate) in the
            # daemon log; the client only sees the message.
            logger.exception("Aborting RPC with INTERNAL: %s", error, exc_info=error.__cause__ or error)
    detail = pb.ErrorDetail(code=conv.ERROR_CODE_TO_PB[error.code], message=str(error))
    await context.abort(status, str(error), trailing_metadata=((ERROR_TRAILER_KEY, detail.SerializeToString()),))


def _translating(
    handler: Callable[..., Awaitable[T]],
) -> Callable[..., Awaitable[T]]:
    """Wrap a unary handler: SupervisorError (or anything else) aborts the RPC."""

    @functools.wraps(handler)
    async def wrapped(self, request, context):
        try:
            return await handler(self, request, context)
        except SupervisorError as error:
            await _abort(context, error)
        except Exception as error:  # - boundary catch-all
            logger.exception("Unhandled error in %s", handler.__name__)
            await _abort(context, translate_exception(error))
        raise AssertionError("abort() must raise")  # pragma: no cover

    return wrapped


class SupervisorService(supervisor_pb2_grpc.SupervisorServicer):
    def __init__(self, supervisor: Supervisor):
        self._supervisor = supervisor

    # ── Host ──
    @_translating
    async def Health(self, request: pb.HealthRequest, context) -> pb.HealthResponse:
        return conv.health_info_to_pb(await self._supervisor.health())

    @_translating
    async def GetHostInfo(self, request: pb.GetHostInfoRequest, context) -> pb.HostInfo:
        return conv.host_info_to_pb(await self._supervisor.get_host_info())

    # ── Lifecycle ──
    @_translating
    async def CreateVm(self, request: pb.CreateVmRequest, context) -> pb.VmInfo:
        spec = conv.create_vm_spec_from_pb(request)
        return conv.vm_info_to_pb(await self._supervisor.create_vm(spec))

    @_translating
    async def GetVm(self, request: pb.GetVmRequest, context) -> pb.VmInfo:
        return conv.vm_info_to_pb(await self._supervisor.get_vm(VmId(request.vm_id)))

    @_translating
    async def GetVmSpec(self, request: pb.GetVmSpecRequest, context) -> pb.CreateVmRequest:
        spec = await self._supervisor.get_vm_spec(VmId(request.vm_id))
        return conv.create_vm_spec_to_pb(spec)

    @_translating
    async def ListVms(self, request: pb.ListVmsRequest, context) -> pb.ListVmsResponse:
        infos = await self._supervisor.list_vms()
        return pb.ListVmsResponse(vms=[conv.vm_info_to_pb(info) for info in infos])

    @_translating
    async def DeleteVm(self, request: pb.DeleteVmRequest, context) -> pb.DeleteVmResponse:
        await self._supervisor.delete_vm(VmId(request.vm_id), wipe=request.wipe)
        return pb.DeleteVmResponse()

    @_translating
    async def StopVm(self, request: pb.StopVmRequest, context) -> pb.VmInfo:
        return conv.vm_info_to_pb(await self._supervisor.stop_vm(VmId(request.vm_id)))

    @_translating
    async def StartVm(self, request: pb.StartVmRequest, context) -> pb.VmInfo:
        return conv.vm_info_to_pb(await self._supervisor.start_vm(VmId(request.vm_id)))

    @_translating
    async def RebootVm(self, request: pb.RebootVmRequest, context) -> pb.VmInfo:
        return conv.vm_info_to_pb(await self._supervisor.reboot_vm(VmId(request.vm_id)))

    @_translating
    async def ReinstallVm(self, request: pb.ReinstallVmRequest, context) -> pb.VmInfo:
        # `optional bool`: an unset field takes the ABC's default (True).
        wipe_volumes = request.wipe_volumes if request.HasField("wipe_volumes") else True
        return conv.vm_info_to_pb(await self._supervisor.reinstall_vm(VmId(request.vm_id), wipe_volumes=wipe_volumes))

    # ── Port forwarding ──
    @_translating
    async def AddPortForward(self, request: pb.AddPortForwardRequest, context) -> pb.PortForwardInfo:
        spec = conv.port_forward_spec_from_pb(request)
        return conv.port_forward_info_to_pb(await self._supervisor.add_port_forward(spec))

    @_translating
    async def RemovePortForward(self, request: pb.RemovePortForwardRequest, context) -> pb.RemovePortForwardResponse:
        await self._supervisor.remove_port_forward(
            VmId(request.vm_id), HostPort(request.host_port), conv.PROTOCOL_FROM_PB[request.protocol]
        )
        return pb.RemovePortForwardResponse()

    @_translating
    async def ListPortForwards(self, request: pb.ListPortForwardsRequest, context) -> pb.ListPortForwardsResponse:
        vm_id = VmId(request.vm_id) if request.vm_id else None
        infos = await self._supervisor.list_port_forwards(vm_id)
        return pb.ListPortForwardsResponse(forwards=[conv.port_forward_info_to_pb(info) for info in infos])

    # ── Events ──
    async def WatchEvents(self, request: pb.WatchEventsRequest, context) -> AsyncIterator[pb.VmEvent]:
        try:
            async for event in self._supervisor.watch_events():
                yield conv.vm_event_to_pb(event)
        except SupervisorError as error:
            await _abort(context, error)
        except Exception as error:  # noqa: BLE001 - boundary catch-all
            logger.exception("Unhandled error in WatchEvents")
            await _abort(context, translate_exception(error))

    # ── Logs ──
    @_translating
    async def GetLogs(self, request: pb.GetLogsRequest, context) -> pb.GetLogsResponse:
        chunks = await self._supervisor.get_logs(
            VmId(request.vm_id), max_lines=request.max_lines, from_tail=request.from_tail
        )
        return pb.GetLogsResponse(lines=[conv.log_chunk_to_pb(chunk) for chunk in chunks])

    async def StreamLogs(self, request: pb.StreamLogsRequest, context) -> AsyncIterator[pb.LogChunk]:
        try:
            async for chunk in self._supervisor.stream_logs(
                VmId(request.vm_id), include_history=request.include_history
            ):
                yield conv.log_chunk_to_pb(chunk)
        except SupervisorError as error:
            await _abort(context, error)
        except Exception as error:  # - boundary catch-all
            logger.exception("Unhandled error in StreamLogs")
            await _abort(context, translate_exception(error))

    # ── Backups ──
    @_translating
    async def StartBackup(self, request: pb.StartBackupRequest, context) -> pb.BackupInfo:
        info = await self._supervisor.start_backup(VmId(request.vm_id), quiesce_guest=request.quiesce_guest)
        return conv.backup_info_to_pb(info)

    @_translating
    async def GetBackupStatus(self, request: pb.GetBackupStatusRequest, context) -> pb.BackupInfo:
        info = await self._supervisor.get_backup_status(VmId(request.vm_id), BackupId(request.backup_id))
        return conv.backup_info_to_pb(info)

    @_translating
    async def ListBackups(self, request: pb.ListBackupsRequest, context) -> pb.ListBackupsResponse:
        vm_id = VmId(request.vm_id) if request.vm_id else None
        infos = await self._supervisor.list_backups(vm_id)
        return pb.ListBackupsResponse(backups=[conv.backup_info_to_pb(info) for info in infos])

    async def DownloadBackup(self, request: pb.DownloadBackupRequest, context) -> AsyncIterator[pb.BackupChunk]:
        try:
            async for chunk in self._supervisor.download_backup(VmId(request.vm_id), BackupId(request.backup_id)):
                yield conv.backup_chunk_to_pb(chunk)
        except SupervisorError as error:
            await _abort(context, error)
        except Exception as error:  # - boundary catch-all
            logger.exception("Unhandled error in DownloadBackup")
            await _abort(context, translate_exception(error))

    @_translating
    async def DeleteBackup(self, request: pb.DeleteBackupRequest, context) -> pb.DeleteBackupResponse:
        await self._supervisor.delete_backup(VmId(request.vm_id), BackupId(request.backup_id))
        return pb.DeleteBackupResponse()

    @_translating
    async def RestoreBackup(self, request: pb.RestoreBackupRequest, context) -> pb.VmInfo:
        info = await self._supervisor.restore_backup(VmId(request.vm_id), BackupId(request.backup_id))
        return conv.vm_info_to_pb(info)

    # ── Migration ──
    @_translating
    async def ExportVm(self, request: pb.ExportVmRequest, context) -> pb.MigrationInfo:
        info = await self._supervisor.export_vm(VmId(request.vm_id), DirectoryPath(Path(request.destination_dir)))
        return conv.migration_info_to_pb(info)

    @_translating
    async def ImportVm(self, request: pb.ImportVmRequest, context) -> pb.VmInfo:
        info = await self._supervisor.import_vm(VmId(request.vm_id), DirectoryPath(Path(request.source_dir)))
        return conv.vm_info_to_pb(info)

    @_translating
    async def GetMigrationStatus(self, request: pb.GetMigrationStatusRequest, context) -> pb.MigrationInfo:
        info = await self._supervisor.get_migration_status(VmId(request.vm_id), MigrationId(request.migration_id))
        return conv.migration_info_to_pb(info)

    # ── Confidential ──
    @_translating
    async def InitializeConfidential(
        self, request: pb.InitializeConfidentialRequest, context
    ) -> pb.InitializeConfidentialResponse:
        await self._supervisor.initialize_confidential(VmId(request.vm_id), request.session_bytes, request.godh_bytes)
        return pb.InitializeConfidentialResponse()

    @_translating
    async def GetMeasurement(self, request: pb.GetMeasurementRequest, context) -> pb.Measurement:
        return conv.measurement_to_pb(await self._supervisor.get_measurement(VmId(request.vm_id)))

    @_translating
    async def InjectSecret(self, request: pb.InjectSecretRequest, context) -> pb.InjectSecretResponse:
        await self._supervisor.inject_secret(VmId(request.vm_id), request.secret_header_bytes, request.secret_bytes)
        return pb.InjectSecretResponse()


async def serve_unix(supervisor: Supervisor, socket_path: Path | str) -> grpc.aio.Server:
    """Build and start a gRPC server for `supervisor` on a Unix socket.

    The caller owns the returned server (`await server.stop(...)` /
    `wait_for_termination()`).
    """
    server = grpc.aio.server()
    supervisor_pb2_grpc.add_SupervisorServicer_to_server(SupervisorService(supervisor), server)
    server.add_insecure_port(f"unix:{socket_path}")
    await server.start()
    logger.info("Supervisor gRPC server listening on unix:%s", socket_path)
    return server
