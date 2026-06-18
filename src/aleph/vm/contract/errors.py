"""Closed error vocabulary for the Supervisor boundary.

SupervisorError subclasses map one-to-one to proto ErrorCode values. The
in-process implementation catches the scattered internal backend exceptions and
re-raises them as this closed set (see ``aleph.vm.supervisor.error_mapping``);
the gRPC server reuses the same table to fill ErrorDetail trailers; views catch
SupervisorError instead of backend internals.

This module is part of the shared contract: it carries no backend dependency
(the exception->code mapping lives supervisor-side in ``error_mapping``).
"""

from __future__ import annotations

from aleph.vm.contract.types import ErrorCode


class SupervisorError(Exception):
    """Base for every error crossing the Supervisor boundary."""

    code: ErrorCode = ErrorCode.INTERNAL

    def __init__(self, message: str = "", *, code: ErrorCode | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code


class VmNotFoundError(SupervisorError):
    code = ErrorCode.VM_NOT_FOUND


class VmAlreadyExistsError(SupervisorError):
    code = ErrorCode.VM_ALREADY_EXISTS


class InsufficientResourcesError(SupervisorError):
    code = ErrorCode.INSUFFICIENT_RESOURCES


class ResourceDownloadError(SupervisorError):
    code = ErrorCode.RESOURCE_DOWNLOAD_FAILED


class FileTooLargeError(SupervisorError):
    code = ErrorCode.FILE_TOO_LARGE


class VmSetupError(SupervisorError):
    code = ErrorCode.VM_SETUP_FAILED


class MicroVMInitError(SupervisorError):
    code = ErrorCode.MICROVM_INIT_FAILED


class InvalidBackendError(SupervisorError):
    code = ErrorCode.INVALID_BACKEND


class TeeUnavailableError(SupervisorError):
    code = ErrorCode.TEE_UNAVAILABLE


class PortUnavailableError(SupervisorError):
    code = ErrorCode.PORT_UNAVAILABLE


class HostNotFoundError(SupervisorError):
    code = ErrorCode.HOST_NOT_FOUND


class BackupNotFoundError(SupervisorError):
    code = ErrorCode.BACKUP_NOT_FOUND


class MigrationInProgressError(SupervisorError):
    code = ErrorCode.MIGRATION_IN_PROGRESS


class MigrationNotFoundError(SupervisorError):
    code = ErrorCode.MIGRATION_NOT_FOUND


class NotImplementedSupervisorError(SupervisorError):
    """A boundary method that is intentionally not implemented yet."""

    code = ErrorCode.INTERNAL


class InternalSupervisorError(SupervisorError):
    code = ErrorCode.INTERNAL
