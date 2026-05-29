"""Closed error vocabulary for the Supervisor boundary.

SupervisorError subclasses map one-to-one to proto ErrorCode values. The
in-process implementation catches the scattered internal backend exceptions
and re-raises them as this closed set; the gRPC server (0.D) reuses the same
table to fill ErrorDetail trailers; views (0.E) catch SupervisorError instead
of backend internals.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from aleph.vm.supervisor.types import ErrorCode


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


class NotImplementedSupervisorError(SupervisorError):
    """A boundary method that is intentionally not implemented yet."""

    code = ErrorCode.INTERNAL


class InternalSupervisorError(SupervisorError):
    code = ErrorCode.INTERNAL


def translate_exception(exc: BaseException) -> SupervisorError:
    """Map an internal backend exception to the closed Supervisor vocabulary.

    Imports are local so this module stays importable even if a backend
    module fails to import in a stripped-down environment.
    """
    if isinstance(exc, SupervisorError):
        return exc

    from aleph.vm.controllers.firecracker.executable import ResourceDownloadError as _ResourceDownloadError
    from aleph.vm.controllers.firecracker.executable import VmSetupError as _VmSetupError
    from aleph.vm.controllers.firecracker.program import FileTooLargeError as _FileTooLargeError
    from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError as _MicroVMFailedInitError
    from aleph.vm.resources import InsufficientResourcesError as _InsufficientResourcesError
    from aleph.vm.utils import HostNotFoundError as _HostNotFoundError

    message = str(exc)
    if isinstance(exc, _InsufficientResourcesError):
        return InsufficientResourcesError(message)
    if isinstance(exc, _ResourceDownloadError):
        return ResourceDownloadError(message)
    if isinstance(exc, _FileTooLargeError):
        return FileTooLargeError(message)
    if isinstance(exc, _VmSetupError):
        return VmSetupError(message)
    if isinstance(exc, _MicroVMFailedInitError):
        return MicroVMInitError(message)
    if isinstance(exc, _HostNotFoundError):
        return HostNotFoundError(message)
    return InternalSupervisorError(message)


@contextlib.contextmanager
def translating_errors() -> Iterator[None]:
    """Re-raise any non-SupervisorError as the translated SupervisorError."""
    try:
        yield
    except SupervisorError:
        raise
    except Exception as exc:  # noqa: BLE001 - deliberate boundary catch-all
        raise translate_exception(exc) from exc
