"""Map internal backend exceptions onto the closed Supervisor vocabulary.

This is supervisor-side, not contract: it imports controller and hypervisor
exception types (locally) to translate them into ``aleph.vm.contract.errors``.
Keeping the mapping here lets the contract layer stay free of any backend
dependency.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

from aleph.vm.contract.errors import (
    FileTooLargeError,
    HostNotFoundError,
    InsufficientResourcesError,
    InternalSupervisorError,
    MicroVMInitError,
    ResourceDownloadError,
    SupervisorError,
    VmSetupError,
)


def translate_exception(exc: BaseException) -> SupervisorError:
    """Map an internal backend exception to the closed Supervisor vocabulary.

    Imports are local so this module stays importable even if a backend
    module fails to import in a stripped-down environment.
    """
    if isinstance(exc, SupervisorError):
        return exc

    from aleph.vm.controllers.firecracker.executable import (
        ResourceDownloadError as _ResourceDownloadError,
    )
    from aleph.vm.controllers.firecracker.executable import (
        VmSetupError as _VmSetupError,
    )
    from aleph.vm.controllers.firecracker.program import (
        FileTooLargeError as _FileTooLargeError,
    )
    from aleph.vm.hypervisors.firecracker.microvm import (
        MicroVMFailedInitError as _MicroVMFailedInitError,
    )
    from aleph.vm.resources import (
        InsufficientResourcesError as _InsufficientResourcesError,
    )
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
    except Exception as exc:  # - deliberate boundary catch-all
        raise translate_exception(exc) from exc
