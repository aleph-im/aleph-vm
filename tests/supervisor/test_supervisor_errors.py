import pytest

from aleph.vm.supervisor.errors import (
    FileTooLargeError as SupFileTooLargeError,
)
from aleph.vm.supervisor.errors import (
    HostNotFoundError as SupHostNotFoundError,
)
from aleph.vm.supervisor.errors import (
    InsufficientResourcesError as SupInsufficientResourcesError,
)
from aleph.vm.supervisor.errors import (
    InternalSupervisorError,
    NotImplementedSupervisorError,
    SupervisorError,
    translate_exception,
    translating_errors,
)
from aleph.vm.supervisor.types import ErrorCode


def test_supervisor_error_carries_code():
    err = SupervisorError("boom", code=ErrorCode.INTERNAL)
    assert err.code is ErrorCode.INTERNAL
    assert str(err) == "boom"


def test_not_implemented_maps_to_internal_code():
    assert NotImplementedSupervisorError("x").code is ErrorCode.INTERNAL


def test_translate_known_internal_exceptions():
    from aleph.vm.resources import InsufficientResourcesError

    translated = translate_exception(
        InsufficientResourcesError("no ram", required={"mem": 1}, available={"mem": 0})
    )
    assert isinstance(translated, SupInsufficientResourcesError)
    assert translated.code is ErrorCode.INSUFFICIENT_RESOURCES


def test_translate_file_too_large():
    from aleph.vm.controllers.firecracker.program import FileTooLargeError

    translated = translate_exception(FileTooLargeError("too big"))
    assert isinstance(translated, SupFileTooLargeError)
    assert translated.code is ErrorCode.FILE_TOO_LARGE


def test_translate_host_not_found():
    from aleph.vm.utils import HostNotFoundError

    translated = translate_exception(HostNotFoundError("no host"))
    assert isinstance(translated, SupHostNotFoundError)
    assert translated.code is ErrorCode.HOST_NOT_FOUND


def test_translate_unknown_exception_maps_to_internal():
    translated = translate_exception(ValueError("surprise"))
    assert isinstance(translated, InternalSupervisorError)
    assert translated.code is ErrorCode.INTERNAL


def test_translating_errors_passes_supervisor_errors_through():
    with pytest.raises(SupHostNotFoundError):
        with translating_errors():
            raise SupHostNotFoundError("already a supervisor error")


def test_translating_errors_converts_internal():
    with pytest.raises(InternalSupervisorError):
        with translating_errors():
            raise ValueError("surprise")
