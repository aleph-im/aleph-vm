"""The closed vocabulary a failed start is published under.

Everything a failure record carries reaches an unauthenticated reader, so the
mapping tested here is the whole guarantee: a code out of a fixed set, and a
message written for that set rather than taken from the exception.
"""

import pytest
from aiohttp import ClientResponseError
from aiohttp.web_exceptions import HTTPBadRequest, HTTPNotFound, HTTPServiceUnavailable

from aleph.vm.agent.allocation.failures import classify_start_failure
from aleph.vm.agent.allocation.refusal import (
    AllocationFailureCode,
    Refusal,
    public_failure_message,
)
from aleph.vm.agent.run import VmStartupError
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface import errors as supervisor_errors
from aleph.vm.supervisor_interface.errors import SupervisorError
from aleph.vm.supervisor_interface.types import ErrorCode


def _no_room() -> InsufficientResourcesError:
    """The node's own admission refusal, as capacity raises it: the figures
    it quotes are the host's, not the VM's."""
    return InsufficientResourcesError(
        "Insufficient capacity to create VM. Node has 512 MiB free",
        required={"memory_mib": 4096},
        available={"memory_mib": 512},
    )


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        # The node's own admission, whose text quotes free memory and the
        # cache path it could not fit a download in.
        (_no_room(), AllocationFailureCode.INSUFFICIENT_CAPACITY),
        # The same refusal arriving through the supervisor boundary.
        (supervisor_errors.InsufficientResourcesError("no room"), AllocationFailureCode.INSUFFICIENT_CAPACITY),
        (supervisor_errors.ResourceDownloadError("404 for https://host/rootfs"), AllocationFailureCode.DOWNLOAD_FAILED),
        (supervisor_errors.FileTooLargeError("too big"), AllocationFailureCode.DOWNLOAD_FAILED),
        (ClientResponseError(None, (), status=404), AllocationFailureCode.DOWNLOAD_FAILED),
        (supervisor_errors.VmSetupError("setup"), AllocationFailureCode.STARTUP_FAILED),
        (supervisor_errors.MicroVMInitError("init"), AllocationFailureCode.STARTUP_FAILED),
        (VmStartupError("never reached running"), AllocationFailureCode.STARTUP_FAILED),
        (supervisor_errors.TeeUnavailableError("no sev"), AllocationFailureCode.UNSUPPORTED),
        (supervisor_errors.InvalidBackendError("no such backend"), AllocationFailureCode.UNSUPPORTED),
        # What create_vm_execution raises for a content type this CRN cannot run.
        (HTTPBadRequest(reason="Unsupported message type"), AllocationFailureCode.UNSUPPORTED),
        # The message could not be read back from the network.
        (HTTPNotFound(reason="Hash not found"), AllocationFailureCode.MESSAGE_UNAVAILABLE),
        (HTTPServiceUnavailable(reason="Aleph Connector unavailable"), AllocationFailureCode.MESSAGE_UNAVAILABLE),
        (supervisor_errors.PortUnavailableError("busy"), AllocationFailureCode.SUPERVISOR_ERROR),
        # The boundary codes that mean this node is confused rather than the
        # hypervisor declining to run the VM.
        (supervisor_errors.InternalSupervisorError("boom"), AllocationFailureCode.INTERNAL),
        (supervisor_errors.VmNotFoundError("gone"), AllocationFailureCode.INTERNAL),
        (supervisor_errors.VmAlreadyExistsError("already here"), AllocationFailureCode.INTERNAL),
        (SupervisorError("no such host", code=ErrorCode.HOST_NOT_FOUND), AllocationFailureCode.INTERNAL),
        (RuntimeError("could not open /var/lib/aleph/vm/private.img"), AllocationFailureCode.INTERNAL),
        (OSError("errno 28"), AllocationFailureCode.INTERNAL),
    ],
)
def test_each_failure_lands_on_the_code_that_describes_it(error, expected):
    assert classify_start_failure(error) is expected


def test_every_supervisor_error_code_is_covered():
    """A code added to the boundary vocabulary must not fall off the map: the
    default is a real answer (the hypervisor refused), not an accident."""
    for code in ErrorCode:
        error = SupervisorError("detail", code=code)

        assert classify_start_failure(error) in AllocationFailureCode


def test_every_code_has_a_message_of_its_own():
    """The message is a function of the code, so a code with none would
    publish an empty error to the scheduler."""
    messages = {code: public_failure_message(code) for code in AllocationFailureCode}

    assert all(messages.values())
    assert len(set(messages.values())) == len(messages)


def test_an_unclassified_failure_says_only_that_it_was_unhandled():
    """The fixed sentence a reader gets whatever the start raised, which is
    what keeps an unforeseen exception's text off the public listing."""
    assert public_failure_message(AllocationFailureCode.INTERNAL) == "Unhandled error"


def test_a_refusal_serializes_the_same_way_wherever_it_is_answered():
    """One wire shape for every "no" this node gives, and one code behind it.

    The refusal a full host answers a push with and the one it publishes for a
    start it could not make used to be two vocabularies: a literal dict in the
    verdict and this enum in the record, with nothing holding the two spellings
    of "no room" together.
    """
    refusal = Refusal.for_code(AllocationFailureCode.INSUFFICIENT_CAPACITY)

    assert refusal.as_dict() == {
        "code": "insufficient_capacity",
        "message": public_failure_message(AllocationFailureCode.INSUFFICIENT_CAPACITY),
    }
    assert classify_start_failure(_no_room()) is refusal.code
