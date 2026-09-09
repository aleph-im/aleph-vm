"""Which refusal code an exception raised by a start is published under.

The mapping is by exception type, never by matching on message text: a type is
part of the contract the raiser signed, while a message is prose that gets
edited. The vocabulary itself lives next door, in ``refusal``, which the
capacity manager imports; naming the exception types here means importing the
create path, and the create path imports the capacity manager.
"""

from aiohttp import ClientResponseError
from aiohttp.web_exceptions import HTTPBadRequest, HTTPNotFound, HTTPServiceUnavailable

from aleph.vm.agent.allocation.refusal import AllocationFailureCode
from aleph.vm.agent.run import VmStartupError
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface.errors import SupervisorError
from aleph.vm.supervisor_interface.types import ErrorCode

# The boundary vocabulary, folded into the refusal one. Anything absent is a
# real answer rather than an oversight: the hypervisor side refused, which is
# what the scheduler needs to know, and the code that says so is in the log.
_BY_SUPERVISOR_CODE: dict[ErrorCode, AllocationFailureCode] = {
    ErrorCode.INSUFFICIENT_RESOURCES: AllocationFailureCode.INSUFFICIENT_CAPACITY,
    ErrorCode.RESOURCE_DOWNLOAD_FAILED: AllocationFailureCode.DOWNLOAD_FAILED,
    ErrorCode.FILE_TOO_LARGE: AllocationFailureCode.DOWNLOAD_FAILED,
    ErrorCode.VM_SETUP_FAILED: AllocationFailureCode.STARTUP_FAILED,
    ErrorCode.MICROVM_INIT_FAILED: AllocationFailureCode.STARTUP_FAILED,
    ErrorCode.INVALID_BACKEND: AllocationFailureCode.UNSUPPORTED,
    ErrorCode.TEE_UNAVAILABLE: AllocationFailureCode.UNSUPPORTED,
}


def classify_start_failure(error: BaseException) -> AllocationFailureCode:
    """The code a failed start is published under.

    Ordered from the most specific claim to the least, and ending on a code
    that says nothing: an exception this does not recognise is a bug on this
    node, and the scheduler is told the node failed, not how.
    """
    if isinstance(error, SupervisorError):
        return _BY_SUPERVISOR_CODE.get(error.code, AllocationFailureCode.SUPERVISOR_ERROR)
    if isinstance(error, InsufficientResourcesError):
        # The node's own admission, which runs before the boundary is called.
        return AllocationFailureCode.INSUFFICIENT_CAPACITY
    if isinstance(error, VmStartupError):
        return AllocationFailureCode.STARTUP_FAILED
    if isinstance(error, HTTPNotFound | HTTPServiceUnavailable):
        # What the message fetch raises for a hash the API does not have and
        # for a connector that is down.
        return AllocationFailureCode.MESSAGE_UNAVAILABLE
    if isinstance(error, HTTPBadRequest):
        # A content type this CRN cannot run: the message's problem, not the
        # node's, and no later attempt will do better.
        return AllocationFailureCode.UNSUPPORTED
    if isinstance(error, ClientResponseError):
        return AllocationFailureCode.DOWNLOAD_FAILED
    return AllocationFailureCode.INTERNAL
