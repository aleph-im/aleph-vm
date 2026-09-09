"""What a failed start is allowed to say about itself in public.

/v2/about/executions/list is unauthenticated and readable from any origin, so
every word of a failure record reaches whoever asks the node for it. The
exceptions a create raises are not written for that audience: a capacity
refusal quotes the node's free memory and the cache path it could not fit a
download in, a download failure quotes the URL it was fetching, and an
unforeseen one carries whatever its raiser put in it. So the published record
holds a code out of the closed set below and nothing else, and each code has
one sentence, written here for a reader rather than taken from an exception.
The exception's own text goes to the log, which is the operator's to read.

The mapping is by exception type, never by matching on message text: a type
is part of the contract the raiser signed, while a message is prose that gets
edited.
"""

import logging
from enum import Enum

from aiohttp import ClientResponseError
from aiohttp.web_exceptions import HTTPBadRequest, HTTPNotFound, HTTPServiceUnavailable

from aleph.vm.agent.run import VmStartupError
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface.errors import SupervisorError
from aleph.vm.supervisor_interface.types import ErrorCode

logger = logging.getLogger(__name__)


class AllocationFailureCode(str, Enum):
    """Why a planned VM is not running, in the node's own words.

    Coarser than the boundary's ErrorCode on purpose: this is what a remote
    scheduler decides on (place the VM elsewhere, wait, or stop asking), not
    what an operator debugs with.
    """

    INSUFFICIENT_CAPACITY = "insufficient_capacity"
    DOWNLOAD_FAILED = "download_failed"
    MESSAGE_UNAVAILABLE = "message_unavailable"
    UNSUPPORTED = "unsupported"
    STARTUP_FAILED = "startup_failed"
    SUPERVISOR_ERROR = "supervisor_error"
    VM_FAILED = "vm_failed"
    INTERNAL = "internal"


_PUBLIC_MESSAGES: dict[AllocationFailureCode, str] = {
    AllocationFailureCode.INSUFFICIENT_CAPACITY: "This node has no room for this VM",
    AllocationFailureCode.DOWNLOAD_FAILED: "A resource this VM needs could not be downloaded",
    AllocationFailureCode.MESSAGE_UNAVAILABLE: "This VM's message could not be read from the network",
    AllocationFailureCode.UNSUPPORTED: "This node cannot run this VM",
    AllocationFailureCode.STARTUP_FAILED: "The VM was created but did not reach the running state",
    AllocationFailureCode.SUPERVISOR_ERROR: "The hypervisor refused to run this VM",
    AllocationFailureCode.VM_FAILED: "The VM was rebuilt after the hypervisor reported it failed",
    AllocationFailureCode.INTERNAL: "Unhandled error",
}

# The boundary vocabulary, folded into the one above. Anything absent is a
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


def public_failure_message(code: AllocationFailureCode) -> str:
    """The one sentence published for a code, for every reader of the list."""
    return _PUBLIC_MESSAGES[code]
