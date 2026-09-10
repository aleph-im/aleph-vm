"""The one vocabulary the allocation plane refuses in, and its wire shape.

Every "no" this node gives a scheduler leaves through here: the immediate
answer to a plan push, the advisory capacity check, and the failure record the
executions list publishes for a VM the loop could not start. They used to be
three sets of hand-written ``{"code": ..., "message": ...}`` dicts with two
independent spellings of the same refusals, which is how ``insufficient
capacity`` came to exist twice with nothing holding the two together.

Split from the exception classifier next door on purpose: this module has to
be importable by the capacity manager, and classifying an exception means
knowing the types the create path raises, which pulls in the create path and
with it the capacity manager itself.

The message is prose for a reader, so it is written here rather than taken
from an exception. /v2/about/executions/list is unauthenticated and readable
from any origin: a capacity refusal quotes the node's free memory and the
cache path a download would not fit in, a download failure quotes the URL it
was fetching, and an unforeseen one carries whatever its raiser put in it.
None of that is the scheduler's business, so a refusal built from a code alone
(``Refusal.for_code``) is what the public paths use, and the exception's own
text goes to the log.
"""

from dataclasses import dataclass
from enum import Enum


class AllocationFailureCode(str, Enum):
    """Why a VM is not running here, in the node's own words.

    Coarser than the boundary's ErrorCode on purpose: this is what a remote
    scheduler decides on (place the VM elsewhere, wait, or stop asking), not
    what an operator debugs with.

    One closed set for both halves of the answer, the refusal a push is given
    at once and the failure a start reports later, because a scheduler reading
    them apart cannot tell that ``insufficient_capacity`` in the two means the
    same thing.
    """

    INSUFFICIENT_CAPACITY = "insufficient_capacity"
    GPU_UNAVAILABLE = "gpu_unavailable"
    NODE_HASH_UNKNOWN = "node_hash_unknown"
    NODE_MISMATCH = "node_mismatch"
    INVALID_MESSAGE = "invalid_message"
    MESSAGE_REQUIRED = "message_required"
    DOWNLOAD_FAILED = "download_failed"
    MESSAGE_UNAVAILABLE = "message_unavailable"
    UNSUPPORTED = "unsupported"
    STARTUP_FAILED = "startup_failed"
    SUPERVISOR_ERROR = "supervisor_error"
    VM_FAILED = "vm_failed"
    INTERNAL = "internal"


_PUBLIC_MESSAGES: dict[AllocationFailureCode, str] = {
    AllocationFailureCode.INSUFFICIENT_CAPACITY: "This node has no room for this VM",
    AllocationFailureCode.GPU_UNAVAILABLE: "No available GPU matches this request",
    AllocationFailureCode.NODE_HASH_UNKNOWN: "This node has not discovered its own hash yet",
    AllocationFailureCode.NODE_MISMATCH: "This VM is allocated to a different node",
    AllocationFailureCode.INVALID_MESSAGE: "The message sent for this VM could not be verified",
    AllocationFailureCode.MESSAGE_REQUIRED: "Embed the signed message for this VM to be sized",
    AllocationFailureCode.DOWNLOAD_FAILED: "A resource this VM needs could not be downloaded",
    AllocationFailureCode.MESSAGE_UNAVAILABLE: "This VM's message could not be read from the network",
    AllocationFailureCode.UNSUPPORTED: "This node cannot run this VM",
    AllocationFailureCode.STARTUP_FAILED: "The VM was created but did not reach the running state",
    AllocationFailureCode.SUPERVISOR_ERROR: "The hypervisor refused to run this VM",
    AllocationFailureCode.VM_FAILED: "The VM was rebuilt after the hypervisor reported it failed",
    AllocationFailureCode.INTERNAL: "Unhandled error",
}


def public_failure_message(code: AllocationFailureCode) -> str:
    """The one sentence published for a code, for every reader of the list."""
    return _PUBLIC_MESSAGES[code]


@dataclass(frozen=True)
class Refusal:
    """One "no", in the shape every allocation route serializes it in.

    Built through ``for_code`` wherever the code says all there is to say,
    which is everywhere but the entry whose signed message would not verify:
    that one carries which of the verifier's fixed reasons it failed on.
    """

    code: AllocationFailureCode
    message: str

    @classmethod
    def for_code(cls, code: AllocationFailureCode) -> "Refusal":
        """The refusal a code alone describes, with its published sentence."""
        return cls(code=code, message=public_failure_message(code))

    def as_dict(self) -> dict[str, str]:
        """The wire shape, written in one place so no route can drift from it."""
        return {"code": self.code.value, "message": self.message}


# The refusals an answer carries, keyed by what it names the entry under: the
# VM's item hash, or the entry's position in the body when it carried no hash
# to be named by.
Refusals = dict[str, Refusal]
