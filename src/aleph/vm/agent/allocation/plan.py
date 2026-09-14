"""What the scheduler asked for, and how far the agent got with it.

The plan is held in memory only. After a restart the agent has no plan, and a
reconciler with no plan deletes nothing: acting on a stale plan risks tearing
down VMs that were migrated elsewhere during the downtime.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.failures import AllocationFailureCode
from aleph.vm.agent.allocation.verify import VerifiedMessage
from aleph.vm.supervisor_interface.types import VmInfo, VmStatus

logger = logging.getLogger(__name__)

# A VM in one of these states is the supervisor's business already: creating it
# again would be a second VM under the same hash.
LIVE_STATUSES = (VmStatus.RUNNING, VmStatus.BOOTING, VmStatus.DEFINED)

# States a VM only reaches because it was told to: the owner's stop through the
# operator API, or a guest shutting itself down. The definition and the disks
# survive, so the VM is down rather than lost, and starting it again is the
# owner's call and nobody else's. STOPPING is here too because a stop caught
# mid-flight is still a stop: a caller that read it as work to do would wait
# the VM out and then recreate it from scratch.
STOPPED_STATUSES = (VmStatus.STOPPING, VmStatus.STOPPED)


def by_hash(infos: list[VmInfo]) -> dict[ItemHash, VmInfo]:
    """The supervisor's VMs, keyed by item hash.

    An id that is not one is dropped rather than raised on, the way
    supervisor_hashes and check_payment drop theirs: it names a VM the plan
    says nothing about, so letting it through would take down a whole push or
    wedge a whole convergence pass over something neither is about.
    """
    known: dict[ItemHash, VmInfo] = {}
    for info in infos:
        try:
            known[ItemHash(str(info.vm_id))] = info
        except (UnknownHashError, ValueError):
            logger.warning("The supervisor lists a VM whose id is not an item hash: %r", info.vm_id)
    return known


class AllocationState(str, Enum):
    """Agent-side phases, which all precede the supervisor knowing the VM.

    Deliberately NOT a mirror of VmStatus: once create_vm returns, VmStatus is
    the answer and this state stops existing. Two disjoint fields cannot drift,
    whereas a merged enum would need maintaining in lockstep forever.

    The reconciler sets DOWNLOADING and FAILED, the only two it can observe.
    The executions list derives the other two from the plan, for an entry the
    loop has not reached: PLANNED when the push carried its message, RESOLVING
    when the create will have to fetch it first.
    """

    PLANNED = "planned"
    RESOLVING = "resolving"
    DOWNLOADING = "downloading"
    FAILED = "failed"


@dataclass
class FailureRecord:
    """What it is taking to keep a planned VM running, and when we try again.

    Two things are counted as one attempt: a start that raised, and a rebuild
    of a VM the supervisor held dead, which is what puts a crash-looping guest
    on the same backoff. So a record can outlive a successful start, and one
    on a running VM means it has died recently, not that it is down now.

    Kept in the reconciler and NOT in AgentVmRegistry on purpose: the registry
    is what CapacityManager sums committed resources over, and a VM that failed
    to start must not count as committed.

    There is no free-text field, and that is the point: the record is served
    verbatim by an unauthenticated endpoint, so what it can hold is a code out
    of a closed set (each with its own published sentence) and nothing an
    exception wrote. The detail lives in the log.
    """

    code: AllocationFailureCode
    attempts: int
    first_failed_at: datetime
    last_failed_at: datetime
    next_retry_at: datetime


@dataclass
class PlannedVm:
    """One entry of the plan. State lives in the reconciler, not here: one owner."""

    vm_hash: ItemHash
    verified: VerifiedMessage | None = None


@dataclass(frozen=True)
class AllocationPlan:
    """What the push asked for, once the answer has had its say.

    ``refused`` are the hashes the push listed and this node turned down,
    over a message it would not verify or for want of room. They are out of
    ``entries`` because nothing is to start them, and they are named here
    because the convergence loop reads a hash the plan does not hold as one
    the scheduler took away, and deleting a VM means reaping its disks.
    "Rejected" is not "deleted": the scheduler still believes the VM exists.
    Most of the shapes that produce a refusal pass on their own (a full host,
    a node that has not read its own hash back since it restarted, a corrupt
    message from a buggy scheduler or a bad CCN read), and one does not: a VM
    allocated to another node stays allocated to it. The set holds every
    refusal all the same, transient or permanent, because waiting for the push
    to stop naming the VM is the safe reading of both.

    A hash the push sent in a form we could not parse is absent from both:
    it names no VM on this node, so there is nothing for it to protect.
    """

    plan_id: str
    received_at: datetime
    entries: dict[ItemHash, PlannedVm]
    refused: frozenset[ItemHash] = frozenset()

    def lists(self, vm_hash: ItemHash) -> bool:
        """Whether the push this plan came from named this VM at all."""
        return vm_hash in self.entries or vm_hash in self.refused


@dataclass
class PlanVerdict:
    """The immediate answer returned to the scheduler."""

    accepted: list[ItemHash] = field(default_factory=list)
    pending: list[ItemHash] = field(default_factory=list)
    unchanged: list[ItemHash] = field(default_factory=list)
    removing: list[ItemHash] = field(default_factory=list)
    rejected: dict[str, dict] = field(default_factory=dict)
    retained: dict[ItemHash, str] = field(default_factory=dict)
