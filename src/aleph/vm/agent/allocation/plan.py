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

from aleph.vm.agent.allocation.verify import VerifiedMessage
from aleph.vm.supervisor_interface.types import VmInfo, VmStatus

logger = logging.getLogger(__name__)

# A VM in one of these states is the supervisor's business already: creating it
# again would be a second VM under the same hash.
LIVE_STATUSES = (VmStatus.RUNNING, VmStatus.BOOTING, VmStatus.DEFINED)


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
    """

    PLANNED = "planned"
    RESOLVING = "resolving"
    DOWNLOADING = "downloading"
    SUBMITTING = "submitting"
    FAILED = "failed"


@dataclass
class FailureRecord:
    """Why a planned VM is not running, and when we will try again.

    Kept in the reconciler and NOT in AgentVmRegistry on purpose: the registry
    is what CapacityManager sums committed resources over, and a VM that failed
    to start must not count as committed.
    """

    code: str
    message: str
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
    plan_id: str
    received_at: datetime
    entries: dict[ItemHash, PlannedVm]


@dataclass
class PlanVerdict:
    """The immediate answer returned to the scheduler."""

    accepted: list[ItemHash] = field(default_factory=list)
    pending: list[ItemHash] = field(default_factory=list)
    unchanged: list[ItemHash] = field(default_factory=list)
    removing: list[ItemHash] = field(default_factory=list)
    rejected: dict[str, dict] = field(default_factory=dict)
    retained: dict[ItemHash, str] = field(default_factory=dict)
