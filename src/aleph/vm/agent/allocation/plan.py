"""What the scheduler asked for, and how far the agent got with it.

The plan is held in memory only. After a restart the agent has no plan, and a
reconciler with no plan deletes nothing: acting on a stale plan risks tearing
down VMs that were migrated elsewhere during the downtime.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.verify import VerifiedMessage


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
class PlanVerdict:
    """The immediate answer returned to the scheduler."""

    accepted: list[ItemHash] = field(default_factory=list)
    pending: list[ItemHash] = field(default_factory=list)
    unchanged: list[ItemHash] = field(default_factory=list)
    removing: list[ItemHash] = field(default_factory=list)
    rejected: dict[ItemHash, dict] = field(default_factory=dict)
    retained: dict[ItemHash, str] = field(default_factory=dict)
