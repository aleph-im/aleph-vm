"""What the scheduler asked for, and how far the agent got with it.

The plan is held in memory only. After a restart the agent has no plan, and a
reconciler with no plan deletes nothing: acting on a stale plan risks tearing
down VMs that were migrated elsewhere during the downtime.
"""

from dataclasses import dataclass, field
from datetime import datetime

from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.verify import VerifiedMessage


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
