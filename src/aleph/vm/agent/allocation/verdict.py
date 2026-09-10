"""Turning a request body into a plan, and a plan into an immediate answer.

The verdict half is pure and await-free by design: the handler must not yield
to the event loop between reading the supervisor's view and swapping the
desired state, or a concurrent push could invalidate the verdict it just
returned.

Building the plan is the one part that awaits, and it is over before that
window opens: it judges each entry on its own, in a worker thread, so a push
carrying thousands of signed messages does not stop the agent from answering
anything else while they are parsed and their signatures recovered.
"""

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from aleph_message.models import ExecutableContent, ItemHash

from aleph.vm.agent.allocation.plan import (
    LIVE_STATUSES,
    STOPPED_STATUSES,
    AllocationPlan,
    PlannedVm,
    PlanVerdict,
    by_hash,
)
from aleph.vm.agent.allocation.refusal import AllocationFailureCode, Refusal, Refusals
from aleph.vm.agent.allocation.teardown import retention_reason
from aleph.vm.agent.allocation.verify import (
    VerificationOutcome,
    VerifiedMessage,
    verify_entry,
)
from aleph.vm.agent.capacity import PlanAdmission, requirements_from_message
from aleph.vm.agent.vm_registry import RecordLookup
from aleph.vm.resources import GpuDevice
from aleph.vm.supervisor_interface.types import VmInfo, VmStatus

logger = logging.getLogger(__name__)

# How many entries one hop into a worker thread judges. Small enough that a
# batch is milliseconds of work rather than seconds, large enough that the hop
# itself stays a rounding error next to the parse and the ecrecover it carries.
VERIFICATION_BATCH_SIZE = 32


def compute_plan_id(planned: list[str], rejected: list[str]) -> str:
    """A stable identity for a plan, for correlation in logs and responses.

    Order-independent within each half, so the scheduler re-pushing the same
    set in a different order is visibly the same plan.

    The two halves are digested apart and then together: one merged sorted list
    gives the same identity to a push that planned A and refused B as to one
    that planned B and refused A. Every key is digested on its own before the
    join, for the same reason one level down: a rejected key is whatever junk
    the push carried in place of a hash, so joining the keys directly lets a
    single key holding the separator pass for the two either side of it.
    """

    def digest(hashes: list[str]) -> str:
        return sha256("\n".join(sorted(sha256(key.encode()).hexdigest() for key in hashes)).encode()).hexdigest()

    return "sha256:" + sha256(f"{digest(planned)}:{digest(rejected)}".encode()).hexdigest()


@dataclass(frozen=True)
class JudgedEntry:
    """One plan entry, judged on nothing but itself.

    Every field is derived from the entry alone, with no shared state read or
    written, which is what makes a batch of these safe to compute in a worker
    thread. ``vm_hash`` is None when the entry's item_hash is not a hash, and
    the answer then names the entry by its position in the body, since there
    is nothing else about it this node is willing to repeat back.
    """

    vm_hash: ItemHash | None
    outcome: VerificationOutcome
    verified: VerifiedMessage | None
    reason: str


def _plan_entries(body: dict) -> list:
    """The body's list of entries, or the ValueError that says it is not one.

    A bad entry is data to reject, but a body we cannot read raises. An empty
    plan is a real instruction, the one that stops everything this node runs,
    so a shape we cannot make sense of must never be read as one: ``vms: 5``
    and ``vms: null`` used to raise a bare TypeError here, and ``vms: "abc"``
    was quietly walked character by character into a plan of nothing at all.
    The list has to be there and be a list; the handler answers 400.
    """
    vms = body.get("vms") if isinstance(body, dict) else None
    if not isinstance(vms, list):
        msg = "plan body has no 'vms' list"
        raise ValueError(msg)
    return vms


def judge_entry(entry: object) -> JudgedEntry:
    """Parse one entry's hash and verify the message it carries.

    This is the validation boundary for a body the scheduler controls, so a
    bad entry is data to reject, never an exception: one unusable hash must
    not take down the whole push.
    """

    def unusable(raw: object) -> JudgedEntry:
        logger.warning("Refusing plan entry with an unusable item_hash: %r", raw)
        return JudgedEntry(
            vm_hash=None,
            outcome=VerificationOutcome.REJECTED,
            verified=None,
            reason="unusable item_hash",
        )

    # An entry that is not an object has no item_hash to read, so it is
    # refused the way a missing one is, and never reaches verify_entry, which
    # reads the entry as a mapping.
    if not isinstance(entry, dict):
        return unusable(None)
    raw_hash = entry.get("item_hash")
    try:
        vm_hash = ItemHash(str(raw_hash))
    except Exception:
        return unusable(raw_hash)
    outcome, verified, reason = verify_entry(entry)
    return JudgedEntry(vm_hash=vm_hash, outcome=outcome, verified=verified, reason=reason)


def judge_entries(entries: list) -> list[JudgedEntry]:
    """Judge a batch of entries. Runs in a worker thread; touches nothing shared."""
    return [judge_entry(entry) for entry in entries]


def assemble_plan(judged: list[JudgedEntry], *, now: datetime) -> tuple[AllocationPlan, Refusals]:
    """Fold the per-entry judgements into one plan, in the order they arrived.

    Rejected entries are returned separately: they are answered in the response
    and never enter the plan, so nothing downstream can act on them.

    Separately is not silently: an entry whose hash we could read is named in
    the plan's ``refused`` set, because the convergence loop tears down every
    VM the push did not name and a message we would not verify is no reason
    to delete the VM it names. An entry whose hash we could not read is left
    out of that set, since it names no VM here and so has nothing to protect.

    An entry with no usable hash is answered under its position in the body,
    ``vms[3]``. Keying it by the string the push sent instead collapsed every
    entry that carried no item_hash at all into one "None", so a push with
    three unreadable entries was answered about one; and that string is
    unbounded text off the request, which this node has no reason to echo.
    """
    entries: dict[ItemHash, PlannedVm] = {}
    rejected: Refusals = {}
    refused: set[ItemHash] = set()
    for index, judgement in enumerate(judged):
        vm_hash = judgement.vm_hash
        if vm_hash is None:
            rejected[f"vms[{index}]"] = Refusal(AllocationFailureCode.INVALID_MESSAGE, judgement.reason)
            continue
        if vm_hash in rejected:
            # The same hash pushed twice, refused once. A later entry must not
            # talk the plan into carrying a hash the answer says was refused.
            logger.warning("Ignoring a repeat entry for %s: already refused by this push", vm_hash)
            continue
        if judgement.outcome is VerificationOutcome.REJECTED:
            rejected[vm_hash] = Refusal(AllocationFailureCode.INVALID_MESSAGE, judgement.reason)
            refused.add(vm_hash)
            # The other order of the same duplicate: an earlier entry may
            # already have put this hash in the plan.
            entries.pop(vm_hash, None)
            continue
        entries[vm_hash] = PlannedVm(vm_hash=vm_hash, verified=judgement.verified)
    plan_id = compute_plan_id([str(h) for h in entries], [str(h) for h in rejected])
    plan = AllocationPlan(plan_id=plan_id, received_at=now, entries=entries, refused=frozenset(refused))
    return plan, rejected


async def build_plan(body: dict, *, now: datetime) -> tuple[AllocationPlan, Refusals]:
    """Verify every entry and assemble the plan.

    The per-entry work, a pydantic parse and a signature recovery each, runs
    in a worker thread a batch at a time. A push is capped at 8 MiB, which is
    thousands of entries and seconds of arithmetic, and doing it inline meant
    the agent answered nothing at all for those seconds: not a status request,
    not a supervisor callback, not its own convergence pass. Judging an entry
    reads no shared state, so a thread is safe; folding the judgements into a
    plan is ordering, and that stays here.

    Awaiting is safe at this point and only at this point: the answer has not
    been computed yet, so there is no verdict for a concurrent push to
    invalidate. Nothing between the supervisor read and submit() may yield.
    """
    entries = _plan_entries(body)
    judged: list[JudgedEntry] = []
    for start in range(0, len(entries), VERIFICATION_BATCH_SIZE):
        judged.extend(await asyncio.to_thread(judge_entries, entries[start : start + VERIFICATION_BATCH_SIZE]))
    return assemble_plan(judged, now=now)


def _required_node_hash(content: ExecutableContent) -> str | None:
    """The CRN this message pins itself to, if it pins one."""
    requirements = getattr(content, "requirements", None)
    node = getattr(requirements, "node", None) if requirements else None
    required = getattr(node, "node_hash", None) if node else None
    return str(required) if required else None


def compute_verdict(
    plan: AllocationPlan,
    *,
    infos: list[VmInfo],
    registry: RecordLookup,
    capacity: PlanAdmission,
    node_hash: str | None = None,
    available_gpus: list[GpuDevice] | None = None,
    removing_now: frozenset[ItemHash] = frozenset(),
) -> PlanVerdict:
    """The immediate answer: what we take, what we drop, what we refuse.

    ``available_gpus`` is the host's unattached cards. Reading them is an
    async call on the supervisor and this stays await-free, for the reason at
    the top of the module, so the handler reads them first and hands them in.
    Without them simulate refuses every candidate that asks for a card, which
    is the right answer to give when the cards were not looked at.

    ``removing_now`` is the set of VMs the convergence loop is deleting as
    this answer is computed. The supervisor goes on listing such a VM until
    its delete returns, so its status alone would have this call report it as
    running and untouched.

    A VM in that set is judged as a candidate, which means it can be refused,
    and a refusal at that moment is final for this push: the delete cannot be
    called off, so the VM goes with its disks and nothing builds it back. That
    is the honest answer rather than a bad one, since a refusal says the host
    has no room for it, and the scheduler learns to place it elsewhere instead
    of believing a VM is running here. The hash still leaves through the plan's
    refused set, so no later pass reads its absence as one more VM to delete.
    """
    verdict = PlanVerdict()
    known = by_hash(infos)
    unchanged: set[ItemHash] = set()

    for vm_hash, info in known.items():
        if vm_hash in plan.entries:
            # A VM this node already holds, up or stopped, is acknowledged
            # rather than sized: what the answer reports is that the
            # scheduler's belief the VM is allocated here still holds. A
            # stopped VM stays that way until its owner starts it, and its
            # registry record goes on committing its memory and vCPUs, so
            # sizing it as a candidate would let a node that is tight on room
            # refuse a VM it is already holding, and a refusal is what takes
            # the VM out of the plan the loop converges on.
            #
            # A VM whose teardown is already running is the exception, however
            # alive or however stopped the supervisor says it is: the retire is
            # past the point where a push can call it off, so the VM is going
            # away with its disks and this node will have to build it again.
            # Judged as a candidate instead, it is answered accepted, or
            # pending while the push carried no message to size it by, which is
            # what the loop will actually do about it on the pass after the
            # delete returns.
            if (
                info.status in LIVE_STATUSES or info.status in STOPPED_STATUSES or info.awaiting_confidential_init
            ) and vm_hash not in removing_now:
                unchanged.add(vm_hash)
                verdict.unchanged.append(vm_hash)
            # A planned VM the supervisor holds dead is about to be created
            # again, and its stale record still counts as committed, but that
            # is simulate's business: it leaves every candidate's own record
            # out of the sums the way check_capacity's exclude_vm_hash does.
            # Listing it as released here would credit that memory to the
            # other candidates too, and for one still waiting on its message
            # or refused for another node it would credit memory nobody is
            # freeing at all.
            continue
        record = registry.get(vm_hash)
        # A VM the supervisor runs that we hold no record for is left alone
        # and reported as neither dropped nor kept. We know nothing about what
        # it is owed, and an allocation push is not the place to find out.
        if record is None or info.status is not VmStatus.RUNNING:
            continue
        # A hash the push named and this node refused is out of the entries but
        # is not a hash the push took away, and the loop keeps its VM for
        # exactly that reason. The answer has to say the same thing, or the two
        # halves of the refusal protection contradict each other: a scheduler
        # told the VM is going away stops naming it, and the next push, naming
        # it nowhere, is the deletion that carrying the refusals forward exists
        # to prevent. Nothing is freeing that memory either, so it must not go
        # on to simulate as capacity the other candidates can be admitted
        # against.
        if plan.lists(vm_hash):
            verdict.retained[vm_hash] = "refused"
            continue
        reason = retention_reason(record, info)
        if reason is None:
            verdict.removing.append(vm_hash)
        else:
            verdict.retained[vm_hash] = reason

    candidates = []
    for vm_hash, planned in plan.entries.items():
        if vm_hash in unchanged:
            continue
        if planned.verified is None:
            verdict.pending.append(vm_hash)
            continue
        content = planned.verified.message.content
        required_node = _required_node_hash(content)
        if required_node and node_hash is None:
            # Not knowing our own hash yet is not the same answer as "you asked
            # for a different CRN": the legacy path returns 503 here so the
            # scheduler retries rather than treating it as settled.
            logger.info("Cannot place %s: this node has not discovered its own hash", vm_hash)
            verdict.rejected[vm_hash] = Refusal.for_code(AllocationFailureCode.NODE_HASH_UNKNOWN)
            continue
        if required_node and required_node != str(node_hash):
            logger.info("Refusing %s: allocated to another node", vm_hash)
            verdict.rejected[vm_hash] = Refusal.for_code(AllocationFailureCode.NODE_MISMATCH)
            continue
        candidates.append((vm_hash, requirements_from_message(content)))

    admissions = capacity.simulate(candidates, releasing=frozenset(verdict.removing), available_gpus=available_gpus)
    for admission in admissions:
        if admission.refusal is None:
            verdict.accepted.append(admission.vm_hash)
        else:
            verdict.rejected[admission.vm_hash] = admission.refusal

    return verdict


def narrow_plan(plan: AllocationPlan, verdict: PlanVerdict) -> AllocationPlan:
    """The plan the reconciler is handed: the push, less what the answer refused.

    A refused entry must never reach the loop. Left in, it would be retried
    forever at backoff rate, and started the moment room appeared, on a node
    the scheduler was told had refused it and has since placed it elsewhere
    from. Pending entries stay: nothing judged them, and the fetch that will
    is the loop's own. The identity stays too, since it names the push, and a
    re-push of the same set is the same plan whatever the host had room for
    the first time.

    Dropped is not forgotten: the refused hashes are carried alongside, so
    the loop can tell a VM this push refused from one it never mentioned. It
    tears down the second kind, and a refusal is no reason to destroy a VM.
    The ones build_plan already refused, over a message it would not verify,
    are carried through for the same reason.
    """
    entries = {vm_hash: planned for vm_hash, planned in plan.entries.items() if vm_hash not in verdict.rejected}
    return AllocationPlan(
        plan_id=plan.plan_id,
        received_at=plan.received_at,
        entries=entries,
        refused=plan.refused | (frozenset(plan.entries) - frozenset(entries)),
    )
