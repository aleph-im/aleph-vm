"""Converging the CRN onto the scheduler's plan, in the background.

Level-triggered, not event-sourced: each pass re-reads the desired state and
diffs it against what the supervisor reports, so a re-pushed identical plan is
an empty diff and a plan arriving mid-convergence simply wins at the next step
boundary. This is the seam pull mode plugs into: replacing "the scheduler
pushed a plan" with "the agent fetched a plan" is a change to submit()'s
caller and nothing else.

A stopped VM and a dead one are not the same thing: only its owner restarts a
stopped VM, so the loop never starts one, while a VM that failed is rebuilt on
the event, damped by the backoff. A stopped VM is still allocated here, and
unallocating it stays the scheduler's move, made by dropping it from the plan.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.failures import classify_start_failure
from aleph.vm.agent.allocation.plan import (
    LIVE_STATUSES,
    STOPPED_STATUSES,
    AllocationPlan,
    AllocationState,
    FailureRecord,
    by_hash,
)
from aleph.vm.agent.allocation.refusal import AllocationFailureCode
from aleph.vm.agent.allocation.teardown import is_removable_by_allocation, teardown_vm
from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.pubsub import PubSub
from aleph.vm.agent.run import start_persistent_vm
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.types import VmInfo, VmStatus

logger = logging.getLogger(__name__)

# States a dropped VM can be torn down from. DEFINED and BOOTING are excluded
# deliberately: those are mid-creation, and deleting one races the creation
# that is still in flight. A VM stuck there is caught on a later pass once it
# reaches one of these.
#
# Wider than the removing list compute_verdict answers with, which is RUNNING
# only: the answer names what this push stops that was up, while a pass sweeps
# in any of these states. What a pass sweeps is what the push never named at
# all, not what the plan does not list: a hash the answer refused is named,
# and refusing a VM is not deleting it. Capacity stays conservative
# under the difference, because a commitment is held by the registry record
# rather than by the status, so a stopped VM left out of releasing has its
# memory counted against the push that is about to free it.
TEARDOWN_STATUSES = (VmStatus.RUNNING, VmStatus.STOPPED, VmStatus.FAILED)


class AllocationReconciler:
    """Holds the desired state and converges to it in the background."""

    def __init__(
        self,
        *,
        supervisor: Supervisor,
        registry: AgentVmRegistry,
        capacity: CapacityManager,
        expiry: ExpiryManager,
        update_watcher: UpdateWatcher,
        pubsub_getter: Callable[[], PubSub | None],
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.supervisor = supervisor
        self.registry = registry
        self.capacity = capacity
        self.expiry = expiry
        self.update_watcher = update_watcher
        # Resolved per use, never stored: app["pubsub"] is created by a startup
        # hook registered after setup_webapp, and only when WATCH_FOR_MESSAGES
        # is on, so it does not exist when this object is built.
        self._pubsub_getter = pubsub_getter
        self._now = now or (lambda: datetime.now(tz=timezone.utc))
        self._desired: AllocationPlan | None = None
        self._wakeup = asyncio.Event()
        self._failures: dict[ItemHash, FailureRecord] = {}
        self._states: dict[ItemHash, AllocationState] = {}
        # The VMs whose teardown is running right now. The supervisor keeps
        # listing them meanwhile, so a push arriving in that window would read
        # a VM that is up but is on its way to GONE with its disks reaped.
        self._removing: set[ItemHash] = set()

    # ── Public surface ──

    def submit(self, plan: AllocationPlan) -> None:
        """Record a new desired state and wake the loop.

        Await-free on purpose: the handler calls this in the same event-loop
        turn as it computed the verdict it is about to return, so nothing can
        change underneath it in between.
        """
        self._desired = plan
        for vm_hash in list(self._failures):
            if vm_hash not in plan.entries:
                self._forget(vm_hash)
        for vm_hash in list(self._states):
            if vm_hash not in plan.entries:
                self._forget(vm_hash)
        self._wakeup.set()

    def notify_vm_down(self, vm_id: str, status: VmStatus | None) -> None:
        """A VM went down. If the plan still wants it up, converge now.

        `status` is what the supervisor reported, or None when the VM is gone
        from its list entirely. A stop does not wake the loop; a VM that failed
        or vanished is rebuilt at once rather than at the backstop interval.
        """
        if self._desired is None:
            return
        if status in STOPPED_STATUSES:
            return
        try:
            vm_hash = ItemHash(str(vm_id))
        except (UnknownHashError, ValueError):
            # Not ours to converge, and the event stream is no place to raise.
            return
        if vm_hash in self._desired.entries:
            self._wakeup.set()

    def has_plan(self) -> bool:
        """Whether a plan governs this node, however few VMs it names.

        Not the same question as "does the plan list anything": the empty plan
        is the instruction to run nothing here, and a node under it is still
        under it. Read by the legacy allocation route, which cannot be honoured
        alongside a plan.

        In memory only, like the plan itself, so an agent restart answers no
        here until the next plan push lands: a plan-governed node briefly
        accepts the legacy route again, and reverts as soon as a plan arrives.
        The same reasoning as the loop's post-restart silence, where a plan the
        agent no longer holds is not a plan it may act on, and an operator who
        restarts the agent should expect that window.
        """
        return self._desired is not None

    def planned_hashes(self) -> set[ItemHash]:
        return set(self._desired.entries) if self._desired else set()

    def pending_hashes(self) -> set[ItemHash]:
        """The planned VMs whose message the push did not carry.

        They are started like any other; the fetch happens inside the create.
        Exposed so the executions list can say "waiting on its message" for
        one the loop has not reached yet, where a verified entry is "planned".
        """
        if self._desired is None:
            return set()
        return {vm_hash for vm_hash, planned in self._desired.entries.items() if planned.verified is None}

    def removing_hashes(self) -> frozenset[ItemHash]:
        """The VMs whose teardown is in flight, for the answer to a push.

        The supervisor still lists these, but the node is committed to
        destroying them, so the verdict must never answer "unchanged" for one.
        """
        return frozenset(self._removing)

    def state_for(self, vm_hash: ItemHash) -> tuple[AllocationState | None, FailureRecord | None]:
        """What the agent is doing about this VM, for the executions list."""
        return self._states.get(vm_hash), self._failures.get(vm_hash)

    async def run(self) -> None:
        """Converge, then wait for a wake-up or the backstop interval."""
        while True:
            try:
                await self._converge_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Allocation reconcile pass failed; retrying at the next wake-up")
            try:
                await asyncio.wait_for(self._wakeup.wait(), timeout=settings.ALLOCATION_RECONCILE_INTERVAL)
            except asyncio.TimeoutError:
                # Not the builtin: the two are only the same class from 3.11,
                # and pyproject still supports 3.10, where catching the builtin
                # would let the first quiet interval kill the reconciler.
                pass
            self._wakeup.clear()

    # ── One pass ──

    async def _converge_once(self) -> None:
        plan = self._desired
        if plan is None:
            # Post-restart: no plan means delete nothing. A stale plan is worse
            # than none, so the agent waits to be told rather than acting on
            # what it remembers.
            return

        # Read once and handed to both halves: the two used to key the
        # supervisor's list by hash apiece, which parsed every id twice and
        # left them free to disagree about what is running.
        known = by_hash(await self.supervisor.list_vms())
        await self._teardown_dropped(plan, known)
        await self._start_missing(plan, known)

    async def _teardown_dropped(self, plan: AllocationPlan, known: dict[ItemHash, VmInfo]) -> None:
        for vm_hash, info in known.items():
            # Torn down only if the push never named this VM: a refused hash
            # was still named, and the scheduler was told the VM was rejected,
            # not deleted, so tearing it down would reap disks it still counts
            # on. Waiting for a push to stop naming it is safe either way.
            if plan.lists(vm_hash) or info.status not in TEARDOWN_STATUSES:
                continue
            # The plan is re-read here rather than taken from the pass, which
            # may have been parked in list_vms or in an earlier teardown while
            # a push re-added this VM. A start can afford to act on a snapshot
            # one push out of date, because the next pass undoes it; a teardown
            # cannot, since GONE reaps the volumes. The read and the await
            # below are in one turn, so nothing lands in between.
            current = self._desired
            if current is None or current.lists(vm_hash):
                continue
            record = self.registry.get(vm_hash)
            if record is None or not is_removable_by_allocation(record, info):
                continue
            logger.info("Plan %s dropped %s; tearing it down", current.plan_id, vm_hash)
            # Marked before the await and cleared however it ends: a hash left
            # behind here would have every later push answered as a rebuild.
            self._removing.add(vm_hash)
            try:
                await teardown_vm(vm_hash, supervisor=self.supervisor, registry=self.registry)
            except Exception:
                # Isolated per VM, the way _start_one isolates a start. One VM
                # the supervisor will not delete used to abort the pass here,
                # before a single start ran, and teardowns carry no backoff, so
                # it did that on every interval for as long as it kept failing.
                logger.exception("Tearing down %s failed; leaving it for the next pass", vm_hash)
            finally:
                self._removing.discard(vm_hash)

    async def _start_missing(self, plan: AllocationPlan, known: dict[ItemHash, VmInfo]) -> None:
        live = {
            vm_hash
            for vm_hash, info in known.items()
            if info.status in LIVE_STATUSES or info.awaiting_confidential_init
        }
        now = self._now()
        self._forget_settled(live, now)
        todo: list[ItemHash] = []
        for vm_hash in plan.entries:
            if vm_hash in live:
                continue
            info = known.get(vm_hash)
            if info is not None and info.status in STOPPED_STATUSES:
                # Somebody stopped this VM, so it stays stopped: a plan listing
                # it does not overrule the owner. The phase is cleared but the
                # failure record stands, so a VM that failed, sat stopped and
                # then crashed climbs the backoff ladder from where it was.
                if vm_hash in self._failures:
                    self._states[vm_hash] = AllocationState.FAILED
                else:
                    self._states.pop(vm_hash, None)
                continue
            if not self._retry_due(vm_hash, now):
                # Down and waiting out its backoff: recorded so the executions
                # list can report the wait and when it ends.
                self._states[vm_hash] = AllocationState.FAILED
                continue
            todo.append(vm_hash)
        if not todo:
            return

        semaphore = asyncio.Semaphore(settings.ALLOCATION_DOWNLOAD_CONCURRENCY)

        async def start(vm_hash: ItemHash) -> None:
            async with semaphore:
                # A VM the supervisor lists that is not live is one it holds
                # dead: the loop started it before, so this start is a rebuild.
                await self._start_one(vm_hash, known.get(vm_hash))

        await asyncio.gather(*(start(vm_hash) for vm_hash in todo), return_exceptions=True)

    def _retry_due(self, vm_hash: ItemHash, now: datetime) -> bool:
        failure = self._failures.get(vm_hash)
        return failure is None or failure.next_retry_at <= now

    def _forget_settled(self, live: set[ItemHash], now: datetime) -> None:
        """Drop the record of a VM that has been up long enough to call healthy.

        The record has to outlive the successful start that follows a rebuild,
        or nothing would gate the next one. The threshold is the longest wait
        the backoff can impose, past which a death is a new problem.
        """
        settled = timedelta(seconds=settings.ALLOCATION_RETRY_MAX_INTERVAL)
        for vm_hash, failure in list(self._failures.items()):
            if vm_hash in live and now - failure.last_failed_at >= settled:
                self._forget(vm_hash)

    async def _start_one(self, vm_hash: ItemHash, down: VmInfo | None = None) -> None:
        """Start a planned VM.

        `down` is what the supervisor holds for it when it already has one,
        which makes this start a rebuild and charges it on the backoff ladder.
        Only a VM the supervisor holds FAILED reaches here with one; a stopped
        VM is left to its owner. The start is marked as a rebuild, so admission
        skips the memory and vCPU checks its record already covers; the backoff
        ladder bounds a rebuild the node cannot really run.
        """
        self._states[vm_hash] = AllocationState.DOWNLOADING
        try:
            await start_persistent_vm(
                vm_hash,
                self._pubsub_getter(),
                supervisor=self.supervisor,
                registry=self.registry,
                capacity=self.capacity,
                expiry=self.expiry,
                update_watcher=self.update_watcher,
                recreate=True,
            )
        except Exception as error:
            if self._desired is None or vm_hash not in self._desired.entries:
                # A newer plan dropped this VM while its create was in flight.
                # submit() has already pruned its state, and recording the
                # failure now would put it back for a VM nothing will retry,
                # leaving state_for reporting on something we have stopped
                # caring about until the next push clears it again.
                logger.info("Start of %s failed after the plan dropped it: %s", vm_hash, error)
                return
            self._record_failure(vm_hash, error)
            return
        if down is None or self._desired is None or vm_hash not in self._desired.entries:
            # A first create, or one the plan dropped while it was in flight:
            # submit() already pruned that VM's records, and putting one back
            # would leave state_for reporting on something nothing will retry.
            self._forget(vm_hash)
            return
        # The rebuild of a VM the supervisor held dead counts as a failed
        # attempt on the same backoff a failing create climbs, or a guest that
        # panics seconds after boot would be rebuilt at boot speed for ever.
        # The record outlives this successful start; _forget_settled drops it.
        record = self._note_attempt(vm_hash, code=AllocationFailureCode.VM_FAILED)
        logger.warning(
            "Rebuilt %s after the supervisor reported it %s (attempt %d, next rebuild not before %s)",
            vm_hash,
            down.status.value,
            record.attempts,
            record.next_retry_at,
        )
        # The supervisor knows the VM again, so the agent has no phase of its
        # own to report; only the count of what it took to get here.
        self._states.pop(vm_hash, None)

    def _forget(self, vm_hash: ItemHash) -> None:
        self._failures.pop(vm_hash, None)
        self._states.pop(vm_hash, None)

    def _record_failure(self, vm_hash: ItemHash, error: Exception) -> None:
        code = classify_start_failure(error)
        record = self._note_attempt(vm_hash, code=code)
        # The only place the exception's own text is kept: the executions list
        # answers anyone, and a create failure quotes host paths and figures.
        logger.warning(
            "Starting %s failed (attempt %d, published as %s): %s",
            vm_hash,
            record.attempts,
            code.value,
            error,
            # The traceback is the whole value of this line for the code that
            # says nothing (internal), and the published record carries no
            # text at all, so the log is the only place it can be read.
            exc_info=True,
        )
        self._states[vm_hash] = AllocationState.FAILED

    def _note_attempt(self, vm_hash: ItemHash, *, code: AllocationFailureCode) -> FailureRecord:
        # There is no terminal failure, on purpose. The plan is the authority
        # on what should run here, so a VM it still lists is still owed an
        # attempt, at the capped interval; giving up would leave a listed VM
        # not running with nothing outside this node able to tell. The
        # scheduler dropping the hash is what ends the retries, and submit()
        # clears the record then.
        now = self._now()
        previous = self._failures.get(vm_hash)
        attempts = (previous.attempts if previous else 0) + 1
        delay = min(
            settings.ALLOCATION_RETRY_BASE_INTERVAL * (2 ** (attempts - 1)),
            settings.ALLOCATION_RETRY_MAX_INTERVAL,
        )
        record = FailureRecord(
            code=code,
            attempts=attempts,
            last_failed_at=now,
            next_retry_at=now + timedelta(seconds=delay),
        )
        self._failures[vm_hash] = record
        return record
