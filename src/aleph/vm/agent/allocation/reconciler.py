"""Converging the CRN onto the scheduler's plan, in the background.

Level-triggered, not event-sourced: each pass re-reads the desired state and
diffs it against what the supervisor reports, so a re-pushed identical plan is
an empty diff and a plan arriving mid-convergence simply wins at the next step
boundary. This is the seam pull mode plugs into: replacing "the scheduler
pushed a plan" with "the agent fetched a plan" is a change to submit()'s
caller and nothing else.
"""

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.plan import (
    LIVE_STATUSES,
    AllocationPlan,
    AllocationState,
    FailureRecord,
    by_hash,
)
from aleph.vm.agent.allocation.teardown import is_removable_by_allocation, teardown_vm
from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.expiry import ExpiryManager
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
        pubsub_getter: Callable[[], object | None],
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

    def notify_vm_down(self, vm_id: str) -> None:
        """A VM went STOPPED or FAILED. If the plan still wants it, converge."""
        if self._desired is None:
            return
        try:
            vm_hash = ItemHash(str(vm_id))
        except (UnknownHashError, ValueError):
            # Not ours to converge, and the event stream is no place to raise.
            return
        if vm_hash in self._desired.entries:
            self._wakeup.set()

    def planned_hashes(self) -> set[ItemHash]:
        return set(self._desired.entries) if self._desired else set()

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

        infos = await self.supervisor.list_vms()
        await self._teardown_dropped(plan, infos)
        await self._start_missing(plan, infos)

    async def _teardown_dropped(self, plan: AllocationPlan, infos: list[VmInfo]) -> None:
        for vm_hash, info in by_hash(infos).items():
            if vm_hash in plan.entries or info.status not in TEARDOWN_STATUSES:
                continue
            # The plan is re-read here rather than taken from the pass, which
            # may have been parked in list_vms or in an earlier teardown while
            # a push re-added this VM. A start can afford to act on a snapshot
            # one push out of date, because the next pass undoes it; a teardown
            # cannot, since GONE reaps the volumes. The read and the await
            # below are in one turn, so nothing lands in between.
            current = self._desired
            if current is None or vm_hash in current.entries:
                continue
            record = self.registry.get(vm_hash)
            if record is None or not is_removable_by_allocation(record, info):
                continue
            logger.info("Plan %s dropped %s; tearing it down", current.plan_id, vm_hash)
            try:
                await teardown_vm(vm_hash, supervisor=self.supervisor, registry=self.registry)
            except Exception:
                # Isolated per VM, the way _start_one isolates a start. One VM
                # the supervisor will not delete used to abort the pass here,
                # before a single start ran, and teardowns carry no backoff, so
                # it did that on every interval for as long as it kept failing.
                logger.exception("Tearing down %s failed; leaving it for the next pass", vm_hash)

    async def _start_missing(self, plan: AllocationPlan, infos: list[VmInfo]) -> None:
        live = {
            vm_hash
            for vm_hash, info in by_hash(infos).items()
            if info.status in LIVE_STATUSES or info.awaiting_confidential_init
        }
        now = self._now()
        todo = [vm_hash for vm_hash in plan.entries if vm_hash not in live and self._retry_due(vm_hash, now)]
        if not todo:
            return

        semaphore = asyncio.Semaphore(settings.ALLOCATION_DOWNLOAD_CONCURRENCY)

        async def start(vm_hash: ItemHash) -> None:
            async with semaphore:
                await self._start_one(vm_hash)

        await asyncio.gather(*(start(vm_hash) for vm_hash in todo), return_exceptions=True)

    def _retry_due(self, vm_hash: ItemHash, now: datetime) -> bool:
        failure = self._failures.get(vm_hash)
        return failure is None or failure.next_retry_at <= now

    async def _start_one(self, vm_hash: ItemHash) -> None:
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
        self._forget(vm_hash)

    def _forget(self, vm_hash: ItemHash) -> None:
        self._failures.pop(vm_hash, None)
        self._states.pop(vm_hash, None)

    def _record_failure(self, vm_hash: ItemHash, error: Exception) -> None:
        now = self._now()
        previous = self._failures.get(vm_hash)
        attempts = (previous.attempts if previous else 0) + 1
        delay = min(
            settings.ALLOCATION_RETRY_BASE_INTERVAL * (2 ** (attempts - 1)),
            settings.ALLOCATION_RETRY_MAX_INTERVAL,
        )
        code = getattr(getattr(error, "code", None), "value", "") or type(error).__name__
        logger.warning("Starting %s failed (attempt %d): %s", vm_hash, attempts, error)
        self._failures[vm_hash] = FailureRecord(
            code=code,
            message=str(error)[:200],
            attempts=attempts,
            first_failed_at=previous.first_failed_at if previous else now,
            last_failed_at=now,
            next_retry_at=now + timedelta(seconds=delay),
        )
        self._states[vm_hash] = AllocationState.FAILED
