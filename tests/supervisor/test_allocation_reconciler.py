"""Convergence: what one reconciler pass does with a plan.

Each test drives _converge_once() rather than the infinite run() loop, and
injects the clock so backoff assertions never sleep.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation import reconciler as reconciler_module
from aleph.vm.agent.allocation.plan import AllocationPlan, AllocationState, PlannedVm
from aleph.vm.agent.allocation.reconciler import AllocationReconciler
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmStatus

NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
HASH_B = ItemHash("b" * 64)
HASH_C = ItemHash("c" * 64)


def _hash(index: int) -> ItemHash:
    return ItemHash(f"{index:064x}")


def _info(vm_hash, status=VmStatus.RUNNING):
    return SimpleNamespace(
        vm_id=str(vm_hash),
        status=status,
        gpus=[],
        confidential_mode=ConfidentialMode.NONE,
        awaiting_confidential_init=False,
    )


def _record(*, stream=False, vprogram=False):
    return SimpleNamespace(
        persistent=True,
        uses_payment_stream=stream,
        uses_payment_credit=False,
        is_vprogram=vprogram,
        message=MagicMock(),
    )


def _plan(*hashes, refused=()):
    return AllocationPlan(
        plan_id="sha256:test",
        received_at=NOW,
        entries={h: PlannedVm(vm_hash=h) for h in hashes},
        refused=frozenset(refused),
    )


@pytest.fixture
def clock():
    return SimpleNamespace(now=NOW)


@pytest.fixture
def reconciler(clock, monkeypatch):
    """A reconciler over a fake supervisor and registry, with teardown and the
    create call replaced so tests can observe them."""
    supervisor = SimpleNamespace(list_vms=AsyncMock(return_value=[]), delete_vm=AsyncMock())
    registry = SimpleNamespace(get=lambda h: _record(), forget=MagicMock())
    monkeypatch.setattr(reconciler_module, "teardown_vm", AsyncMock())
    instance = AllocationReconciler(
        supervisor=supervisor,
        registry=registry,
        capacity=MagicMock(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
        pubsub_getter=lambda: None,
        now=lambda: clock.now,
    )
    instance.started = []
    return instance


def _record_starts(reconciler, monkeypatch, *, fail=False):
    """Replace start_persistent_vm, tracking attempts and peak concurrency."""
    state = SimpleNamespace(attempts=0, live=0, peak=0)

    async def fake_start(vm_hash, _pubsub, **_kwargs):
        state.attempts += 1
        state.live += 1
        state.peak = max(state.peak, state.live)
        try:
            await asyncio.sleep(0)
            if fail:
                msg = "download failed"
                raise RuntimeError(msg)
            reconciler.started.append(vm_hash)
        finally:
            state.live -= 1

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fake_start)
    return state


@pytest.mark.asyncio
async def test_with_no_plan_nothing_is_torn_down(reconciler):
    """The post-restart state. Acting on a remembered plan risks tearing down
    VMs that were migrated elsewhere during the downtime."""
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B)]

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_vm_dropped_from_the_plan_is_torn_down(reconciler, monkeypatch):
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    assert reconciler_module.teardown_vm.await_args.args[0] == HASH_B


@pytest.mark.asyncio
async def test_a_vm_a_newer_plan_re_added_is_not_torn_down(reconciler, monkeypatch):
    """A push landing while the pass was parked in list_vms, or in an earlier
    teardown, went unread: the pass held its own snapshot, so a VM the newer
    plan wants was retired as GONE and its volumes reaped. Every other step is
    safe to take one push out of date, because the next pass undoes it. This
    one is not."""
    _record_starts(reconciler, monkeypatch)
    reconciler.submit(_plan())

    async def list_vms():
        reconciler.submit(_plan(HASH_B))
        return [_info(HASH_B)]

    reconciler.supervisor.list_vms = list_vms

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_stream_paid_vm_is_never_torn_down(reconciler, monkeypatch):
    _record_starts(reconciler, monkeypatch)
    reconciler.registry = SimpleNamespace(get=lambda h: _record(stream=True), forget=MagicMock())
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_teardown_that_keeps_failing_does_not_block_the_starts(reconciler, monkeypatch):
    """Starts are isolated per VM; teardowns were not, so one VM the supervisor
    refused to delete aborted the pass before _start_missing ran, on every
    interval, and teardowns have no backoff to slow that down."""
    starts = _record_starts(reconciler, monkeypatch)
    monkeypatch.setattr(reconciler_module, "teardown_vm", AsyncMock(side_effect=RuntimeError("delete failed")))
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B)]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert starts.attempts == 1


@pytest.mark.asyncio
async def test_a_vm_id_that_is_not_a_hash_does_not_wedge_the_pass(reconciler, monkeypatch):
    """The supervisor's list is not ours to vouch for: an operator's own VM, or
    a second tenant's, carries an id we cannot parse. Converting it unguarded
    raised out of the pass before any teardown or start ran, and since run()
    logs and retries, the reconciler went on looking alive while converging
    nothing for as long as that VM existed."""
    starts = _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info("operator-scratch-vm")]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert starts.attempts == 1


@pytest.mark.asyncio
async def test_a_planned_vm_the_supervisor_does_not_have_is_started(reconciler, monkeypatch):
    _record_starts(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert reconciler.started == [HASH_C]


@pytest.mark.asyncio
async def test_a_planned_vm_already_running_is_left_alone(reconciler, monkeypatch):
    starts = _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_C)]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert starts.attempts == 0


@pytest.mark.asyncio
async def test_creates_respect_the_concurrency_bound(reconciler, monkeypatch):
    """Downloads overlap, but not without bound: one host, one disk."""
    monkeypatch.setattr(settings, "ALLOCATION_DOWNLOAD_CONCURRENCY", 2)
    starts = _record_starts(reconciler, monkeypatch)
    reconciler.submit(_plan(*[_hash(i) for i in range(6)]))

    await reconciler._converge_once()

    assert starts.attempts == 6
    assert starts.peak == 2


@pytest.mark.asyncio
async def test_a_failed_start_is_remembered_with_a_retry_time(reconciler, monkeypatch):
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    state, failure = reconciler.state_for(HASH_C)
    assert state is AllocationState.FAILED
    assert failure.attempts == 1
    assert failure.next_retry_at == NOW + timedelta(seconds=settings.ALLOCATION_RETRY_BASE_INTERVAL)


@pytest.mark.asyncio
async def test_a_failure_is_not_retried_before_its_backoff_expires(reconciler, monkeypatch):
    starts = _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()
    await reconciler._converge_once()

    assert starts.attempts == 1


@pytest.mark.asyncio
async def test_backoff_doubles_and_is_capped(reconciler, monkeypatch, clock):
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    delays = []

    for _ in range(8):
        await reconciler._converge_once()
        _, failure = reconciler.state_for(HASH_C)
        delays.append((failure.next_retry_at - clock.now).total_seconds())
        clock.now = failure.next_retry_at

    assert delays[0] == settings.ALLOCATION_RETRY_BASE_INTERVAL
    assert delays[1] == settings.ALLOCATION_RETRY_BASE_INTERVAL * 2
    assert max(delays) == settings.ALLOCATION_RETRY_MAX_INTERVAL


@pytest.mark.asyncio
async def test_a_start_that_fails_after_the_plan_drops_it_is_not_remembered(reconciler, monkeypatch):
    """submit() prunes the state of a VM it drops, but a create already in
    flight recorded its failure afterwards and put the record back, so
    state_for went on reporting a VM nothing would ever retry."""

    async def fake_start(vm_hash, _pubsub, **_kwargs):
        reconciler.submit(_plan())
        msg = "download failed"
        raise RuntimeError(msg)

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fake_start)
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_vm_that_leaves_the_plan_loses_its_failure_record(reconciler, monkeypatch):
    """Otherwise a hash the scheduler gave up on is retried forever."""
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    reconciler.submit(_plan())

    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_vm_the_plan_still_lists_keeps_its_backoff(reconciler, monkeypatch):
    """The complement of the test above: submit() prunes the state of the VMs
    it drops and only those. Pruning every VM would hand a scheduler polling
    with the same plan a fresh attempt on each push, which is exactly the
    hammering the backoff exists to stop."""
    starts = _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    assert starts.attempts == 1
    _, failure = reconciler.state_for(HASH_C)
    assert failure.attempts == 1


@pytest.mark.asyncio
async def test_a_successful_start_clears_a_previous_failure(reconciler, monkeypatch, clock):
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    _, failure = reconciler.state_for(HASH_C)
    clock.now = failure.next_retry_at
    _record_starts(reconciler, monkeypatch, fail=False)

    await reconciler._converge_once()

    assert reconciler.state_for(HASH_C) == (None, None)


# ── A guest that dies after it started ─────────────────────────────────────


def _boots_then(reconciler, monkeypatch, status=VmStatus.FAILED):
    """A start that works, after which the supervisor holds the VM in `status`.

    With FAILED that is a guest which boots and dies, the crash loop; with
    RUNNING it is a VM that stays up. Returns the list the fake supervisor
    answers with, so a test can change what the VM is doing afterwards.
    """
    listed: list = []

    async def fake_start(vm_hash, _pubsub, **_kwargs):
        reconciler.started.append(vm_hash)
        listed[:] = [_info(vm_hash, status=status)]

    async def list_vms():
        return list(listed)

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fake_start)
    reconciler.supervisor.list_vms = list_vms
    return listed


@pytest.mark.asyncio
async def test_a_guest_that_dies_after_it_started_is_rebuilt_on_the_backoff(reconciler, monkeypatch, clock):
    """Rebuilding a VM the supervisor already holds dead is a retry like any
    other, and used to be free: the successful start erased the failure
    record, the FAILED event woke the loop, and the next pass found nothing to
    gate it. A guest that panics on boot was rebuilt from scratch at boot
    speed, disks and all, for as long as the plan listed it."""
    _boots_then(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()  # the first create
    await reconciler._converge_once()  # it died: rebuilt at once, and counted

    assert reconciler.started == [HASH_C, HASH_C]
    _, failure = reconciler.state_for(HASH_C)
    assert failure.attempts == 1
    assert failure.next_retry_at == NOW + timedelta(seconds=settings.ALLOCATION_RETRY_BASE_INTERVAL)

    await reconciler._converge_once()  # still dead, but not due yet
    assert reconciler.started == [HASH_C, HASH_C]

    clock.now = failure.next_retry_at
    await reconciler._converge_once()

    assert reconciler.started == [HASH_C, HASH_C, HASH_C]
    _, failure = reconciler.state_for(HASH_C)
    assert failure.attempts == 2
    assert failure.next_retry_at == clock.now + timedelta(seconds=settings.ALLOCATION_RETRY_BASE_INTERVAL * 2)


@pytest.mark.asyncio
async def test_the_rebuild_backoff_doubles_and_is_capped(reconciler, monkeypatch, clock):
    """The same ladder a failed create climbs, on the same two settings."""
    _boots_then(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()  # the first create
    delays = []

    for _ in range(8):
        await reconciler._converge_once()
        _, failure = reconciler.state_for(HASH_C)
        delays.append((failure.next_retry_at - clock.now).total_seconds())
        clock.now = failure.next_retry_at

    assert delays[0] == settings.ALLOCATION_RETRY_BASE_INTERVAL
    assert delays[1] == settings.ALLOCATION_RETRY_BASE_INTERVAL * 2
    assert max(delays) == settings.ALLOCATION_RETRY_MAX_INTERVAL


@pytest.mark.asyncio
async def test_a_vm_that_stays_up_accumulates_no_attempts(reconciler, monkeypatch, clock):
    """The rebuild count is charged for a death, not for existing."""
    _boots_then(reconciler, monkeypatch, status=VmStatus.RUNNING)
    reconciler.submit(_plan(HASH_C))

    for _ in range(3):
        await reconciler._converge_once()
        clock.now += timedelta(seconds=settings.ALLOCATION_RECONCILE_INTERVAL)

    assert reconciler.started == [HASH_C]
    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_rebuilt_vm_that_stays_up_loses_its_crash_record(reconciler, monkeypatch, clock):
    """The count must not be immortal, or a VM that crashed once a month ago
    would take the capped wait for a rebuild it deserves at once. It is
    dropped once the VM has been up longer than the longest wait the backoff
    can impose, past which the next death is a new problem rather than the
    tail of the old one."""
    listed = _boots_then(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    await reconciler._converge_once()
    assert reconciler.state_for(HASH_C)[1].attempts == 1

    listed[:] = [_info(HASH_C, status=VmStatus.RUNNING)]
    clock.now = NOW + timedelta(seconds=settings.ALLOCATION_RETRY_MAX_INTERVAL - 1)
    await reconciler._converge_once()
    assert reconciler.state_for(HASH_C)[1].attempts == 1

    clock.now = NOW + timedelta(seconds=settings.ALLOCATION_RETRY_MAX_INTERVAL)
    await reconciler._converge_once()

    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_vm_waiting_out_its_rebuild_backoff_says_so(reconciler, monkeypatch):
    """What the executions list has to report while a rebuild is held back:
    the attempts and when it will happen, rather than a dead VM the agent
    looks to have no opinion about."""
    _boots_then(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    await reconciler._converge_once()

    await reconciler._converge_once()

    state, failure = reconciler.state_for(HASH_C)
    assert state is AllocationState.FAILED
    assert failure.attempts == 1
    assert failure.next_retry_at == NOW + timedelta(seconds=settings.ALLOCATION_RETRY_BASE_INTERVAL)


@pytest.mark.asyncio
async def test_a_rebuild_the_plan_dropped_mid_flight_is_not_remembered(reconciler, monkeypatch):
    """The same rule the failing create follows: submit() prunes the state of
    a VM it drops, and a rebuild that lands afterwards must not put it back
    for a VM nothing will retry."""

    async def fake_start(vm_hash, _pubsub, **_kwargs):
        reconciler.submit(_plan())

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fake_start)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_C, status=VmStatus.FAILED)]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert reconciler.state_for(HASH_C) == (None, None)


# ── A VM the owner stopped ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_owner_stopped_vm_is_left_alone_even_when_the_plan_lists_it(reconciler, monkeypatch):
    """Stop means stop. The operator API leaves a persistent VM STOPPED and
    still defined, and the loop used to read that as a VM it owed a start: the
    down event woke it and the next pass started the VM again. A push does not
    override it either, which is the whole of the rule: the plan is
    level-triggered and re-pushed for as long as the VM is allocated here, so
    a push that restarted it would leave the owner unable to keep the VM down
    at all. Whoever stopped it is who starts it again."""
    listed = _boots_then(reconciler, monkeypatch, status=VmStatus.RUNNING)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    assert reconciler.started == [HASH_C]

    listed[:] = [_info(HASH_C, status=VmStatus.STOPPED)]
    await reconciler._converge_once()
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    assert reconciler.started == [HASH_C]


@pytest.mark.asyncio
async def test_a_stop_does_not_wake_the_loop_but_a_failure_does(reconciler):
    """The watcher reports both, and the loop has work to do for one of them:
    a stopped VM is left where its owner put it, a failed one is rebuilt now."""
    reconciler.submit(_plan(HASH_C))
    reconciler._wakeup.clear()

    reconciler.notify_vm_down(str(HASH_C), VmStatus.STOPPED)
    assert reconciler._wakeup.is_set() is False

    reconciler.notify_vm_down(str(HASH_C), VmStatus.FAILED)
    assert reconciler._wakeup.is_set() is True


@pytest.mark.asyncio
async def test_a_vm_that_died_is_still_rebuilt_on_a_nudge(reconciler, monkeypatch):
    """The complement: only a stop is somebody's decision. A guest that
    crashed is rebuilt on the event, without waiting for anything."""
    listed = _boots_then(reconciler, monkeypatch, status=VmStatus.RUNNING)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    reconciler._wakeup.clear()

    listed[:] = [_info(HASH_C, status=VmStatus.FAILED)]
    reconciler.notify_vm_down(str(HASH_C), VmStatus.FAILED)
    assert reconciler._wakeup.is_set() is True

    await reconciler._converge_once()

    assert reconciler.started == [HASH_C, HASH_C]


@pytest.mark.asyncio
async def test_a_stopped_vm_reports_nothing_of_its_own(reconciler, monkeypatch):
    """What the executions list renders for a stopped VM. The supervisor
    already says STOPPED, and the agent has no plan of its own for it, so an
    allocation block would have to claim the VM is failing or being worked on,
    and neither is true."""
    listed = _boots_then(reconciler, monkeypatch, status=VmStatus.RUNNING)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    listed[:] = [_info(HASH_C, status=VmStatus.STOPPED)]
    await reconciler._converge_once()

    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_vm_caught_mid_stop_is_left_alone_too(reconciler, monkeypatch):
    """A stop caught in flight is still a stop. Read as work to do, STOPPING
    sends the loop down start_persistent_vm's wait-until-gone path, so it
    would wait the VM out and recreate from scratch the one the owner is only
    stopping."""
    listed = _boots_then(reconciler, monkeypatch, status=VmStatus.RUNNING)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()
    assert reconciler.started == [HASH_C]

    listed[:] = [_info(HASH_C, status=VmStatus.STOPPING)]
    await reconciler._converge_once()
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    assert reconciler.started == [HASH_C]
    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_vm_this_node_already_holds_stopped_is_not_started_by_a_plan(reconciler, monkeypatch):
    """The rule does not rest on the loop remembering that it started the VM.
    After an agent restart the loop knows nothing about who stopped what, and
    a plan listing a VM this node holds stopped says the VM is allocated here,
    not that the node should boot it."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_C, status=VmStatus.STOPPED)]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert reconciler.started == []
    assert reconciler.state_for(HASH_C) == (None, None)


@pytest.mark.asyncio
async def test_a_stopped_vm_whose_last_start_failed_still_says_why(reconciler, monkeypatch):
    """A start the node was asked to make and could not is its own news, and
    it survives the VM turning up stopped: the create got as far as defining
    the VM and then raised. An owner's stop is nothing for the agent to
    report, since the supervisor already says STOPPED, but the failure and the
    attempt count behind it are."""
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    reconciler.supervisor.list_vms.return_value = [_info(HASH_C, status=VmStatus.STOPPED)]
    await reconciler._converge_once()

    state, failure = reconciler.state_for(HASH_C)
    assert state is AllocationState.FAILED
    assert failure.code == "RuntimeError"


@pytest.mark.asyncio
async def test_a_stopped_vm_the_plan_stops_naming_is_still_torn_down(reconciler, monkeypatch):
    """The scheduler's own move, and the only one that ends a stop. Refusing
    to restart a stopped VM is not holding on to it forever: dropping the hash
    unallocates it, and the sweep reaps a stopped VM the way it reaps a
    running one."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B, status=VmStatus.STOPPED)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    assert reconciler_module.teardown_vm.await_args.args[0] == HASH_B


def test_pending_hashes_are_the_entries_the_push_carried_no_message_for(reconciler):
    reconciler.submit(
        AllocationPlan(
            plan_id="sha256:test",
            received_at=NOW,
            entries={
                HASH_B: PlannedVm(vm_hash=HASH_B, verified=SimpleNamespace(message=MagicMock())),
                HASH_C: PlannedVm(vm_hash=HASH_C),
            },
        )
    )

    assert reconciler.pending_hashes() == {HASH_C}
    assert reconciler.planned_hashes() == {HASH_B, HASH_C}


@pytest.mark.asyncio
async def test_a_newer_plan_supersedes_the_previous_one(reconciler, monkeypatch):
    """Level-triggered: the desired state is re-read every pass."""
    _record_starts(reconciler, monkeypatch)
    reconciler.submit(_plan(HASH_C))
    reconciler.submit(_plan(HASH_B))

    await reconciler._converge_once()

    assert reconciler.started == [HASH_B]


@pytest.mark.asyncio
async def test_the_event_watcher_nudges_the_reconciler_when_a_vm_goes_down():
    """A VM that dies while still planned must be retried at once, not at the
    backstop interval. The watcher is the agent's only push channel for it.

    Covered here rather than in the watcher's own suite, which no longer
    exists: removing the Python supervisor daemon deleted that file wholesale
    because its fixtures were built on LocalSupervisor, even though
    watch_supervisor_events is agent-side and survived.
    """
    from aleph.vm.agent.supervisor import watch_supervisor_events
    from aleph.vm.supervisor_interface.types import VmEvent, VmId

    vm_id = VmId(str(HASH_C))
    boot = VmEvent(vm_id=vm_id, old_status=VmStatus.DEFINED, new_status=VmStatus.RUNNING, timestamp_ns=1)
    stop = VmEvent(vm_id=vm_id, old_status=VmStatus.RUNNING, new_status=VmStatus.STOPPED, timestamp_ns=2)
    consumed = asyncio.Event()

    class FakeSupervisor:
        async def watch_events(self):
            yield boot  # coming up is not going down: must not nudge
            yield stop
            consumed.set()
            await asyncio.Event().wait()  # block like a live stream

    app: dict[str, Any] = {
        "supervisor": FakeSupervisor(),
        "expiry": MagicMock(),
        "update_watcher": MagicMock(),
        "program_client": MagicMock(forget=AsyncMock()),
        "allocation_reconciler": MagicMock(),
    }

    task = asyncio.ensure_future(watch_supervisor_events(app))
    await asyncio.wait_for(consumed.wait(), timeout=2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    # The status travels with the nudge: what the reconciler owes a VM that
    # went down depends on whether somebody stopped it or it died.
    app["allocation_reconciler"].notify_vm_down.assert_called_once_with(vm_id, VmStatus.STOPPED)


@pytest.mark.asyncio
async def test_notify_vm_down_wakes_the_loop_only_for_a_planned_vm(reconciler):
    """The watcher calls this for every VM that goes down, most of which this
    reconciler has no opinion about. Waking on those is pure churn."""
    reconciler.submit(_plan(HASH_C))
    reconciler._wakeup.clear()

    reconciler.notify_vm_down(str(HASH_B), VmStatus.FAILED)
    assert reconciler._wakeup.is_set() is False

    reconciler.notify_vm_down(str(HASH_C), VmStatus.FAILED)
    assert reconciler._wakeup.is_set() is True


@pytest.mark.asyncio
async def test_a_dropped_vm_is_torn_down_even_if_it_already_died(reconciler, monkeypatch):
    """A FAILED VM dropped from the plan still owns disks and a registry record
    that keeps counting against capacity, so leaving it is a slow leak."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B, status=VmStatus.FAILED)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    assert reconciler_module.teardown_vm.await_args.args[0] == HASH_B


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [VmStatus.STOPPED, VmStatus.FAILED])
async def test_a_vm_the_answer_only_refused_is_not_torn_down(reconciler, monkeypatch, status):
    """A refused VM is not in the plan's entries, and that absence used to
    read as "the scheduler dropped it": the pass retired it GONE, which drops
    the record and the DB rows and reaps the volumes. The scheduler was told
    the VM was rejected, which is not that it was deleted, and every refusal
    the answer can give here is temporary: no room today, or a node that has
    not learned its own hash back yet."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B, status=status)]
    reconciler.submit(_plan(refused=[HASH_B]))

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_refusal_does_not_spare_the_vms_the_push_left_out(reconciler, monkeypatch):
    """The skip is exactly the hashes the push named. A VM it did not name is
    still dropped, refusals elsewhere in the same push or not."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B, status=VmStatus.STOPPED), _info(HASH_C)]
    reconciler.submit(_plan(refused=[HASH_B]))

    await reconciler._converge_once()

    assert [call.args[0] for call in reconciler_module.teardown_vm.await_args_list] == [HASH_C]


@pytest.mark.asyncio
async def test_a_vm_a_newer_plan_refused_is_not_torn_down(reconciler, monkeypatch):
    """The mid-pass re-read covers a refusal like it covers a re-add: a push
    that lands while the pass is parked in list_vms and refuses this VM has
    still named it, so the pass must not carry on and delete it."""
    _record_starts(reconciler, monkeypatch)
    reconciler.submit(_plan())

    async def list_vms():
        reconciler.submit(_plan(refused=[HASH_B]))
        return [_info(HASH_B)]

    reconciler.supervisor.list_vms = list_vms

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [VmStatus.DEFINED, VmStatus.BOOTING])
async def test_a_vm_still_being_created_is_not_torn_down(reconciler, monkeypatch, status):
    """Both are mid-creation: deleting one races the create still in flight."""
    _record_starts(reconciler, monkeypatch)
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B, status=status)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_vm_waiting_on_its_confidential_session_is_not_started_again(reconciler, monkeypatch):
    """A confidential VM sits in a non-live status until its owner uploads the
    session certificates, so status alone reads as one that needs creating.
    Creating it again would throw away the VM the owner is about to boot."""
    starts = _record_starts(reconciler, monkeypatch)
    awaiting = _info(HASH_C, status=VmStatus.STOPPED)
    awaiting.awaiting_confidential_init = True
    reconciler.supervisor.list_vms.return_value = [awaiting]
    reconciler.submit(_plan(HASH_C))

    await reconciler._converge_once()

    assert starts.attempts == 0


# ── The loop around a pass ─────────────────────────────────────────────────


def _stop_after(reconciler, monkeypatch, passes: int, *, failing: int | None = None):
    """Drive run() for a fixed number of passes, then cancel out of it."""
    seen: list[int] = []

    async def fake_converge():
        seen.append(len(seen) + 1)
        if failing is not None and len(seen) == failing:
            msg = "pass blew up"
            raise RuntimeError(msg)
        if len(seen) == passes:
            raise asyncio.CancelledError

    monkeypatch.setattr(reconciler, "_converge_once", fake_converge)
    return seen


@pytest.mark.asyncio
async def test_the_loop_converges_again_when_it_is_woken(reconciler, monkeypatch):
    """A wake-up already set must be seen rather than waited out: the interval
    is the backstop, not the pace."""
    monkeypatch.setattr(settings, "ALLOCATION_RECONCILE_INTERVAL", 3600)
    seen = _stop_after(reconciler, monkeypatch, passes=2)
    reconciler._wakeup.set()

    # Bounded, so a wake-up cleared before the wait fails here in a second
    # rather than sitting out the backstop it was supposed to pre-empt.
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(reconciler.run(), timeout=1)

    assert len(seen) == 2


@pytest.mark.asyncio
async def test_a_quiet_interval_does_not_end_the_loop(reconciler, monkeypatch):
    """Nothing wakes it, so the backstop expires and wait_for raises. Letting
    that escape would end convergence for the life of the process."""
    monkeypatch.setattr(settings, "ALLOCATION_RECONCILE_INTERVAL", 0.01)
    seen = _stop_after(reconciler, monkeypatch, passes=2)

    with pytest.raises(asyncio.CancelledError):
        await reconciler.run()

    assert len(seen) == 2


@pytest.mark.asyncio
async def test_a_pass_that_raises_does_not_end_the_loop(reconciler, monkeypatch):
    """One bad pass is not a reason to stop converging: the next one may find
    the supervisor answering again."""
    monkeypatch.setattr(settings, "ALLOCATION_RECONCILE_INTERVAL", 0.01)
    seen = _stop_after(reconciler, monkeypatch, passes=2, failing=1)

    with pytest.raises(asyncio.CancelledError):
        await reconciler.run()

    assert len(seen) == 2
