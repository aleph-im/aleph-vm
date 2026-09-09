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


def _plan(*hashes):
    return AllocationPlan(plan_id="sha256:test", received_at=NOW, entries={h: PlannedVm(vm_hash=h) for h in hashes})


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

    app["allocation_reconciler"].notify_vm_down.assert_called_once_with(vm_id)


@pytest.mark.asyncio
async def test_notify_vm_down_wakes_the_loop_only_for_a_planned_vm(reconciler):
    """The watcher calls this for every VM that goes down, most of which this
    reconciler has no opinion about. Waking on those is pure churn."""
    reconciler.submit(_plan(HASH_C))
    reconciler._wakeup.clear()

    reconciler.notify_vm_down(str(HASH_B))
    assert reconciler._wakeup.is_set() is False

    reconciler.notify_vm_down(str(HASH_C))
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
