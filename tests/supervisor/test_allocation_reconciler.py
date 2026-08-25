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
async def test_a_stream_paid_vm_is_never_torn_down(reconciler, monkeypatch):
    _record_starts(reconciler, monkeypatch)
    reconciler.registry = SimpleNamespace(get=lambda h: _record(stream=True), forget=MagicMock())
    reconciler.supervisor.list_vms.return_value = [_info(HASH_B)]
    reconciler.submit(_plan())

    await reconciler._converge_once()

    reconciler_module.teardown_vm.assert_not_awaited()


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
async def test_a_vm_that_leaves_the_plan_loses_its_failure_record(reconciler, monkeypatch):
    """Otherwise a hash the scheduler gave up on is retried forever."""
    _record_starts(reconciler, monkeypatch, fail=True)
    reconciler.submit(_plan(HASH_C))
    await reconciler._converge_once()

    reconciler.submit(_plan())

    assert reconciler.state_for(HASH_C) == (None, None)


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
