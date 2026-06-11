"""WatchEvents: in-process emission, wire transport, and the agent watcher."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import VmEvent, VmId, VmStatus

VM_ID = VmId("itemhash123")


def _pool_with_running_vm():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    return pool, execution


async def _collect_events(supervisor, count: int, timeout: float = 2.0) -> list[VmEvent]:
    events: list[VmEvent] = []
    gen = supervisor.watch_events()

    async def consume():
        async for event in gen:
            events.append(event)
            if len(events) == count:
                return

    await asyncio.wait_for(consume(), timeout=timeout)
    await gen.aclose()
    return events


@pytest.mark.asyncio
async def test_delete_vm_emits_stopped_event():
    pool, _ = _pool_with_running_vm()
    sup = InProcessSupervisor(pool=pool)

    collector = asyncio.ensure_future(_collect_events(sup, 1))
    await asyncio.sleep(0)  # let the watcher subscribe
    await sup.delete_vm(VM_ID)
    events = await collector

    assert events[0].vm_id == VM_ID
    assert events[0].old_status is VmStatus.RUNNING
    assert events[0].new_status is VmStatus.STOPPED
    assert events[0].timestamp_ns > 0


@pytest.mark.asyncio
async def test_reboot_persistent_emits_down_then_up():
    pool, _ = _pool_with_running_vm()
    pool.systemd_manager.restart = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    collector = asyncio.ensure_future(_collect_events(sup, 2))
    await asyncio.sleep(0)
    await sup.reboot_vm(VM_ID)
    events = await collector

    assert [e.new_status for e in events] == [VmStatus.STOPPED, VmStatus.RUNNING]


@pytest.mark.asyncio
async def test_events_without_watchers_are_a_noop():
    pool, _ = _pool_with_running_vm()
    sup = InProcessSupervisor(pool=pool)
    await sup.delete_vm(VM_ID)  # no watcher subscribed: must not raise


@pytest.mark.asyncio
async def test_closing_the_stream_unsubscribes():
    pool, _ = _pool_with_running_vm()
    sup = InProcessSupervisor(pool=pool)

    gen = sup.watch_events()
    task = asyncio.ensure_future(anext(gen))
    await asyncio.sleep(0)
    assert len(sup._event_queues) == 1
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)
    await gen.aclose()
    assert len(sup._event_queues) == 0


@pytest.mark.asyncio
async def test_agent_watcher_drops_program_state_on_stop_event():
    """The split-mode agent watcher cancels timers and forgets guest state
    when the supervisor reports a VM going down."""
    from aleph.vm.orchestrator.supervisor import watch_supervisor_events

    stop_event = VmEvent(vm_id=VM_ID, old_status=VmStatus.RUNNING, new_status=VmStatus.STOPPED, timestamp_ns=1)
    boot_event = VmEvent(vm_id=VM_ID, old_status=VmStatus.DEFINED, new_status=VmStatus.RUNNING, timestamp_ns=2)
    consumed = asyncio.Event()

    class FakeSupervisor:
        async def watch_events(self):
            yield boot_event  # must not trigger any drop
            yield stop_event
            consumed.set()
            await asyncio.Event().wait()  # block like a live stream

    app = {
        "supervisor": FakeSupervisor(),
        "expiry": MagicMock(),
        "update_watcher": MagicMock(),
        "program_client": MagicMock(forget=AsyncMock()),
    }

    task = asyncio.ensure_future(watch_supervisor_events(app))
    await asyncio.wait_for(consumed.wait(), timeout=2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    app["expiry"].cancel.assert_called_once_with(VM_ID)
    app["update_watcher"].cancel.assert_called_once_with(VM_ID)
    app["program_client"].forget.assert_awaited_once_with(VM_ID)


@pytest.mark.asyncio
async def test_watch_events_round_trips_over_the_wire():
    from test_supervisor_grpc import _ServerHarness

    pool, _ = _pool_with_running_vm()
    inprocess = InProcessSupervisor(pool=pool)
    harness = _ServerHarness(inprocess)
    async with harness as client:
        received: list[VmEvent] = []
        got_one = asyncio.Event()

        async def consume():
            async for event in client.watch_events():
                received.append(event)
                got_one.set()
                return

        consumer = asyncio.ensure_future(consume())
        # Wait for the server-side subscription before emitting.
        for _ in range(100):
            if inprocess._event_queues:
                break
            await asyncio.sleep(0.01)
        inprocess._emit_event(VM_ID, VmStatus.RUNNING, VmStatus.STOPPED)
        await asyncio.wait_for(got_one.wait(), timeout=2)
        await consumer

    assert received[0].vm_id == VM_ID
    assert received[0].old_status is VmStatus.RUNNING
    assert received[0].new_status is VmStatus.STOPPED
