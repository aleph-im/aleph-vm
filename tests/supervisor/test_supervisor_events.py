"""WatchEvents: in-process emission, wire transport, and the agent watcher."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.types import VmEvent, VmId, VmStatus

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
    sup = LocalSupervisor(pool=pool)

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
    sup = LocalSupervisor(pool=pool)

    collector = asyncio.ensure_future(_collect_events(sup, 2))
    await asyncio.sleep(0)
    await sup.reboot_vm(VM_ID)
    events = await collector

    assert [e.new_status for e in events] == [VmStatus.STOPPED, VmStatus.RUNNING]


@pytest.mark.asyncio
async def test_events_without_watchers_are_a_noop():
    pool, _ = _pool_with_running_vm()
    sup = LocalSupervisor(pool=pool)
    await sup.delete_vm(VM_ID)  # no watcher subscribed: must not raise


@pytest.mark.asyncio
async def test_closing_the_stream_unsubscribes():
    pool, _ = _pool_with_running_vm()
    sup = LocalSupervisor(pool=pool)

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
    from aleph.vm.agent.supervisor import watch_supervisor_events

    stop_event = VmEvent(vm_id=VM_ID, old_status=VmStatus.RUNNING, new_status=VmStatus.STOPPED, timestamp_ns=1)
    boot_event = VmEvent(vm_id=VM_ID, old_status=VmStatus.DEFINED, new_status=VmStatus.RUNNING, timestamp_ns=2)
    consumed = asyncio.Event()

    class FakeSupervisor:
        async def watch_events(self):
            yield boot_event  # must not trigger any drop
            yield stop_event
            consumed.set()
            await asyncio.Event().wait()  # block like a live stream

    app: dict[str, Any] = {
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
    local = LocalSupervisor(pool=pool)
    harness = _ServerHarness(local)
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
            if local._event_queues:
                break
            await asyncio.sleep(0.01)
        local._emit_event(VM_ID, VmStatus.RUNNING, VmStatus.STOPPED)
        await asyncio.wait_for(got_one.wait(), timeout=2)
        await consumer

    assert received[0].vm_id == VM_ID
    assert received[0].old_status is VmStatus.RUNNING
    assert received[0].new_status is VmStatus.STOPPED


@pytest.mark.asyncio
async def test_agent_watcher_reconciles_missed_events_on_reconnect(monkeypatch):
    """Events lost while the stream was down must be compensated on reconnect:
    every tracked VM that is now STOPPED, FAILED or gone gets the same drop
    the missed event would have triggered; running VMs are left alone."""
    from aleph.vm.agent import supervisor as agent_supervisor

    running_vm = VmId("vm-running")
    stopped_vm = VmId("vm-stopped")
    gone_vm = VmId("vm-gone")

    reconnected = asyncio.Event()

    class FakeSupervisor:
        def __init__(self):
            self.calls = 0

        async def watch_events(self):
            self.calls += 1
            if self.calls == 1:
                msg = "stream dropped"
                raise ConnectionError(msg)
            reconnected.set()
            await asyncio.Event().wait()  # block like a live stream
            yield  # pragma: no cover  (makes this an async generator)

        async def list_vms(self):
            return [
                MagicMock(vm_id=running_vm, status=VmStatus.RUNNING),
                MagicMock(vm_id=stopped_vm, status=VmStatus.STOPPED),
            ]

    tracked = {running_vm, stopped_vm, gone_vm}
    app: dict[str, Any] = {
        "supervisor": FakeSupervisor(),
        "expiry": MagicMock(tracked=MagicMock(return_value=set(tracked))),
        "update_watcher": MagicMock(tracked=MagicMock(return_value=set(tracked))),
        "program_client": MagicMock(tracked=MagicMock(return_value=set(tracked)), forget=AsyncMock()),
    }

    monkeypatch.setattr(agent_supervisor, "RECONNECT_DELAY", 0)
    task = asyncio.ensure_future(agent_supervisor.watch_supervisor_events(app))
    await asyncio.wait_for(reconnected.wait(), timeout=2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    dropped = {call.args[0] for call in app["expiry"].cancel.call_args_list}
    assert dropped == {stopped_vm, gone_vm}
    dropped = {call.args[0] for call in app["update_watcher"].cancel.call_args_list}
    assert dropped == {stopped_vm, gone_vm}
    forgotten = {call.args[0] for call in app["program_client"].forget.await_args_list}
    assert forgotten == {stopped_vm, gone_vm}


@pytest.mark.asyncio
async def test_agent_watcher_retries_when_reconcile_itself_fails(monkeypatch):
    """If the daemon is still down when the reconcile runs, the watcher keeps
    retrying and reconciles once the daemon is back."""
    from aleph.vm.agent import supervisor as agent_supervisor

    stopped_vm = VmId("vm-stopped")
    reconnected = asyncio.Event()

    class FakeSupervisor:
        def __init__(self):
            self.watch_calls = 0
            self.list_calls = 0

        async def watch_events(self):
            self.watch_calls += 1
            if self.watch_calls == 1:
                msg = "stream dropped"
                raise ConnectionError(msg)
            reconnected.set()
            await asyncio.Event().wait()
            yield  # pragma: no cover

        async def list_vms(self):
            self.list_calls += 1
            if self.list_calls == 1:
                msg = "daemon still down"
                raise ConnectionError(msg)
            return []

    app: dict[str, Any] = {
        "supervisor": FakeSupervisor(),
        "expiry": MagicMock(tracked=MagicMock(return_value={stopped_vm})),
        "update_watcher": MagicMock(tracked=MagicMock(return_value=set())),
        "program_client": MagicMock(tracked=MagicMock(return_value=set()), forget=AsyncMock()),
    }

    monkeypatch.setattr(agent_supervisor, "RECONNECT_DELAY", 0)
    task = asyncio.ensure_future(agent_supervisor.watch_supervisor_events(app))
    await asyncio.wait_for(reconnected.wait(), timeout=2)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    assert app["supervisor"].list_calls == 2  # first reconcile failed, retried
    app["expiry"].cancel.assert_called_once_with(stopped_vm)
    app["program_client"].forget.assert_awaited_once_with(stopped_vm)
