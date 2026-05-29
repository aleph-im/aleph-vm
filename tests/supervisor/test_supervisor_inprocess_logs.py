import asyncio
from types import SimpleNamespace

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import LogChunk, LogSource

from test_supervisor_inprocess_query import FakePool


def make_execution_with_logs(lines):
    queue = asyncio.Queue()
    for entry in lines:
        queue.put_nowait(entry)
    unregistered = {"called": False}

    def unregister(q):
        unregistered["called"] = True

    vm = SimpleNamespace(get_log_queue=lambda: queue, unregister_queue=unregister)
    execution = SimpleNamespace(vm_hash="vm1", vm=vm)
    return execution, unregistered


@pytest.mark.asyncio
async def test_stream_logs_yields_logchunks_then_unregisters():
    execution, unregistered = make_execution_with_logs([("stdout", "hello"), ("stderr", "oops")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    gen = sup.stream_logs("vm1")
    received = []
    async for chunk in gen:
        received.append(chunk)
        if len(received) == 2:
            break
    await gen.aclose()

    assert isinstance(received[0], LogChunk)
    assert received[0].line == "hello"
    assert received[0].source is LogSource.STDOUT
    assert received[1].source in (LogSource.STDOUT, LogSource.SERIAL)
    assert unregistered["called"] is True


@pytest.mark.asyncio
async def test_get_logs_drains_available_lines():
    execution, _ = make_execution_with_logs([("stdout", "a"), ("stdout", "b")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    chunks = await sup.get_logs("vm1")

    assert [c.line for c in chunks] == ["a", "b"]


@pytest.mark.asyncio
async def test_logs_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_logs("nope")


@pytest.mark.asyncio
async def test_get_logs_from_tail_returns_last_lines():
    execution, _ = make_execution_with_logs([("stdout", "a"), ("stdout", "b"), ("stdout", "c")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    chunks = await sup.get_logs("vm1", max_lines=2, from_tail=True)

    assert [c.line for c in chunks] == ["b", "c"]


@pytest.mark.asyncio
async def test_get_logs_max_lines_returns_head_by_default():
    execution, _ = make_execution_with_logs([("stdout", "a"), ("stdout", "b"), ("stdout", "c")])
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    chunks = await sup.get_logs("vm1", max_lines=2)

    assert [c.line for c in chunks] == ["a", "b"]
