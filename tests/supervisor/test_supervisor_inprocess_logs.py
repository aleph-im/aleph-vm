import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool

from aleph.vm.supervisor.errors import InternalSupervisorError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import LogChunk, LogSource, VmId

VM_ID = VmId("vm1")


def _entries(vm_hash: str):
    base = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)
    return [
        {"SYSLOG_IDENTIFIER": f"vm-{vm_hash}-stdout", "MESSAGE": "boot ok", "__REALTIME_TIMESTAMP": base},
        {"SYSLOG_IDENTIFIER": f"vm-{vm_hash}-stderr", "MESSAGE": b"warn\xc3\xa9", "__REALTIME_TIMESTAMP": base},
    ]


def _make_vm_with_queue(queue: asyncio.Queue) -> SimpleNamespace:
    unregistered = {"called": False}

    def unregister(q):
        unregistered["called"] = True

    vm = SimpleNamespace(
        get_log_queue=MagicMock(return_value=queue),
        unregister_queue=MagicMock(side_effect=unregister),
    )
    return vm, unregistered


def _make_execution_with_vm(vm) -> SimpleNamespace:
    return SimpleNamespace(
        vm_hash=str(VM_ID),
        vm=vm,
        persistent=True,
    )


# ---------------------------------------------------------------------------
# get_logs — journald history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_logs_returns_journald_history(monkeypatch):
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    chunks = await supervisor.get_logs(VM_ID)

    assert [c.line for c in chunks] == ["boot ok", "warné"]
    assert [c.source for c in chunks] == [LogSource.STDOUT, LogSource.STDERR]
    assert chunks[0].timestamp_ns == int(
        datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000_000
    )


@pytest.mark.asyncio
async def test_get_logs_max_lines_from_tail(monkeypatch):
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    chunks = await supervisor.get_logs(VM_ID, max_lines=1, from_tail=True)
    assert [c.line for c in chunks] == ["warné"]

    # Also check head behavior
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )
    chunks_head = await supervisor.get_logs(VM_ID, max_lines=1, from_tail=False)
    assert [c.line for c in chunks_head] == ["boot ok"]


@pytest.mark.asyncio
async def test_get_logs_unknown_vm_returns_history_not_raises(monkeypatch):
    """get_logs no longer raises VmNotFoundError — history for stopped VMs is valid."""
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    # Should return history, not raise
    chunks = await supervisor.get_logs(VM_ID)
    assert len(chunks) == 2


@pytest.mark.asyncio
async def test_get_logs_raises_supervisor_error_on_journald_oserror(monkeypatch):
    """journald OSError in get_logs must surface as InternalSupervisorError."""
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: (_ for _ in ()).throw(OSError("journald unavailable")),
    )

    with pytest.raises(InternalSupervisorError):
        await supervisor.get_logs(VM_ID)


@pytest.mark.asyncio
async def test_get_logs_returns_empty_when_no_history(monkeypatch):
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter([]),
    )

    chunks = await supervisor.get_logs(VM_ID)
    assert chunks == []


# ---------------------------------------------------------------------------
# stream_logs — history then live queue
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stream_logs_raises_supervisor_error_on_journald_oserror(monkeypatch):
    """journald OSError in stream_logs history read must surface as InternalSupervisorError."""
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: (_ for _ in ()).throw(OSError("journald unavailable")),
    )

    with pytest.raises(InternalSupervisorError):
        async for _ in supervisor.stream_logs(VM_ID, include_history=True):
            pass


@pytest.mark.asyncio
async def test_stream_logs_with_history_then_live(monkeypatch):
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(("stdout", "live line"))
    vm, unregistered = _make_vm_with_queue(queue)
    execution = _make_execution_with_vm(vm)
    pool = FakePool(executions={VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    received = []
    gen = supervisor.stream_logs(VM_ID, include_history=True)
    async for chunk in gen:
        received.append(chunk.line)
        if len(received) == 3:
            break
    await gen.aclose()

    assert received == ["boot ok", "warné", "live line"]
    assert unregistered["called"] is True


@pytest.mark.asyncio
async def test_stream_logs_unknown_vm_ends_after_history(monkeypatch):
    """An unknown / stopped VM: stream_logs yields history then ends without exception."""
    pool = FakePool(executions={})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    collected = []
    async for chunk in supervisor.stream_logs(VM_ID, include_history=True):
        collected.append(chunk.line)

    assert collected == ["boot ok", "warné"]


@pytest.mark.asyncio
async def test_stream_logs_stderr_maps_to_stderr_source(monkeypatch):
    """Live queue 'stderr' type should produce LogSource.STDERR."""
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(("stderr", "oops"))
    vm, unregistered = _make_vm_with_queue(queue)
    execution = _make_execution_with_vm(vm)
    pool = FakePool(executions={VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter([]),
    )

    received = []
    gen = supervisor.stream_logs(VM_ID, include_history=False)
    async for chunk in gen:
        received.append(chunk)
        break
    await gen.aclose()

    assert received[0].source is LogSource.STDERR
    assert received[0].line == "oops"
    assert unregistered["called"] is True


@pytest.mark.asyncio
async def test_stream_logs_yields_logchunks_and_unregisters(monkeypatch):
    """Live stream: yields LogChunks for stdout and unregisters queue on close."""
    queue: asyncio.Queue = asyncio.Queue()
    queue.put_nowait(("stdout", "hello"))
    queue.put_nowait(("stderr", "oops"))
    vm, unregistered = _make_vm_with_queue(queue)
    execution = _make_execution_with_vm(vm)
    pool = FakePool(executions={VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter([]),
    )

    gen = supervisor.stream_logs(VM_ID)
    received = []
    async for chunk in gen:
        received.append(chunk)
        if len(received) == 2:
            break
    await gen.aclose()

    assert isinstance(received[0], LogChunk)
    assert received[0].line == "hello"
    assert received[0].source is LogSource.STDOUT
    assert received[1].source is LogSource.STDERR
    assert unregistered["called"] is True
