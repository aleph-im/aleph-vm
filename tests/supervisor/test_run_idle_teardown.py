"""Idle-teardown behavior of the run_code_on_* paths.

The expiry guard these tests pin down: serving a request must re-arm the idle
timer for on-demand executions only. Persistent executions (instances and
persistent programs) are long-running by design and must never be idle-reaped
— the guard that used to live inside VmExecution.stop_after_timeout.

On-demand programs run through the supervisor + ProgramGuestClient path;
persistent programs still take the legacy pool/VmExecution path.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import msgpack
import pytest
from aleph_message.models import ItemHash, ProgramContent

from aleph.vm.conf import settings
from aleph.vm.orchestrator.run import run_code_on_event, run_code_on_request
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.types import Backend, IpAssignment, VmId, VmInfo, VmStatus

VM_HASH = ItemHash(settings.FAKE_INSTANCE_ID)
REUSE_TIMEOUT = 42.0

OK_RESULT = {"headers": {"headers": [[b"content-type", b"text/plain"]], "status": 200}, "body": {"body": b"ok"}}


class SpyExpiry:
    def __init__(self):
        self.scheduled: list[tuple[str, float]] = []
        self.cancelled: list[str] = []

    def schedule(self, vm_id: VmId, timeout: float) -> None:
        self.scheduled.append((str(vm_id), timeout))

    def cancel(self, vm_id: VmId) -> bool:
        self.cancelled.append(str(vm_id))
        return False


def _program_content(*, persistent: bool) -> MagicMock:
    # Pydantic v2 fields are not class attributes, so MagicMock(spec=...)
    # would hide them; overriding __class__ keeps isinstance() working while
    # leaving attribute access free.
    content = MagicMock()
    content.__class__ = ProgramContent
    content.on.persistent = persistent
    content.resources.seconds = 30
    content.code.ref = "code-ref"
    return content


def _running_info() -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(VM_HASH)),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(address="172.16.4.2"),
        ipv6=IpAssignment(),
        uptime_secs=1,
        backend=Backend.FIRECRACKER,
        numa_node=None,
        status_message="",
        guest_channel_path="/tmp/does-not-matter/v.sock",
        guest_ready_payload=b"",
    )


class FakeProgramClient:
    """A program VM already configured by this agent process."""

    def __init__(self, result: dict):
        self._result_raw = msgpack.dumps(result)
        self.forgotten: list[str] = []
        self._locks: dict[VmId, asyncio.Lock] = {}

    def creation_lock(self, vm_id: VmId) -> asyncio.Lock:
        return self._locks.setdefault(vm_id, asyncio.Lock())

    def is_ready(self, vm_id: VmId) -> bool:
        return True

    async def run_code(self, info: VmInfo, scope: dict, *, timeout: float) -> bytes:
        return self._result_raw

    async def forget(self, vm_id: VmId) -> None:
        self.forgotten.append(str(vm_id))


class FakeExecution:
    """Legacy pool execution (persistent programs)."""

    def __init__(self, *, persistent: bool, result: dict):
        self.persistent = persistent
        self.vm_hash = VM_HASH
        self.vm_id = 3
        self.has_resources = True
        self.message = SimpleNamespace(code=SimpleNamespace(ref="code-ref"))
        self._result_raw = msgpack.dumps(result)

    async def becomes_ready(self) -> None:
        pass

    async def run_code(self, scope: dict) -> bytes:
        return self._result_raw


class FakePool:
    def __init__(self, execution: FakeExecution):
        self._execution = execution

    def get_running_vm(self, vm_hash: ItemHash) -> FakeExecution:
        assert vm_hash == VM_HASH
        return self._execution


class FakeRequest:
    method = "GET"
    query_string = ""
    raw_headers: list[tuple[bytes, bytes]] = []

    def __init__(self, app: dict):
        self.app = app

    async def read(self) -> bytes:
        return b""


@pytest.fixture
def reuse_settings(monkeypatch):
    monkeypatch.setattr(settings, "REUSE_TIMEOUT", REUSE_TIMEOUT)
    monkeypatch.setattr(settings, "WATCH_FOR_UPDATES", False)


def _registry_with(content) -> AgentVmRegistry:
    registry = AgentVmRegistry()
    registry.record(VM_HASH, message=content, original=content, persistent=bool(content.on.persistent))
    return registry


def _on_demand_fakes():
    content = _program_content(persistent=False)
    expiry = SpyExpiry()
    program_client = FakeProgramClient(OK_RESULT)
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=_running_info()), delete_vm=AsyncMock())
    app = {
        "supervisor": supervisor,
        "expiry": expiry,
        "pubsub": None,
        "update_watcher": None,
        "vm_registry": _registry_with(content),
        "program_client": program_client,
    }
    return content, expiry, supervisor, program_client, app


@pytest.mark.asyncio
async def test_request_rearms_idle_timer_for_on_demand_vm(reuse_settings):
    _content, expiry, _supervisor, _program_client, app = _on_demand_fakes()

    response = await run_code_on_request(VM_HASH, "/", SimpleNamespace(), FakeRequest(app=app))

    assert response.status == 200
    assert expiry.cancelled == [str(VM_HASH)]
    assert expiry.scheduled == [(str(VM_HASH), REUSE_TIMEOUT)]


@pytest.mark.asyncio
async def test_request_never_schedules_expiry_for_persistent_vm(reuse_settings):
    content = _program_content(persistent=True)
    execution = FakeExecution(persistent=True, result=OK_RESULT)
    expiry = SpyExpiry()
    app = {
        "supervisor": None,
        "expiry": expiry,
        "pubsub": None,
        "update_watcher": None,
        "vm_registry": _registry_with(content),
        "program_client": FakeProgramClient(OK_RESULT),
    }

    response = await run_code_on_request(VM_HASH, "/", FakePool(execution), FakeRequest(app=app))

    assert response.status == 200
    assert expiry.scheduled == []


@pytest.mark.asyncio
async def test_event_rearms_idle_timer_for_on_demand_vm(reuse_settings):
    content = _program_content(persistent=False)
    expiry = SpyExpiry()
    program_client = FakeProgramClient({"body": "ok"})
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=_running_info()), delete_vm=AsyncMock())

    result = await run_code_on_event(
        VM_HASH,
        None,
        None,
        SimpleNamespace(),
        supervisor=supervisor,
        expiry=expiry,
        update_watcher=None,
        registry=_registry_with(content),
        program_client=program_client,
    )

    assert result == "ok"
    assert expiry.scheduled == [(str(VM_HASH), REUSE_TIMEOUT)]


@pytest.mark.asyncio
async def test_event_never_schedules_expiry_for_persistent_vm(reuse_settings):
    content = _program_content(persistent=True)
    execution = FakeExecution(persistent=True, result={"body": "ok"})
    expiry = SpyExpiry()

    result = await run_code_on_event(
        VM_HASH,
        None,
        None,
        FakePool(execution),
        supervisor=None,
        expiry=expiry,
        update_watcher=None,
        registry=_registry_with(content),
        program_client=FakeProgramClient({"body": "ok"}),
    )

    assert result == "ok"
    assert expiry.scheduled == []
