"""Idle-teardown behavior of the run_code_on_* paths.

The expiry guard these tests pin down: serving a request must re-arm the idle
timer for on-demand executions only. Persistent executions (instances and
persistent programs) are long-running by design and must never be idle-reaped
— the guard that used to live inside VmExecution.stop_after_timeout.
"""

import asyncio
from types import SimpleNamespace

import msgpack
import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.run import run_code_on_event, run_code_on_request
from aleph.vm.supervisor.types import VmId

VM_HASH = ItemHash(settings.FAKE_INSTANCE_ID)
REUSE_TIMEOUT = 42.0


class SpyExpiry:
    def __init__(self):
        self.scheduled: list[tuple[str, float]] = []
        self.cancelled: list[str] = []

    def schedule(self, vm_id: VmId, timeout: float) -> None:
        self.scheduled.append((str(vm_id), timeout))

    def cancel(self, vm_id: VmId) -> bool:
        self.cancelled.append(str(vm_id))
        return False


class FakeExecution:
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


def _request_fakes(*, persistent: bool):
    execution = FakeExecution(
        persistent=persistent,
        result={"headers": {"headers": [[b"content-type", b"text/plain"]], "status": 200}, "body": {"body": b"ok"}},
    )
    expiry = SpyExpiry()
    request = FakeRequest(app={"supervisor": None, "expiry": expiry, "pubsub": None})
    return execution, expiry, request


@pytest.mark.asyncio
async def test_request_rearms_idle_timer_for_on_demand_vm(reuse_settings):
    execution, expiry, request = _request_fakes(persistent=False)

    response = await run_code_on_request(VM_HASH, "/", FakePool(execution), request)

    assert response.status == 200
    assert expiry.cancelled == [str(VM_HASH)]
    assert expiry.scheduled == [(str(VM_HASH), REUSE_TIMEOUT)]


@pytest.mark.asyncio
async def test_request_never_schedules_expiry_for_persistent_vm(reuse_settings):
    execution, expiry, request = _request_fakes(persistent=True)

    response = await run_code_on_request(VM_HASH, "/", FakePool(execution), request)

    assert response.status == 200
    assert expiry.scheduled == []


@pytest.mark.asyncio
async def test_event_rearms_idle_timer_for_on_demand_vm(reuse_settings):
    execution = FakeExecution(persistent=False, result={"body": "ok"})
    expiry = SpyExpiry()

    result = await run_code_on_event(VM_HASH, None, None, FakePool(execution), supervisor=None, expiry=expiry)

    assert result == "ok"
    assert expiry.cancelled == [str(VM_HASH)]
    assert expiry.scheduled == [(str(VM_HASH), REUSE_TIMEOUT)]


@pytest.mark.asyncio
async def test_event_never_schedules_expiry_for_persistent_vm(reuse_settings):
    execution = FakeExecution(persistent=True, result={"body": "ok"})
    expiry = SpyExpiry()

    result = await run_code_on_event(VM_HASH, None, None, FakePool(execution), supervisor=None, expiry=expiry)

    assert result == "ok"
    assert expiry.scheduled == []
