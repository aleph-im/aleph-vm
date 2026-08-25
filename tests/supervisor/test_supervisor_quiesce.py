"""QuiesceOps on LocalSupervisor: freeze_guest / thaw_guest, the
supervisor's only part in a backup, with the QEMU guest agent stubbed."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.conf import settings
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId

VM_ID = VmId("itemhash123")


def _supervisor(*, running: bool = True):
    execution = make_execution(running=running)
    pool = FakePool(
        executions={str(execution.vm_id): execution},
        systemd=FakeSystemd({execution.controller_service: running}),
    )
    return LocalSupervisor(pool=pool), execution


def _stub_guest_agent(monkeypatch, sup, *, available: bool = True):
    """Replace the QGA freeze with a recording stub; returns the client whose
    thaw the tests observe."""
    client = MagicMock(guest_fsfreeze_thaw=AsyncMock())

    async def fake_freeze(execution):
        if not available:
            return None, False
        return client, True

    monkeypatch.setattr(sup, "_try_fsfreeze", fake_freeze)
    return client


@pytest.mark.asyncio
async def test_freeze_unknown_vm_raises():
    sup = LocalSupervisor(pool=FakePool(executions={}))
    with pytest.raises(VmNotFoundError):
        await sup.freeze_guest(VmId("missing"))
    with pytest.raises(VmNotFoundError):
        await sup.thaw_guest(VmId("missing"))


@pytest.mark.asyncio
async def test_freeze_then_thaw(monkeypatch):
    sup, _ = _supervisor()
    client = _stub_guest_agent(monkeypatch, sup)

    assert await sup.freeze_guest(VM_ID) is True
    assert VM_ID in sup._frozen_guests

    await sup.thaw_guest(VM_ID)

    client.guest_fsfreeze_thaw.assert_awaited_once()
    assert VM_ID not in sup._frozen_guests


@pytest.mark.asyncio
async def test_freeze_is_idempotent_while_frozen(monkeypatch):
    sup, _ = _supervisor()
    client = _stub_guest_agent(monkeypatch, sup)

    assert await sup.freeze_guest(VM_ID) is True
    assert await sup.freeze_guest(VM_ID) is True

    await sup.thaw_guest(VM_ID)
    client.guest_fsfreeze_thaw.assert_awaited_once()


@pytest.mark.asyncio
async def test_thaw_of_an_unfrozen_guest_is_a_noop(monkeypatch):
    sup, _ = _supervisor()
    client = _stub_guest_agent(monkeypatch, sup)

    await sup.thaw_guest(VM_ID)

    client.guest_fsfreeze_thaw.assert_not_awaited()


@pytest.mark.asyncio
async def test_freeze_without_guest_agent_is_a_no(monkeypatch):
    """Best effort: no guest agent means nothing is frozen and the caller's
    copy is crash-consistent."""
    sup, _ = _supervisor()
    _stub_guest_agent(monkeypatch, sup, available=False)

    assert await sup.freeze_guest(VM_ID) is False
    assert VM_ID not in sup._frozen_guests


@pytest.mark.asyncio
async def test_freeze_of_a_stopped_vm_is_a_no(monkeypatch):
    sup, _ = _supervisor(running=False)
    freeze = AsyncMock()
    monkeypatch.setattr(sup, "_try_fsfreeze", freeze)

    assert await sup.freeze_guest(VM_ID) is False

    freeze.assert_not_awaited()


@pytest.mark.asyncio
async def test_frozen_guest_is_thawed_after_the_timeout(monkeypatch):
    """An agent that dies mid-copy must not leave a guest frozen: the
    supervisor thaws it itself after GUEST_FREEZE_TIMEOUT."""
    sup, _ = _supervisor()
    client = _stub_guest_agent(monkeypatch, sup)
    monkeypatch.setattr(settings, "GUEST_FREEZE_TIMEOUT", 0.01)

    assert await sup.freeze_guest(VM_ID) is True
    await asyncio.sleep(0.05)

    client.guest_fsfreeze_thaw.assert_awaited_once()
    assert VM_ID not in sup._frozen_guests
    # A late thaw from the agent is then a no-op, not a second QGA thaw.
    await sup.thaw_guest(VM_ID)
    client.guest_fsfreeze_thaw.assert_awaited_once()


@pytest.mark.asyncio
async def test_thaw_cancels_the_timeout(monkeypatch):
    sup, _ = _supervisor()
    client = _stub_guest_agent(monkeypatch, sup)
    monkeypatch.setattr(settings, "GUEST_FREEZE_TIMEOUT", 0.01)

    await sup.freeze_guest(VM_ID)
    timer = sup._frozen_guests[VM_ID].timer
    await sup.thaw_guest(VM_ID)
    await asyncio.sleep(0.05)

    assert timer.cancelled()
    client.guest_fsfreeze_thaw.assert_awaited_once()


@pytest.mark.asyncio
async def test_thaw_of_a_deleted_vm_drops_the_record_before_raising(monkeypatch):
    """A VM deleted behind the agent's back must not leave a frozen record
    (and its auto-thaw timer) behind just because thaw finds it gone."""
    sup, execution = _supervisor()
    _stub_guest_agent(monkeypatch, sup)

    await sup.freeze_guest(VM_ID)
    timer = sup._frozen_guests[VM_ID].timer
    del sup.pool.executions[str(execution.vm_id)]

    with pytest.raises(VmNotFoundError):
        await sup.thaw_guest(VM_ID)
    await asyncio.sleep(0)

    assert VM_ID not in sup._frozen_guests
    assert timer.cancelled()


@pytest.mark.asyncio
async def test_delete_vm_cancels_a_pending_freeze_deadline(monkeypatch):
    sup, _ = _supervisor()
    _stub_guest_agent(monkeypatch, sup)
    sup.pool.stop_vm = AsyncMock()
    sup.pool.forget_vm = MagicMock()
    monkeypatch.setattr("aleph.vm.supervisor.local.delete_port_mappings", AsyncMock())

    await sup.freeze_guest(VM_ID)
    timer = sup._frozen_guests[VM_ID].timer
    await sup.delete_vm(VM_ID)
    await asyncio.sleep(0)

    assert VM_ID not in sup._frozen_guests
    assert timer.cancelled()
