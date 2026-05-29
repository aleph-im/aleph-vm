from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor

from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution


@pytest.mark.asyncio
async def test_delete_vm_stops_and_forgets():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    await sup.delete_vm("itemhash123")

    pool.stop_vm.assert_awaited_once_with("itemhash123")
    pool.forget_vm.assert_called_once_with("itemhash123")


@pytest.mark.asyncio
async def test_delete_unknown_vm_raises():
    pool = FakePool()
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)
    with pytest.raises(VmNotFoundError):
        await sup.delete_vm("nope")
    pool.stop_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_reboot_persistent_vm_restarts_systemd_and_returns_info():
    execution = make_execution(running=True)
    systemd = FakeSystemd({"aleph-vm-controller@itemhash123.service": True})
    systemd.restart = MagicMock()
    pool = FakePool(executions={"itemhash123": execution}, systemd=systemd)
    sup = InProcessSupervisor(pool=pool)

    info = await sup.reboot_vm("itemhash123")

    systemd.restart.assert_called_once_with("aleph-vm-controller@itemhash123.service")
    assert info.vm_id == "itemhash123"


@pytest.mark.asyncio
async def test_reboot_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.reboot_vm("nope")


@pytest.mark.asyncio
async def test_reinstall_persistent_vm_stops_then_restarts():
    execution = make_execution(running=True)
    systemd = FakeSystemd({"aleph-vm-controller@itemhash123.service": True})
    systemd.restart = MagicMock()
    pool = FakePool(executions={"itemhash123": execution}, systemd=systemd)
    pool.stop_vm = AsyncMock()
    sup = InProcessSupervisor(pool=pool)

    info = await sup.reinstall_vm("itemhash123")

    pool.stop_vm.assert_awaited_once_with("itemhash123")
    systemd.restart.assert_called_once_with("aleph-vm-controller@itemhash123.service")
    assert info.vm_id == "itemhash123"
