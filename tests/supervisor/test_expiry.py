import asyncio

import pytest

from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId


class FakeSupervisor:
    def __init__(self, *, raise_not_found: bool = False):
        self.deleted: list[tuple[str, bool]] = []
        self.raise_not_found = raise_not_found

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        self.deleted.append((str(vm_id), wipe))
        if self.raise_not_found:
            raise VmNotFoundError(str(vm_id))


@pytest.mark.asyncio
async def test_schedule_reaps_after_timeout():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.01)
    await asyncio.sleep(0.05)

    assert sup.deleted == [("vm-a", False)]
    assert expiry.cancel(vm_id) is False  # task removed itself after firing


@pytest.mark.asyncio
async def test_cancel_prevents_reap():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.05)
    assert expiry.cancel(vm_id) is True
    await asyncio.sleep(0.1)

    assert sup.deleted == []
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_reschedule_replaces_pending_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.2)
    expiry.schedule(vm_id, 0.01)  # re-arm shorter
    await asyncio.sleep(0.1)

    assert sup.deleted == [("vm-a", False)]  # fired once, on the second timer


@pytest.mark.asyncio
async def test_expire_swallows_vm_not_found():
    sup = FakeSupervisor(raise_not_found=True)
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-gone")

    expiry.schedule(vm_id, 0.01)
    await asyncio.sleep(0.05)  # must not raise

    assert sup.deleted == [("vm-gone", False)]
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_cancel_all_clears_every_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)

    expiry.schedule(VmId("vm-a"), 0.05)
    expiry.schedule(VmId("vm-b"), 0.05)
    await expiry.cancel_all()
    await asyncio.sleep(0.1)

    assert sup.deleted == []
