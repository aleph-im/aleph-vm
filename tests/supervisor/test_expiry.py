import asyncio

import pytest

from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId

# Cap on every wait for a timer that is expected to fire: generous enough for a
# loaded CI worker, only ever reached on an actual failure.
WAIT_TIMEOUT = 5.0


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

    expiry.schedule(vm_id, 0.001)
    await asyncio.wait_for(expiry._tasks[vm_id], timeout=WAIT_TIMEOUT)

    assert sup.deleted == [("vm-a", False)]
    assert expiry.cancel(vm_id) is False  # task removed itself after firing


@pytest.mark.asyncio
async def test_cancel_prevents_reap():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 60)
    task = expiry._tasks[vm_id]
    assert expiry.cancel(vm_id) is True
    await asyncio.gather(task, return_exceptions=True)

    assert task.cancelled()
    assert sup.deleted == []
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_reschedule_replaces_pending_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 60)
    first = expiry._tasks[vm_id]
    expiry.schedule(vm_id, 0.001)  # re-arm shorter
    second = expiry._tasks[vm_id]
    assert first is not second

    await asyncio.wait_for(second, timeout=WAIT_TIMEOUT)
    await asyncio.gather(first, return_exceptions=True)

    assert first.cancelled()
    assert sup.deleted == [("vm-a", False)]  # fired once, on the second timer


@pytest.mark.asyncio
async def test_expire_swallows_vm_not_found():
    sup = FakeSupervisor(raise_not_found=True)
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-gone")

    expiry.schedule(vm_id, 0.001)
    # Awaiting the task directly also surfaces any exception _expire let through.
    await asyncio.wait_for(expiry._tasks[vm_id], timeout=WAIT_TIMEOUT)

    assert sup.deleted == [("vm-gone", False)]
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_cancel_all_clears_every_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)

    expiry.schedule(VmId("vm-a"), 60)
    expiry.schedule(VmId("vm-b"), 60)
    tasks = list(expiry._tasks.values())
    await expiry.cancel_all()
    await asyncio.gather(*tasks, return_exceptions=True)

    assert all(task.cancelled() for task in tasks)
    assert sup.deleted == []
    assert not expiry._tasks


@pytest.mark.asyncio
async def test_expiry_on_reaped_called_after_reap():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    reaped: list = []
    expiry.on_reaped = reaped.append
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.01)
    # on_reaped fires inside _expire's finally, before the task completes, so
    # awaiting the task deterministically guarantees the callback has run.
    await asyncio.wait_for(expiry._tasks[vm_id], timeout=WAIT_TIMEOUT)

    assert reaped == [vm_id]


@pytest.mark.asyncio
async def test_expiry_on_reaped_not_called_on_cancel():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    reaped: list = []
    expiry.on_reaped = reaped.append
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.05)
    task = expiry._tasks[vm_id]
    expiry.cancel(vm_id)
    # Awaiting the cancelled task drives it to completion (its finally runs and
    # leaves reaped False), so the assertion no longer races a wall-clock sleep.
    with pytest.raises(asyncio.CancelledError):
        await task

    assert reaped == []
