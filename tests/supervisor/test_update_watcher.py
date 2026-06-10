import asyncio
import json

import pytest

# Import the existing instance-message builder (instance branch of update_refs).
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.orchestrator.update_watcher import UpdateWatcher, update_refs
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId
from aleph.vm.utils import get_message_executable_content


def _program_content():
    # examples/program_message_from_aleph.json is a full message envelope; the
    # helper wants the bare content dict.
    with open("examples/program_message_from_aleph.json") as fd:
        return get_message_executable_content(json.load(fd)["content"])


class FakeSupervisor:
    def __init__(self, *, raise_not_found: bool = False):
        self.deleted: list[tuple[str, bool]] = []
        self.raise_not_found = raise_not_found

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        self.deleted.append((str(vm_id), wipe))
        if self.raise_not_found:
            raise VmNotFoundError(str(vm_id))


class FakePubSub:
    """msubscribe blocks until the test triggers it, recording the keys."""

    def __init__(self):
        self.event = asyncio.Event()
        self.subscribed: tuple | None = None

    async def msubscribe(self, *keys):
        self.subscribed = tuple(k for k in keys if k is not None)
        await self.event.wait()

    def trigger(self):
        self.event.set()


def _registry_with(vm_hash: str, original):
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=original, original=original, persistent=False)
    return registry


_HASH = "a" * 64
WAIT_TIMEOUT = 5.0


def test_update_refs_instance_uses_volume_refs():
    content = _make_qemu_instance_message()  # volumes=[]
    assert update_refs(content) == []


def test_update_refs_program_uses_code_runtime_data():
    content = _program_content()
    refs = update_refs(content)
    assert content.code.ref in refs
    assert content.runtime.ref in refs


@pytest.mark.asyncio
async def test_watch_reaps_on_update():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)  # let the task reach msubscribe
    pubsub.trigger()
    await asyncio.sleep(0.02)

    assert sup.deleted == [(_HASH, False)]
    assert watcher.cancel(vm_id) is False  # task removed itself after firing


@pytest.mark.asyncio
async def test_cancel_prevents_reap():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)
    assert watcher.cancel(vm_id) is True
    pubsub.trigger()
    await asyncio.sleep(0.02)

    assert sup.deleted == []


@pytest.mark.asyncio
async def test_watch_is_idempotent_keeps_existing_subscription():
    sup, pubsub1, pubsub2 = FakeSupervisor(), FakePubSub(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub1)
    await asyncio.sleep(0)
    watcher.watch(vm_id, _HASH, pubsub2)  # second call must NOT restart
    await asyncio.sleep(0)

    assert pubsub1.subscribed is not None  # first subscription is live
    assert pubsub2.subscribed is None  # second was a no-op

    watcher.cancel(vm_id)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_watch_noop_when_unrecorded():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    watcher = UpdateWatcher(sup, AgentVmRegistry())  # empty registry
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0.01)

    assert watcher.cancel(vm_id) is False  # nothing scheduled
    assert pubsub.subscribed is None


@pytest.mark.asyncio
async def test_watch_swallows_vm_not_found():
    sup = FakeSupervisor(raise_not_found=True)
    pubsub = FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)
    pubsub.trigger()
    await asyncio.sleep(0.02)  # must not raise

    assert sup.deleted == [(_HASH, False)]
    assert watcher.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_cancel_all_clears_every_watch():
    sup = FakeSupervisor()
    registry = AgentVmRegistry()
    registry.record(
        "a" * 64,
        message=_make_qemu_instance_message(),
        original=_make_qemu_instance_message(),
        persistent=False,
    )
    registry.record(
        "b" * 64,
        message=_make_qemu_instance_message(),
        original=_make_qemu_instance_message(),
        persistent=False,
    )
    watcher = UpdateWatcher(sup, registry)
    watcher.watch(VmId("a" * 64), "a" * 64, FakePubSub())
    watcher.watch(VmId("b" * 64), "b" * 64, FakePubSub())
    await asyncio.sleep(0)

    await watcher.cancel_all()
    await asyncio.sleep(0.02)

    assert sup.deleted == []


@pytest.mark.asyncio
async def test_watch_again_after_completion_rewatches():
    sup, pubsub1, pubsub2 = FakeSupervisor(), FakePubSub(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub1)
    await asyncio.sleep(0)
    pubsub1.trigger()  # fires -> deletes -> task completes
    await asyncio.sleep(0.02)
    assert sup.deleted == [(_HASH, False)]

    watcher.watch(vm_id, _HASH, pubsub2)  # prior task done -> a new watch starts
    await asyncio.sleep(0)
    assert pubsub2.subscribed is not None
    watcher.cancel(vm_id)
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_expiry_reap_cancels_update_watch():
    # Regression: an idle-expired VM must not leak its update-watch subscription.
    from aleph.vm.orchestrator.expiry import ExpiryManager

    sup = FakeSupervisor()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    expiry = ExpiryManager(sup)
    expiry.on_reaped = watcher.cancel
    watcher.on_reaped = expiry.cancel
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, FakePubSub())
    expiry.schedule(vm_id, 0.01)
    # expiry.on_reaped (= watcher.cancel) runs inside _expire's finally before the
    # task completes, so awaiting the task is enough to observe the cancellation.
    await asyncio.wait_for(expiry._tasks[vm_id], timeout=WAIT_TIMEOUT)

    assert sup.deleted == [(_HASH, False)]  # expiry reaped
    assert watcher.cancel(vm_id) is False  # the watch was cancelled (gone)


@pytest.mark.asyncio
async def test_update_watch_on_reaped_called_after_reap():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    reaped: list = []
    watcher.on_reaped = reaped.append
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)
    pubsub.trigger()
    await asyncio.sleep(0.02)

    assert reaped == [vm_id]


@pytest.mark.asyncio
async def test_update_watch_on_reaped_not_called_on_cancel():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    reaped: list = []
    watcher.on_reaped = reaped.append
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    task = watcher._tasks[vm_id]
    watcher.cancel(vm_id)
    # Awaiting the cancelled task runs its finally (reaped stays False) without
    # relying on a wall-clock sleep to let the cancellation settle.
    with pytest.raises(asyncio.CancelledError):
        await task

    assert reaped == []  # cancellation is not a reap
