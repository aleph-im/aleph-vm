"""retire_vm: the one agent-side deletion function and its reasons."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import InstanceContent, ItemHash
from reclaim_fixtures import VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.vm.retire as retire_module
from aleph.vm.agent.vm.reclaimable import MARKER_NAME, read_marker
from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId

OWNER = "0x1234567890123456789012345678901234567890"


@pytest.fixture
def env(pools, mocker):  # noqa: F811
    """A registry with one recorded VM, its files on disk, and every side
    effect that leaves the filesystem mocked."""
    registry = AgentVmRegistry()
    rootfs = MagicMock()
    rootfs.parent.ref = "parent-ref"
    content = MagicMock(spec=InstanceContent, volumes=[], rootfs=rootfs)
    content.address = OWNER
    registry.record(ItemHash(VM_HASH), message=content, original=content, persistent=True)
    rootfs = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    data = volume(pools["pool1"], VM_HASH, "data.ext4", size=4096)
    session = pools["sessions"] / VM_HASH
    session.mkdir()
    (session / "vm_session.b64").write_bytes(b"s")
    staging = pools["execution_root"] / "vprogram" / VM_HASH
    staging.mkdir(parents=True)
    (staging / "bundle").write_bytes(b"b")
    delete_records = mocker.patch.object(retire_module, "delete_records_for_vm", new_callable=AsyncMock)
    purge_backups = mocker.patch.object(retire_module, "purge_vm_backups")
    supervisor = MagicMock(delete_vm=AsyncMock())
    return {
        "registry": registry,
        "supervisor": supervisor,
        "rootfs": rootfs,
        "data": data,
        "session": session,
        "staging": staging,
        "delete_records": delete_records,
        "purge_backups": purge_backups,
    }


def _all_present(env) -> bool:
    return all(env[k].exists() for k in ("rootfs", "data", "session", "staging"))


@pytest.mark.asyncio
async def test_recreate_only_quiesces(env):
    await retire_vm(VM_HASH, RetireReason.RECREATE, supervisor=env["supervisor"])

    env["supervisor"].delete_vm.assert_awaited_once_with(VmId(VM_HASH), keep_port_mappings=True)
    assert _all_present(env)
    assert ItemHash(VM_HASH) in env["registry"]
    env["delete_records"].assert_not_awaited()
    env["purge_backups"].assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [RetireReason.GONE, RetireReason.ERASE, RetireReason.FAILED_CREATE])
async def test_purging_reasons_under_reap(env, monkeypatch, reason):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")

    await retire_vm(VM_HASH, reason, supervisor=env["supervisor"], registry=env["registry"])

    env["supervisor"].delete_vm.assert_awaited_once_with(VmId(VM_HASH), keep_port_mappings=False)
    assert not env["rootfs"].exists()
    assert not env["data"].exists()
    assert not env["session"].exists()
    assert not env["staging"].exists()
    assert ItemHash(VM_HASH) not in env["registry"]
    env["delete_records"].assert_awaited_once_with(VM_HASH)
    env["purge_backups"].assert_called_once_with(VM_HASH)


@pytest.mark.asyncio
async def test_gone_under_keep_marks_volumes_and_removes_the_rest(env, monkeypatch, pools):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")

    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    assert env["rootfs"].exists()
    assert env["data"].exists()
    marker = read_marker(pools["pool0"] / VM_HASH)
    assert marker is not None and marker.reason == "gone"
    assert marker.depends_on == ("parent-ref",)
    assert read_marker(pools["pool1"] / VM_HASH) is not None
    assert not env["session"].exists()
    assert not env["staging"].exists()
    assert ItemHash(VM_HASH) not in env["registry"]
    env["purge_backups"].assert_called_once_with(VM_HASH)


@pytest.mark.asyncio
async def test_gone_under_keep_records_the_owner_in_the_marker(env, monkeypatch, pools):  # noqa: F811
    """The marker is the only thing left that says whose disks these are: the
    registry record is forgotten and delete_records_for_vm drops the DB rows
    at GONE. Without the owner in the marker, nobody can ever be authorized
    to ask for the retained data to be erased."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")

    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    written = json.loads((pools["pool0"] / VM_HASH / MARKER_NAME).read_text())
    assert written["owner"] == OWNER
    assert written["version"] == 1
    assert read_marker(pools["pool1"] / VM_HASH).owner == OWNER


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [RetireReason.ERASE, RetireReason.FAILED_CREATE])
async def test_erase_and_failed_create_ignore_keep(env, monkeypatch, reason):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")

    await retire_vm(VM_HASH, reason, supervisor=env["supervisor"], registry=env["registry"])

    assert not env["rootfs"].exists()
    assert not env["data"].exists()


@pytest.mark.asyncio
async def test_vm_unknown_to_the_supervisor_is_still_retired(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    env["supervisor"].delete_vm.side_effect = VmNotFoundError(VM_HASH)

    await retire_vm(VM_HASH, RetireReason.FAILED_CREATE, supervisor=env["supervisor"], registry=env["registry"])

    assert not env["rootfs"].exists()
    assert not env["staging"].exists()


@pytest.mark.asyncio
async def test_non_recreate_requires_a_registry(env):
    with pytest.raises(ValueError):
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"])


@pytest.mark.asyncio
async def test_retire_is_idempotent(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    assert env["supervisor"].delete_vm.await_count == 2


@pytest.mark.asyncio
async def test_gone_under_keep_runs_the_after_gone_hook(env, monkeypatch):
    """Retention is a budget, so it is enforced the moment a VM becomes
    reclaimable, not only at the next periodic pass (spec section 1)."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    hook = AsyncMock()
    retire_module.set_after_gone_hook(hook)
    try:
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    finally:
        retire_module.set_after_gone_hook(None)

    hook.assert_awaited_once()


@pytest.mark.asyncio
async def test_gone_under_reap_does_not_run_the_after_gone_hook(env, monkeypatch):
    """Nothing is retained under reap: the disks are already gone, so there is
    no budget to enforce."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    hook = AsyncMock()
    retire_module.set_after_gone_hook(hook)
    try:
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    finally:
        retire_module.set_after_gone_hook(None)

    hook.assert_not_awaited()


@pytest.mark.asyncio
async def test_erase_does_not_run_the_after_gone_hook(env, monkeypatch):
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    hook = AsyncMock()
    retire_module.set_after_gone_hook(hook)
    try:
        await retire_vm(VM_HASH, RetireReason.ERASE, supervisor=env["supervisor"], registry=env["registry"])
    finally:
        retire_module.set_after_gone_hook(None)

    hook.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failing_after_gone_hook_does_not_break_the_retire(env, monkeypatch, caplog):
    """The GONE call sites sweep in a loop (terminal messages, unpaid VMs)
    without a local try: a reconcile pass that raises must not take the rest
    of the sweep down with it."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    retire_module.set_after_gone_hook(AsyncMock(side_effect=RuntimeError("pool on fire")))
    try:
        with caplog.at_level("WARNING"):
            await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])
    finally:
        retire_module.set_after_gone_hook(None)

    # The retire itself completed: the volumes are marked, not lost.
    assert read_marker(env["rootfs"].parent) is not None
    assert "pool on fire" in caplog.text


def _parent_backed_volumes(record) -> None:
    """One parent-backed volume named "data" and one plain volume."""
    # `name` and `parent` are both MagicMock constructor keywords, so they
    # have to be assigned after the fact to land on the mock as attributes.
    parent_backed = MagicMock()
    parent_backed.name = "data"
    parent_backed.parent = MagicMock(ref="parent-ref")
    plain = MagicMock()
    plain.name = "plain"
    plain.parent = None
    record.message.volumes = [parent_backed, plain]


@pytest.mark.asyncio
@pytest.mark.parametrize("reason", [RetireReason.GONE, RetireReason.ERASE, RetireReason.FAILED_CREATE])
async def test_purging_reasons_tear_down_parent_backed_volume_devices(env, monkeypatch, mocker, reason):
    """A parent-backed volume is a loop device under a dm snapshot: its file
    cannot be reclaimed while those are live."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    remove = mocker.patch.object(retire_module, "remove_devmapper", new_callable=AsyncMock)
    _parent_backed_volumes(env["registry"].get(ItemHash(VM_HASH)))

    await retire_vm(VM_HASH, reason, supervisor=env["supervisor"], registry=env["registry"])

    remove.assert_awaited_once_with(VM_HASH, "data")


@pytest.mark.asyncio
async def test_recreate_leaves_devices_in_place(env, mocker):
    remove = mocker.patch.object(retire_module, "remove_devmapper", new_callable=AsyncMock)

    await retire_vm(VM_HASH, RetireReason.RECREATE, supervisor=env["supervisor"])

    remove.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failing_device_teardown_does_not_abort_the_retire(env, monkeypatch, mocker, caplog):
    """dmsetup can refuse (device busy); the volume file then stays behind for
    the next reconcile pass, but the rest of the retire still happens."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    mocker.patch.object(
        retire_module, "remove_devmapper", new_callable=AsyncMock, side_effect=RuntimeError("device busy")
    )
    _parent_backed_volumes(env["registry"].get(ItemHash(VM_HASH)))

    with caplog.at_level("ERROR"):
        await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    assert "device busy" in caplog.text
    assert ItemHash(VM_HASH) not in env["registry"]
    assert not env["rootfs"].exists()


@pytest.mark.asyncio
async def test_devices_are_torn_down_after_the_quiesce_and_before_the_storage_pass(env, monkeypatch, mocker):
    """The order is the point: the supervisor must have released the VM
    before its devices go, and the devices must be gone before the storage
    pass, which cannot usefully unlink a file a loop device still pins."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    order: list[str] = []
    env["supervisor"].delete_vm.side_effect = lambda *args, **kwargs: order.append("delete_vm")
    mocker.patch.object(
        retire_module,
        "remove_devmapper",
        new_callable=AsyncMock,
        side_effect=lambda *args: order.append("teardown"),
    )
    mocker.patch.object(retire_module, "_release_storage", side_effect=lambda *args: order.append("release_storage"))
    _parent_backed_volumes(env["registry"].get(ItemHash(VM_HASH)))

    await retire_vm(VM_HASH, RetireReason.GONE, supervisor=env["supervisor"], registry=env["registry"])

    assert order == ["delete_vm", "teardown", "release_storage"]
