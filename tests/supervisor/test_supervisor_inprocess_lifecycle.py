from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.models import VmExecution
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import VmId

VM_ID = VmId("itemhash123")


def _make_execution(*, persistent: bool = True):
    """Create a fake execution with configurable persistence flag.

    Wraps make_execution() (always persistent=True) and patches the flag.
    """
    ex = make_execution()
    ex.persistent = persistent
    ex.prepare = AsyncMock()
    return ex


def _make_pool(executions: dict | None = None):
    """Create a FakePool with stop_vm and forget_vm pre-mocked."""
    pool = FakePool(executions=executions or {})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    return pool


@pytest.mark.asyncio
async def test_delete_vm_stops_and_forgets():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    await sup.delete_vm(VmId("itemhash123"))

    pool.stop_vm.assert_awaited_once_with("itemhash123")
    pool.forget_vm.assert_called_once_with("itemhash123")


@pytest.mark.asyncio
async def test_delete_unknown_vm_raises():
    pool = FakePool()
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)
    with pytest.raises(VmNotFoundError):
        await sup.delete_vm(VmId("nope"))
    pool.stop_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_reboot_persistent_vm_restarts_systemd_and_returns_info():
    execution = make_execution(running=True)
    systemd = FakeSystemd({"aleph-vm-controller@itemhash123.service": True})
    systemd.restart = MagicMock()
    pool = FakePool(executions={"itemhash123": execution}, systemd=systemd)
    sup = InProcessSupervisor(pool=pool)

    info = await sup.reboot_vm(VmId("itemhash123"))

    systemd.restart.assert_called_once_with("aleph-vm-controller@itemhash123.service")
    assert info.vm_id == "itemhash123"


@pytest.mark.asyncio
async def test_reboot_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.reboot_vm(VmId("nope"))


@pytest.mark.asyncio
async def test_reinstall_persistent_erases_prepares_and_restarts():
    execution = _make_execution(persistent=True)
    execution.erase_volumes = MagicMock()
    pool = _make_pool({VM_ID: execution})
    pool.restart_persistent_vm = AsyncMock()
    supervisor = InProcessSupervisor(pool)

    await supervisor.reinstall_vm(VM_ID, wipe_volumes=False)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    execution.erase_volumes.assert_called_once_with(include_rootfs=True, include_data_volumes=False)
    assert execution.resources is None
    execution.prepare.assert_awaited_once()
    pool.restart_persistent_vm.assert_awaited_once_with(execution)


@pytest.mark.asyncio
async def test_reinstall_non_persistent_stops_forgets_and_erases():
    execution = _make_execution(persistent=False)
    execution.erase_volumes = MagicMock()
    pool = _make_pool({VM_ID: execution})
    supervisor = InProcessSupervisor(pool)

    await supervisor.reinstall_vm(VM_ID)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    pool.forget_vm.assert_called_once_with(VM_ID)
    execution.erase_volumes.assert_called_once_with(include_rootfs=True, include_data_volumes=True)


@pytest.mark.asyncio
async def test_delete_vm_wipe_erases_data_volumes_and_port_mappings(monkeypatch):
    execution = make_execution()
    pool = FakePool(executions={VM_ID: execution})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    supervisor = InProcessSupervisor(pool)
    deleted = AsyncMock()
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.delete_port_mappings", deleted)
    erased = MagicMock(return_value=1)
    execution.erase_volumes = erased

    await supervisor.delete_vm(VM_ID, wipe=True)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    deleted.assert_awaited_once_with(execution.vm_hash)
    erased.assert_called_once_with()


@pytest.mark.asyncio
async def test_delete_vm_without_wipe_keeps_data(monkeypatch):
    execution = make_execution()
    pool = FakePool(executions={VM_ID: execution})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    supervisor = InProcessSupervisor(pool)
    deleted = AsyncMock()
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.delete_port_mappings", deleted)
    execution.erase_volumes = MagicMock()

    await supervisor.delete_vm(VM_ID)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    pool.forget_vm.assert_called_once_with(VM_ID)
    deleted.assert_not_awaited()
    execution.erase_volumes.assert_not_called()


def test_erase_volumes_deletes_rootfs_and_data(tmp_path):
    """Verify the erase_volumes logic against real tmp-path files.

    Calls VmExecution.erase_volumes as an unbound method on a SimpleNamespace
    so we can test the file-deletion logic without a full VmExecution instance.
    """
    rootfs = tmp_path / "rootfs.qcow2"
    rootfs.touch()
    vol = tmp_path / "data.qcow2"
    vol.touch()
    ro = tmp_path / "ro.sqsh"
    ro.touch()
    # Use a plain SimpleNamespace as `self` — erase_volumes only reads
    # self.resources, so no VmExecution __init__ is needed.
    execution = SimpleNamespace(
        resources=SimpleNamespace(
            rootfs_path=rootfs,
            volumes=[
                SimpleNamespace(read_only=False, path_on_host=vol),
                SimpleNamespace(read_only=True, path_on_host=ro),
            ],
        )
    )

    deleted = VmExecution.erase_volumes(execution, include_rootfs=True)

    assert deleted == 2
    assert not rootfs.exists() and not vol.exists() and ro.exists()


def _spec_for(vm_hash: str):
    from pathlib import Path

    from aleph.vm.supervisor.types import (
        Backend,
        CreateVmSpec,
        DiskFormat,
        DiskRole,
        DiskSpec,
        NetworkConfig,
    )

    return CreateVmSpec(
        vm_id=VmId(vm_hash),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)
        ],
        vcpus=1,
        memory_mib=256,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=False,
    )


@pytest.mark.asyncio
async def test_reboot_ephemeral_spec_vm_recreates_from_held_spec():
    """A spec-built ephemeral VM reboots for real: stop, then re-create from
    the spec the supervisor holds — the client is not expected to know."""
    spec = _spec_for("itemhash123")
    execution = _make_execution(persistent=False)
    execution.vm_spec = spec
    recreated = make_execution(vm_hash="itemhash123", running=True)
    pool = _make_pool(executions={"itemhash123": execution})
    pool.create_vm_from_spec = AsyncMock(return_value=recreated)
    sup = InProcessSupervisor(pool=pool)

    info = await sup.reboot_vm(VM_ID)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    pool.create_vm_from_spec.assert_awaited_once_with(spec)
    assert info.vm_id == "itemhash123"


@pytest.mark.asyncio
async def test_reboot_ephemeral_message_vm_stops_only():
    """Message-built (legacy) ephemeral VMs keep the old contract: the agent
    owns the message and re-creates through its own path."""
    execution = _make_execution(persistent=False)
    execution.vm_spec = None
    pool = _make_pool(executions={"itemhash123": execution})
    pool.create_vm_from_spec = AsyncMock()
    sup = InProcessSupervisor(pool=pool)

    await sup.reboot_vm(VM_ID)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    pool.create_vm_from_spec.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_vm_spec_returns_held_spec():
    spec = _spec_for("itemhash123")
    execution = make_execution()
    execution.vm_spec = spec
    sup = InProcessSupervisor(pool=FakePool(executions={"itemhash123": execution}))

    assert await sup.get_vm_spec(VM_ID) == spec


@pytest.mark.asyncio
async def test_get_vm_spec_unknown_vm_raises_not_found():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_vm_spec(VmId("nope"))


@pytest.mark.asyncio
async def test_get_vm_spec_message_built_vm_raises_unimplemented():
    from aleph.vm.supervisor.errors import NotImplementedSupervisorError

    execution = make_execution()  # vm_spec=None: legacy, message-built
    sup = InProcessSupervisor(pool=FakePool(executions={"itemhash123": execution}))
    with pytest.raises(NotImplementedSupervisorError):
        await sup.get_vm_spec(VM_ID)
