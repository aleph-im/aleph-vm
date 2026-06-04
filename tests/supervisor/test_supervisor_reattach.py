"""Config-driven, message-free reattach helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        ],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    return pool


@pytest.mark.asyncio
async def test_handle_dead_controller_stops_service():
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH)

    await pool._handle_dead_controller(config)

    pool.systemd_manager.stop_and_disable.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_restore_running_execution_from_config_registers_execution(monkeypatch):
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH, vm_id=7)

    monkeypatch.setattr("aleph.vm.pool.spec_from_controller_configuration", lambda _c: _spec())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))

    from aleph.vm.models import VmExecution

    monkeypatch.setattr(VmExecution, "prepare", AsyncMock())
    fake_vm = SimpleNamespace(support_snapshot=False, start_guest_api=AsyncMock())
    monkeypatch.setattr(VmExecution, "create", MagicMock(return_value=fake_vm))

    await pool._restore_running_execution_from_config(config, vm_id=7, vm_hash=_HASH)

    assert _HASH in pool.executions
    execution = pool.executions[_HASH]
    assert execution.spec is not None
    assert execution.message is None
    fake_vm.start_guest_api.assert_awaited_once()
    assert execution.ready_event.is_set()
