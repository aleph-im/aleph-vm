"""pool.create_vm_from_spec — message-free, no-download create wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.errors import InvalidBackendError
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


def _spec(backend: Backend = Backend.QEMU) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=backend,
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
    import asyncio

    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.network = None  # exercise the no-network branch
    pool.snapshot_manager = None
    pool.creation_lock = asyncio.Lock()
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    pool.systemd_manager = systemd
    return pool


@pytest.mark.asyncio
async def test_create_vm_from_spec_wires_into_pool(monkeypatch):
    pool = _bare_pool()

    build_cfg = AsyncMock(return_value="fake-config")
    save_cfg = MagicMock()
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", save_cfg)
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    # Controller reports active immediately.
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    execution = await pool.create_vm_from_spec(_spec())

    assert pool.executions[execution.vm_hash] is execution
    assert execution.message is None
    assert execution.vm is not None
    build_cfg.assert_awaited_once()
    save_cfg.assert_called_once_with(_HASH, "fake-config")
    pool.systemd_manager.enable_and_start.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_vm_from_spec_preloads_persisted_port_mappings(monkeypatch):
    """create_vm_from_spec loads persisted port mappings and recreates nft rules."""
    pool = _bare_pool()

    persisted = {22: {"host": 24022, "tcp": True, "udp": False}}
    get_pm = AsyncMock(return_value=persisted)
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", AsyncMock(return_value="cfg"))
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", get_pm)
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )
    recreate = AsyncMock()
    monkeypatch.setattr("aleph.vm.models.VmExecution.recreate_port_redirect_rules", recreate)

    execution = await pool.create_vm_from_spec(_spec())

    get_pm.assert_awaited_once_with(_HASH)
    assert execution.mapped_ports == persisted
    recreate.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_vm_from_spec_rejects_non_qemu():
    pool = _bare_pool()
    with pytest.raises(InvalidBackendError):
        await pool.create_vm_from_spec(_spec(backend=Backend.QEMU_SEV))
    assert pool.executions == {}
