"""pool._create_firecracker_from_spec boots persistent programs under systemd."""

from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GuestChannelSpec,
    NetworkConfig,
    VmId,
)

_HASH = "feed" * 16


def _program_spec(*, persistent: bool) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=Backend.FIRECRACKER,
        kernel_path=Path("/opt/vmlinux.bin"),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.squashfs"), readonly=True, format=DiskFormat.SQUASHFS, role=DiskRole.ROOTFS
            )
        ],
        vcpus=1,
        memory_mib=128,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=persistent,
        guest_channel=GuestChannelSpec(ready_port=52),
    )


def _bare_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.creation_lock = asyncio.Lock()
    pool.systemd_manager = MagicMock()
    return pool


@pytest.mark.asyncio
@pytest.mark.parametrize("persistent", [True, False])
async def test_create_firecracker_from_spec_boots_program(monkeypatch, persistent):
    pool = _bare_pool()
    monkeypatch.setattr(pool, "check_spec_admission", MagicMock())
    monkeypatch.setattr(pool, "get_unique_vm_index", MagicMock(return_value=7))
    monkeypatch.setattr(pool, "_schedule_forget_on_stop", MagicMock())

    execution = MagicMock()
    execution.vm_id = VmId(_HASH)
    execution.vm = None
    execution.prepare = AsyncMock()
    execution.create = MagicMock()
    execution.start = AsyncMock()
    execution.persistent = persistent
    monkeypatch.setattr("aleph.vm.pool.VmExecution.from_spec", MagicMock(return_value=execution))

    result = await pool.create_vm_from_spec(_program_spec(persistent=persistent))

    assert result is execution
    execution.start.assert_awaited_once()
    # No InvalidBackendError raised for persistent: the guard is gone.
    assert pool.executions[execution.vm_id] is execution
