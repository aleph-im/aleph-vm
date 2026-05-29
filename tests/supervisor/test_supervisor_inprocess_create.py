"""InProcessSupervisor.create_vm delegates to pool.create_vm_from_spec."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
    VmStatus,
)

_HASH = "itemhash123"


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


@pytest.mark.asyncio
async def test_create_vm_delegates_and_returns_info():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={_HASH: execution},
        systemd=FakeSystemd({f"aleph-vm-controller@{_HASH}.service": True}),
    )
    pool.create_vm_from_spec = AsyncMock(return_value=execution)
    sup = InProcessSupervisor(pool=pool)

    spec = _spec()
    info = await sup.create_vm(spec)

    pool.create_vm_from_spec.assert_awaited_once_with(spec)
    assert info.vm_id == _HASH
    assert info.status is VmStatus.RUNNING
