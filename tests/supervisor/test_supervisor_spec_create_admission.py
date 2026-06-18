"""create_vm_from_spec enforces capacity admission atomically (Phase 1 P1.5).

An over-capacity spec must raise InsufficientResourcesError before any
execution is registered in the pool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.conf import settings
from aleph.vm.contract.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)
from aleph.vm.pool import VmPool
from aleph.vm.resources import InsufficientResourcesError

_HASH = "deadbeef" * 8


def _spec(*, vcpus: int, memory_mib: int) -> CreateVmSpec:
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
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


@pytest.fixture
def pool(mocker) -> VmPool:
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    return VmPool()


@pytest.mark.asyncio
async def test_over_capacity_spec_raises_and_registers_nothing(pool, mocker):
    # 1 GiB host: instance memory cap is tiny once reservations are subtracted.
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=1024 * 1024 * 1024))
    mocker.patch("aleph.vm.pool.psutil.cpu_count", return_value=16)

    with pytest.raises(InsufficientResourcesError):
        await pool.create_vm_from_spec(_spec(vcpus=1, memory_mib=64 * 1024))

    assert pool.executions == {}
