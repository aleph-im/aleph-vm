"""A message-less (spec-built) execution must not break pool-wide iterations."""

from __future__ import annotations

from pathlib import Path

from aleph.vm.models import VmExecution
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


def test_allocated_properties_from_spec():
    execution = VmExecution.from_spec(_spec(), snapshot_manager=None, systemd_manager=None)
    assert execution.allocated_memory_mib == 1024
    assert execution.allocated_vcpus == 2
