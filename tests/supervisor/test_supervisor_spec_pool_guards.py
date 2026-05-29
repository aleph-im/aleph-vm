"""A message-less (spec-built) execution must not break pool-wide iterations."""

from __future__ import annotations

from pathlib import Path

from aleph_message.models import PaymentType

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


def test_get_executions_by_address_skips_message_less():
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    spec_exec = VmExecution.from_spec(_spec(), snapshot_manager=None, systemd_manager=None)
    # Mark it "running" so the iteration does not skip it for that reason;
    # systemd_manager is None so is_running falls back to the times check.
    spec_exec.times.started_at = spec_exec.times.starting_at = spec_exec.times.defined_at
    pool.executions[_HASH] = spec_exec

    # Must not raise even though execution.message is None.
    result = pool.get_executions_by_address(PaymentType.hold)
    assert result == {}
