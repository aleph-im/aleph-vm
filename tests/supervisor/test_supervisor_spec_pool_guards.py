"""A message-less (spec-built) execution must not break pool-wide iterations."""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.models import VmExecution
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


@pytest.mark.asyncio
async def test_forget_on_stop_does_not_remove_a_recreated_execution():
    """The forget-on-stop task of a stopped execution must not remove a NEW
    execution registered under the same vm_id (reboot and delete+create
    recreate the VM while the old stop is still being reaped)."""
    import asyncio
    from types import SimpleNamespace

    from aleph.vm.pool import VmPool

    pool = VmPool.__new__(VmPool)  # only .executions/.forget_vm are exercised
    pool.executions = {}

    old = SimpleNamespace(vm_hash=_HASH, stop_event=asyncio.Event(), _forget_task=None)
    pool.executions[_HASH] = old
    VmPool._schedule_forget_on_stop(pool, old)

    # The VM is recreated under the same id before the old reap task ran.
    pool.forget_vm(_HASH)
    new = SimpleNamespace(vm_hash=_HASH, stop_event=asyncio.Event())
    pool.executions[_HASH] = new

    old.stop_event.set()
    await asyncio.sleep(0.05)

    assert pool.executions.get(_HASH) is new
