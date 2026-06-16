"""Unit tests for VmPool.check_spec_admission (Phase 1 P1.5).

Spec-based capacity admission folds the memory/vCPU accounting of
check_admission into the message-free create path. Disk is deferred
(DiskSpec carries no size_mib today).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    NetworkConfig,
    VmId,
)


def _spec(*, vcpus: int, memory_mib: int) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId("itemhash123"),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[],
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
    # check_spec_admission only reads self.executions and psutil host figures;
    # disable networking so the bare pool constructs without a host interface.
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    return VmPool()


def test_in_budget_spec_returns_none(pool, mocker):
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=64 * 1024 * 1024 * 1024))
    mocker.patch("aleph.vm.pool.psutil.cpu_count", return_value=16)

    assert pool.check_spec_admission(_spec(vcpus=2, memory_mib=2048)) is None


def test_over_memory_cap_spec_raises(pool, mocker):
    # 1 GiB physical: after host/program reservations the instance cap is small,
    # so a large memory request blows the bucket.
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=1024 * 1024 * 1024))
    mocker.patch("aleph.vm.pool.psutil.cpu_count", return_value=16)

    with pytest.raises(InsufficientResourcesError):
        pool.check_spec_admission(_spec(vcpus=1, memory_mib=64 * 1024))


def test_over_vcpu_cap_spec_raises(pool, mocker):
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=256 * 1024 * 1024 * 1024))
    mocker.patch("aleph.vm.pool.psutil.cpu_count", return_value=1)

    with pytest.raises(InsufficientResourcesError):
        pool.check_spec_admission(_spec(vcpus=10_000, memory_mib=1024))
