"""Supervisor mechanism backstops at create: physical memory and GPU attach.

Admission POLICY (memory buckets, vCPU overcommit, user-scoped reservations)
lives agent-side (see test_agent_capacity.py). The pool only enforces two
invariants: never oversubscribe physical memory beyond the host reserve, and
never attach the same GPU twice.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.resources import GpuDevice, GpuDeviceClass, InsufficientResourcesError
from aleph.vm.supervisor_interface.types import GpuSpec, PciAddress

_DEVICE_ID = "10de:2504"


@pytest.fixture
def pool(mocker) -> VmPool:
    # The backstops only read self.executions, self.gpus and psutil host
    # figures; disable networking so the bare pool constructs without a host
    # interface.
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    return VmPool()


def _gpu_device(pci_host: str = "0000:01:00.0") -> GpuDevice:
    return GpuDevice(
        vendor="NVIDIA",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host=pci_host,
        device_id=_DEVICE_ID,
    )


def _resolved_spec_gpu(pci_host: str = "0000:01:00.0") -> GpuSpec:
    return GpuSpec(pci_host=PciAddress(pci_host), supports_x_vga=True)


# ── Physical memory backstop ────────────────────────────────────────────────


def test_in_budget_memory_passes(pool, mocker):
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=64 * 1024 * 1024 * 1024))

    assert pool._check_memory_backstop(2048) is None


def test_memory_beyond_physical_raises(pool, mocker):
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=4 * 1024 * 1024 * 1024))

    with pytest.raises(InsufficientResourcesError):
        pool._check_memory_backstop(64 * 1024)


def test_committed_memory_counts_against_the_backstop(pool, mocker):
    # 8 GiB physical, 2 GiB host reserve: cap 6144 MiB. With 4096 MiB already
    # committed, 2048 fits exactly and 2049 does not. No buckets: instance and
    # program memory count together.
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=8 * 1024 * 1024 * 1024))
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    pool.executions["a" * 64] = SimpleNamespace(allocated_memory_mib=4096)

    assert pool._check_memory_backstop(2048) is None
    with pytest.raises(InsufficientResourcesError):
        pool._check_memory_backstop(2049)


def test_memory_backstop_carries_structured_dicts(pool, mocker):
    mocker.patch("aleph.vm.pool.psutil.virtual_memory", return_value=mocker.Mock(total=4 * 1024 * 1024 * 1024))
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)

    with pytest.raises(InsufficientResourcesError) as excinfo:
        pool._check_memory_backstop(64 * 1024)

    assert excinfo.value.required == {"memory_mib": 64 * 1024}
    assert excinfo.value.available == {"memory_mib": 2048}


def test_bucket_policy_is_gone(pool):
    # vCPU overcommit and the memory buckets are agent policy now; the pool
    # keeps no policy entry points.
    assert not hasattr(pool, "check_capacity")
    assert not hasattr(pool, "check_spec_admission")
    assert not hasattr(pool, "reserve_gpus")
    assert not hasattr(pool, "reservations")


# ── GPU attach invariant ────────────────────────────────────────────────────


def test_validate_spec_gpus_accepts_free_inventory_card(pool):
    pool.gpus = [_gpu_device()]

    validated = pool._validate_spec_gpus([_resolved_spec_gpu()])

    assert len(validated) == 1
    assert validated[0].pci_host == "0000:01:00.0"
    assert validated[0].device_id == _DEVICE_ID


def test_validate_spec_gpus_unknown_pci_host_raises(pool):
    pool.gpus = [_gpu_device("0000:01:00.0")]

    with pytest.raises(InsufficientResourcesError) as excinfo:
        pool._validate_spec_gpus([_resolved_spec_gpu("0000:99:00.0")])

    assert excinfo.value.required == {"gpu_pci_host": "0000:99:00.0"}


def test_validate_spec_gpus_refuses_double_attach(pool):
    pool.gpus = [_gpu_device()]
    # A current execution already holds the card.
    pool.executions["a" * 64] = SimpleNamespace(uses_gpu=lambda pci_host: pci_host == "0000:01:00.0")

    with pytest.raises(InsufficientResourcesError) as excinfo:
        pool._validate_spec_gpus([_resolved_spec_gpu()])

    assert "already attached" in str(excinfo.value)


def test_validate_spec_gpus_refuses_same_card_twice_in_one_spec(pool):
    pool.gpus = [_gpu_device()]

    with pytest.raises(InsufficientResourcesError) as excinfo:
        pool._validate_spec_gpus([_resolved_spec_gpu(), _resolved_spec_gpu()])

    assert "claimed twice" in str(excinfo.value)
