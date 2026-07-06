"""pool.create_vm_from_spec GPU attach validation.

The spec arrives with RESOLVED GPUs (concrete pci_host, chosen by the agent's
ledger). The engine validates each card against its inventory and current
attachments atomically inside the create path, attaches it to the execution
so it shows up in VmInfo, and refuses impossible attachments.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.resources import GpuDevice as ResourceGpuDevice
from aleph.vm.resources import GpuDeviceClass, InsufficientResourcesError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    VmId,
)

_HASH = "deadbeef" * 8
_DEVICE_ID = "10de:2504"


def _gpu_device(pci_host: str, *, device_id: str = _DEVICE_ID) -> ResourceGpuDevice:
    return ResourceGpuDevice(
        vendor="NVIDIA",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host=pci_host,
        device_id=device_id,
    )


def _resolved_gpu(pci_host: str = "0000:01:00.0") -> GpuSpec:
    # A resolved assignment: the agent already bound the request to this card.
    return GpuSpec(pci_host=PciAddress(pci_host), supports_x_vga=True)


def _spec(gpus: list[GpuSpec]) -> CreateVmSpec:
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
        gpus=gpus,
        numa_node=None,
        persistent=True,
    )


def _bare_pool(gpus: list[ResourceGpuDevice]) -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool._failed_reattach = {}
    pool.gpus = gpus
    pool.network = None
    pool.creation_lock = asyncio.Lock()
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    pool.systemd_manager = systemd
    return pool


def _patch_boot(monkeypatch) -> None:
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", AsyncMock(return_value="cfg"))
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )


@pytest.mark.asyncio
async def test_create_vm_from_spec_attaches_validated_gpu(monkeypatch):
    """A spec carrying a resolved GPU attaches the inventory card: the
    execution carries it (device_id from the inventory) and the card is no
    longer available to a future create."""
    pool = _bare_pool([_gpu_device("0000:01:00.0")])
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_resolved_gpu()]))

    assert len(execution.gpus) == 1
    assert execution.gpus[0].pci_host == "0000:01:00.0"
    assert execution.gpus[0].device_id == _DEVICE_ID
    # Held against other creates: no longer available.
    assert pool.get_available_gpus() == []


@pytest.mark.asyncio
async def test_create_vm_from_spec_passes_spec_gpu_to_config(monkeypatch):
    """The spec (already carrying the concrete pci_host) is what
    build_qemu_configuration sees."""
    pool = _bare_pool([_gpu_device("0000:02:00.0")])
    build_cfg = AsyncMock(return_value="cfg")
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    await pool.create_vm_from_spec(_spec([_resolved_gpu("0000:02:00.0")]))

    assert build_cfg.await_args is not None
    passed_spec = build_cfg.await_args.args[0]
    assert passed_spec.gpus[0].pci_host == "0000:02:00.0"


@pytest.mark.asyncio
async def test_create_vm_from_spec_unknown_pci_host_raises(monkeypatch):
    """A pci_host absent from the host inventory is refused."""
    pool = _bare_pool([_gpu_device("0000:01:00.0")])
    _patch_boot(monkeypatch)

    with pytest.raises(InsufficientResourcesError):
        await pool.create_vm_from_spec(_spec([_resolved_gpu("0000:99:00.0")]))

    # The half-registered execution is forgotten.
    assert pool.executions == {}


@pytest.mark.asyncio
async def test_create_vm_from_spec_refuses_attached_gpu(monkeypatch):
    """A card already attached to a running VM cannot be attached again."""
    pool = _bare_pool([_gpu_device("0000:01:00.0")])
    _patch_boot(monkeypatch)

    await pool.create_vm_from_spec(_spec([_resolved_gpu()]))

    second_spec = replace(_spec([_resolved_gpu()]), vm_id=VmId("cafebabe" * 8))
    with pytest.raises(InsufficientResourcesError):
        await pool.create_vm_from_spec(second_spec)


@pytest.mark.asyncio
async def test_create_vm_from_spec_two_resolved_gpus(monkeypatch):
    """Two resolved cards attach as given, in spec order."""
    pool = _bare_pool([_gpu_device("0000:01:00.0"), _gpu_device("0000:02:00.0")])
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_resolved_gpu("0000:01:00.0"), _resolved_gpu("0000:02:00.0")]))

    assert [g.pci_host for g in execution.gpus] == ["0000:01:00.0", "0000:02:00.0"]
