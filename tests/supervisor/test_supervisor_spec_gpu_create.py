"""pool.create_vm_from_spec GPU resolution and reservation (Slice 1).

The spec path resolves an unresolved GPU REQUEST (device_id, empty pci_host)
to a concrete available host card atomically inside the create path, mirroring
what the message path (create_a_vm + prepare_gpus) does, and attaches it to the
execution so it shows up in VmInfo and is held against other creates.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.contract.types import (
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
from aleph.vm.pool import Reservation, VmPool
from aleph.vm.resources import GpuDevice as ResourceGpuDevice
from aleph.vm.resources import GpuDeviceClass, InsufficientResourcesError

_HASH = "deadbeef" * 8
_DEVICE_ID = "10de:2504"


def _gpu_device(pci_host: str, *, device_id: str = _DEVICE_ID) -> ResourceGpuDevice:
    return ResourceGpuDevice(
        vendor="NVIDIA",
        model="RTX 4000",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host=pci_host,
        device_id=device_id,
        compatible=True,
    )


def _gpu_request(device_id: str = _DEVICE_ID) -> GpuSpec:
    # An unresolved request: device_id set, pci_host empty.
    return GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=device_id, model="")


def _spec(gpus: list[GpuSpec], *, owner_address: str = "") -> CreateVmSpec:
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
        owner_address=owner_address,
    )


def _bare_pool(gpus: list[ResourceGpuDevice]) -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.gpus = gpus
    pool.network = None
    pool.snapshot_manager = None
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
async def test_create_vm_from_spec_resolves_and_reserves_available_gpu(monkeypatch):
    """A spec carrying a GPU request reserves an available host card: the
    execution carries the resolved pci_host and the GPU is no longer available."""
    pool = _bare_pool([_gpu_device("0000:01:00.0")])
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_gpu_request()]))

    # The execution carries the resolved host GPU.
    assert len(execution.gpus) == 1
    assert execution.gpus[0].pci_host == "0000:01:00.0"
    assert execution.gpus[0].device_id == _DEVICE_ID
    # The resolved spec now carries the concrete pci_host.
    assert execution.vm_spec.gpus[0].pci_host == "0000:01:00.0"
    # And it is reserved: no longer available to a future create.
    assert pool.get_available_gpus() == []


@pytest.mark.asyncio
async def test_create_vm_from_spec_passes_resolved_gpu_to_config(monkeypatch):
    """The resolved spec (concrete pci_host) is what build_qemu_configuration sees."""
    pool = _bare_pool([_gpu_device("0000:02:00.0")])
    build_cfg = AsyncMock(return_value="cfg")
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    await pool.create_vm_from_spec(_spec([_gpu_request()]))

    assert build_cfg.await_args is not None
    passed_spec = build_cfg.await_args.args[0]
    assert passed_spec.gpus[0].pci_host == "0000:02:00.0"


@pytest.mark.asyncio
async def test_create_vm_from_spec_no_matching_gpu_raises(monkeypatch):
    """A request for a device_id with no available host card is refused."""
    pool = _bare_pool([_gpu_device("0000:01:00.0", device_id="1002:aaaa")])
    _patch_boot(monkeypatch)

    with pytest.raises(InsufficientResourcesError):
        await pool.create_vm_from_spec(_spec([_gpu_request(device_id="10de:2504")]))

    # The half-registered execution is forgotten.
    assert pool.executions == {}


@pytest.mark.asyncio
async def test_create_vm_from_spec_skips_gpu_reserved_by_other_user(monkeypatch):
    """A GPU with a valid reservation held by ANOTHER user is skipped: the
    engine resolves to a card free of other users' holds."""
    reserved_gpu = _gpu_device("0000:01:00.0")
    free_gpu = _gpu_device("0000:02:00.0")
    pool = _bare_pool([reserved_gpu, free_gpu])
    pool.reservations[reserved_gpu] = Reservation(
        user="0xother",
        resource=reserved_gpu,
        expiration=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
    )
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_gpu_request()], owner_address="0xowner"))

    # Skipped the reserved one, took the free one.
    assert execution.gpus[0].pci_host == "0000:02:00.0"
    # The other user's reservation is untouched.
    assert pool.reservations.get(reserved_gpu) is not None


@pytest.mark.asyncio
async def test_create_vm_from_spec_consumes_owner_reservation(monkeypatch):
    """A GPU reserved by THIS owner (spec.owner_address) is consumed by the
    engine: the card is taken even though it carries a valid reservation, and
    that reservation is dropped. This replaces the agent-side
    release_user_reservations call."""
    reserved_gpu = _gpu_device("0000:01:00.0")
    pool = _bare_pool([reserved_gpu])
    pool.reservations[reserved_gpu] = Reservation(
        user="0xowner",
        resource=reserved_gpu,
        expiration=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
    )
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_gpu_request()], owner_address="0xowner"))

    # The owner's own reservation did not block the create.
    assert execution.gpus[0].pci_host == "0000:01:00.0"
    # And it was consumed (dropped), not left dangling.
    assert pool.reservations.get(reserved_gpu) is None


@pytest.mark.asyncio
async def test_create_vm_from_spec_owner_reservation_does_not_unblock_other(monkeypatch):
    """The owner's reservation is consumed but a DIFFERENT user's reservation on
    a different card still blocks that card."""
    owner_gpu = _gpu_device("0000:01:00.0")
    other_gpu = _gpu_device("0000:02:00.0")
    pool = _bare_pool([owner_gpu, other_gpu])
    now = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
    pool.reservations[owner_gpu] = Reservation(user="0xowner", resource=owner_gpu, expiration=now)
    pool.reservations[other_gpu] = Reservation(user="0xother", resource=other_gpu, expiration=now)
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_gpu_request()], owner_address="0xowner"))

    # Took the owner's card (reservation consumed), skipped the other user's.
    assert execution.gpus[0].pci_host == "0000:01:00.0"
    assert pool.reservations.get(owner_gpu) is None
    assert pool.reservations.get(other_gpu) is not None


@pytest.mark.asyncio
async def test_create_vm_from_spec_two_gpus_distinct_hosts(monkeypatch):
    """Two requests for the same device_id resolve to two distinct host cards."""
    pool = _bare_pool([_gpu_device("0000:01:00.0"), _gpu_device("0000:02:00.0")])
    _patch_boot(monkeypatch)

    execution = await pool.create_vm_from_spec(_spec([_gpu_request(), _gpu_request()]))

    hosts = {g.pci_host for g in execution.gpus}
    assert hosts == {"0000:01:00.0", "0000:02:00.0"}
