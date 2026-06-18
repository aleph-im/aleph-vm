"""pool.create_vm_from_spec — message-free, no-download create wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models.execution.environment import AMDSEVPolicy

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    TeeBackend,
    TeeConfig,
    VmId,
)

_HASH = "deadbeef" * 8
_DEVICE_ID = "10de:2504"


def _spec(
    backend: Backend = Backend.QEMU,
    tee: TeeConfig | None = None,
    gpus: list[GpuSpec] | None = None,
) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=backend,
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
        tee=tee,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=gpus or [],
        numa_node=None,
        persistent=True,
    )


def _tee(
    firmware_path: Path | None = Path("/data/firmware.fd"),
    policy: int = int(AMDSEVPolicy.NO_DBG),
) -> TeeConfig:
    return TeeConfig(
        backend=TeeBackend.SEV,
        policy=hex(policy),
        session_dir=DirectoryPath(Path("/tmp/session")),
        firmware_path=firmware_path,
    )


def _bare_pool() -> VmPool:
    import asyncio

    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.network = None  # exercise the no-network branch
    pool.snapshot_manager = None
    pool.creation_lock = asyncio.Lock()
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    pool.systemd_manager = systemd
    return pool


@pytest.mark.asyncio
async def test_create_vm_from_spec_wires_into_pool(monkeypatch):
    pool = _bare_pool()

    build_cfg = AsyncMock(return_value="fake-config")
    save_cfg = MagicMock()
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", save_cfg)
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    # Controller reports active immediately.
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    execution = await pool.create_vm_from_spec(_spec())

    assert pool.executions[execution.vm_hash] is execution
    assert execution.message is None
    assert execution.vm is not None
    build_cfg.assert_awaited_once()
    save_cfg.assert_called_once_with(_HASH, "fake-config")
    pool.systemd_manager.enable_and_start.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_vm_from_spec_preloads_persisted_port_mappings(monkeypatch):
    """create_vm_from_spec loads persisted port mappings and recreates nft rules."""
    pool = _bare_pool()

    persisted = {22: {"host": 24022, "tcp": True, "udp": False}}
    get_pm = AsyncMock(return_value=persisted)
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", AsyncMock(return_value="cfg"))
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", get_pm)
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )
    recreate = AsyncMock()
    monkeypatch.setattr("aleph.vm.models.VmExecution.recreate_port_redirect_rules", recreate)

    execution = await pool.create_vm_from_spec(_spec())

    get_pm.assert_awaited_once_with(_HASH)
    assert execution.mapped_ports == persisted
    recreate.assert_awaited_once()


def _patch_confidential_boot(monkeypatch) -> MagicMock:
    """Patch the create path so the real confidential config builder runs
    (cloud-init drive stubbed) and return the save_controller_configuration mock
    so tests can inspect the QemuConfidentialVMConfiguration it received."""
    monkeypatch.setattr(
        "aleph.vm.supervisor.qemu_build.build_cloud_init_drive",
        AsyncMock(return_value=Path("/data/cloud-init.img")),
    )
    save_cfg = MagicMock()
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", save_cfg)
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )
    return save_cfg


@pytest.mark.asyncio
async def test_create_vm_from_spec_confidential_builds_confidential_config(monkeypatch):
    """A confidential spec builds a QemuConfidentialVMConfiguration with the
    resolved firmware as ovmf_path and the converted SEV policy, creates the
    execution, and leaves it awaiting_confidential_init: the controller service
    is NOT enabled/started (only the owner starts it via initialize)."""
    from aleph.vm.controllers.configuration import QemuConfidentialVMConfiguration
    from aleph.vm.controllers.qemu_confidential.instance import (
        AlephQemuConfidentialInstance,
    )

    pool = _bare_pool()
    # An awaiting-init confidential VM has no active controller service.
    pool.systemd_manager.is_service_active.return_value = False
    save_cfg = _patch_confidential_boot(monkeypatch)
    # The plain builder must NOT be used for a confidential spec.
    plain_builder = AsyncMock(return_value="plain-cfg")
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", plain_builder)

    execution = await pool.create_vm_from_spec(_spec(tee=_tee()))

    # The confidential controller object, not the plain one.
    assert isinstance(execution.vm, AlephQemuConfidentialInstance)
    assert execution.is_confidential is True

    # The saved config is a confidential configuration with the right fields.
    save_cfg.assert_called_once()
    saved_config = save_cfg.call_args.args[1]
    vm_cfg = saved_config.vm_configuration
    assert isinstance(vm_cfg, QemuConfidentialVMConfiguration)
    assert str(vm_cfg.ovmf_path) == "/data/firmware.fd"
    assert vm_cfg.sev_policy == int(AMDSEVPolicy.NO_DBG)

    # The plain builder was never reached: no chance of an unprotected boot.
    plain_builder.assert_not_awaited()

    # Awaiting confidential init: started but not running, controller untouched.
    pool.systemd_manager.enable_and_start.assert_not_awaited()
    assert execution.is_awaiting_confidential_init is True


@pytest.mark.asyncio
async def test_create_vm_from_spec_confidential_applies_requested_policy(monkeypatch):
    """The requested SEV policy on spec.tee flows through verbatim to the engine
    configuration: the supervisor neither defaults nor clamps it."""
    from aleph.vm.controllers.configuration import QemuConfidentialVMConfiguration
    from aleph.vm.controllers.qemu_confidential.instance import (
        AlephQemuConfidentialInstance,
    )

    requested_policy = int(AMDSEVPolicy.NO_DBG | AMDSEVPolicy.SEV_ES)
    assert requested_policy != int(AMDSEVPolicy.NO_DBG)

    pool = _bare_pool()
    pool.systemd_manager.is_service_active.return_value = False
    save_cfg = _patch_confidential_boot(monkeypatch)
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", AsyncMock(return_value="plain-cfg"))

    execution = await pool.create_vm_from_spec(_spec(tee=_tee(policy=requested_policy)))

    # The requested policy reached the controller object and the saved config.
    assert isinstance(execution.vm, AlephQemuConfidentialInstance)
    assert execution.vm.confidential_policy == requested_policy
    saved_config = save_cfg.call_args.args[1]
    vm_cfg = saved_config.vm_configuration
    assert isinstance(vm_cfg, QemuConfidentialVMConfiguration)
    assert vm_cfg.sev_policy == requested_policy


@pytest.mark.asyncio
async def test_create_vm_from_spec_confidential_without_firmware_raises_no_plain_config(monkeypatch):
    """A confidential spec whose firmware could not be resolved must fail loudly
    and NEVER fall back to a plain QemuVMConfiguration."""
    pool = _bare_pool()
    _patch_confidential_boot(monkeypatch)
    plain_builder = AsyncMock(return_value="plain-cfg")
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", plain_builder)

    with pytest.raises(InvalidBackendError, match="(?i)firmware"):
        await pool.create_vm_from_spec(_spec(tee=_tee(firmware_path=None)))

    # No fallback to a plain config, and the half-registered execution is gone.
    plain_builder.assert_not_awaited()
    assert pool.executions == {}


@pytest.mark.asyncio
async def test_create_vm_from_spec_confidential_with_gpu_carries_resolved_gpu(monkeypatch):
    """Confidential + GPU compose: the GPU request is resolved to a concrete
    host card and that pci_host lands in the confidential configuration."""
    from aleph.vm.controllers.configuration import QemuConfidentialVMConfiguration
    from aleph.vm.resources import GpuDevice as ResourceGpuDevice
    from aleph.vm.resources import GpuDeviceClass

    gpu = ResourceGpuDevice(
        vendor="NVIDIA",
        model="RTX 4000",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host="0000:01:00.0",
        device_id=_DEVICE_ID,
        compatible=True,
    )
    pool = _bare_pool()
    pool.gpus = [gpu]
    save_cfg = _patch_confidential_boot(monkeypatch)

    request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=_DEVICE_ID, model="")
    execution = await pool.create_vm_from_spec(_spec(tee=_tee(), gpus=[request]))

    # The resolved GPU is attached to the execution.
    assert execution.gpus[0].pci_host == "0000:01:00.0"

    # And carried into the confidential config.
    saved_config = save_cfg.call_args.args[1]
    vm_cfg = saved_config.vm_configuration
    assert isinstance(vm_cfg, QemuConfidentialVMConfiguration)
    assert [g.pci_host for g in vm_cfg.gpus] == ["0000:01:00.0"]


@pytest.mark.asyncio
async def test_create_vm_from_spec_same_spec_returns_live_vm():
    """CreateVm idempotency: a retry with the identical spec is a no-op read."""
    from types import SimpleNamespace

    pool = _bare_pool()
    spec = _spec()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=spec)
    from aleph_message.models import ItemHash

    pool.executions[ItemHash(_HASH)] = live

    assert await pool.create_vm_from_spec(spec) is live


@pytest.mark.asyncio
async def test_create_vm_from_spec_conflicting_spec_raises_already_exists():
    """A different spec for a live vm_id is a conflict, not a silent reuse."""
    from dataclasses import replace
    from types import SimpleNamespace

    from aleph_message.models import ItemHash

    from aleph.vm.supervisor.errors import VmAlreadyExistsError

    pool = _bare_pool()
    spec = _spec()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=spec)
    pool.executions[ItemHash(_HASH)] = live

    with pytest.raises(VmAlreadyExistsError):
        await pool.create_vm_from_spec(replace(spec, memory_mib=4096))


@pytest.mark.asyncio
async def test_create_vm_from_spec_collision_with_message_built_vm_raises():
    """A live message-built execution (vm_spec=None) for the same hash is a
    conflict too: the pool cannot prove the spec matches."""
    from types import SimpleNamespace

    from aleph_message.models import ItemHash

    from aleph.vm.supervisor.errors import VmAlreadyExistsError

    pool = _bare_pool()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=None)
    pool.executions[ItemHash(_HASH)] = live

    with pytest.raises(VmAlreadyExistsError):
        await pool.create_vm_from_spec(_spec())


# ── pool.reserve_gpus — message-free GPU reservation ───────────────────────


def _gpu_device(device_id: str = _DEVICE_ID, pci_host: str = "0000:01:00.0"):
    from aleph.vm.resources import GpuDevice as ResourceGpuDevice
    from aleph.vm.resources import GpuDeviceClass

    return ResourceGpuDevice(
        vendor="NVIDIA",
        model="RTX 4000",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host=pci_host,
        device_id=device_id,
        compatible=True,
    )


@pytest.mark.asyncio
async def test_reserve_gpus_reserves_by_device_id():
    """reserve_gpus matches a request to a free card by device_id and holds it
    for the user."""
    pool = _bare_pool()
    gpu = _gpu_device()
    pool.gpus = [gpu]

    request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=_DEVICE_ID, model="")
    expiry = await pool.reserve_gpus([request], "0xUSER")

    assert gpu in pool.reservations
    assert pool.reservations[gpu].user == "0xUSER"
    assert pool.reservations[gpu].expiration == expiry


@pytest.mark.asyncio
async def test_reserve_gpus_empty_request_holds_nothing():
    """An empty GPU request returns an expiry without touching reservations."""
    pool = _bare_pool()
    pool.gpus = []

    expiry = await pool.reserve_gpus([], "0xUSER")

    assert pool.reservations == {}
    assert expiry is not None


@pytest.mark.asyncio
async def test_reserve_gpus_raises_when_none_free():
    """A request whose device_id matches no host card raises
    InsufficientResourcesError."""
    from aleph.vm.resources import InsufficientResourcesError

    pool = _bare_pool()
    pool.gpus = [_gpu_device(device_id="10de:OTHER")]

    request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=_DEVICE_ID, model="")
    with pytest.raises(InsufficientResourcesError):
        await pool.reserve_gpus([request], "0xUSER")

    assert pool.reservations == {}


@pytest.mark.asyncio
async def test_reserve_gpus_respects_another_users_hold():
    """A card already reserved by another user blocks the request; with only one
    card the second user gets InsufficientResourcesError."""
    from datetime import datetime, timedelta, timezone

    from aleph.vm.pool import Reservation
    from aleph.vm.resources import InsufficientResourcesError

    pool = _bare_pool()
    gpu = _gpu_device()
    pool.gpus = [gpu]
    # First user holds the only matching card.
    pool.reservations[gpu] = Reservation(
        user="0xOWNER",
        expiration=datetime.now(tz=timezone.utc) + timedelta(seconds=60),
        resource=gpu,
    )

    request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=_DEVICE_ID, model="")
    with pytest.raises(InsufficientResourcesError):
        await pool.reserve_gpus([request], "0xOTHER")

    # The owner's hold is untouched.
    assert pool.reservations[gpu].user == "0xOWNER"


@pytest.mark.asyncio
async def test_reserve_gpus_no_partial_commit_when_one_request_unmatched():
    """A multi-GPU request that cannot be fully satisfied holds nothing: the
    matched card must not leave a stray reservation when a later request fails."""
    from aleph.vm.resources import InsufficientResourcesError

    pool = _bare_pool()
    matching = _gpu_device(device_id=_DEVICE_ID, pci_host="0000:01:00.0")
    pool.gpus = [matching]

    matched_request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id=_DEVICE_ID, model="")
    unmatched_request = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id="10de:OTHER", model="")

    with pytest.raises(InsufficientResourcesError):
        await pool.reserve_gpus([matched_request, unmatched_request], "0xUSER")

    # The card matched by the first request must not have been held.
    assert pool.reservations == {}
