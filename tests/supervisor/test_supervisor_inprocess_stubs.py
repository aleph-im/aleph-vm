from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.conf import settings
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import ConfidentialMode, TeeBackend, VmId


class FakePool:
    def __init__(self):
        self.executions = {}
        # Reservation entrypoints LocalSupervisor.reserve_resources drives; tests
        # override these with mocks. Declared here so static typing sees them.
        self.check_capacity = MagicMock()
        self.reserve_gpus = AsyncMock()


@pytest.fixture
def supervisor():
    return LocalSupervisor(pool=FakePool())


def test_can_instantiate(supervisor):
    assert isinstance(supervisor, LocalSupervisor)


@pytest.mark.asyncio
async def test_migration_rides_standard_lifecycle(supervisor):
    # Migration carries no dedicated method: the export stop is a plain stop_vm,
    # which is implemented (an unknown VM is a lookup error, not a stub).
    assert not hasattr(supervisor, "stop_vm_for_export")
    with pytest.raises(VmNotFoundError):
        await supervisor.stop_vm(VmId("abc"))


# ── Confidential ─────────────────────────────────────────────────────────────


class FakeSystemd:
    def __init__(self):
        self.enable_and_start = AsyncMock()


class ConfidentialPool:
    def __init__(self, vm_id, execution):
        self.executions = {vm_id: execution}
        self.systemd_manager = FakeSystemd()


def _confidential_execution(vm_id):
    return SimpleNamespace(
        vm_hash=vm_id,
        controller_service=f"aleph-vm-controller@{vm_id}.service",
        is_confidential=True,
        vm=SimpleNamespace(confidential_policy=0),
    )


@pytest.mark.asyncio
async def test_initialize_confidential_unknown_vm_raises(supervisor):
    with pytest.raises(VmNotFoundError):
        await supervisor.initialize_confidential(VmId("nope"), b"session", b"godh")


@pytest.mark.asyncio
async def test_initialize_confidential_writes_files_and_starts_service(monkeypatch, tmp_path):
    vm_id = VmId("hash-conf")
    monkeypatch.setattr(settings, "CONFIDENTIAL_SESSION_DIRECTORY", tmp_path)
    execution = _confidential_execution(vm_id)
    pool = ConfidentialPool(vm_id, execution)
    sup = LocalSupervisor(pool=pool)

    await sup.initialize_confidential(vm_id, b"session-bytes", b"godh-bytes")

    session_dir = tmp_path / vm_id
    assert (session_dir / "vm_session.b64").read_bytes() == b"session-bytes"
    assert (session_dir / "vm_godh.b64").read_bytes() == b"godh-bytes"
    pool.systemd_manager.enable_and_start.assert_awaited_once_with(execution.controller_service)


@pytest.mark.asyncio
async def test_get_measurement_unknown_vm_raises(supervisor):
    with pytest.raises(VmNotFoundError):
        await supervisor.get_measurement(VmId("nope"))


@pytest.mark.asyncio
async def test_get_measurement_returns_sev_info_and_launch_measure(monkeypatch):
    vm_id = VmId("hash-conf")
    execution = _confidential_execution(vm_id)
    pool = ConfidentialPool(vm_id, execution)
    sup = LocalSupervisor(pool=pool)

    sev_info = SimpleNamespace(
        enabled=True,
        api_major=1,
        api_minor=55,
        build_id=21,
        policy=3,
        state="launch-update",
        handle=7,
    )
    client = MagicMock()
    client.query_sev_info.return_value = sev_info
    client.query_launch_measure.return_value = "bWVhc3VyZQ=="
    client_factory = MagicMock(return_value=client)
    monkeypatch.setattr("aleph.vm.supervisor.local.QemuVmClient", client_factory)

    measurement = await sup.get_measurement(vm_id)

    client_factory.assert_called_once_with(execution.vm)
    client.query_sev_info.assert_called_once()
    client.query_launch_measure.assert_called_once()
    client.close.assert_called_once()
    assert measurement.vm_id == vm_id
    assert measurement.tee_backend is TeeBackend.SEV
    assert measurement.launch_measure == "bWVhc3VyZQ=="


async def test_get_measurement_tee_backend_is_derived_not_hardcoded(monkeypatch):
    """tee_backend comes from the VM's confidential config, not a literal SEV."""
    vm_id = VmId("hash-conf")
    execution = _confidential_execution(vm_id)
    pool = ConfidentialPool(vm_id, execution)
    sup = LocalSupervisor(pool=pool)

    client = MagicMock()
    client.query_sev_info.return_value = SimpleNamespace(
        enabled=True, api_major=1, api_minor=55, build_id=21, policy=3, state="launch-update", handle=7
    )
    client.query_launch_measure.return_value = "bWVhc3VyZQ=="
    monkeypatch.setattr("aleph.vm.supervisor.local.QemuVmClient", MagicMock(return_value=client))
    monkeypatch.setattr(
        "aleph.vm.supervisor.local._confidential_mode",
        lambda execution: ConfidentialMode.SEV_SNP,
    )

    measurement = await sup.get_measurement(vm_id)

    assert measurement.tee_backend is TeeBackend.SEV_SNP
    assert measurement.sev_info.enabled is True
    assert measurement.sev_info.api_major == 1
    assert measurement.sev_info.api_minor == 55
    assert measurement.sev_info.build_id == 21
    assert measurement.sev_info.policy == 3
    assert measurement.sev_info.state == "launch-update"
    assert measurement.sev_info.handle == 7


@pytest.mark.asyncio
async def test_inject_secret_unknown_vm_raises(supervisor):
    with pytest.raises(VmNotFoundError):
        await supervisor.inject_secret(VmId("nope"), b"header", b"secret")


@pytest.mark.asyncio
async def test_inject_secret_injects_and_continues(monkeypatch):
    vm_id = VmId("hash-conf")
    execution = _confidential_execution(vm_id)
    pool = ConfidentialPool(vm_id, execution)
    sup = LocalSupervisor(pool=pool)

    client = MagicMock()
    client_factory = MagicMock(return_value=client)
    monkeypatch.setattr("aleph.vm.supervisor.local.QemuVmClient", client_factory)

    result = await sup.inject_secret(vm_id, b"header", b"secret")

    assert result is None
    client_factory.assert_called_once_with(execution.vm)
    client.inject_secret.assert_called_once_with("header", "secret")
    client.continue_execution.assert_called_once()
    client.query_status.assert_not_called()
    client.close.assert_called_once()


# ── Reservation ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reserve_resources_runs_capacity_then_reserves_gpus():
    """The engine reserves against a message-free ReservationRequest DTO: it runs
    check_capacity from the scalar fields and reserve_gpus from the GPU list, and
    never parses an Aleph message."""
    from datetime import datetime, timezone

    from aleph.vm.supervisor_interface.types import (
        GpuSpec,
        PciAddress,
        ReservationRequest,
    )

    expiry = datetime(2030, 1, 1, tzinfo=timezone.utc)
    pool = FakePool()
    pool.check_capacity = MagicMock()
    pool.reserve_gpus = AsyncMock(return_value=expiry)
    sup = LocalSupervisor(pool=pool)

    gpu = GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id="10de:2504", model="")
    request = ReservationRequest(
        owner_id="0xUSER",
        vcpus=2,
        memory_mib=2048,
        disk_mib=10,
        is_instance=True,
        gpus=[gpu],
    )

    result = await sup.reserve_resources(request)

    assert result == expiry
    pool.check_capacity.assert_called_once_with(
        memory_mib=2048,
        vcpus=2,
        disk_mib=10,
        is_instance=True,
    )
    pool.reserve_gpus.assert_awaited_once_with([gpu], "0xUSER")
