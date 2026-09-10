"""Agent-side capacity policy and GPU reservation ledger (CapacityManager).

The two-bucket memory accounting, vCPU overcommit and user-scoped GPU holds
are agent policy: these tests drive them against the agent's registry and a
mocked supervisor HostInfo (the supervisor only supplies the GPU inventory).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from aleph_message.models.execution.instance import InstanceContent
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.capacity import (
    RESERVATION_TTL_SECONDS,
    CapacityManager,
    GpuHold,
    ResourceRequirements,
    requirements_from_message,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import GpuDevice, GpuDeviceClass, InsufficientResourcesError
from aleph.vm.supervisor_interface.types import HostInfo

_DEVICE_ID = "10de:2504"
_HASH_A = ItemHash("a" * 64)
_HASH_B = ItemHash("b" * 64)
_HASH_C = ItemHash("c" * 64)
_HASH_D = ItemHash("d" * 64)


def _gpu_device(pci_host: str = "0000:01:00.0", *, device_id: str = _DEVICE_ID) -> GpuDevice:
    return GpuDevice(
        vendor="NVIDIA",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host=pci_host,
        device_id=device_id,
    )


def _manager(available: list[GpuDevice] | None = None, registry: AgentVmRegistry | None = None) -> CapacityManager:
    gpus = available or []
    host_info = HostInfo(
        gpu_inventory=[gpu.model_dump() for gpu in gpus],
        available_gpus=[gpu.model_dump() for gpu in gpus],
    )
    supervisor = SimpleNamespace(get_host_info=AsyncMock(return_value=host_info))
    return CapacityManager(supervisor, registry or AgentVmRegistry())


def _patch_host(mocker, *, memory_bytes: int, cores: int, disk_bytes: int = 100 * 1024 * 1024 * 1024) -> None:
    mocker.patch(
        "aleph.vm.agent.capacity.psutil.virtual_memory",
        return_value=mocker.Mock(total=memory_bytes),
    )
    mocker.patch("aleph.vm.agent.capacity.psutil.cpu_count", return_value=cores)
    # Hermetic: PERSISTENT_VOLUMES_DIR does not exist on CI runners.
    mocker.patch.object(CapacityManager, "_available_disk_bytes", return_value=disk_bytes)


# ── check_capacity: two-bucket memory policy and vCPU overcommit ───────────


def test_in_budget_request_passes(mocker):
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)

    assert _manager().check_capacity(memory_mib=2048, vcpus=2, disk_mib=0, is_instance=True) is None


def test_over_memory_cap_raises(mocker):
    # 1 GiB physical: after host/program reservations the instance cap is
    # small, so a large memory request blows the bucket.
    _patch_host(mocker, memory_bytes=1024 * 1024 * 1024, cores=16)

    with pytest.raises(InsufficientResourcesError):
        _manager().check_capacity(memory_mib=64 * 1024, vcpus=1, disk_mib=0, is_instance=True)


def test_over_vcpu_cap_raises(mocker):
    _patch_host(mocker, memory_bytes=256 * 1024 * 1024 * 1024, cores=1)

    with pytest.raises(InsufficientResourcesError):
        _manager().check_capacity(memory_mib=1024, vcpus=10_000, disk_mib=0, is_instance=True)


def test_program_uses_program_bucket_when_instance_cap_is_zero(mocker):
    # A small host where physical - host_reserved - program_reserved <= 0, so
    # the instance bucket cap is 0. A program must still be admitted against
    # the program bucket (cap = PROGRAM_MEMORY_RESERVED_MIB), not refused by
    # the 0 instance cap.
    _patch_host(mocker, memory_bytes=3915 * 1024 * 1024, cores=2)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)

    manager = _manager()
    # An instance of the same size is refused (instance cap is 0)...
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=256, vcpus=1, disk_mib=0, is_instance=True)

    # ...but the program is admitted against the program bucket.
    assert manager.check_capacity(memory_mib=256, vcpus=1, disk_mib=0, is_instance=False) is None


def test_committed_memory_from_registry_is_bucketed(mocker):
    # Physical 16 GiB, host reserve 2 GiB, program reserve 4 GiB: instance
    # cap 10240 MiB, program cap 4096 MiB.
    _patch_host(mocker, memory_bytes=16 * 1024 * 1024 * 1024, cores=16)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 4096)

    registry = AgentVmRegistry()
    instance_message = _make_qemu_instance_message(vcpus=2, memory=8192)
    registry.record("i" * 64, message=instance_message, original=instance_message, persistent=True)
    # Any non-InstanceContent record lands in the program bucket.
    program_message = SimpleNamespace(resources=SimpleNamespace(memory=3072, vcpus=1))
    registry.record("p" * 64, message=program_message, original=program_message, persistent=True)

    manager = _manager(registry=registry)

    # Instance bucket: 8192 committed, cap 10240, so 2048 fits and 4096 does not.
    assert manager.check_capacity(memory_mib=2048, vcpus=1, disk_mib=0, is_instance=True) is None
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=4096, vcpus=1, disk_mib=0, is_instance=True)

    # Program bucket: 3072 committed, cap 4096, so 1024 fits and 2048 does not.
    assert manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=0, is_instance=False) is None
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=2048, vcpus=1, disk_mib=0, is_instance=False)


def test_committed_vprogram_memory_uses_instance_bucket(mocker):
    # Regression: a V-PROGRAM is admitted against the instance bucket
    # (run.py passes is_instance=True), so a *running* V-PROGRAM's memory must
    # also be counted there. Bucketing it as a program would starve the small
    # program bucket and hide its memory from instance admission (over-commit).
    from test_vprogram import load_vprogram_message

    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 4096)

    content = load_vprogram_message().content
    committed = content.resources.memory  # MiB the running V-PROGRAM holds
    instance_cap = 64 * 1024 - 2048 - 4096

    registry = AgentVmRegistry()
    registry.record("v" * 64, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)

    # Instance bucket sees the V-PROGRAM's memory committed: a request that
    # exactly fills the remainder passes, one MiB more does not.
    assert manager.check_capacity(memory_mib=instance_cap - committed, vcpus=1, disk_mib=0, is_instance=True) is None
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=instance_cap - committed + 1, vcpus=1, disk_mib=0, is_instance=True)

    # Program bucket sees nothing committed by the V-PROGRAM: its full cap is free.
    assert manager.check_capacity(memory_mib=4096, vcpus=1, disk_mib=0, is_instance=False) is None


def test_exclude_vm_hash_skips_the_vms_own_record(mocker):
    # The create paths record the VM before admission (owner record, or a
    # leftover record on a recreate): its own record must not count against
    # its own request. 16 GiB physical, 2 GiB host reserve, 4 GiB program
    # reserve: instance cap 10240 MiB. An 8192 MiB instance already recorded
    # would double-count to 16384 without the exclusion.
    _patch_host(mocker, memory_bytes=16 * 1024 * 1024 * 1024, cores=16)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 4096)

    registry = AgentVmRegistry()
    vm_hash = "i" * 64
    message = _make_qemu_instance_message(vcpus=2, memory=8192)
    registry.record(vm_hash, message=message, original=message, persistent=True)
    manager = _manager(registry=registry)

    # Without the exclusion the request is refused (8192 committed + 8192).
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=8192, vcpus=2, disk_mib=0, is_instance=True)

    # Excluding the VM's own record admits it.
    assert (
        manager.check_capacity(memory_mib=8192, vcpus=2, disk_mib=0, is_instance=True, exclude_vm_hash=vm_hash) is None
    )


def test_disk_is_only_checked_when_requested(mocker):
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16, disk_bytes=10 * 1024 * 1024 * 1024)

    manager = _manager()
    # disk_mib=0 skips the disk check entirely.
    assert manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=0, is_instance=True) is None
    # A request within the free space passes, one beyond it is refused.
    assert manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=1024, is_instance=True) is None
    with pytest.raises(InsufficientResourcesError):
        manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=20 * 1024, is_instance=True)


def test_missing_persistent_volumes_dir_reports_zero_disk(mocker):
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", "/nonexistent/aleph-test/volumes")
    assert CapacityManager._available_disk_bytes() == 0


def test_insufficient_capacity_carries_structured_dicts(mocker):
    _patch_host(mocker, memory_bytes=1024 * 1024 * 1024, cores=16)

    with pytest.raises(InsufficientResourcesError) as excinfo:
        _manager().check_capacity(memory_mib=64 * 1024, vcpus=2, disk_mib=0, is_instance=True)

    error = excinfo.value
    assert error.required == {"vcpus": 2, "memory_mib": 64 * 1024, "disk_mib": 0}
    assert set(error.available) == {"vcpus", "memory_mib", "disk_mib"}


# ── requirements_from_message ───────────────────────────────────────────────


def test_requirements_from_message_extracts_resources():
    from aleph_message.models.execution.environment import (
        GpuProperties,
        HostRequirements,
    )

    message = _make_qemu_instance_message(vcpus=2, memory=2048)
    message = message.model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="GH100",
                        device_class="0300",
                        device_id=_DEVICE_ID,
                    )
                ]
            )
        }
    )

    req = requirements_from_message(message)

    assert (req.vcpus, req.memory_mib, req.is_instance) == (2, 2048, True)
    assert req.gpu_device_ids == [_DEVICE_ID]
    assert req.owner == message.address
    # rootfs size is summed into disk_mib (the message fixture sets size_mib=10000)
    assert req.disk_mib == 10000


# ── GPU reservation ledger ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_reserve_gpus_holds_available_card():
    manager = _manager([_gpu_device()])

    expiry = await manager.reserve_gpus([_DEVICE_ID], "0xUSER")

    hold = manager.holds["0000:01:00.0"]
    assert hold.user == "0xUSER"
    assert hold.expiration == expiry
    assert expiry <= datetime.now(tz=timezone.utc) + timedelta(seconds=RESERVATION_TTL_SECONDS)


@pytest.mark.asyncio
async def test_reserve_gpus_empty_request_holds_nothing():
    manager = _manager([])

    expiry = await manager.reserve_gpus([], "0xUSER")

    assert manager.holds == {}
    assert expiry is not None


@pytest.mark.asyncio
async def test_reserve_gpus_raises_when_none_match():
    manager = _manager([_gpu_device(device_id="10de:OTHER")])

    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.reserve_gpus([_DEVICE_ID], "0xUSER")

    assert excinfo.value.required == {"gpu_device_id": _DEVICE_ID}
    assert excinfo.value.available == {"gpus": ["10de:OTHER"]}
    assert manager.holds == {}


@pytest.mark.asyncio
async def test_reserve_gpus_no_partial_commit_when_one_request_unmatched():
    # One matching card, two requests: nothing may be held when the second
    # request fails.
    manager = _manager([_gpu_device()])

    with pytest.raises(InsufficientResourcesError):
        await manager.reserve_gpus([_DEVICE_ID, "10de:OTHER"], "0xUSER")

    assert manager.holds == {}


@pytest.mark.asyncio
async def test_reserve_gpus_blocked_by_another_users_hold():
    manager = _manager([_gpu_device()])
    await manager.reserve_gpus([_DEVICE_ID], "0xOWNER")

    with pytest.raises(InsufficientResourcesError):
        await manager.reserve_gpus([_DEVICE_ID], "0xOTHER")

    # The owner's hold is untouched.
    assert manager.holds["0000:01:00.0"].user == "0xOWNER"


@pytest.mark.asyncio
async def test_reserve_gpus_refreshes_own_hold():
    manager = _manager([_gpu_device()])

    first = await manager.reserve_gpus([_DEVICE_ID], "0xUSER")
    second = await manager.reserve_gpus([_DEVICE_ID], "0xUSER")

    assert second >= first
    assert len(manager.holds) == 1
    assert manager.holds["0000:01:00.0"].expiration == second


@pytest.mark.asyncio
async def test_expired_hold_is_ignored():
    manager = _manager([_gpu_device()])
    manager.holds["0000:01:00.0"] = GpuHold(
        user="0xOWNER",
        expiration=datetime.now(tz=timezone.utc) - timedelta(seconds=1),
    )

    # Another user can reserve the card: the stale hold is dropped lazily.
    await manager.reserve_gpus([_DEVICE_ID], "0xOTHER")

    assert manager.holds["0000:01:00.0"].user == "0xOTHER"


@pytest.mark.asyncio
async def test_resolve_gpus_returns_resolved_cards():
    manager = _manager([_gpu_device()])

    resolved = await manager.resolve_gpus([_DEVICE_ID], owner="0xUSER")

    assert len(resolved) == 1
    assert str(resolved[0].pci_host) == "0000:01:00.0"
    # VGA-compatible controller class supports x-vga.
    assert resolved[0].supports_x_vga is True


@pytest.mark.asyncio
async def test_resolve_gpus_consumes_own_hold():
    manager = _manager([_gpu_device()])
    await manager.reserve_gpus([_DEVICE_ID], "0xOWNER")

    resolved = await manager.resolve_gpus([_DEVICE_ID], owner="0xOWNER")

    # The owner's own hold did not block the resolve and was consumed.
    assert str(resolved[0].pci_host) == "0000:01:00.0"
    assert manager.holds == {}


@pytest.mark.asyncio
async def test_resolve_gpus_skips_card_held_by_another_user():
    held = _gpu_device("0000:01:00.0")
    free = _gpu_device("0000:02:00.0")
    manager = _manager([held, free])
    await manager.reserve_gpus([_DEVICE_ID], "0xOTHER")
    held_pci = next(iter(manager.holds))

    resolved = await manager.resolve_gpus([_DEVICE_ID], owner="0xOWNER")

    # Resolution took the card the other user does NOT hold, and the other
    # user's hold is untouched.
    assert str(resolved[0].pci_host) != held_pci
    assert manager.holds[held_pci].user == "0xOTHER"


@pytest.mark.asyncio
async def test_resolve_gpus_blocked_by_another_users_hold_raises():
    manager = _manager([_gpu_device()])
    await manager.reserve_gpus([_DEVICE_ID], "0xOTHER")

    with pytest.raises(InsufficientResourcesError):
        await manager.resolve_gpus([_DEVICE_ID], owner="0xOWNER")


@pytest.mark.asyncio
async def test_resolve_gpus_no_match_raises_with_structured_dicts():
    manager = _manager([_gpu_device(device_id="10de:OTHER")])

    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.resolve_gpus([_DEVICE_ID], owner="0xUSER")

    assert excinfo.value.required == {"gpu_device_id": _DEVICE_ID}
    assert excinfo.value.available == {"gpus": ["10de:OTHER"]}


@pytest.mark.asyncio
async def test_resolve_gpus_two_requests_two_distinct_cards():
    manager = _manager([_gpu_device("0000:01:00.0"), _gpu_device("0000:02:00.0")])

    resolved = await manager.resolve_gpus([_DEVICE_ID, _DEVICE_ID], owner="0xUSER")

    assert {str(gpu.pci_host) for gpu in resolved} == {"0000:01:00.0", "0000:02:00.0"}


@pytest.mark.asyncio
async def test_resolve_gpus_empty_request_makes_no_supervisor_call():
    supervisor = SimpleNamespace(get_host_info=AsyncMock())
    manager = CapacityManager(supervisor, AgentVmRegistry())

    assert await manager.resolve_gpus([], owner="0xUSER") == []
    supervisor.get_host_info.assert_not_awaited()


_BLACKWELL_ID = "10de:2b85"


def _cc_gpu(
    pci_host: str,
    cc_mode: str | None,
    *,
    arch: str | None = "blackwell",
    device_id: str = _BLACKWELL_ID,
) -> GpuDevice:
    gpu = GpuDevice(vendor="NVIDIA", device_name="GB202", device_class="0300", pci_host=pci_host, device_id=device_id)
    return gpu.model_copy(update={"cc_mode": cc_mode, "arch": arch})


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_takes_only_on_mode_cards():
    manager = _manager([_cc_gpu("06:00.0", "off"), _cc_gpu("07:00.0", None), _cc_gpu("08:00.0", "on")])
    resolved = await manager.resolve_confidential_gpus(arch="blackwell", count=1, models=None, owner="0xUSER")
    assert [str(g.pci_host) for g in resolved] == ["08:00.0"]
    assert resolved[0].supports_x_vga is False


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_matches_any_card_of_the_family():
    # The message names a family, never a device: a second Blackwell SKU is
    # as good a match as the first.
    manager = _manager([_cc_gpu("06:00.0", "on", device_id="10de:2c02")])
    resolved = await manager.resolve_confidential_gpus(arch="blackwell", count=1, models=None, owner="0xUSER")
    assert [str(g.pci_host) for g in resolved] == ["06:00.0"]


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_models_narrow_the_family():
    manager = _manager([_cc_gpu("06:00.0", "on", device_id="10de:2c02"), _cc_gpu("07:00.0", "on")])
    resolved = await manager.resolve_confidential_gpus(
        arch="blackwell", count=1, models=[_BLACKWELL_ID], owner="0xUSER"
    )
    assert [str(g.pci_host) for g in resolved] == ["07:00.0"]


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_rejects_another_architecture():
    manager = _manager([_cc_gpu("06:00.0", "on")])  # blackwell only
    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.resolve_confidential_gpus(arch="hopper", count=1, models=None, owner="0xUSER")
    assert "hopper" in str(excinfo.value)
    # The blackwell card is not a candidate, so it is not offered either.
    assert excinfo.value.available == {"confidential_gpus": []}


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_names_the_confidential_requirement():
    manager = _manager([_cc_gpu("06:00.0", "devtools")])
    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.resolve_confidential_gpus(arch="blackwell", count=1, models=None, owner="0xUSER")
    assert excinfo.value.required == {"confidential_gpu": {"arch": "blackwell", "count": 1, "models": None}}


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_shortage_reports_the_candidates():
    manager = _manager([_cc_gpu("06:00.0", "on")])
    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.resolve_confidential_gpus(arch="blackwell", count=2, models=None, owner="0xUSER")
    assert excinfo.value.required == {"confidential_gpu": {"arch": "blackwell", "count": 2, "models": None}}
    assert excinfo.value.available == {"confidential_gpus": [{"device_id": _BLACKWELL_ID, "arch": "blackwell"}]}


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_takes_count_distinct_cards():
    manager = _manager([_cc_gpu("06:00.0", "on"), _cc_gpu("07:00.0", "on"), _cc_gpu("08:00.0", "on")])
    resolved = await manager.resolve_confidential_gpus(arch="blackwell", count=2, models=None, owner="0xUSER")
    assert {str(gpu.pci_host) for gpu in resolved} == {"06:00.0", "07:00.0"}


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_skips_another_users_hold():
    held = _cc_gpu("06:00.0", "on")
    free = _cc_gpu("07:00.0", "on")
    manager = _manager([held, free])
    await manager.reserve_gpus([_BLACKWELL_ID], "0xOTHER")
    held_pci = next(iter(manager.holds))

    resolved = await manager.resolve_confidential_gpus(arch="blackwell", count=1, models=None, owner="0xOWNER")

    assert str(resolved[0].pci_host) != held_pci
    assert manager.holds[held_pci].user == "0xOTHER"


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_consumes_the_owners_own_hold():
    manager = _manager([_cc_gpu("06:00.0", "on")])
    await manager.reserve_gpus([_BLACKWELL_ID], "0xOWNER")

    resolved = await manager.resolve_confidential_gpus(arch="blackwell", count=1, models=None, owner="0xOWNER")

    assert [str(gpu.pci_host) for gpu in resolved] == ["06:00.0"]
    assert manager.holds == {}


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_shortage_leaves_the_ledger_untouched():
    manager = _manager([_cc_gpu("06:00.0", "on")])
    await manager.reserve_gpus([_BLACKWELL_ID], "0xOWNER")

    with pytest.raises(InsufficientResourcesError):
        await manager.resolve_confidential_gpus(arch="blackwell", count=2, models=None, owner="0xOWNER")

    # The partial match is not committed: the owner's hold survives the failure.
    assert manager.holds["06:00.0"].user == "0xOWNER"


def test_manager_never_calls_unrelated_supervisor_methods(mocker):
    # check_capacity is pure agent policy: registry sums plus host figures.
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    supervisor = MagicMock()
    manager = CapacityManager(supervisor, AgentVmRegistry())

    manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=0, is_instance=True)

    supervisor.get_host_info.assert_not_called()


# ── pooled disk accounting ──────────────────────────────────────────────────


def test_requirements_carry_the_largest_single_volume():
    message = _make_qemu_instance_message()
    requirements = requirements_from_message(message)
    # The fixture message has a rootfs and no sized extra volumes: the largest
    # single volume IS the rootfs.
    assert requirements.max_volume_mib == message.rootfs.size_mib
    assert requirements.disk_mib >= requirements.max_volume_mib


def _patch_pools(mocker, *free_bytes: int, reclaimable: int = 0):
    """One eligible pool per free-bytes figure, each holding ``reclaimable``
    retained bytes."""
    pools = [SimpleNamespace(path=Path(f"/pool{index}"), index=index) for index in range(len(free_bytes))]
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.eligible_pool_free_bytes",
        return_value=list(zip(pools, free_bytes)),
    )
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=reclaimable)


def test_check_capacity_rejects_a_volume_no_pool_can_hold(mocker):
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=900 * 1024**3)
    # Aggregate says 900 GiB free, but the roomiest single pool has 400 GiB.
    _patch_pools(mocker, 400 * 1024**3)
    with pytest.raises(InsufficientResourcesError, match="single volume"):
        manager.check_capacity(
            memory_mib=1024,
            vcpus=1,
            disk_mib=500 * 1024,
            max_volume_mib=500 * 1024,
            is_instance=True,
        )


def test_check_capacity_accepts_when_the_roomiest_pool_fits(mocker):
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=900 * 1024**3)
    _patch_pools(mocker, 400 * 1024**3)
    manager.check_capacity(
        memory_mib=1024,
        vcpus=1,
        disk_mib=500 * 1024,
        max_volume_mib=300 * 1024,
        is_instance=True,
    )


def test_available_disk_bytes_is_the_pooled_aggregate(mocker):
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.pools_disk_usage",
        return_value=(2 * 1024**4, 3 * 1024**3),
    )
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=0)
    assert CapacityManager._available_disk_bytes() == 3 * 1024**3


# ── simulate: batch admission for a whole plan ─────────────────────────────


def _requirements(
    *, memory_mib: int, vcpus: int = 1, disk_mib: int = 0, is_instance: bool = True
) -> ResourceRequirements:
    return ResourceRequirements(
        vcpus=vcpus, memory_mib=memory_mib, disk_mib=disk_mib, max_volume_mib=disk_mib, is_instance=is_instance
    )


def test_simulate_is_cumulative(mocker):
    """Three VMs that only fit twice get two yeses. Judging each candidate
    independently against current commitments would say yes three times.

    48 GiB physical, minus HOST_MEMORY_RESERVED_MIB (2048) and
    PROGRAM_MEMORY_RESERVED_MIB (8192), leaves a 38912 MiB instance bucket:
    room for two 16384 MiB instances and not a third.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=48 * 1024 * 1024 * 1024, cores=16)
    candidates = [
        (_HASH_A, _requirements(memory_mib=16384)),
        (_HASH_B, _requirements(memory_mib=16384)),
        (_HASH_C, _requirements(memory_mib=16384)),
    ]

    verdicts = _manager().simulate(candidates)

    assert [v.accepted for v in verdicts] == [True, True, False]
    assert verdicts[2].code == "insufficient_capacity"
    assert verdicts[2].vm_hash == _HASH_C


def test_simulate_counts_a_released_vm_as_freed(mocker):
    """'allocate C and delete B' must admit C against B's memory.

    40 GiB gives a 30720 MiB bucket, so B (16384) plus C (16384) does not fit
    but C alone does: the release is the whole difference.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_B, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidate = (_HASH_C, _requirements(memory_mib=16384))

    assert manager.simulate([candidate])[0].accepted is False
    assert manager.simulate([candidate], releasing=frozenset({_HASH_B}))[0].accepted is True


def test_simulate_judges_disk(mocker):
    # _patch_host only stubs _available_disk_bytes; the per-pool check reads
    # storage_pools directly, so stub it too or it hits the real filesystem.
    _patch_pools(mocker, 1024 * 1024 * 1024)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16, disk_bytes=1024 * 1024 * 1024)

    verdicts = _manager().simulate([(_HASH_A, _requirements(memory_mib=1024, disk_mib=100_000))])

    assert verdicts[0].accepted is False
    assert verdicts[0].code == "insufficient_capacity"


def test_simulate_reserves_nothing(mocker):
    """The capacity-check endpoint calls this speculatively against several
    CRNs, so a call must leave no trace.

    The candidate is sized past half the bucket on purpose. 64 GiB leaves
    55296 MiB for instances, and 30000 fits once: had the first call committed
    anything, 30000 + 30000 would put the second over and flip it to False. At
    a smaller size a leaking implementation would answer True twice and the
    test would pass while proving nothing.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    manager = _manager(registry=registry)
    candidate = (_HASH_A, _requirements(memory_mib=30000))

    first = manager.simulate([candidate])
    second = manager.simulate([candidate])

    assert first[0].accepted is second[0].accepted is True
    assert len(tuple(registry.items())) == 0
    assert manager.holds == {}


def test_simulate_is_cumulative_on_disk_too(mocker):
    """Disk has no committed sum anywhere: free space is read live, and nothing
    is written until the VM is actually created. Without an accumulator each
    candidate sees the same free space and a plan that cannot fit is admitted
    whole.

    10 GiB free, two candidates wanting 6000 MiB each: the first fits, the
    second does not.
    """
    _patch_pools(mocker, 20 * 1024**3)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16, disk_bytes=10 * 1024**3)
    candidates = [
        (_HASH_A, _requirements(memory_mib=1024, disk_mib=6000)),
        (_HASH_B, _requirements(memory_mib=1024, disk_mib=6000)),
    ]

    verdicts = _manager().simulate(candidates)

    assert [v.accepted for v in verdicts] == [True, False]
    assert verdicts[1].code == "insufficient_capacity"


def test_simulate_ignores_a_release_of_a_vm_it_does_not_know(mocker):
    """The scheduler's plan is its own view of the world. A hash we have no
    record of frees nothing, and must not throw."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_B, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidate = (_HASH_C, _requirements(memory_mib=16384))

    verdicts = manager.simulate([candidate], releasing=frozenset({_HASH_A}))

    assert verdicts[0].accepted is False


def test_simulate_releases_vcpus_not_only_memory(mocker):
    """vCPUs are the binding constraint here, so the release only shows up if
    the loop subtracts them too. 2 cores at 4x overcommit caps vCPUs at 8."""
    mocker.patch.object(settings, "VCPU_OVERCOMMIT_FACTOR", 4.0)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=2)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=1024, vcpus=6)
    registry.record(_HASH_B, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidate = (_HASH_C, _requirements(memory_mib=1024, vcpus=6))

    assert manager.simulate([candidate])[0].accepted is False
    assert manager.simulate([candidate], releasing=frozenset({_HASH_B}))[0].accepted is True


# ── simulate: GPU admission ────────────────────────────────────────────────


def _gpu_requirements(
    *, device_ids: list[str], memory_mib: int = 1024, owner: str | None = None
) -> ResourceRequirements:
    return ResourceRequirements(
        vcpus=1,
        memory_mib=memory_mib,
        disk_mib=0,
        max_volume_mib=0,
        is_instance=True,
        gpu_device_ids=device_ids,
        owner=owner,
    )


def test_simulate_refuses_a_gpu_candidate_when_no_inventory_was_given(mocker):
    """Without an inventory there is nothing to judge the request against. The
    verdict is all the scheduler sees, so an unchecked GPU must not read as a
    yes earned on memory alone."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)

    verdicts = _manager().simulate([(_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID]))])

    assert verdicts[0].accepted is False
    assert verdicts[0].code == "gpu_unavailable"


def test_simulate_admits_a_gpu_candidate_the_host_can_serve(mocker):
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    gpu = _gpu_device()

    verdicts = _manager().simulate([(_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID]))], available_gpus=[gpu])

    assert verdicts[0].accepted is True


def test_simulate_refuses_a_card_the_host_does_not_have(mocker):
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)

    verdicts = _manager().simulate(
        [(_HASH_A, _gpu_requirements(device_ids=["10de:dead"]))], available_gpus=[_gpu_device()]
    )

    assert verdicts[0].accepted is False
    assert verdicts[0].code == "gpu_unavailable"


def test_simulate_is_cumulative_on_gpus(mocker):
    """One card, two candidates that each want it: one yes. Judging each
    against the same inventory would hand the same card out twice."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    candidates = [
        (_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID])),
        (_HASH_B, _gpu_requirements(device_ids=[_DEVICE_ID])),
    ]

    verdicts = _manager().simulate(candidates, available_gpus=[_gpu_device()])

    assert [v.accepted for v in verdicts] == [True, False]
    assert verdicts[1].code == "gpu_unavailable"


def test_simulate_treats_a_held_card_as_taken(mocker):
    """A hold is some user's pending create. Counting it as free would make the
    advisory answer stronger than the one create will give."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    gpu = _gpu_device()
    manager = _manager()
    manager.holds[gpu.pci_host] = GpuHold(
        user="someone-else", expiration=datetime.now(tz=timezone.utc) + timedelta(hours=1)
    )

    verdicts = manager.simulate([(_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID]))], available_gpus=[gpu])

    assert verdicts[0].accepted is False


def test_simulate_lets_a_candidate_use_the_hold_its_own_user_took(mocker):
    """The reserve endpoint exists so a user can hold a card before asking
    the scheduler for the VM. resolve_gpus consumes that user's own hold at
    create; an advisory answer that counted it as taken would refuse exactly
    the allocation the hold was placed for."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    gpu = _gpu_device()
    manager = _manager()
    manager.holds[gpu.pci_host] = GpuHold(user="0xUSER", expiration=datetime.now(tz=timezone.utc) + timedelta(hours=1))
    mine = _gpu_requirements(device_ids=[_DEVICE_ID], owner="0xUSER")
    theirs = _gpu_requirements(device_ids=[_DEVICE_ID], owner="0xOTHER")

    assert manager.simulate([(_HASH_A, mine)], available_gpus=[gpu])[0].accepted is True
    assert manager.simulate([(_HASH_A, theirs)], available_gpus=[gpu])[0].accepted is False
    assert manager.holds[gpu.pci_host].user == "0xUSER"


def test_simulate_does_not_evict_expired_holds(mocker):
    """An expired hold frees the card, but reaping it is a write, and simulate
    is the one call that must not touch the ledger."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    gpu = _gpu_device()
    manager = _manager()
    expired = GpuHold(user="someone-else", expiration=datetime.now(tz=timezone.utc) - timedelta(hours=1))
    manager.holds[gpu.pci_host] = expired

    verdicts = manager.simulate([(_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID]))], available_gpus=[gpu])

    assert verdicts[0].accepted is True
    assert manager.holds[gpu.pci_host] is expired


def test_simulate_takes_no_card_when_it_cannot_take_them_all(mocker):
    """All or nothing, like reserve_gpus: a candidate that wanted two cards and
    could only get one must not strand that one away from the next candidate."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    candidates = [
        (_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID, _DEVICE_ID])),
        (_HASH_B, _gpu_requirements(device_ids=[_DEVICE_ID])),
    ]

    verdicts = _manager().simulate(candidates, available_gpus=[_gpu_device()])

    assert [v.accepted for v in verdicts] == [False, True]


def test_simulate_does_not_take_cards_for_a_candidate_refused_on_memory(mocker):
    """The card is only spent once everything else has cleared, so a candidate
    that fails admission leaves the inventory for the next one."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=48 * 1024 * 1024 * 1024, cores=16)
    candidates = [
        (_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID], memory_mib=999_999)),
        (_HASH_B, _gpu_requirements(device_ids=[_DEVICE_ID])),
    ]

    verdicts = _manager().simulate(candidates, available_gpus=[_gpu_device()])

    assert [v.accepted for v in verdicts] == [False, True]
    assert verdicts[0].code == "insufficient_capacity"


def test_simulate_does_not_let_a_recorded_candidate_refuse_itself(mocker):
    """A hash can be recorded here and still be a candidate: a recreate, or an
    owner record from a create that died part way. Counting the record and the
    request both would judge the VM against its own memory.

    40 GiB leaves 30720 MiB, and 16384 twice does not fit, so a double count
    turns this into a no.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_A, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)

    verdicts = manager.simulate([(_HASH_A, _requirements(memory_mib=16384))])

    assert verdicts[0].accepted is True


def test_simulate_does_not_credit_a_candidate_twice_when_also_released(mocker):
    """A caller that discounts the record itself, by listing the hash in
    releasing, must not get the memory back a second time.

    30720 MiB bucket. D holds 8192 and stays, so A (16384, already recorded and
    also a candidate) is judged against 8192 and fits, leaving 24576 committed
    and no room for B's 8192. Subtracting A a second time would drop the
    committed sum to 0 instead, and B would wrongly fit. The other record
    matters: without it the second subtraction goes negative and the clamp
    hides the bug.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    recorded = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_A, message=recorded, original=recorded, persistent=True)
    staying = _make_qemu_instance_message(memory=8192)
    registry.record(_HASH_D, message=staying, original=staying, persistent=True)
    manager = _manager(registry=registry)
    candidates = [
        (_HASH_A, _requirements(memory_mib=16384)),
        (_HASH_B, _requirements(memory_mib=8192)),
    ]

    verdicts = manager.simulate(candidates, releasing=frozenset({_HASH_A}))

    assert [v.accepted for v in verdicts] == [True, False]


def test_simulate_does_not_credit_disk_back_on_release(mocker):
    """Stopping a VM does not delete its volumes, so the space is still gone.
    Crediting it would make the advisory answer stronger than the enforced one.
    """
    _patch_pools(mocker, 100 * 1024**3)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16, disk_bytes=10 * 1024**3)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=1024)
    registry.record(_HASH_B, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidate = (_HASH_C, _requirements(memory_mib=1024, disk_mib=50_000))

    assert manager.simulate([candidate], releasing=frozenset({_HASH_B}))[0].accepted is False


def test_simulate_credits_a_released_program_to_the_program_bucket(mocker):
    """The release loop buckets the same way the committed sums do, so a
    released program frees the program bucket and not the instance one.

    The program bucket is PROGRAM_MEMORY_RESERVED_MIB (4096) on its own: one
    3072 MiB program fits, two do not.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 4096)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    # Any non-InstanceContent record lands in the program bucket.
    content = SimpleNamespace(resources=SimpleNamespace(memory=3072, vcpus=1))
    registry.record(_HASH_B, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidate = (_HASH_C, _requirements(memory_mib=3072, is_instance=False))

    assert manager.simulate([candidate])[0].accepted is False
    assert manager.simulate([candidate], releasing=frozenset({_HASH_B}))[0].accepted is True


def test_simulate_puts_a_refused_candidates_record_back(mocker):
    """Discounting a candidate's record bets that its request will replace it.
    A refused candidate leaves the recorded VM running, so the bet is off and
    the rest of the batch has to see that memory again.

    30720 MiB bucket. A is recorded at 16384 and refused on its GPU, so B's
    24576 does not fit: 16384 + 24576 is over. Leaving A discounted would judge
    B against an empty node and hand back a yes that create would refuse.
    """
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_A, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidates = [
        (_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID], memory_mib=16384)),
        (_HASH_B, _requirements(memory_mib=24576)),
    ]

    verdicts = manager.simulate(candidates)

    assert [v.accepted for v in verdicts] == [False, False]
    assert verdicts[0].code == "gpu_unavailable"
    assert verdicts[1].code == "insufficient_capacity"


def test_simulate_puts_the_record_back_when_the_refusal_was_capacity(mocker):
    """Same restoration, through the other refusal branch."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_A, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidates = [
        (_HASH_A, _requirements(memory_mib=999_999)),
        (_HASH_B, _requirements(memory_mib=24576)),
    ]

    verdicts = manager.simulate(candidates)

    assert [v.accepted for v in verdicts] == [False, False]


def test_simulate_keeps_a_refused_candidate_released_if_the_plan_stops_it(mocker):
    """A refused candidate the plan is also stopping stays discounted: the
    release frees it whatever the verdict on recreating it was."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    _patch_host(mocker, memory_bytes=40 * 1024 * 1024 * 1024, cores=16)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=16384)
    registry.record(_HASH_A, message=content, original=content, persistent=True)
    manager = _manager(registry=registry)
    candidates = [
        (_HASH_A, _gpu_requirements(device_ids=[_DEVICE_ID], memory_mib=16384)),
        (_HASH_B, _requirements(memory_mib=24576)),
    ]

    verdicts = manager.simulate(candidates, releasing=frozenset({_HASH_A}))

    assert [v.accepted for v in verdicts] == [False, True]


def test_simulate_does_not_echo_the_requested_device_id_back(mocker):
    """device_id is free-form text off the message. The verdict is what goes to
    the scheduler, and it already knows what it asked for."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)

    verdicts = _manager().simulate([(_HASH_A, _gpu_requirements(device_ids=["10de:evil"]))])

    assert verdicts[0].accepted is False
    assert "evil" not in verdicts[0].detail


def test_simulate_is_cumulative_on_vcpus(mocker):
    """vCPUs accumulate like memory does. 2 cores at 4x overcommit caps them at
    8, so two 6-vCPU candidates fit once between them."""
    mocker.patch.object(settings, "VCPU_OVERCOMMIT_FACTOR", 4.0)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=2)
    candidates = [
        (_HASH_A, _requirements(memory_mib=1024, vcpus=6)),
        (_HASH_B, _requirements(memory_mib=1024, vcpus=6)),
    ]

    verdicts = _manager().simulate(candidates)

    assert [v.accepted for v in verdicts] == [True, False]


def test_requirements_put_a_vprogram_in_the_instance_bucket():
    """The bucket travels on the requirements, so a caller cannot pick the
    wrong one for a V-PROGRAM by reaching for the obvious field."""
    from test_vprogram import load_vprogram_message

    content = load_vprogram_message().content

    assert requirements_from_message(content).is_instance is True


def test_available_disk_counts_reclaimable_bytes_as_free(mocker):
    """Retained volumes are a cache, not usage: they are advertised as free
    because the reconciler evicts them when a placement needs the room."""
    mocker.patch("aleph.vm.agent.capacity.storage_pools.pools_disk_usage", return_value=(100, 10))
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=5)
    assert CapacityManager._available_disk_bytes() == 15


def test_max_volume_check_counts_that_pools_reclaimable_bytes(mocker):
    """Retention is a budgeted cache: a volume that fits once the pool's
    retained directories are evicted must be admitted, since the room maker
    evicts them at placement time."""
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=900 * 1024**3)
    # 200 GiB free, 300 GiB retained: a 400 GiB volume still fits.
    _patch_pools(mocker, 200 * 1024**3, reclaimable=300 * 1024**3)

    manager.check_capacity(memory_mib=1024, vcpus=1, disk_mib=400 * 1024, max_volume_mib=400 * 1024, is_instance=True)


def test_max_volume_check_still_refuses_what_no_pool_can_hold_even_after_eviction(mocker):
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=900 * 1024**3)
    _patch_pools(mocker, 200 * 1024**3, reclaimable=100 * 1024**3)

    with pytest.raises(InsufficientResourcesError, match="single volume"):
        manager.check_capacity(
            memory_mib=1024, vcpus=1, disk_mib=400 * 1024, max_volume_mib=400 * 1024, is_instance=True
        )


def test_a_phantom_record_never_blocks_the_retry_of_its_own_create(mocker):
    """A create that fails against volumes that already existed retires
    RECREATE, which keeps the registry record on purpose: dropping it while
    keeping the disks would make the reconciler treat the directory as an
    orphan. The record then describes a VM that is not running and counts in
    the committed sums until the next allocation cycle. The one thing that
    must not happen is the retry being refused by its own phantom, and it is
    not: the create path admits through check_message, which excludes the VM's
    own record."""
    _patch_host(mocker, memory_bytes=16 * 1024 * 1024 * 1024, cores=16)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 4096)
    mocker.patch.object(CapacityManager, "_check_max_volume", return_value=None)
    mocker.patch("aleph.vm.agent.capacity.existing_volume_files", return_value={})

    vm_hash = "i" * 64
    message = _make_qemu_instance_message(vcpus=2, memory=8192)
    registry = AgentVmRegistry()
    # The record _retire_after_create_failure leaves behind on a RECREATE.
    registry.record(vm_hash, message=message, original=message, persistent=True)
    manager = _manager(registry=registry)

    assert manager.check_message(message, exclude_vm_hash=vm_hash) is None

    # The phantom is not free: it still counts against every *other* VM until
    # the next allocation cycle drops it.
    with pytest.raises(InsufficientResourcesError):
        manager.check_message(message, exclude_vm_hash="j" * 64)


# ── check_message: one admission path, ahead of any allocation ─────────────

_VM_HASH = ItemHash("ab" * 32)


def _volume(name: str, size_mib: int) -> MagicMock:
    """A persistent volume declaration. ``name`` is set after construction:
    passing it to MagicMock() would name the mock, not the attribute."""
    volume = MagicMock(size_mib=size_mib)
    volume.name = name
    return volume


def _instance_content(*, rootfs_mib: int | None = 20_000, volumes: tuple[MagicMock, ...] = ()) -> MagicMock:
    """An InstanceContent stand-in with the sizes admission reads."""
    content = MagicMock(spec=InstanceContent)
    content.resources = MagicMock(vcpus=2, memory=2048)
    content.rootfs = MagicMock(size_mib=rootfs_mib) if rootfs_mib is not None else None
    content.volumes = list(volumes)
    content.requirements = None
    return content


def _hold_nothing(mocker) -> None:
    """No file on disk for this VM."""
    mocker.patch("aleph.vm.agent.capacity.existing_volume_files", return_value={})


def _stage_volume_files(mocker, pool: Path, files: dict[str, int]) -> Path:
    """Create ``{pool}/{vm_hash}/`` holding ``{filename: allocated bytes}``.

    The files are real (so the stem matching, the symlink skip and the pool
    layout are exercised for real); only the allocated-bytes measurement is
    stubbed, since a test cannot cheaply allocate 20 GiB.
    """
    directory = pool / str(_VM_HASH)
    directory.mkdir(parents=True, exist_ok=True)
    sizes = {}
    for name, size_bytes in files.items():
        (directory / name).write_bytes(b"")
        sizes[directory / name] = size_bytes
    mocker.patch("aleph.vm.agent.capacity.file_size_bytes", side_effect=lambda path: sizes.get(path, 0))
    return directory


def _patch_namespace_dirs(mocker, *directories: Path) -> None:
    mocker.patch("aleph.vm.agent.capacity.storage_pools.iter_namespace_dirs", return_value=list(directories))


def _patch_eligible_pools(mocker, *pools: tuple[Path, int]) -> None:
    """Eligible pools, given as (path, free bytes), with nothing reclaimable."""
    entries = [(SimpleNamespace(path=path, index=index), free) for index, (path, free) in enumerate(pools)]
    mocker.patch("aleph.vm.agent.capacity.storage_pools.eligible_pool_free_bytes", return_value=entries)
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=0)


def test_check_message_admits_disk_from_the_message(mocker):
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    _hold_nothing(mocker)
    content = _instance_content(rootfs_mib=20_000, volumes=(_volume("data", 5_000),))

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    kwargs = check.call_args.kwargs
    assert kwargs["disk_mib"] == 25_000
    assert kwargs["max_volume_mib"] == 20_000
    assert kwargs["is_instance"] is True
    assert kwargs["memory_mib"] == 2048
    assert kwargs["vcpus"] == 2
    assert kwargs["exclude_vm_hash"] == _VM_HASH


def test_check_message_discounts_bytes_the_vm_already_holds(mocker, tmp_path):
    """A RECREATE of a VM whose disks are still on the host must not be
    refused for space it already occupies: creating() adopted the directory,
    so those bytes are neither free nor reclaimable any more."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    directory = _stage_volume_files(mocker, tmp_path / "pool0", {"rootfs.qcow2": 20_000 * 1024 * 1024})
    _patch_namespace_dirs(mocker, directory)
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    assert check.call_args.kwargs["disk_mib"] == 0


def test_check_message_caps_a_volumes_discount_at_what_it_declares(mocker, tmp_path):
    """A file that outgrew its declaration credits only the declared size,
    and the total never goes negative."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    directory = _stage_volume_files(mocker, tmp_path / "pool0", {"rootfs.qcow2": 90_000 * 1024 * 1024})
    _patch_namespace_dirs(mocker, directory)
    content = _instance_content(rootfs_mib=20_000, volumes=(_volume("data", 5_000),))

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    # 25 000 declared, the rootfs discounts its declared 20 000 and not the
    # 90 000 it occupies, so the unallocated data volume is still required.
    assert check.call_args.kwargs["disk_mib"] == 5_000


def test_check_message_ignores_a_file_no_declared_volume_claims(mocker, tmp_path):
    """The discount is per declared volume, not per directory. A user who
    renames or drops a persistent volume in an updated message leaves the old
    file behind; it must not pay for the new one."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    directory = _stage_volume_files(mocker, tmp_path / "pool0", {"old.ext4": 10_000 * 1024 * 1024})
    _patch_namespace_dirs(mocker, directory)
    content = _instance_content(rootfs_mib=None, volumes=(_volume("new", 10_000),))

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    kwargs = check.call_args.kwargs
    assert kwargs["disk_mib"] == 10_000
    assert kwargs["max_volume_mib"] == 10_000
    assert kwargs["max_volume_credit"] is None


def test_two_spellings_of_a_name_discount_one_file_once(mocker, tmp_path):
    """Two declared volumes can look up the same file: "a b" is sanitized to
    "a_b" by storage.get_volume_path, so a message declaring both names has
    two volumes claiming a_b.ext4. One file backs one volume, so it discounts
    once and the second volume is still required whole."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    directory = _stage_volume_files(mocker, tmp_path / "pool0", {"a_b.ext4": 10_000 * 1024 * 1024})
    _patch_namespace_dirs(mocker, directory)
    content = _instance_content(rootfs_mib=None, volumes=(_volume("a b", 10_000), _volume("a_b", 10_000)))

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    assert check.call_args.kwargs["disk_mib"] == 10_000


def test_the_boot_disk_is_credited_its_own_file(mocker, tmp_path):
    """Matching on the stem alone let rootfs.ext4 shadow rootfs.qcow2 (they
    share a stem, and the ext4 sorts first), crediting the boot disk a file it
    will not use. The suffix decides: a QEMU boot disk is a qcow2."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    directory = _stage_volume_files(
        mocker,
        tmp_path / "pool0",
        {"rootfs.ext4": 1_000 * 1024 * 1024, "rootfs.qcow2": 20_000 * 1024 * 1024},
    )
    _patch_namespace_dirs(mocker, directory)
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    kwargs = check.call_args.kwargs
    assert kwargs["disk_mib"] == 0
    assert kwargs["max_volume_credit"].path == directory / "rootfs.qcow2"


def test_check_message_without_a_hash_discounts_nothing(mocker):
    """The reserve endpoint admits a message no VM owns yet: there is no
    directory to discount, and none is looked for."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    existing = mocker.patch("aleph.vm.agent.capacity.existing_volume_files")
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content)

    existing.assert_not_called()
    assert check.call_args.kwargs["disk_mib"] == 20_000
    assert check.call_args.kwargs["exclude_vm_hash"] is None


def test_check_message_buckets_a_vprogram_as_an_instance(mocker):
    """A V-PROGRAM is a full SNP VM: it belongs in the instance memory
    bucket, which is where _committed_resources already counts it. Bucketing
    it as a program would both starve the small program bucket and hide its
    memory from instance admission."""
    from aleph_message.models import VerifiableProgramContent

    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    _hold_nothing(mocker)
    content = MagicMock(spec=VerifiableProgramContent)
    content.resources = MagicMock(vcpus=2, memory=4096)
    content.volumes = []
    content.requirements = None

    manager.check_message(content, exclude_vm_hash=_VM_HASH)

    assert check.call_args.kwargs["is_instance"] is True


# ── the stale-file counter-example, end to end through check_capacity ───────


def test_a_stale_file_never_admits_a_volume_the_node_cannot_hold(mocker, tmp_path):
    """The reviewer's counter-example. A directory holding a stale 10 GiB
    old.ext4, a message declaring only a fresh 10 GiB "new" volume, and a
    node with 5 GiB free: refused. A discount summed over the directory would
    have floored the total to 0 and the per-pool figure with it, switching
    both disk guards off for exactly the create that needs the space."""
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=5 * 1024**3)
    pool = tmp_path / "pool0"
    directory = _stage_volume_files(mocker, pool, {"old.ext4": 10 * 1024**3})
    _patch_namespace_dirs(mocker, directory)
    _patch_eligible_pools(mocker, (pool, 5 * 1024**3))
    content = _instance_content(rootfs_mib=None, volumes=(_volume("new", 10 * 1024),))

    with pytest.raises(InsufficientResourcesError) as excinfo:
        manager.check_message(content, exclude_vm_hash=_VM_HASH)

    detail = str(excinfo.value)
    assert "Disk: required 10240 MiB" in detail
    assert "single volume" in detail


def test_a_plain_recreate_is_admitted_with_its_own_pool_credited(mocker, tmp_path):
    """The other side of the same coin: the file backing the declared volume
    is on pool0, so pool0 does not have to find that room again even though
    its free space alone could never fit the volume."""
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=1 * 1024**3)
    pool = tmp_path / "pool0"
    directory = _stage_volume_files(mocker, pool, {"rootfs.qcow2": 20 * 1024**3})
    _patch_namespace_dirs(mocker, directory)
    _patch_eligible_pools(mocker, (pool, 1 * 1024**3))
    content = _instance_content(rootfs_mib=20 * 1024)

    assert manager.check_message(content, exclude_vm_hash=_VM_HASH) is None


def test_the_credit_goes_only_to_the_pool_that_holds_the_file(mocker, tmp_path):
    """Crediting globally (by shrinking max_volume_mib) would excuse every
    pool. The file sits on a pool that is not eligible for new volumes, so
    no eligible pool may claim its bytes."""
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=1 * 1024**3)
    directory = _stage_volume_files(mocker, tmp_path / "pool0", {"rootfs.qcow2": 20 * 1024**3})
    _patch_namespace_dirs(mocker, directory)
    _patch_eligible_pools(mocker, (tmp_path / "pool1", 1 * 1024**3))
    content = _instance_content(rootfs_mib=20 * 1024)

    with pytest.raises(InsufficientResourcesError, match="single volume"):
        manager.check_message(content, exclude_vm_hash=_VM_HASH)


def test_a_colliding_stem_never_discounts_one_file_twice(mocker, tmp_path):
    """A schema-valid message can declare a rootfs AND a persistent volume
    named "rootfs": both look up the same stem. The directory holds one file,
    which may pay for one of them and never for both. Here the node still has
    to allocate a 20 GiB volume with 5 GiB free, so the create is refused;
    letting the single qcow2 discount both declarations would have floored the
    total to 0 and admitted it."""
    manager = _manager()
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=5 * 1024**3)
    pool = tmp_path / "pool0"
    directory = _stage_volume_files(mocker, pool, {"rootfs.qcow2": 20 * 1024**3})
    _patch_namespace_dirs(mocker, directory)
    _patch_eligible_pools(mocker, (pool, 5 * 1024**3))
    content = _instance_content(rootfs_mib=20 * 1024, volumes=(_volume("rootfs", 20 * 1024),))

    with pytest.raises(InsufficientResourcesError) as excinfo:
        manager.check_message(content, exclude_vm_hash=_VM_HASH)

    assert "Disk: required 20480 MiB" in str(excinfo.value)


# ── simulate: the same discount, for a whole plan ──────────────────────────


def test_simulate_discounts_disk_the_candidate_already_holds(mocker, tmp_path):
    """simulate charged every candidate its declared disk in full, while
    check_message, the path that actually creates the VM, subtracts what the
    VM's files already occupy. The advisory answer was the stricter of the
    two, so a nearly full node refused a VM it was perfectly able to run, and
    a refusal here is not free: the answer drops the VM from the plan the
    reconciler converges on."""
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=1 * 1024**3)
    pool = tmp_path / "pool0"
    directory = _stage_volume_files(mocker, pool, {"rootfs.qcow2": 20 * 1024**3})
    _patch_namespace_dirs(mocker, directory)
    _patch_eligible_pools(mocker, (pool, 1 * 1024**3))
    candidate = (_VM_HASH, requirements_from_message(_instance_content(rootfs_mib=20 * 1024)))

    verdicts = _manager().simulate([candidate])

    assert verdicts[0].accepted is True


def test_simulate_still_charges_a_candidate_that_holds_nothing(mocker):
    """The discount must not switch the disk check off. A VM whose volumes
    are not on this node is charged them whole, and refused when they do not
    fit."""
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=1 * 1024**3)
    _patch_pools(mocker, 1 * 1024**3)
    _hold_nothing(mocker)
    candidate = (_VM_HASH, requirements_from_message(_instance_content(rootfs_mib=20 * 1024)))

    verdicts = _manager().simulate([candidate])

    assert verdicts[0].accepted is False
    assert verdicts[0].code == "insufficient_capacity"


def test_a_held_volume_is_not_charged_to_the_rest_of_the_plan(mocker, tmp_path):
    """The batch accumulator has to charge what a candidate still has to
    allocate, not what it declares: 20 GiB the first candidate already holds
    is not 20 GiB the second one cannot have."""
    _patch_host(mocker, memory_bytes=64 * 1024**3, cores=16, disk_bytes=20 * 1024**3)
    pool = tmp_path / "pool0"
    directory = _stage_volume_files(mocker, pool, {"rootfs.qcow2": 20 * 1024**3})
    # Keyed on the namespace, unlike _patch_namespace_dirs: the second
    # candidate must not find the first one's directory and be credited it.
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.iter_namespace_dirs",
        side_effect=lambda namespace: [directory] if namespace == str(_VM_HASH) else [],
    )
    _patch_eligible_pools(mocker, (pool, 20 * 1024**3))
    candidates = [
        (_VM_HASH, requirements_from_message(_instance_content(rootfs_mib=20 * 1024))),
        (_HASH_B, requirements_from_message(_instance_content(rootfs_mib=None, volumes=(_volume("data", 15 * 1024),)))),
    ]

    verdicts = _manager().simulate(candidates)

    assert [verdict.accepted for verdict in verdicts] == [True, True]


# ── existing_volume_files ───────────────────────────────────────────────────


def test_existing_volume_files_refuses_an_implausible_hash():
    """The namespace reaches a bare ``pool.path / namespace`` join, so it is
    validated like every other iter_namespace_dirs caller: without this,
    "../.." resolves, its bytes are summed as space the VM already holds, and
    the inflated discount relaxes admission."""
    from aleph.vm.agent.capacity import existing_volume_files

    with pytest.raises(ValueError, match="implausible VM hash"):
        existing_volume_files("../..")


def test_existing_volume_files_spans_pools_and_skips_what_is_not_a_volume(mocker, tmp_path):
    from aleph.vm.agent.capacity import existing_volume_files

    first = tmp_path / "pool0" / str(_VM_HASH)
    second = tmp_path / "pool1" / str(_VM_HASH)
    for directory in (first, second):
        directory.mkdir(parents=True)
    (first / "rootfs.qcow2").write_bytes(b"x")
    (first / ".reclaimable").write_text("{}")
    (first / "elsewhere.ext4").symlink_to(tmp_path / "somewhere-else")
    (second / "data.ext4").write_bytes(b"x")
    _patch_namespace_dirs(mocker, first, second)

    found = existing_volume_files(_VM_HASH)

    # The marker is not a volume, and a symlink is not this directory's space.
    # Files are keyed by name, suffix included: rootfs.qcow2 and rootfs.ext4
    # share a stem but are different volumes.
    assert set(found) == {"rootfs.qcow2", "data.ext4"}
    assert found["rootfs.qcow2"] == first / "rootfs.qcow2"
    assert found["data.ext4"] == second / "data.ext4"


# ── headroom: what the capacity-check endpoint advertises ──────────────────


def test_headroom_is_the_caps_less_what_is_recorded(mocker):
    """64 GiB, 16 cores, reservations of 2048 and 8192: a 55296 MiB instance
    bucket, 8192 MiB of program bucket, 64 vCPUs at the default factor.
    Recording an instance takes its memory and vCPUs out of the figures."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    mocker.patch.object(settings, "VCPU_OVERCOMMIT_FACTOR", 4.0)
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16, disk_bytes=100 * 1024 * 1024 * 1024)
    manager = _manager()

    before = manager.headroom()
    content = _make_qemu_instance_message(memory=16384, vcpus=4)
    manager.registry.record(_HASH_A, message=content, original=content, persistent=True)
    after = manager.headroom()

    assert before == {
        "instance_memory_mib": 55296,
        "program_memory_mib": 8192,
        "vcpus": 64,
        "disk_mib": 100 * 1024,
        "gpus": None,
    }
    assert after["instance_memory_mib"] == 55296 - 16384
    assert after["vcpus"] == 64 - 4
    assert after["program_memory_mib"] == 8192


def test_headroom_lists_the_cards_a_plan_may_count_on(mocker):
    """Given the inventory, the cards not under a live hold, by device id.
    Without it, None rather than an empty list: unknown is not zero."""
    _patch_host(mocker, memory_bytes=64 * 1024 * 1024 * 1024, cores=16)
    free = _gpu_device("0000:01:00.0")
    held = _gpu_device("0000:02:00.0")
    manager = _manager()
    live = datetime.now(tz=timezone.utc) + timedelta(hours=1)
    manager.holds[held.pci_host] = GpuHold(user="someone", expiration=live)

    assert manager.headroom(available_gpus=[free, held])["gpus"] == [free.device_id]
    assert manager.headroom()["gpus"] is None


def test_headroom_never_advertises_below_zero(mocker):
    """A registry holding more than the caps (a phantom record, a shrunk
    host) reads as nothing left, not as a negative figure."""
    _patch_host(mocker, memory_bytes=8 * 1024 * 1024 * 1024, cores=1)
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message(memory=65536, vcpus=64)
    registry.record(_HASH_A, message=content, original=content, persistent=True)

    headroom = _manager(registry=registry).headroom()

    assert headroom["instance_memory_mib"] == 0
    assert headroom["vcpus"] == 0


@pytest.mark.asyncio
async def test_available_gpus_reads_the_supervisors_unattached_cards():
    """The inventory simulate and headroom are handed comes from here: the
    handler reads it, since the read is async and those two are not."""
    gpu = _gpu_device()

    assert await _manager([gpu]).available_gpus() == [gpu]
