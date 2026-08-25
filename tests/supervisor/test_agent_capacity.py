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
    requirements_from_message,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import GpuDevice, GpuDeviceClass, InsufficientResourcesError
from aleph.vm.supervisor_interface.types import HostInfo

_DEVICE_ID = "10de:2504"


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


def test_available_disk_counts_reclaimable_bytes_as_free(mocker):
    """Retained volumes are a cache, not usage: they are advertised as free
    because the reconciler evicts them when a placement needs the room
    (spec section 1)."""
    mocker.patch("aleph.vm.agent.capacity.storage_pools.pools_disk_usage", return_value=(100, 10))
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=5)
    assert CapacityManager._available_disk_bytes() == 15


def test_max_volume_check_counts_that_pools_reclaimable_bytes(mocker):
    """Retention is a budgeted cache: a volume that fits once the pool's
    retained directories are evicted must be admitted, since the room maker
    evicts them at placement time (spec section 1)."""
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
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=0)

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


def _instance_content(*, rootfs_mib: int = 20_000, volumes_mib: tuple[int, ...] = ()) -> MagicMock:
    """An InstanceContent stand-in with the sizes admission reads."""
    content = MagicMock(spec=InstanceContent)
    content.resources = MagicMock(vcpus=2, memory=2048)
    content.rootfs = MagicMock(size_mib=rootfs_mib)
    content.volumes = [MagicMock(size_mib=size) for size in volumes_mib]
    content.requirements = None
    return content


def test_check_message_admits_disk_from_the_message(mocker):
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=0)
    content = _instance_content(rootfs_mib=20_000, volumes_mib=(5_000,))

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    kwargs = check.call_args.kwargs
    assert kwargs["disk_mib"] == 25_000
    assert kwargs["max_volume_mib"] == 20_000
    assert kwargs["is_instance"] is True
    assert kwargs["memory_mib"] == 2048
    assert kwargs["vcpus"] == 2
    assert kwargs["exclude_vm_hash"] == ItemHash("ab" * 32)


def test_check_message_discounts_bytes_the_vm_already_holds(mocker):
    """A RECREATE of a VM whose disks are still on the host must not be
    refused for space it already occupies: creating() adopted the directory,
    so those bytes are neither free nor reclaimable any more."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=20_000 * 1024 * 1024)
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    assert check.call_args.kwargs["disk_mib"] == 0


def test_check_message_never_asks_for_negative_disk(mocker):
    """A VM holding more than the message declares (an extra staged file)
    floors the requirement at 0 rather than crediting the difference."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=90_000 * 1024 * 1024)
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    assert check.call_args.kwargs["disk_mib"] == 0


def test_check_message_without_a_hash_discounts_nothing(mocker):
    """The reserve endpoint admits a message no VM owns yet: there is no
    directory to discount, and none is looked for."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    allocated = mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for")
    content = _instance_content(rootfs_mib=20_000)

    manager.check_message(content)

    allocated.assert_not_called()
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
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=0)
    content = MagicMock(spec=VerifiableProgramContent)
    content.resources = MagicMock(vcpus=2, memory=4096)
    content.volumes = []
    content.requirements = None

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    assert check.call_args.kwargs["is_instance"] is True


def test_allocated_bytes_for_sums_the_vms_dirs_on_every_pool(mocker, tmp_path):
    """The discount is measured from the real directories, one per pool."""
    from aleph.vm.agent.capacity import allocated_bytes_for

    vm_hash = "ab" * 32
    dirs = []
    for pool in ("pool0", "pool1"):
        directory = tmp_path / pool / vm_hash
        directory.mkdir(parents=True)
        (directory / "rootfs.qcow2").write_bytes(b"x" * 8192)
        dirs.append(directory)
    mocker.patch("aleph.vm.agent.capacity.storage_pools.iter_namespace_dirs", return_value=iter(dirs))

    # st_blocks rounds to the filesystem block size, so assert the shape
    # (both pools counted) rather than an exact byte count.
    assert allocated_bytes_for(vm_hash) >= 2 * 8192


def test_allocated_bytes_for_looks_up_the_hash_as_a_namespace(mocker):
    """ItemHash goes to iter_namespace_dirs as a plain string."""
    from aleph.vm.agent.capacity import allocated_bytes_for

    iter_dirs = mocker.patch("aleph.vm.agent.capacity.storage_pools.iter_namespace_dirs", return_value=iter(()))

    assert allocated_bytes_for(ItemHash("ab" * 32)) == 0
    iter_dirs.assert_called_once_with("ab" * 32)


def test_check_message_caps_the_single_volume_figure_at_what_is_left_to_place(mocker):
    """The per-pool largest-volume check gets the same discount as the total.

    A recreate whose 20 GiB rootfs is already on a pool must not require a
    pool with 20 GiB free: creating() adopted the directory, so those bytes
    stopped counting as reclaimable, and no pool has to place that volume
    again."""
    manager = _manager()
    check = mocker.patch.object(manager, "check_capacity")
    mocker.patch("aleph.vm.agent.capacity.allocated_bytes_for", return_value=20_000 * 1024 * 1024)
    content = _instance_content(rootfs_mib=20_000, volumes_mib=(5_000,))

    manager.check_message(content, exclude_vm_hash=ItemHash("ab" * 32))

    kwargs = check.call_args.kwargs
    # 25 000 declared, 20 000 already held: 5 000 left to allocate, and no
    # single volume larger than that still needs placing.
    assert (kwargs["disk_mib"], kwargs["max_volume_mib"]) == (5_000, 5_000)
