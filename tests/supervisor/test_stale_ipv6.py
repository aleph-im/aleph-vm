"""The agent's startup pass that moves VMs off an address outside the pool."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent import stale_ipv6 as pass_module
from aleph.vm.agent.vm.retire import RetireReason
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    IpAssignment,
    NetworkConfig,
    VmId,
    VmInfo,
    VmStatus,
)

HASH_A = ItemHash("a" * 64)
HASH_B = ItemHash("b" * 64)
HASH_C = ItemHash("c" * 64)


def _info(vm_hash: ItemHash, status: VmStatus, network: str = "") -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(address="", network_cidr=network, gateway=""),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _spec(vm_hash: ItemHash, requested: str) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)
        ],
        vcpus=1,
        memory_mib=256,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6=requested, ipv6_prefix_len=124 if requested else 0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _registry(*persistent: ItemHash, on_demand: tuple[ItemHash, ...] = ()) -> AgentVmRegistry:
    registry = AgentVmRegistry()
    content = _make_qemu_instance_message()
    for vm_hash in persistent:
        registry.record(vm_hash, message=content, original=content, persistent=True)
    for vm_hash in on_demand:
        registry.record(vm_hash, message=content, original=content, persistent=False)
    return registry


@pytest.fixture
def pool(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_VM_NETWORKING", True)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "fc00:1:2:3::/64")


async def _run(supervisor, registry, *, start=None, retire=None, program_client=None, monkeypatch=None):
    if monkeypatch is not None:
        monkeypatch.setattr(pass_module, "start_persistent_vm", start or AsyncMock())
        monkeypatch.setattr(pass_module, "retire_vm", retire or AsyncMock())
    return await pass_module.rebuild_stale_vms_once(
        supervisor=supervisor,
        registry=registry,
        capacity=MagicMock(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
        program_client=program_client or MagicMock(forget=AsyncMock()),
        pubsub_getter=lambda: None,
    )


@pytest.mark.asyncio
async def test_pass_moves_running_vms_outside_the_pool(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        return_value=[
            _info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124"),
            _info(HASH_B, VmStatus.RUNNING, "fc00:1:2:3::10/124"),
        ]
    )
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_A, VmStatus.RUNNING, "fc00:1:2:3::20/124"))
    start = AsyncMock()

    report = await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)

    assert report.checked == 2
    assert report.stale_running == [VmId(str(HASH_A))]
    assert report.moved == [VmId(str(HASH_A))]
    start.assert_awaited_once()
    call = start.await_args
    assert call is not None
    assert call.args[0] == HASH_A
    assert call.kwargs["recreate"] is True


@pytest.mark.asyncio
async def test_pass_retires_a_stale_on_demand_program_instead_of_starting_it(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_C, VmStatus.RUNNING, "2001:db8::30/124")])
    start = AsyncMock()
    retire = AsyncMock()
    forget = AsyncMock()

    report = await _run(
        supervisor,
        _registry(on_demand=(HASH_C,)),
        start=start,
        retire=retire,
        program_client=MagicMock(forget=forget),
        monkeypatch=monkeypatch,
    )

    start.assert_not_awaited()
    retire.assert_awaited_once()
    call = retire.await_args
    assert call is not None
    assert call.args[1] is RetireReason.RECREATE
    forget.assert_awaited_once_with(VmId(str(HASH_C)))
    assert report.moved == [VmId(str(HASH_C))]


@pytest.mark.asyncio
async def test_pass_leaves_stale_stopped_vms_stopped(pool, monkeypatch):
    # A stopped VM stays stopped; its owner's next start rebuilds it.
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.STOPPED)])
    supervisor.get_vm_spec = AsyncMock(return_value=_spec(HASH_A, "2001:db8::10/124"))
    start = AsyncMock()
    retire = AsyncMock()

    report = await _run(supervisor, _registry(HASH_A), start=start, retire=retire, monkeypatch=monkeypatch)

    assert report.stale_stopped == [VmId(str(HASH_A))]
    assert report.moved == []
    start.assert_not_awaited()
    retire.assert_not_awaited()


@pytest.mark.asyncio
async def test_pass_skips_a_vm_without_a_record(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124")])
    start = AsyncMock()
    retire = AsyncMock()

    report = await _run(supervisor, AgentVmRegistry(), start=start, retire=retire, monkeypatch=monkeypatch)

    assert report.skipped == [VmId(str(HASH_A))]
    start.assert_not_awaited()
    retire.assert_not_awaited()


@pytest.mark.asyncio
async def test_pass_continues_past_a_failed_move(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        return_value=[
            _info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124"),
            _info(HASH_B, VmStatus.RUNNING, "2001:db8::20/124"),
        ]
    )
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_B, VmStatus.RUNNING, "fc00:1:2:3::20/124"))
    start = AsyncMock(side_effect=[RuntimeError("boom"), None])

    report = await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)

    assert report.failed == [VmId(str(HASH_A))]
    assert report.moved == [VmId(str(HASH_B))]
    assert start.await_count == 2


@pytest.mark.asyncio
async def test_pass_skips_on_an_unparseable_pool(pool, monkeypatch, caplog):
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "nonsense")
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock()

    with caplog.at_level(logging.ERROR, logger="aleph.vm.agent.stale_ipv6"):
        report = await _run(supervisor, AgentVmRegistry(), monkeypatch=monkeypatch)

    assert report.checked == 0
    assert any(r.levelno == logging.ERROR and "IPV6_ADDRESS_POOL" in r.getMessage() for r in caplog.records)
    supervisor.list_vms.assert_not_awaited()


@pytest.mark.asyncio
async def test_pass_moves_vms_one_at_a_time(pool, monkeypatch):
    # Two rebuilds never overlap: the second start begins after the first
    # returned.
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        return_value=[
            _info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124"),
            _info(HASH_B, VmStatus.RUNNING, "2001:db8::20/124"),
        ]
    )
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_A, VmStatus.RUNNING, "fc00:1:2:3::20/124"))
    order: list[str] = []

    async def start(vm_hash, *args, **kwargs):
        order.append(f"begin {vm_hash[:1]}")
        await asyncio.sleep(0)
        order.append(f"end {vm_hash[:1]}")

    await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)
    assert order == ["begin a", "end a", "begin b", "end b"]
