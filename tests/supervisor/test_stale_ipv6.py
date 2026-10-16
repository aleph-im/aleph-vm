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
from aleph.vm.agent.run import StaleRebuild
from aleph.vm.agent.vm.retire import RetireReason
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import (
    InternalSupervisorError,
    VmNotFoundError,
)
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


async def _run(
    supervisor,
    registry,
    *,
    start=None,
    retire=None,
    program_client=None,
    update_watcher=None,
    expiry=None,
    stop=None,
    monkeypatch=None,
):
    if monkeypatch is not None:
        monkeypatch.setattr(pass_module, "rebuild_if_stale", start or AsyncMock(return_value=StaleRebuild.MOVED))
        monkeypatch.setattr(pass_module, "retire_vm", retire or AsyncMock())
    return await pass_module.rebuild_stale_vms_once(
        supervisor=supervisor,
        registry=registry,
        capacity=MagicMock(),
        expiry=expiry or MagicMock(),
        update_watcher=update_watcher or MagicMock(),
        program_client=program_client or MagicMock(forget=AsyncMock()),
        pubsub_getter=lambda: None,
        stop=stop,
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
    start = AsyncMock(return_value=StaleRebuild.MOVED)

    report = await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)

    assert report.checked == 2
    assert report.stale_running == [VmId(str(HASH_A))]
    assert report.moved == [VmId(str(HASH_A))]
    start.assert_awaited_once()
    call = start.await_args
    assert call is not None
    assert call.args[0] == HASH_A


@pytest.mark.asyncio
async def test_pass_retires_a_stale_on_demand_program_instead_of_starting_it(pool, monkeypatch):
    supervisor = MagicMock()
    stale = _info(HASH_C, VmStatus.RUNNING, "2001:db8::30/124")
    supervisor.list_vms = AsyncMock(return_value=[stale])
    supervisor.get_vm = AsyncMock(return_value=stale)
    start = AsyncMock()
    retire = AsyncMock()
    forget = AsyncMock()
    watcher = MagicMock()
    expiry = MagicMock()

    report = await _run(
        supervisor,
        _registry(on_demand=(HASH_C,)),
        start=start,
        retire=retire,
        program_client=MagicMock(forget=forget),
        update_watcher=watcher,
        expiry=expiry,
        monkeypatch=monkeypatch,
    )

    start.assert_not_awaited()
    expiry.cancel.assert_called_once_with(VmId(str(HASH_C)))
    watcher.cancel.assert_called_once_with(VmId(str(HASH_C)))
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
    start = AsyncMock(side_effect=[RuntimeError("boom"), StaleRebuild.MOVED])

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
        return StaleRebuild.MOVED

    await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)
    assert order == ["begin a", "end a", "begin b", "end b"]


@pytest.mark.asyncio
async def test_pass_reports_a_vm_judged_fine_at_action_time_as_skipped(pool, monkeypatch):
    # The owner stopped it (or it moved) between the listing and its turn.
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124")])
    start = AsyncMock(return_value=StaleRebuild.SKIPPED)

    report = await _run(supervisor, _registry(HASH_A), start=start, monkeypatch=monkeypatch)

    assert report.skipped == [VmId(str(HASH_A))]
    assert report.moved == []


@pytest.mark.asyncio
async def test_pass_names_the_owner_session_for_a_moved_confidential_vm(pool, monkeypatch, caplog):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124")])
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_A, VmStatus.BOOTING, "fc00:1:2:3::20/124"))
    start = AsyncMock(return_value=StaleRebuild.MOVED_AWAITING_INIT)

    with caplog.at_level(logging.INFO, logger="aleph.vm.agent.stale_ipv6"):
        report = await _run(supervisor, _registry(HASH_A), start=start, monkeypatch=monkeypatch)

    assert report.moved == [VmId(str(HASH_A))]
    assert report.awaiting_init == [VmId(str(HASH_A))]
    assert any("confidential/initialize" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_pass_leaves_an_on_demand_program_stopped_since_the_listing(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_C, VmStatus.RUNNING, "2001:db8::30/124")])
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_C, VmStatus.STOPPED))
    retire = AsyncMock()
    forget = AsyncMock()

    report = await _run(
        supervisor,
        _registry(on_demand=(HASH_C,)),
        retire=retire,
        program_client=MagicMock(forget=forget),
        monkeypatch=monkeypatch,
    )

    retire.assert_not_awaited()
    forget.assert_not_awaited()
    assert report.skipped == [VmId(str(HASH_C))]


@pytest.mark.asyncio
async def test_pass_counts_starting_vms_as_not_judged(pool, monkeypatch, caplog):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        return_value=[_info(HASH_A, VmStatus.BOOTING, "2001:db8::10/124"), _info(HASH_B, VmStatus.DEFINED)]
    )
    start = AsyncMock()

    with caplog.at_level(logging.INFO, logger="aleph.vm.agent.stale_ipv6"):
        report = await _run(supervisor, _registry(HASH_A, HASH_B), start=start, monkeypatch=monkeypatch)

    assert report.not_judged == [VmId(str(HASH_A)), VmId(str(HASH_B))]
    assert report.checked == 0
    start.assert_not_awaited()
    assert any(r.levelno == logging.INFO and "not judged" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_pass_summary_is_debug_when_nothing_is_stale(pool, monkeypatch, caplog):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.RUNNING, "fc00:1:2:3::10/124")])

    with caplog.at_level(logging.DEBUG, logger="aleph.vm.agent.stale_ipv6"):
        await _run(supervisor, _registry(HASH_A), monkeypatch=monkeypatch)

    summary = [r for r in caplog.records if "VMs checked" in r.getMessage()]
    assert [r.levelno for r in summary] == [logging.DEBUG]


@pytest.mark.asyncio
async def test_pass_waits_for_the_supervisor_to_answer(pool, monkeypatch):
    monkeypatch.setattr(pass_module, "_LIST_RETRY_INTERVAL_SECONDS", 0)
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        side_effect=[
            InternalSupervisorError("down"),
            InternalSupervisorError("down"),
            [_info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124")],
        ]
    )
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_A, VmStatus.RUNNING, "fc00:1:2:3::20/124"))
    start = AsyncMock(return_value=StaleRebuild.MOVED)

    report = await _run(supervisor, _registry(HASH_A), start=start, monkeypatch=monkeypatch)

    assert supervisor.list_vms.await_count == 3
    assert report.moved == [VmId(str(HASH_A))]


@pytest.mark.asyncio
async def test_pass_gives_up_loudly_when_the_supervisor_never_answers(pool, monkeypatch, caplog):
    monkeypatch.setattr(pass_module, "_LIST_RETRY_INTERVAL_SECONDS", 0)
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(side_effect=InternalSupervisorError("down"))

    with caplog.at_level(logging.ERROR, logger="aleph.vm.agent.stale_ipv6"):
        report = await _run(supervisor, _registry(HASH_A), monkeypatch=monkeypatch)

    assert report.checked == 0
    assert supervisor.list_vms.await_count == pass_module._LIST_RETRY_ATTEMPTS
    assert any(r.levelno == logging.ERROR and "Could not list VMs" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_pass_stops_between_vms_when_asked(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(
        return_value=[
            _info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124"),
            _info(HASH_B, VmStatus.RUNNING, "2001:db8::20/124"),
        ]
    )
    supervisor.get_vm = AsyncMock(return_value=_info(HASH_A, VmStatus.RUNNING, "fc00:1:2:3::20/124"))
    stop = asyncio.Event()

    async def start(vm_hash, *args, **kwargs):
        stop.set()  # The agent is told to stop during the first move.
        return StaleRebuild.MOVED

    mock = AsyncMock(side_effect=start)
    report = await _run(supervisor, _registry(HASH_A, HASH_B), start=mock, stop=stop, monkeypatch=monkeypatch)

    assert mock.await_count == 1
    assert report.moved == [VmId(str(HASH_A))]


@pytest.mark.asyncio
async def test_stop_hook_lets_the_move_in_flight_finish():
    stop = asyncio.Event()
    finished: list[bool] = []

    async def move():
        await stop.wait()
        await asyncio.sleep(0)
        finished.append(True)

    task = asyncio.ensure_future(move())
    app = {"_stale_ipv6_pass": task, "_stale_ipv6_stop": stop}

    await pass_module.stop_stale_ipv6_pass(app)  # type: ignore[arg-type]

    assert finished == [True]
    assert not task.cancelled()


@pytest.mark.asyncio
async def test_pass_counts_a_move_as_moved_when_the_new_address_cannot_be_read(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.RUNNING, "2001:db8::10/124")])
    supervisor.get_vm = AsyncMock(side_effect=VmNotFoundError("gone"))
    start = AsyncMock(return_value=StaleRebuild.MOVED)

    report = await _run(supervisor, _registry(HASH_A), start=start, monkeypatch=monkeypatch)

    assert report.moved == [VmId(str(HASH_A))]
    assert report.failed == []


@pytest.mark.asyncio
async def test_pass_reports_failed_and_stopping_vms_as_left_to_their_start_paths(pool, monkeypatch):
    supervisor = MagicMock()
    supervisor.list_vms = AsyncMock(return_value=[_info(HASH_A, VmStatus.FAILED, "2001:db8::10/124")])
    start = AsyncMock()

    report = await _run(supervisor, _registry(HASH_A), start=start, monkeypatch=monkeypatch)

    assert report.left_to_start_paths == [VmId(str(HASH_A))]
    assert report.moved == []
    assert report.checked == 0
    start.assert_not_awaited()
