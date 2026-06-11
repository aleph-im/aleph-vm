from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import Backend, ConfidentialMode, VmId, VmStatus


def make_execution(
    *, vm_hash="itemhash123", running=True, confidential=False, hypervisor=HypervisorType.qemu, with_ip=True
):
    started = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
    times = SimpleNamespace(
        defined_at=started,
        preparing_at=None,
        prepared_at=None,
        starting_at=started,
        started_at=started if running else None,
        stopping_at=None,
        stopped_at=None,
    )
    tap = SimpleNamespace(
        guest_ip=SimpleNamespace(ip="10.0.0.2"),
        guest_ipv6=SimpleNamespace(ip="fd00::2"),
        ip_network="172.16.3.0/24",
        ipv6_network="fc00:1:2:3::/64",
    )
    vm = SimpleNamespace(tap_interface=tap if with_ip else None)
    return SimpleNamespace(
        vm_hash=vm_hash,
        times=times,
        persistent=True,
        controller_service=f"aleph-vm-controller@{vm_hash}.service",
        systemd_manager=object(),
        is_program=False,
        is_instance=True,
        is_confidential=confidential,
        hypervisor=hypervisor,
        vm=vm,
        gpus=[],
    )


class FakeSystemd:
    def __init__(self, active: dict[str, bool] | None = None):
        self._active = active or {}

    def get_services_active_states(self, services):
        return {s: self._active.get(s, False) for s in services}


class FakePool:
    def __init__(self, executions=None, systemd=None, network=None):
        self.executions = executions or {}
        self.systemd_manager = systemd or FakeSystemd()
        self.network = network


@pytest.mark.asyncio
async def test_get_vm_maps_a_running_qemu_instance():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm(VmId("itemhash123"))

    assert info.vm_id == "itemhash123"
    assert info.status is VmStatus.RUNNING
    assert info.backend is Backend.QEMU
    assert info.ipv4 == "10.0.0.2"
    assert info.ipv6 == "fd00::2"
    assert info.uptime_secs >= 100


@pytest.mark.asyncio
async def test_vm_info_has_no_is_instance_field():
    """The instance/program distinction is agent vocabulary: the wire must not
    carry it. The agent derives it from its registry (or from the guest
    channel's presence as a registry-miss fallback)."""
    execution = make_execution(vm_hash="i", hypervisor=HypervisorType.firecracker)
    sup = InProcessSupervisor(pool=FakePool(executions={"i": execution}))
    info = await sup.get_vm(VmId("i"))
    assert not hasattr(info, "is_instance")
    # An instance under Firecracker still reports the FIRECRACKER backend.
    assert info.backend is Backend.FIRECRACKER


@pytest.mark.asyncio
async def test_get_vm_unknown_raises_vm_not_found():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_vm(VmId("nope"))


@pytest.mark.asyncio
async def test_confidential_instance_reports_qemu_backend_and_tee_mode():
    """Backend is the VMM only; the TEE is carried by confidential_mode."""
    execution = make_execution(confidential=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)
    info = await sup.get_vm(VmId("itemhash123"))
    assert info.backend is Backend.QEMU
    assert info.confidential_mode is not ConfidentialMode.NONE


@pytest.mark.asyncio
async def test_list_vms_returns_one_info_per_execution():
    pool = FakePool(
        executions={
            "a": make_execution(vm_hash="hash-a"),
            "b": make_execution(vm_hash="hash-b", running=False),
        },
        systemd=FakeSystemd(
            {
                "aleph-vm-controller@hash-a.service": True,
                "aleph-vm-controller@hash-b.service": False,
            }
        ),
    )
    sup = InProcessSupervisor(pool=pool)
    infos = await sup.list_vms()
    assert {i.vm_id for i in infos} == {"hash-a", "hash-b"}
    assert len(infos) == 2


@pytest.mark.asyncio
async def test_list_vms_empty_pool_returns_empty_list():
    sup = InProcessSupervisor(pool=FakePool())
    assert await sup.list_vms() == []


@pytest.mark.asyncio
async def test_get_vm_reports_networks_and_lifecycle_timestamps():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm(VmId("itemhash123"))

    assert info.ipv4_network == "172.16.3.0/24"
    assert info.ipv6_network == "fc00:1:2:3::/64"
    started = execution.times.started_at
    assert info.started_at_ns == int(started.timestamp()) * 1_000_000_000 + started.microsecond * 1_000
    assert info.preparing_at_ns == 0
    assert info.stopped_at_ns == 0


@pytest.mark.asyncio
async def test_get_vm_without_tap_reports_empty_networks():
    execution = make_execution(running=False, with_ip=False)
    pool = FakePool(executions={"itemhash123": execution})
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm(VmId("itemhash123"))

    assert info.ipv4_network == ""
    assert info.ipv6_network == ""


@pytest.mark.asyncio
async def test_list_vms_batches_the_systemd_query():
    calls: list[list[str]] = []

    class CountingSystemd(FakeSystemd):
        def get_services_active_states(self, services):
            calls.append(list(services))
            return super().get_services_active_states(services)

    pool = FakePool(
        executions={"hash-a": make_execution(vm_hash="hash-a"), "hash-b": make_execution(vm_hash="hash-b")},
        systemd=CountingSystemd({"aleph-vm-controller@hash-a.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    infos = await sup.list_vms()

    assert len(calls) == 1
    assert sorted(calls[0]) == [
        "aleph-vm-controller@hash-a.service",
        "aleph-vm-controller@hash-b.service",
    ]
    by_id = {i.vm_id: i for i in infos}
    assert by_id["hash-a"].status is VmStatus.RUNNING
    assert by_id["hash-b"].status is not VmStatus.RUNNING


@pytest.mark.asyncio
async def test_get_host_info_reports_host_ipv4():
    pool = FakePool()
    pool.network = SimpleNamespace(host_ipv4="10.0.5.201")
    sup = InProcessSupervisor(pool=pool)
    assert (await sup.get_host_info()).host_ipv4 == "10.0.5.201"


@pytest.mark.asyncio
async def test_get_host_info_empty_host_ipv4_without_network():
    sup = InProcessSupervisor(pool=FakePool())
    assert (await sup.get_host_info()).host_ipv4 == ""
