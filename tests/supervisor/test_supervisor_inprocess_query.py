from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import Backend, VmId, VmStatus


def make_execution(
    *, vm_hash="itemhash123", running=True, confidential=False, hypervisor=HypervisorType.qemu, with_ip=True
):
    started = datetime.now(tz=timezone.utc) - timedelta(seconds=120)
    times = SimpleNamespace(
        defined_at=started,
        starting_at=started,
        started_at=started if running else None,
        stopping_at=None,
        stopped_at=None,
    )
    tap = SimpleNamespace(
        guest_ip=SimpleNamespace(ip="10.0.0.2"),
        guest_ipv6=SimpleNamespace(ip="fd00::2"),
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
    )


class FakeSystemd:
    def __init__(self, active: dict[str, bool] | None = None):
        self._active = active or {}

    def get_services_active_states(self, services):
        return {s: self._active.get(s, False) for s in services}


class FakePool:
    def __init__(self, executions=None, systemd=None):
        self.executions = executions or {}
        self.systemd_manager = systemd or FakeSystemd()


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
async def test_get_vm_unknown_raises_vm_not_found():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.get_vm(VmId("nope"))


@pytest.mark.asyncio
async def test_confidential_instance_reports_qemu_sev_backend():
    execution = make_execution(confidential=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)
    info = await sup.get_vm(VmId("itemhash123"))
    assert info.backend is Backend.QEMU_SEV


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
