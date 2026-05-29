from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import PortForwardSpec, Protocol

from test_supervisor_inprocess_query import FakePool


def make_execution_with_ports(mapped_ports=None):
    execution = SimpleNamespace(
        vm_hash="vm1",
        mapped_ports=mapped_ports if mapped_ports is not None else {},
    )
    execution.update_port_redirects = AsyncMock()
    return execution


@pytest.mark.asyncio
async def test_add_port_forward_calls_update_and_returns_info():
    execution = make_execution_with_ports()

    async def fake_update(requested):
        for vm_port, proto in requested.items():
            execution.mapped_ports[vm_port] = {"host": 34000, **proto}

    execution.update_port_redirects.side_effect = fake_update
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    info = await sup.add_port_forward(PortForwardSpec(vm_id="vm1", host_port=0, vm_port=8080, protocol=Protocol.TCP))

    execution.update_port_redirects.assert_awaited_once()
    assert info.vm_id == "vm1"
    assert info.vm_port == 8080
    assert info.host_port == 34000
    assert info.protocol is Protocol.TCP


@pytest.mark.asyncio
async def test_list_port_forwards_for_one_vm():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    forwards = await sup.list_port_forwards("vm1")

    assert len(forwards) == 1
    assert forwards[0].host_port == 34000
    assert forwards[0].vm_port == 8080
    assert forwards[0].protocol is Protocol.TCP


@pytest.mark.asyncio
async def test_list_port_forwards_all_vms():
    e1 = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    e1.vm_hash = "vm1"
    e2 = make_execution_with_ports({53: {"host": 34001, "tcp": False, "udp": True}})
    e2.vm_hash = "vm2"
    pool = FakePool(executions={"vm1": e1, "vm2": e2})
    sup = InProcessSupervisor(pool=pool)

    forwards = await sup.list_port_forwards(None)

    assert {f.host_port for f in forwards} == {34000, 34001}


@pytest.mark.asyncio
async def test_remove_port_forward_updates_redirects():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": False}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    await sup.remove_port_forward("vm1", host_port=34000, protocol=Protocol.TCP)

    execution.update_port_redirects.assert_awaited_once()


@pytest.mark.asyncio
async def test_port_forward_unknown_vm_raises():
    sup = InProcessSupervisor(pool=FakePool())
    with pytest.raises(VmNotFoundError):
        await sup.add_port_forward(PortForwardSpec(vm_id="nope", host_port=0, vm_port=80, protocol=Protocol.TCP))


@pytest.mark.asyncio
async def test_remove_one_protocol_keeps_sibling():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": True}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    await sup.remove_port_forward("vm1", host_port=34000, protocol=Protocol.TCP)

    requested = execution.update_port_redirects.await_args.args[0]
    assert requested[8080] == {"tcp": False, "udp": True}


@pytest.mark.asyncio
async def test_list_port_forwards_emits_one_info_per_protocol():
    execution = make_execution_with_ports({8080: {"host": 34000, "tcp": True, "udp": True}})
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    forwards = await sup.list_port_forwards("vm1")

    assert len(forwards) == 2
    assert {f.protocol for f in forwards} == {Protocol.TCP, Protocol.UDP}


@pytest.mark.asyncio
async def test_add_port_forward_udp():
    execution = make_execution_with_ports()

    async def fake_update(requested):
        for vm_port, proto in requested.items():
            execution.mapped_ports[vm_port] = {"host": 34002, **proto}

    execution.update_port_redirects.side_effect = fake_update
    pool = FakePool(executions={"vm1": execution})
    sup = InProcessSupervisor(pool=pool)

    info = await sup.add_port_forward(PortForwardSpec(vm_id="vm1", host_port=0, vm_port=53, protocol=Protocol.UDP))

    assert info.protocol is Protocol.UDP
    assert info.host_port == 34002
