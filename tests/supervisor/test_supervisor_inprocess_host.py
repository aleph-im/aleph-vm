import pytest
from test_supervisor_inprocess_query import FakePool, make_execution

from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import HealthInfo, HealthStatus, HostInfo


@pytest.mark.asyncio
async def test_health_reports_ok_and_vm_count():
    pool = FakePool(executions={"a": make_execution(), "b": make_execution()})
    sup = InProcessSupervisor(pool=pool)

    health = await sup.health()

    assert isinstance(health, HealthInfo)
    assert health.status is HealthStatus.OK
    assert health.vm_count == 2


@pytest.mark.asyncio
async def test_get_host_info_reports_cpu_and_memory():
    sup = InProcessSupervisor(pool=FakePool())

    info = await sup.get_host_info()

    assert isinstance(info, HostInfo)
    assert info.cpu_count >= 1
    assert info.memory_mib > 0
