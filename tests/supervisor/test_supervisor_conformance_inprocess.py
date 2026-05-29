import pytest
from conformance import SupervisorContractTests

from aleph.vm.supervisor.inprocess import InProcessSupervisor


class FakePool:
    def __init__(self):
        self.executions = {}


class TestInProcessSupervisorConformance(SupervisorContractTests):
    @pytest.fixture
    def supervisor(self):
        return InProcessSupervisor(pool=FakePool())
