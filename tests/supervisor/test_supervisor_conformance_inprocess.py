import pytest
from conformance import SupervisorContractTests

from aleph.vm.supervisor.local import LocalSupervisor


class FakePool:
    def __init__(self):
        self.executions = {}


class TestLocalSupervisorConformance(SupervisorContractTests):
    @pytest.fixture
    def supervisor(self):
        return LocalSupervisor(pool=FakePool())
