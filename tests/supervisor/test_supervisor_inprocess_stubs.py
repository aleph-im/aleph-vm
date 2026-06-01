from pathlib import Path

import pytest

from aleph.vm.supervisor.errors import NotImplementedSupervisorError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import BackupId, DirectoryPath, VmId


class FakePool:
    def __init__(self):
        self.executions = {}


@pytest.fixture
def supervisor():
    return InProcessSupervisor(pool=FakePool())


def test_can_instantiate(supervisor):
    assert isinstance(supervisor, InProcessSupervisor)


@pytest.mark.asyncio
async def test_backup_migration_confidential_are_stubbed(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.start_backup(VmId("abc"))
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.export_vm(VmId("abc"), DirectoryPath(Path("/tmp/x")))
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.get_measurement(VmId("abc"))


@pytest.mark.asyncio
async def test_streaming_stubs_raise_on_iteration(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        async for _ in supervisor.download_backup(VmId("abc"), BackupId("b1")):
            pass
