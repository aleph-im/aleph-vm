from pathlib import Path

import pytest

from aleph.vm.supervisor.errors import NotImplementedSupervisorError
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import (
    Backend,
    BackupId,
    CreateVmSpec,
    DirectoryPath,
    NetworkConfig,
    VmId,
)


class FakePool:
    def __init__(self):
        self.executions = {}


def make_spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId("abc"),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[],
        vcpus=1,
        memory_mib=512,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


@pytest.fixture
def supervisor():
    return InProcessSupervisor(pool=FakePool())


def test_can_instantiate(supervisor):
    assert isinstance(supervisor, InProcessSupervisor)


@pytest.mark.asyncio
async def test_create_vm_is_stubbed(supervisor):
    with pytest.raises(NotImplementedSupervisorError):
        await supervisor.create_vm(make_spec())


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
