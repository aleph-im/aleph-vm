from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, make_execution

from aleph.vm.resources import (
    InsufficientResourcesError as InternalInsufficientResources,
)
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError as SupInsufficientResources,
)
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    ErrorCode,
    NetworkConfig,
    TeeBackend,
    TeeConfig,
    VmId,
)


@pytest.mark.asyncio
async def test_internal_exception_in_delete_is_translated():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock(side_effect=InternalInsufficientResources("no", required={"a": 1}, available={"a": 0}))
    pool.forget_vm = MagicMock()
    sup = LocalSupervisor(pool=pool)

    with pytest.raises(SupInsufficientResources) as excinfo:
        await sup.delete_vm(VmId("itemhash123"))

    assert excinfo.value.code is ErrorCode.INSUFFICIENT_RESOURCES


def _snp_spec(tmp_path: Path) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId("deadbeef" * 8),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[],
        vcpus=1,
        memory_mib=512,
        tee=TeeConfig(
            backend=TeeBackend.SEV_SNP,
            policy="0x30000",
            session_dir=tmp_path,
            kernel_cmdline="console=ttyS0",
            cpu_model="EPYC-v4",
        ),
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


@pytest.mark.asyncio
async def test_python_supervisor_rejects_snp_specs(tmp_path):
    # The Python supervisor's confidential path is SEV-session-only: it would
    # create the VM and never start it (awaiting_confidential_init forever,
    # field report F3). Fail the create loudly instead.
    pool = MagicMock()
    sup = LocalSupervisor(pool=pool)

    with pytest.raises(VmSetupError, match="Rust supervisor"):
        await sup.create_vm(_snp_spec(tmp_path))

    pool.create_vm_from_spec.assert_not_called()
