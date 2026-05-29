from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.resources import InsufficientResourcesError as InternalInsufficientResources
from aleph.vm.supervisor.errors import InsufficientResourcesError as SupInsufficientResources
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import ErrorCode

from test_supervisor_inprocess_query import FakePool, make_execution


@pytest.mark.asyncio
async def test_internal_exception_in_delete_is_translated():
    execution = make_execution()
    pool = FakePool(executions={"itemhash123": execution})
    pool.stop_vm = AsyncMock(
        side_effect=InternalInsufficientResources("no", required={"a": 1}, available={"a": 0})
    )
    pool.forget_vm = MagicMock()
    sup = InProcessSupervisor(pool=pool)

    with pytest.raises(SupInsufficientResources) as excinfo:
        await sup.delete_vm("itemhash123")

    assert excinfo.value.code is ErrorCode.INSUFFICIENT_RESOURCES
