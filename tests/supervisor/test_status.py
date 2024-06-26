from unittest.mock import AsyncMock, MagicMock, Mock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator.status import check_internet


@pytest.mark.asyncio
async def test_check_internet_no_server_header():
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    mock_session = Mock()
    mock_session.get = MagicMock()
    mock_session.get.__aenter__.return_value.json = AsyncMock(return_value={"result": 200})

    # A "Server" header is always expected in the result from the VM.
    # If it is not present, the diagnostic VM is not working correctly
    # and an error must be raised.
    with pytest.raises(ValueError):
        await check_internet(mock_session, vm_id)


@pytest.mark.asyncio
async def test_check_internet_wrong_result_code():
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    mock_session = Mock()
    mock_session.get = MagicMock()

    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"result": 200, "headers": {"Server": "nginx"}}
    )
    assert await check_internet(mock_session, vm_id) is True

    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"result": 400, "headers": {"Server": "nginx"}}
    )
    assert await check_internet(mock_session, vm_id) is False
