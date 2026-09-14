"""What /status/config tells the scheduler about this node's API."""

from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.supervisor_interface.types import HostInfo


def _app():
    supervisor = MagicMock(
        list_vms=AsyncMock(return_value=[]),
        get_host_info=AsyncMock(return_value=HostInfo()),
    )
    return setup_webapp(supervisor=supervisor)


@pytest.mark.asyncio
async def test_public_config_advertises_the_allocation_protocol(aiohttp_client):
    """The scheduler picks /v2/control/allocations from this field alone, so
    absence means the legacy endpoint and the number is the highest version
    this node serves."""
    client = await aiohttp_client(_app())

    response = await client.get("/status/config")

    assert response.status == 200
    body = await response.json()
    assert body["api"]["allocations"] == 2


@pytest.mark.asyncio
async def test_public_config_advertises_the_control_routes_a_client_cannot_assume(aiohttp_client):
    """A client discovers the owner start route here: the route answers 404 for
    a VM this node does not hold, so trying it cannot tell an old node apart
    from an unknown hash."""
    client = await aiohttp_client(_app())

    response = await client.get("/status/config")

    assert response.status == 200
    body = await response.json()
    assert "machine_start" in body["api"]["control"]
