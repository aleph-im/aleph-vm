import pytest
from aiohttp import web

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp


@pytest.mark.asyncio
async def test_allocation_fails_on_invalid_item_hash(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid item_hash is provided."""
    app = setup_webapp()
    client = await aiohttp_client(app)
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    response: web.Response = await client.post(
        "/control/allocations", json={"persistent_vms": ["not-an-ItemHash"]}, headers={"X-Auth-Signature": "test"}
    )
    assert response.status == 400
    assert await response.json() == [
        {
            "loc": [
                "persistent_vms",
                0,
            ],
            "msg": "Could not determine hash type: 'not-an-ItemHash'",
            "type": "value_error.unknownhash",
        },
    ]


@pytest.mark.asyncio
async def test_system_usage(aiohttp_client):
    """Test that the usage system endpoints responds. No auth needed"""
    app = setup_webapp()
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert "cpu" in resp
    assert resp["cpu"]["count"] > 0


@pytest.mark.asyncio
async def test_allocation_invalid_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth token is provided."""
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp()
    client = await aiohttp_client(app)
    response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "notTest"},
    )
    assert response.status == 401
    assert await response.text() == "Authentication token received is invalid"


@pytest.mark.asyncio
async def test_allocation_missing_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when auth token is not provided."""
    app = setup_webapp()
    client = await aiohttp_client(app)
    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
    )
    assert response.status == 401
    assert await response.text() == "Authentication token is missing"


@pytest.mark.asyncio
async def test_allocation_valid_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth is provided.

    This is a very simple test that don't start or stop any VM so the mock is minimal"""

    class FakeVmPool:
        def get_persistent_executions(self):
            return []

    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp()
    app["vm_pool"] = FakeVmPool()
    app["pubsub"] = FakeVmPool()
    client = await aiohttp_client(app)

    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    assert await response.json() == {"success": True, "successful": [], "failing": [], "errors": {}}
