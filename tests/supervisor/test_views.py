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
    """Test that the allocation endpoint fails when an invalid item_hash is provided."""
    app = setup_webapp()
    client = await aiohttp_client(app)
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert "cpu" in resp
    assert resp["cpu"]["count"] > 0
