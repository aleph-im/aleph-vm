import pytest
from aiohttp.test_utils import TestClient

from aleph.vm.orchestrator.supervisor import setup_webapp


@pytest.mark.asyncio
async def test_json_404_about(aiohttp_client, mocker):
    app = setup_webapp(pool=None)
    client: TestClient = await aiohttp_client(app)
    response = await client.get(
        "/about/non_existing_path",
    )
    assert response.status == 404
    assert response.content_type == "application/json"
    assert await response.json() == {"error": "404: Not Found"}


@pytest.mark.asyncio
async def test_json_err_allocation_notify(aiohttp_client, mocker):
    app = setup_webapp(pool=None)
    client: TestClient = await aiohttp_client(app)
    response = await client.post("/control/allocation/notify", data="invalid_json")
    assert response.status == 400
    assert response.content_type == "application/json"
    assert await response.json() == {"error": "Body is not valid JSON"}
