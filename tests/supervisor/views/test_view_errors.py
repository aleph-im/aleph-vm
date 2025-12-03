from unittest import mock

import pytest
from aiohttp.test_utils import TestClient

from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.resources import InsufficientResourcesError


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


@pytest.mark.asyncio
async def test_json_err_allocation_notify_insufficient_resources(aiohttp_client, mocker):
    """Test that allocation/notify returns proper JSON error when resources are insufficient."""
    from aleph.vm.pool import VmPool

    # Create a mock pool
    mock_pool = mocker.Mock(spec=VmPool)

    app = setup_webapp(pool=mock_pool)
    client: TestClient = await aiohttp_client(app)

    # Mock the try_get_message function to return a valid instance message
    mocker.patch(
        "aleph.vm.orchestrator.views.try_get_message",
        return_value=mocker.AsyncMock(
            type="INSTANCE",
            sender="0x123",
            content=mocker.Mock(
                payment=None, environment=mocker.Mock(trusted_execution=None), requirements=None, address="0x123"
            ),
        ),
    )

    # Mock start_persistent_vm to raise InsufficientResourcesError
    required = {"vcpus": 4, "memory_mb": 2048, "disk_mb": 10240}
    available = {"vcpus": 2, "memory_mb": 1024, "disk_mb": 5120}
    error = InsufficientResourcesError(
        "Insufficient resources to create VM. vCPUs: required 4, available 2; "
        "Memory: required 2048 MB, available 1024.00 MB; "
        "Disk: required 10240 MB, available 5120.00 MB",
        required=required,
        available=available,
    )

    mocker.patch("aleph.vm.orchestrator.views.start_persistent_vm", side_effect=error)
    mocker.patch("aleph.vm.orchestrator.views.update_aggregate_settings", return_value=mocker.AsyncMock())

    # Make the request
    response = await client.post(
        "/control/allocation/notify",
        json={"instance": "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"},
    )

    # Assert the response
    assert response.status == 507  # Insufficient Storage
    assert response.content_type == "application/json"

    response_json = await response.json()
    assert response_json["success"] is False
    assert response_json["error"] == "Insufficient resources"
    assert "vCPUs" in response_json["message"]
    assert "Memory" in response_json["message"]
    assert "Disk" in response_json["message"]
    assert response_json["required"] == required
    assert response_json["available"] == available
