import tempfile
from pathlib import Path
from unittest import mock
from unittest.mock import call

import pytest
from aiohttp import web

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.sevclient import SevClient


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

    response = await response.json()
    for error in response:
        error.pop("url", None)

    assert response == [
        {
            "loc": ["persistent_vms", 0],
            "msg": "Value error, Could not determine hash type: 'not-an-ItemHash'",
            "type": "value_error",
            "ctx": {"error": "Could not determine hash type: 'not-an-ItemHash'"},
            "input": "not-an-ItemHash",
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
async def test_system_usage_mock(aiohttp_client, mocker):
    """Test that the usage system endpoints response value. No auth needed"""
    mocker.patch(
        "cpuinfo.cpuinfo.get_cpu_info",
        {
            "arch_string_raw": "x86_64",
            "vendor_id_raw": "AuthenticAMD",
        },
    )
    mocker.patch(
        "psutil.getloadavg",
        lambda: [1, 2, 3],
    )
    mocker.patch(
        "psutil.cpu_count",
        lambda: 200,
    )
    app = setup_webapp()
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert resp["properties"]["cpu"]["architecture"] == "x86_64"
    assert resp["properties"]["cpu"]["vendor"] == "AuthenticAMD"
    assert resp["cpu"]["load_average"] == {"load1": 1.0, "load15": 3.0, "load5": 2.0}
    assert resp["cpu"]["count"] == 200


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


@pytest.mark.asyncio
async def test_about_certificates_missing_setting(aiohttp_client):
    """Test that the certificates system endpoint returns an error if the setting isn't enabled"""
    settings.ENABLE_CONFIDENTIAL_COMPUTING = False

    app = setup_webapp()
    app["sev_client"] = SevClient(Path().resolve(), Path("/opt/sevctl").resolve())
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/certificates")
    assert response.status == 400
    assert await response.text() == "400: Confidential computing setting not enabled on that server"


@pytest.mark.asyncio
async def test_about_certificates(aiohttp_client):
    """Test that the certificates system endpoint responds. No auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    with mock.patch(
        "pathlib.Path.is_file",
        return_value=False,
    ) as is_file_mock:
        with mock.patch(
            "aleph.vm.sevclient.run_in_subprocess",
            return_value=True,
        ) as export_mock:
            with tempfile.TemporaryDirectory() as tmp_dir:
                app = setup_webapp()
                sev_client = SevClient(Path(tmp_dir), Path("/opt/sevctl"))
                app["sev_client"] = sev_client
                # Create mock file to return it
                Path(sev_client.certificates_archive).touch(exist_ok=True)

                client = await aiohttp_client(app)
                response: web.Response = await client.get("/about/certificates")
                assert response.status == 200
                is_file_mock.assert_has_calls([call()])
                certificates_expected_dir = sev_client.certificates_archive
                export_mock.assert_called_once_with(
                    ["/opt/sevctl", "export", str(certificates_expected_dir)], check=True
                )
