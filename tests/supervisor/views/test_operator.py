import asyncio
import json
import tempfile
from unittest import mock
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.metrics import ExecutionRecord
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.orchestrator.views.operator import _security_aggregate_cache
from aleph.vm.storage import get_message
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import (
    Backend,
    LogChunk,
    LogSource,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils.test_helpers import (
    generate_signer_and_signed_headers_for_operation,
    patch_datetime_now,
)

_FAKE_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


def _vm_info(status: VmStatus = VmStatus.RUNNING, vm_id: str = _FAKE_HASH) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_id),
        status=status,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _fake_supervisor(status: VmStatus = VmStatus.RUNNING) -> MagicMock:
    return MagicMock(
        get_vm=AsyncMock(return_value=_vm_info(status)),
        delete_vm=AsyncMock(),
        reboot_vm=AsyncMock(),
        reinstall_vm=AsyncMock(),
        get_logs=AsyncMock(return_value=[]),
        stream_logs=_fake_stream([]),
    )


def _fake_stream(chunks: list[LogChunk]):
    """Return a function that, when called with (vm_id,), yields each chunk.

    supervisor.stream_logs must be a callable returning an async iterator —
    a plain AsyncMock(side_effect=...) won't work here.
    """

    async def _gen(vm_id):
        for chunk in chunks:
            yield chunk

    return _gen


# Ensure this is not removed by ruff
assert patch_datetime_now


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all API response caches between tests."""
    _security_aggregate_cache.clear()
    yield
    _security_aggregate_cache.clear()


@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_authorized(aiohttp_client):
    """Rejects when the sender is not authorized; auth message comes from the registry."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    class FakeVmPool:
        # The 403 is returned at the registry-auth check, before the pool is read,
        # so an empty pool is sufficient.
        executions: dict = {}

    with mock.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="",
    ):
        with mock.patch(
            "aleph.vm.orchestrator.views.operator.is_sender_authorized",
            return_value=False,
        ) as is_sender_authorized_mock:
            app = setup_webapp(pool=FakeVmPool())
            app["vm_registry"].record(
                vm_hash,
                message=instance_message.content,
                original=instance_message.content,
                persistent=True,
            )
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{settings.FAKE_INSTANCE_ID}/confidential/initialize",
            )
            assert response.status == 403
            assert await response.text() == "Unauthorized sender"
            is_sender_authorized_mock.assert_called_once()


@pytest.mark.asyncio
async def test_operator_confidential_initialize_already_running(aiohttp_client, mocker):
    """Test that the confidential initialize endpoint rejects if the VM is already running. Auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.Mock(
        executions={
            vm_hash: mocker.Mock(
                vm_hash=vm_hash,
                message=instance_message.content,
                is_confidential=False,
                is_running=True,
            ),
        },
    )

    # Disable auth
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/confidential/initialize",
        json={"persistent_vms": []},
    )
    assert response.status == 400
    assert response.content_type == "application/json"
    assert await response.json() == {
        "code": "vm_running",
        "description": "Operation not allowed, instance already running",
    }


@pytest.mark.asyncio
async def test_operator_stop(aiohttp_client, mocker):
    """Test that the stop endpoint drives the supervisor, not the pool directly."""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    # Disable auth
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )
    assert response.status == 200, await response.text()
    fake_sup.delete_vm.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_confidential(aiohttp_client, mocker):
    """Test that the confidential initialize endpoint rejects if the VM is not confidential"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.Mock(
        executions={
            vm_hash: mocker.Mock(
                vm_hash=vm_hash,
                message=instance_message.content,
                is_confidential=False,
                is_running=False,
            ),
        },
    )

    # Disable auth
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/confidential/initialize",
        json={"persistent_vms": []},
    )
    assert response.status == 400
    assert response.content_type == "application/json"
    assert await response.json() == {
        "code": "not_confidential",
        "description": "Instance is not a confidential instance",
    }


@pytest.mark.asyncio
async def test_operator_confidential_initialize(aiohttp_client, mocker):
    """Test that the certificates system endpoint responds. No auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    class FakeExecution:
        message = instance_message.content
        is_running: bool = False
        is_confidential: bool = True
        controller_service: str = ""

    class MockSystemDManager:
        enable_and_start = mocker.AsyncMock(return_value=True)

    class FakeVmPool:
        executions: dict[ItemHash, FakeExecution] = {}

        def __init__(self):
            self.executions[vm_hash] = FakeExecution()
            self.systemd_manager = MockSystemDManager()

    with tempfile.NamedTemporaryFile() as temp_file:
        form_data = aiohttp.FormData()
        form_data.add_field("session", open(temp_file.name, "rb"), filename="session.b64")
        form_data.add_field("godh", open(temp_file.name, "rb"), filename="godh.b64")

        with mock.patch(
            "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
            return_value=instance_message.sender,
        ):
            app = setup_webapp(pool=FakeVmPool())
            app["vm_registry"].record(
                vm_hash,
                message=instance_message.content,
                original=instance_message.content,
                persistent=True,
            )
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{vm_hash}/confidential/initialize",
                data=form_data,
            )
            assert response.status == 200
            assert await response.text() == f"Started VM with ref {vm_hash}"
            app["vm_pool"].systemd_manager.enable_and_start.assert_called_once()


@pytest.mark.asyncio
async def test_reboot_ok(aiohttp_client, mocker):
    """Reboot a persistent VM: supervisor.reboot_vm is called."""
    mock_address = "mock_address"
    mock_hash = _FAKE_HASH
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = mocker.Mock()
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup

    client = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{mock_hash}/reboot",
    )
    assert response.status == 200
    assert await response.text() == f"Rebooted VM with ref {mock_hash}"
    fake_sup.reboot_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_websocket_logs_missing_auth(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    # Seed the registry so _logs_auth_message succeeds and ws.prepare is called
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
    )
    # stream_logs is not reached before auth fails; empty stream is a safe default
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client = await aiohttp_client(app)
    websocket = await client.ws_connect(
        f"/control/machine/{mock_hash}/stream_logs",
    )
    # Wait for message without sending an auth package.
    # Test with a timeout because we receive nothing
    with pytest.raises((TimeoutError, asyncio.exceptions.TimeoutError)):
        response = await websocket.receive_json(timeout=1)
        assert False

    # It's totally reachable with the pytest.raises
    # noinspection PyUnreachableCode
    await websocket.close()
    assert websocket.closed


@pytest.mark.asyncio
async def test_websocket_logs_invalid_auth(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    # Seed the registry so _logs_auth_message succeeds and ws.prepare is called
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
    )
    # stream_logs is not reached before auth fails; empty stream is a safe default
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    websocket = await client.ws_connect(
        f"/control/machine/{mock_hash}/stream_logs",
    )

    await websocket.send_json({"auth": "invalid auth package"})
    response = await websocket.receive()
    # Subject to change in the future, for now the connexion si broken and closed
    assert response.type == aiohttp.WSMsgType.TEXT
    assert (
        response.data == '{"status": "failed", "reason": "Invalid format for auth packet, see /doc/operator_auth.md"}'
    )
    response = await websocket.receive()
    assert response.type == aiohttp.WSMsgType.CLOSE
    assert websocket.closed


@pytest.mark.asyncio
async def test_websocket_logs_good_auth(aiohttp_client, mocker, patch_datetime_now):
    "Test valid authentification for websocket logs endpoint"
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}
    signer_account, headers = await generate_signer_and_signed_headers_for_operation(patch_datetime_now, payload)

    mock_address = signer_account.address
    mock_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    # Seed registry so _logs_auth_message finds the message
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
    )
    log_chunk = LogChunk(timestamp_ns=0, line="this is a first log entry", source=LogSource.STDOUT)
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    fake_sup.stream_logs = _fake_stream([log_chunk])
    app["supervisor"] = fake_sup
    client = await aiohttp_client(app)
    websocket = await client.ws_connect(
        f"/control/machine/{mock_hash}/stream_logs",
    )
    # Need to deserialize since we pass a json otherwhise it get double json encoded
    # which is not what the endpoint expect
    auth_package = {
        "X-SignedPubKey": json.loads(headers["X-SignedPubKey"]),
        "X-SignedOperation": json.loads(headers["X-SignedOperation"]),
    }

    await websocket.send_json({"auth": auth_package})
    response = await websocket.receive_json()
    assert response == {"status": "connected"}

    response = await websocket.receive_json()
    assert response == {"message": "this is a first log entry", "type": "stdout"}

    await websocket.close()
    assert websocket.closed


@pytest.mark.asyncio
async def test_get_past_logs(aiohttp_client, mocker, patch_datetime_now):
    mock_address = "0x40684b43B88356F62DCc56017547B6A7AC68780B"
    mock_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )
    mocker.patch(
        "aleph.vm.orchestrator.metrics.get_last_record_for_vm",
        return_value=ExecutionRecord(
            message="""{
  "address": "0x40684b43B88356F62DCc56017547B6A7AC68780B",
  "time": 1720816744.639107,
  "allow_amend": false,
  "metadata": null,
  "authorized_keys": null,
  "variables": null,
  "environment": {
    "reproducible": false,
    "internet": true,
    "aleph_api": true,
    "shared_cache": false
  },
  "resources": {
    "vcpus": 1,
    "memory": 1024,
    "seconds": 300,
    "published_ports": null
  },
  "payment": null,
  "requirements": null,
  "volumes": [
    {
      "comment": null,
      "mount": "/opt/packages",
      "ref": "7338478721e2e966da6395dbfa37dab7b017b48da55b1be22d4eccf3487b836c",
      "use_latest": true
    }
  ],
  "replaces": null,
  "type": "vm-function",
  "code": {
    "encoding": "squashfs",
    "entrypoint": "main:app",
    "ref": "c4253bf514d2e0a271456c9023c4b3f13f324e53c176e9ec29b98b5972b02bc7",
    "interface": null,
    "args": null,
    "use_latest": true
  },
  "runtime": {
    "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
    "use_latest": true,
    "comment": ""
  },
  "data": null,
  "export": null,
  "on": {
    "http": true,
    "message": null,
    "persistent": false
  }
}"""
        ),
    )

    # timestamp_ns values correspond to 2020-10-12 01:02:00 UTC and 2020-10-12 01:03:00 UTC
    _TS1 = 1602464520000000000
    _TS2 = 1602464580000000000
    log_chunks = [
        LogChunk(timestamp_ns=_TS1, line="logline1", source=LogSource.STDOUT),
        LogChunk(timestamp_ns=_TS2, line="logline2", source=LogSource.STDERR),
    ]
    fake_sup = MagicMock(
        get_logs=AsyncMock(return_value=log_chunks),
    )

    pool = mocker.MagicMock(executions={})
    app = setup_webapp(pool=pool)
    app["supervisor"] = fake_sup
    client = await aiohttp_client(app)
    response = await client.get(
        f"/control/machine/{mock_hash}/logs",
    )

    assert response.status == 200
    assert await response.json() == [
        {
            "MESSAGE": "logline1",
            "SYSLOG_IDENTIFIER": "vm-decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca-stdout",
            "__REALTIME_TIMESTAMP": "2020-10-12 01:02:00+00:00",
            "file": "stdout",
        },
        {
            "MESSAGE": "logline2",
            "SYSLOG_IDENTIFIER": "vm-decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca-stderr",
            "__REALTIME_TIMESTAMP": "2020-10-12 01:03:00+00:00",
            "file": "stderr",
        },
    ]


@pytest.mark.asyncio
async def test_operator_stop_with_delegation_authorized(aiohttp_client, mocker):
    """Test that a delegated address can successfully stop a VM"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    # Mock authentication to return the delegated address
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response for security aggregate with valid delegation
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 200, await response.text()
    fake_sup.delete_vm.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_stop_with_delegation_unauthorized(aiohttp_client, mocker):
    """Test that a non-delegated address cannot stop a VM"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    unauthorized_address = "0x8888888888888888888888888888888888888888"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    # Mock authentication to return an unauthorized address
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=unauthorized_address,
    )

    # Mock the API response for security aggregate with no delegations for this address
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": "0x9999999999999999999999999999999999999999",
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_reboot_with_delegation(aiohttp_client, mocker):
    """Test that a delegated address can successfully reboot a VM"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response for security aggregate with valid delegation
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = mocker.Mock()
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/reboot",
    )

    assert response.status == 200
    fake_sup.reboot_vm.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_erase_with_delegation(aiohttp_client, mocker):
    """Test that a delegated address can successfully erase a VM via the supervisor."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response for security aggregate with valid delegation
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/erase",
    )

    assert response.status == 200
    assert await response.text() == f"Erased VM with ref {vm_hash}"
    fake_sup.delete_vm.assert_awaited_once_with(VmId(str(vm_hash)), wipe=True)
    # registry record must be forgotten after erase
    assert app["vm_registry"].get(vm_hash) is None


@pytest.mark.asyncio
async def test_operator_backup_status_authorized_reads_registry(aiohttp_client, mocker, tmp_path):
    """Authorized backup-status reaches the backup logic with an empty pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=True,
    )
    # get_backup_directory() mkdirs under settings.EXECUTION_ROOT; patch the
    # operator-local name to a tmp dir.
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.get_backup_directory",
        return_value=tmp_path,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    # Past auth: no backup exists, so the backup logic returns its own 404.
    body = await response.text()
    assert response.status == 404, body
    assert "No backup found" in body


@pytest.mark.asyncio
async def test_operator_backup_status_unauthorized_reads_registry(aiohttp_client, mocker):
    """Backup-status authorizes against the registry, not the pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_delete_authorized_reads_registry(aiohttp_client, mocker, tmp_path):
    """Authorized backup-delete reaches the delete logic with an empty pool."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=True,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.get_backup_directory",
        return_value=tmp_path,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.delete(f"/control/machine/{vm_hash}/backup/{vm_hash}aa")
    # Past auth: no such backup file, so the delete logic returns its own 404.
    body = await response.text()
    assert response.status == 404, body
    assert "not found" in body


@pytest.mark.asyncio
async def test_operator_reinstall(aiohttp_client, mocker):
    """Reinstall a persistent VM: supervisor.reinstall_vm is called with wipe_volumes=True."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    mock_create_vm = mocker.patch(
        "aleph.vm.orchestrator.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/reinstall",
    )

    assert response.status == 200
    assert await response.text() == f"Reinstalled VM with ref {vm_hash}"
    fake_sup.reinstall_vm.assert_awaited_once_with(VmId(str(vm_hash)), wipe_volumes=True)
    mock_create_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_reinstall_unauthorized(aiohttp_client, mocker):
    """Test that reinstall endpoint requires authorization; reinstall_vm is NOT called."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="unauthorized_address",
    )

    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/reinstall",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"
    fake_sup.reinstall_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_delegation_with_empty_authorizations(aiohttp_client, mocker):
    """Test that empty authorizations list denies access"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response with empty authorizations
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(return_value={"data": {"security": {"authorizations": []}}})
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"


@pytest.mark.asyncio
async def test_delegation_with_wrong_message_type(aiohttp_client, mocker):
    """Test that delegation with wrong message type denies access"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response with wrong message type (not INSTANCE)
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": ["POST", "AGGREGATE"],  # Wrong types
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"


@pytest.mark.asyncio
async def test_delegation_with_case_insensitive_address(aiohttp_client, mocker):
    """Test that address comparison is case insensitive"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address_lower = "0x9999999999999999999999999999999999999aaa"
    delegated_address_mixed = delegated_address_lower.upper()
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address_lower,
    )

    # Mock the API response with uppercase address
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address_mixed,
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 200
    fake_sup.delete_vm.assert_awaited_once()


@pytest.mark.asyncio
async def test_delegation_api_error_denies_access(aiohttp_client, mocker):
    """Test that API errors during delegation check deny access"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API to raise an error
    mock_response = mocker.AsyncMock()
    mock_response.raise_for_status = mocker.Mock(side_effect=aiohttp.ClientResponseError(None, None, status=500))

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"


@pytest.mark.asyncio
async def test_delegation_with_empty_types_allows_all(aiohttp_client, mocker):
    """Test that delegation with empty types list allows INSTANCE operations"""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response with empty types (should allow all types)
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": [],  # Empty types means all types allowed
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.orchestrator.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/stop",
    )

    assert response.status == 200
    fake_sup.delete_vm.assert_awaited_once()


# ---------------------------------------------------------------------------
# New test cases added for Task 6
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_operator_stop_already_stopped(aiohttp_client, mocker):
    """Stop when the supervisor reports STOPPED → 200 'Already stopped', delete_vm NOT called."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.STOPPED)
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/stop")

    assert response.status == 200
    assert await response.text() == "Already stopped, nothing to do"
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_reboot_non_persistent(aiohttp_client, mocker):
    """Reboot a non-persistent VM: delete_vm then create_vm_execution_or_raise_http_error called."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    mock_create_vm = mocker.patch(
        "aleph.vm.orchestrator.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=False,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reboot")

    assert response.status == 200
    assert await response.text() == f"Rebooted VM with ref {vm_hash}"
    fake_sup.delete_vm.assert_awaited_once()
    fake_sup.reboot_vm.assert_not_awaited()
    mock_create_vm.assert_awaited_once_with(
        vm_hash=vm_hash,
        pool=fake_vm_pool,
        supervisor=fake_sup,
        registry=app["vm_registry"],
    )


@pytest.mark.asyncio
async def test_operator_stop_unknown_vm_hash_registry_empty(aiohttp_client, mocker):
    """Registry is empty → stop returns 404 immediately."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="some_sender",
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    # No record in registry

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/stop")

    assert response.status == 404


@pytest.mark.asyncio
async def test_operator_stop_registry_exists_but_supervisor_not_found(aiohttp_client, mocker):
    """Registry has record but supervisor raises VmNotFoundError → 404."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    # Supervisor raises VmNotFoundError on get_vm
    app["supervisor"] = MagicMock(
        get_vm=AsyncMock(side_effect=VmNotFoundError("not found")),
        delete_vm=AsyncMock(),
        reboot_vm=AsyncMock(),
    )

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/stop")

    assert response.status == 404


@pytest.mark.asyncio
async def test_operator_reboot_registry_exists_but_supervisor_not_found(aiohttp_client, mocker):
    """Registry has record but supervisor raises VmNotFoundError on reboot → 404."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    # Supervisor raises VmNotFoundError on get_vm
    app["supervisor"] = MagicMock(
        get_vm=AsyncMock(side_effect=VmNotFoundError("not found")),
        delete_vm=AsyncMock(),
        reboot_vm=AsyncMock(),
    )

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reboot")

    assert response.status == 404


@pytest.mark.asyncio
async def test_operator_stop_booting_vm_is_stopped(aiohttp_client, mocker):
    """Stop when the supervisor reports BOOTING → 200 'Stopped VM with ref ...', delete_vm called once."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.BOOTING)
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/stop")

    assert response.status == 200
    assert await response.text() == f"Stopped VM with ref {vm_hash}"
    fake_sup.delete_vm.assert_awaited_once()


# ---------------------------------------------------------------------------
# New test cases added for Task 7
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_operator_reinstall_rootfs_only(aiohttp_client, mocker):
    """?erase_volumes=false → reinstall_vm called with wipe_volumes=False."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/reinstall?erase_volumes=false",
    )

    assert response.status == 200
    fake_sup.reinstall_vm.assert_awaited_once_with(VmId(str(vm_hash)), wipe_volumes=False)


@pytest.mark.asyncio
async def test_operator_reinstall_non_persistent_recreates(aiohttp_client, mocker):
    """Non-persistent record: reinstall_vm called AND create_vm_execution_or_raise_http_error called."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    mock_create_vm = mocker.patch(
        "aleph.vm.orchestrator.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=False,  # non-persistent
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reinstall")

    assert response.status == 200
    fake_sup.reinstall_vm.assert_awaited_once_with(VmId(str(vm_hash)), wipe_volumes=True)
    mock_create_vm.assert_awaited_once_with(
        vm_hash=vm_hash,
        pool=fake_vm_pool,
        supervisor=fake_sup,
        registry=app["vm_registry"],
    )


@pytest.mark.asyncio
async def test_operator_erase_unknown_vm_404(aiohttp_client, mocker):
    """Registry is empty → erase returns 404 immediately; delete_vm not called."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="some_sender",
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    # No record in registry
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/erase")

    assert response.status == 404
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_erase_supervisor_not_found_404(aiohttp_client, mocker):
    """Registry seeded, delete_vm raises VmNotFoundError → 404; registry record NOT forgotten."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    # Supervisor raises VmNotFoundError on delete_vm
    app["supervisor"] = MagicMock(
        delete_vm=AsyncMock(side_effect=VmNotFoundError("not found")),
        reinstall_vm=AsyncMock(),
    )

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/erase")

    assert response.status == 404
    # Registry record was NOT forgotten (erase didn't actually happen)
    assert app["vm_registry"].get(vm_hash) is not None


@pytest.mark.asyncio
async def test_operator_erase_unauthorized(aiohttp_client, mocker):
    """Test that erase endpoint requires authorization; delete_vm is NOT called."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="unauthorized_address",
    )

    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/erase",
    )

    assert response.status == 403
    assert await response.text() == "Unauthorized sender"
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_reinstall_supervisor_not_found_404(aiohttp_client, mocker):
    """Registry seeded, reinstall_vm raises VmNotFoundError → 404; registry record kept."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    fake_vm_pool = mocker.AsyncMock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    # Supervisor raises VmNotFoundError on reinstall_vm
    app["supervisor"] = MagicMock(
        reinstall_vm=AsyncMock(side_effect=VmNotFoundError("not found")),
        delete_vm=AsyncMock(),
    )

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reinstall")

    assert response.status == 404
    # Registry record was NOT forgotten (reinstall didn't actually happen)
    assert app["vm_registry"].get(vm_hash) is not None


# ---------------------------------------------------------------------------
# New test cases added for Task 8: logs endpoints onto supervisor
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_websocket_logs_stopped_vm_sends_past_logs(aiohttp_client, mocker, patch_datetime_now):
    """Stopped VM (supervisor raises VmNotFoundError): ws receives past log chunks then system message."""
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}
    signer_account, headers = await generate_signer_and_signed_headers_for_operation(patch_datetime_now, payload)

    mock_address = signer_account.address
    mock_hash = _FAKE_HASH

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
    )
    past_chunk = LogChunk(timestamp_ns=0, line="past log line", source=LogSource.STDOUT)
    # Supervisor has no running VM: VmNotFoundError on get_vm; get_logs returns past chunks
    fake_sup = MagicMock(
        get_vm=AsyncMock(side_effect=VmNotFoundError("stopped")),
        get_logs=AsyncMock(return_value=[past_chunk]),
        stream_logs=_fake_stream([]),
    )
    app["supervisor"] = fake_sup

    client = await aiohttp_client(app)
    websocket = await client.ws_connect(f"/control/machine/{mock_hash}/stream_logs")

    auth_package = {
        "X-SignedPubKey": json.loads(headers["X-SignedPubKey"]),
        "X-SignedOperation": json.loads(headers["X-SignedOperation"]),
    }
    await websocket.send_json({"auth": auth_package})

    response = await websocket.receive_json(timeout=2)
    assert response == {"status": "connected"}

    response = await websocket.receive_json(timeout=2)
    assert response == {"type": "stdout", "message": "past log line"}

    response = await websocket.receive_json(timeout=2)
    assert response == {"type": "system", "message": "VM is not running, past logs sent"}

    await websocket.close()
    assert websocket.closed


@pytest.mark.asyncio
async def test_websocket_logs_booting_vm_sends_starting_message(aiohttp_client, mocker, patch_datetime_now):
    """BOOTING VM: ws receives 'VM is starting, try again shortly' and closes."""
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}
    signer_account, headers = await generate_signer_and_signed_headers_for_operation(patch_datetime_now, payload)

    mock_address = signer_account.address
    mock_hash = _FAKE_HASH

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    app["vm_registry"].record(
        ItemHash(mock_hash),
        message=mocker.Mock(address=mock_address),
        original=mocker.Mock(address=mock_address),
    )
    fake_sup = _fake_supervisor(VmStatus.BOOTING)
    app["supervisor"] = fake_sup

    client = await aiohttp_client(app)
    websocket = await client.ws_connect(f"/control/machine/{mock_hash}/stream_logs")

    auth_package = {
        "X-SignedPubKey": json.loads(headers["X-SignedPubKey"]),
        "X-SignedOperation": json.loads(headers["X-SignedOperation"]),
    }
    await websocket.send_json({"auth": auth_package})

    response = await websocket.receive_json(timeout=2)
    assert response == {"status": "connected"}

    response = await websocket.receive_json(timeout=2)
    assert response == {"type": "system", "message": "VM is starting, try again shortly"}

    response = await websocket.receive(timeout=2)
    assert response.type == aiohttp.WSMsgType.CLOSE
    assert websocket.closed


@pytest.mark.asyncio
async def test_operate_logs_json_unknown_vm_404(aiohttp_client, mocker):
    """Neither registry nor DB record: operate_logs_json returns 404."""
    mock_address = "0x40684b43B88356F62DCc56017547B6A7AC68780B"
    mock_hash = _FAKE_HASH

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )
    mocker.patch(
        "aleph.vm.orchestrator.metrics.get_last_record_for_vm",
        return_value=None,
    )

    pool = mocker.MagicMock(executions={})
    app = setup_webapp(pool=pool)
    # No registry record seeded
    client = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{mock_hash}/logs")

    assert response.status == 404


@pytest.mark.asyncio
async def test_websocket_logs_db_fallback_auth(aiohttp_client, mocker, patch_datetime_now):
    """Auth succeeds via DB fallback (no registry); ws receives streamed logs."""
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}
    signer_account, headers = await generate_signer_and_signed_headers_for_operation(patch_datetime_now, payload)

    mock_address = signer_account.address
    mock_hash = _FAKE_HASH

    fake_vm_pool = mocker.Mock(executions={})
    app = setup_webapp(pool=fake_vm_pool)
    app["pubsub"] = None
    # Do NOT seed the registry; test DB fallback
    # Mock metrics.get_last_record_for_vm to return a record with message that parses to same content
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.metrics.get_last_record_for_vm",
        return_value=ExecutionRecord(
            message=f"""{{
  "address": "{mock_address}",
  "time": 1720816744.639107,
  "allow_amend": false,
  "metadata": null,
  "authorized_keys": null,
  "variables": null,
  "environment": {{
    "reproducible": false,
    "internet": true,
    "aleph_api": true,
    "shared_cache": false
  }},
  "resources": {{
    "vcpus": 1,
    "memory": 1024,
    "seconds": 300,
    "published_ports": null
  }},
  "payment": null,
  "requirements": null,
  "volumes": [
    {{
      "comment": null,
      "mount": "/opt/packages",
      "ref": "7338478721e2e966da6395dbfa37dab7b017b48da55b1be22d4eccf3487b836c",
      "use_latest": true
    }}
  ],
  "replaces": null,
  "type": "vm-function",
  "code": {{
    "encoding": "squashfs",
    "entrypoint": "main:app",
    "ref": "c4253bf514d2e0a271456c9023c4b3f13f324e53c176e9ec29b98b5972b02bc7",
    "interface": null,
    "args": null,
    "use_latest": true
  }},
  "runtime": {{
    "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
    "use_latest": true,
    "comment": ""
  }},
  "data": null,
  "export": null,
  "on": {{
    "http": true,
    "message": null,
    "persistent": false
  }}
}}"""
        ),
    )
    log_chunk = LogChunk(timestamp_ns=0, line="this is a log from db fallback", source=LogSource.STDOUT)
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    fake_sup.stream_logs = _fake_stream([log_chunk])
    app["supervisor"] = fake_sup
    client = await aiohttp_client(app)
    websocket = await client.ws_connect(f"/control/machine/{mock_hash}/stream_logs")

    auth_package = {
        "X-SignedPubKey": json.loads(headers["X-SignedPubKey"]),
        "X-SignedOperation": json.loads(headers["X-SignedOperation"]),
    }

    await websocket.send_json({"auth": auth_package})
    response = await websocket.receive_json(timeout=2)
    assert response == {"status": "connected"}

    response = await websocket.receive_json(timeout=2)
    assert response == {"message": "this is a log from db fallback", "type": "stdout"}

    await websocket.close()
    assert websocket.closed


@pytest.mark.asyncio
async def test_operate_update_reconciles_when_running(aiohttp_client, mocker):
    """operate_update calls reconcile_port_forwards when the VM is RUNNING."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    reconcile_mock = AsyncMock()
    mocker.patch(
        "aleph.vm.orchestrator.views.reconcile_port_forwards",
        reconcile_mock,
    )

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)

    response = await client.post(f"/control/machine/{vm_hash}/update")

    assert response.status == 200
    reconcile_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_operate_update_skips_reconcile_when_not_running(aiohttp_client, mocker):
    """operate_update returns 200 without reconciling when VM is not RUNNING."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    reconcile_mock = AsyncMock()
    mocker.patch(
        "aleph.vm.orchestrator.views.reconcile_port_forwards",
        reconcile_mock,
    )

    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor(VmStatus.BOOTING)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)

    response = await client.post(f"/control/machine/{vm_hash}/update")

    assert response.status == 200
    data = await response.json()
    assert data["msg"] == "VM not starting yet"
    reconcile_mock.assert_not_awaited()


def test_dead_websocket_auth_helper_is_removed():
    """authenticate_websocket_for_vm_or_403 had no callers; it must be gone."""
    from aleph.vm.orchestrator.views import operator

    assert not hasattr(operator, "authenticate_websocket_for_vm_or_403")


@pytest.mark.asyncio
async def test_operator_confidential_measurement_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/confidential/measurement")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_confidential_inject_secret_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    # InjectSecretParams (packet_header, secret) is validated before auth, so the
    # body must be schema-valid for the request to reach the registry-auth check.
    response = await client.post(
        f"/control/machine/{vm_hash}/confidential/inject_secret",
        json={"packet_header": "aGVhZGVy", "secret": "c2VjcmV0"},
    )
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/backup")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_restore_unauthorized_reads_registry(aiohttp_client, mocker):
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    fake_vm_pool = mocker.AsyncMock(executions={})

    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="0xstranger",
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=False,
    )
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)
    # operate_restore acquires the per-VM backup lock then delegates to _do_restore,
    # whose first act (after migration) is the registry-auth check — before any body
    # parsing — so an empty JSON body is fine for the 403 path.
    response = await client.post(
        f"/control/machine/{vm_hash}/restore",
        json={},
    )
    assert response.status == 403, await response.text()


def test_operator_module_does_not_read_execution_message():
    """Owner-auth and content reads must come from the registry, not the pool execution."""
    import inspect

    from aleph.vm.orchestrator.views import operator

    source = inspect.getsource(operator)
    assert "execution.message" not in source, (
        "operator.py must not read `execution.message`; authorize from the agent "
        "registry (get_agent_record_or_404 -> record.message) instead."
    )
