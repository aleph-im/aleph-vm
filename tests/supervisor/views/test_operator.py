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
    BackupId,
    BackupInfo,
    BackupStatus,
    ConfidentialMode,
    IpAssignment,
    LogChunk,
    LogSource,
    Measurement,
    SevInfo,
    TeeBackend,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils.test_helpers import (
    generate_signer_and_signed_headers_for_operation,
    patch_datetime_now,
)

_FAKE_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


def _vm_info(
    status: VmStatus = VmStatus.RUNNING,
    vm_id: str = _FAKE_HASH,
    confidential_mode: ConfidentialMode = ConfidentialMode.NONE,
    awaiting_confidential_init: bool = False,
) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_id),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=confidential_mode,
        awaiting_confidential_init=awaiting_confidential_init,
    )


_RECREATE_NETWORK_SUMMARY = {
    "success": True,
    "removed_chains_count": 1,
    "removed_chains": ["aleph-supervisor-nat"],
    "recreated_count": 1,
    "failed_count": 0,
    "recreated_vms": [_FAKE_HASH],
    "failed_vms": [],
}


def _measurement(vm_id: str = _FAKE_HASH) -> Measurement:
    return Measurement(
        vm_id=VmId(vm_id),
        measurement_bytes=b"",
        tee_backend=TeeBackend.SEV,
        sev_info=SevInfo(
            enabled=True,
            api_major=1,
            api_minor=55,
            build_id=21,
            policy=3,
            state="launch-update",
            handle=7,
        ),
        launch_measure="bWVhc3VyZQ==",
    )


_BACKUP_TS = 1_700_000_000


def _backup_info(
    status: BackupStatus = BackupStatus.COMPLETE,
    vm_id: str = _FAKE_HASH,
    backup_id: str | None = None,
) -> BackupInfo:
    return BackupInfo(
        vm_id=VmId(vm_id),
        backup_id=BackupId(backup_id or f"{vm_id}-20260616T000000Z"),
        status=status,
        size_bytes=4096,
        created_at_unix_secs=_BACKUP_TS,
        error_message="" if status is not BackupStatus.FAILED else "boom",
        checksum="sha256:abc123" if status is BackupStatus.COMPLETE else "",
        volumes=["rootfs.qcow2"] if status is BackupStatus.COMPLETE else [],
        source_sizes={"rootfs.qcow2": 8192} if status is BackupStatus.COMPLETE else {},
    )


def _fake_supervisor(status: VmStatus = VmStatus.RUNNING) -> MagicMock:
    return MagicMock(
        get_vm=AsyncMock(return_value=_vm_info(status)),
        delete_vm=AsyncMock(),
        stop_vm=AsyncMock(return_value=_vm_info(VmStatus.STOPPED)),
        start_vm=AsyncMock(return_value=_vm_info(VmStatus.RUNNING)),
        reboot_vm=AsyncMock(),
        reinstall_vm=AsyncMock(),
        get_logs=AsyncMock(return_value=[]),
        stream_logs=_fake_stream([]),
        recreate_network=AsyncMock(return_value=dict(_RECREATE_NETWORK_SUMMARY)),
        initialize_confidential=AsyncMock(),
        get_measurement=AsyncMock(return_value=_measurement()),
        inject_secret=AsyncMock(),
        start_backup=AsyncMock(return_value=_backup_info(BackupStatus.RUNNING)),
        get_backup_status=AsyncMock(return_value=_backup_info()),
        list_backups=AsyncMock(return_value=[]),
        delete_backup=AsyncMock(),
        download_backup=_fake_stream([]),
        restore_backup=AsyncMock(return_value=_vm_info(VmStatus.RUNNING)),
        restore_from_image=AsyncMock(return_value=_vm_info(VmStatus.RUNNING)),
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
    """The endpoint rejects a running VM, deriving the guard from
    supervisor.get_vm (not the pool). Auth needed."""

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
    fake_sup = _fake_supervisor()
    fake_sup.get_vm = AsyncMock(
        return_value=_vm_info(VmStatus.RUNNING, vm_id=str(vm_hash), confidential_mode=ConfidentialMode.SEV)
    )
    app["supervisor"] = fake_sup
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
    fake_sup.initialize_confidential.assert_not_awaited()


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
    fake_sup.stop_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_confidential(aiohttp_client, mocker):
    """The endpoint rejects a non-confidential VM, deriving the guard from
    supervisor.get_vm's confidential_mode."""

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
    fake_sup = _fake_supervisor()
    fake_sup.get_vm = AsyncMock(
        return_value=_vm_info(VmStatus.STOPPED, vm_id=str(vm_hash), confidential_mode=ConfidentialMode.NONE)
    )
    app["supervisor"] = fake_sup
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
    fake_sup.initialize_confidential.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_confidential_initialize(aiohttp_client, mocker):
    """The endpoint delegates the session/godh upload to the supervisor and
    preserves the 200 body. The engine owns the file writes and service start."""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    with tempfile.NamedTemporaryFile() as temp_file:
        temp_file.write(b"cert-bytes")
        temp_file.flush()
        form_data = aiohttp.FormData()
        form_data.add_field("session", open(temp_file.name, "rb"), filename="session.b64")
        form_data.add_field("godh", open(temp_file.name, "rb"), filename="godh.b64")

        with mock.patch(
            "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
            return_value=instance_message.sender,
        ):
            app = setup_webapp(pool=mocker.AsyncMock(executions={}))
            app["vm_registry"].record(
                vm_hash,
                message=instance_message.content,
                original=instance_message.content,
                persistent=True,
            )
            fake_sup = _fake_supervisor()
            # A confidential VM ready for its owner's session reports
            # awaiting_confidential_init; the endpoint waits for this state
            # before uploading the session files.
            fake_sup.get_vm = AsyncMock(
                return_value=_vm_info(
                    VmStatus.BOOTING,
                    vm_id=str(vm_hash),
                    confidential_mode=ConfidentialMode.SEV,
                    awaiting_confidential_init=True,
                )
            )
            app["supervisor"] = fake_sup
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{vm_hash}/confidential/initialize",
                data=form_data,
            )
            assert response.status == 200
            assert await response.text() == f"Started VM with ref {vm_hash}"
            fake_sup.initialize_confidential.assert_awaited_once_with(VmId(str(vm_hash)), b"cert-bytes", b"cert-bytes")


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
    fake_sup.stop_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


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
    fake_sup.stop_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


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
    fake_sup.stop_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


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
    fake_sup.stop_vm.assert_awaited_once()
    fake_sup.delete_vm.assert_not_awaited()


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
async def test_operator_confidential_measurement_delegates_and_preserves_response(aiohttp_client, mocker):
    """The endpoint delegates to supervisor.get_measurement and emits the
    legacy {"sev_info": {7 fields}, "launch_measure": ...} body."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
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
    app = setup_webapp(pool=fake_vm_pool)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    fake_sup.get_measurement = AsyncMock(return_value=_measurement(vm_id=str(vm_hash)))
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    response = await client.get(f"/control/machine/{vm_hash}/confidential/measurement")
    assert response.status == 200, await response.text()
    fake_sup.get_measurement.assert_awaited_once_with(VmId(str(vm_hash)))
    assert await response.json() == {
        "sev_info": {
            "enabled": True,
            "api_major": 1,
            "api_minor": 55,
            "build_id": 21,
            "policy": 3,
            "state": "launch-update",
            "handle": 7,
        },
        "launch_measure": "bWVhc3VyZQ==",
    }


@pytest.mark.asyncio
async def test_operator_confidential_inject_secret_delegates(aiohttp_client, mocker):
    """The endpoint delegates to supervisor.inject_secret (header/secret as
    bytes) and returns the running query-status body the pre-Phase-1 endpoint
    returned on success."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
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
    # After injecting the secret the endpoint reconciles the now-running VM's
    # port forwards; that path is covered by the run helper's own tests.
    mocker.patch("aleph.vm.orchestrator.run.reconcile_port_forwards", AsyncMock())
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
        f"/control/machine/{vm_hash}/confidential/inject_secret",
        json={"packet_header": "aGVhZGVy", "secret": "c2VjcmV0"},
    )
    assert response.status == 200, await response.text()
    assert await response.json() == {"status": {"status": "running", "running": True, "singlestep": False}}
    fake_sup.inject_secret.assert_awaited_once_with(VmId(str(vm_hash)), b"aGVhZGVy", b"c2VjcmV0")


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


def _backup_stream(chunks):
    """download_backup is a callable returning an async iterator of BackupChunk."""
    from aleph.vm.supervisor.types import BackupChunk

    async def _gen(vm_id, backup_id):
        offset = 0
        for data in chunks:
            yield BackupChunk(data=data, offset=offset)
            offset += len(data)

    return _gen


async def _seed_authorized_backup_app(aiohttp_client, mocker, **supervisor_overrides):
    """An app whose registry is seeded and whose sender is authorized, with a
    fake supervisor; returns (client, vm_hash, fake_sup)."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.is_sender_authorized",
        return_value=True,
    )
    app = setup_webapp(pool=mocker.AsyncMock(executions={}))
    # secret_token is set by the startup hook (setup), not setup_webapp; the
    # presigned download URL signing needs it.
    app["secret_token"] = "test-secret-token"
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    for key, value in supervisor_overrides.items():
        setattr(fake_sup, key, value)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)
    return client, vm_hash, fake_sup


@pytest.mark.asyncio
async def test_operator_backup_running_returns_202(aiohttp_client, mocker):
    """A RUNNING backup returns 202 in_progress; quiesce/include flags flow through."""
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, start_backup=AsyncMock(return_value=_backup_info(BackupStatus.RUNNING))
    )
    response = await client.post(f"/control/machine/{vm_hash}/backup?include_volumes=true&skip_fsfreeze=true")
    assert response.status == 202, await response.text()
    assert (await response.json())["status"] == "in_progress"
    fake_sup.start_backup.assert_awaited_once_with(VmId(str(vm_hash)), quiesce_guest=False, include_volumes=True)


@pytest.mark.asyncio
async def test_operator_backup_complete_returns_metadata_and_url(aiohttp_client, mocker):
    """A COMPLETE backup returns the metadata body sourced from BackupInfo plus a presigned URL."""
    info = _backup_info(BackupStatus.COMPLETE)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, start_backup=AsyncMock(return_value=info)
    )
    response = await client.post(f"/control/machine/{vm_hash}/backup")
    assert response.status == 200, await response.text()
    body = await response.json()
    assert body["backup_id"] == str(info.backup_id)
    assert body["size"] == info.size_bytes
    assert body["checksum"] == "sha256:abc123"
    assert body["volumes"] == ["rootfs.qcow2"]
    assert body["source_sizes"] == {"rootfs.qcow2": 8192}
    assert "signature=" in body["download_url"]
    assert f"/backup/{info.backup_id}" in body["download_url"]


@pytest.mark.asyncio
async def test_operator_backup_quiesce_default(aiohttp_client, mocker):
    """Without skip_fsfreeze the engine is asked to quiesce the guest."""
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, start_backup=AsyncMock(return_value=_backup_info(BackupStatus.RUNNING))
    )
    await client.post(f"/control/machine/{vm_hash}/backup")
    fake_sup.start_backup.assert_awaited_once_with(VmId(str(vm_hash)), quiesce_guest=True, include_volumes=False)


@pytest.mark.asyncio
async def test_operator_backup_insufficient_space_returns_507(aiohttp_client, mocker):
    from aleph.vm.supervisor.errors import InsufficientResourcesError

    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, start_backup=AsyncMock(side_effect=InsufficientResourcesError("no space"))
    )
    response = await client.post(f"/control/machine/{vm_hash}/backup")
    assert response.status == 507, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_invalid_backend_returns_400(aiohttp_client, mocker):
    from aleph.vm.supervisor.errors import InvalidBackendError

    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, start_backup=AsyncMock(side_effect=InvalidBackendError("not qemu"))
    )
    response = await client.post(f"/control/machine/{vm_hash}/backup")
    assert response.status == 400, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_status_running_returns_202(aiohttp_client, mocker):
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, list_backups=AsyncMock(return_value=[_backup_info(BackupStatus.RUNNING)])
    )
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    assert response.status == 202, await response.text()
    assert (await response.json())["status"] == "in_progress"


@pytest.mark.asyncio
async def test_operator_backup_status_complete_returns_metadata(aiohttp_client, mocker):
    info = _backup_info(BackupStatus.COMPLETE)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, list_backups=AsyncMock(return_value=[info])
    )
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    assert response.status == 200, await response.text()
    body = await response.json()
    assert body["backup_id"] == str(info.backup_id)
    assert body["checksum"] == "sha256:abc123"
    assert "download_url" in body
    fake_sup.list_backups.assert_awaited_once_with(VmId(str(vm_hash)))


@pytest.mark.asyncio
async def test_operator_backup_status_none_returns_404(aiohttp_client, mocker):
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, list_backups=AsyncMock(return_value=[])
    )
    response = await client.get(f"/control/machine/{vm_hash}/backup")
    assert response.status == 404, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_download_streams_with_sidecar_headers(aiohttp_client, mocker):
    """download verifies the presigned URL, streams from the engine, and sets
    Content-Length, X-Backup-Checksum and X-Source-Size from BackupInfo."""
    import dataclasses

    from aleph.vm.orchestrator.views.operator import _sign_backup_url

    chunks = [b"AAAA", b"BBBB"]
    # Content-Length is sourced from BackupInfo.size_bytes, which is the tar
    # size: it must match the streamed total or the client waits forever.
    info = dataclasses.replace(_backup_info(BackupStatus.COMPLETE), size_bytes=sum(len(c) for c in chunks))
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client,
        mocker,
        get_backup_status=AsyncMock(return_value=info),
        download_backup=_backup_stream(chunks),
    )
    secret = client.app["secret_token"]
    import time as _time

    expires = int(_time.time()) + 3600
    backup_id = str(info.backup_id)
    signature = _sign_backup_url(secret, backup_id, str(vm_hash), expires)
    response = await client.get(
        f"/control/machine/{vm_hash}/backup/{backup_id}?signature={signature}&expires={expires}"
    )
    assert response.status == 200, await response.text()
    assert response.headers["X-Backup-Checksum"] == "sha256:abc123"
    assert response.headers["X-Source-Size"] == "8192"
    assert response.headers["Content-Length"] == str(info.size_bytes)
    assert await response.read() == b"AAAABBBB"


@pytest.mark.asyncio
async def test_operator_backup_download_bad_signature_403(aiohttp_client, mocker):
    info = _backup_info(BackupStatus.COMPLETE)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, get_backup_status=AsyncMock(return_value=info)
    )
    backup_id = str(info.backup_id)
    response = await client.get(f"/control/machine/{vm_hash}/backup/{backup_id}?signature=bad&expires=9999999999")
    assert response.status == 403, await response.text()


@pytest.mark.asyncio
async def test_operator_backup_delete_delegates(aiohttp_client, mocker):
    info = _backup_info(BackupStatus.COMPLETE)
    backup_id = str(info.backup_id)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(aiohttp_client, mocker)
    response = await client.delete(f"/control/machine/{vm_hash}/backup/{backup_id}")
    assert response.status == 200, await response.text()
    fake_sup.delete_backup.assert_awaited_once_with(VmId(str(vm_hash)), BackupId(backup_id))


@pytest.mark.asyncio
async def test_operator_backup_delete_unknown_returns_404(aiohttp_client, mocker):
    from aleph.vm.supervisor.errors import BackupNotFoundError

    info = _backup_info(BackupStatus.COMPLETE)
    backup_id = str(info.backup_id)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, delete_backup=AsyncMock(side_effect=BackupNotFoundError(backup_id))
    )
    response = await client.delete(f"/control/machine/{vm_hash}/backup/{backup_id}")
    assert response.status == 404, await response.text()


@pytest.mark.asyncio
async def test_operator_restore_volume_ref_stages_and_restores(aiohttp_client, mocker, tmp_path):
    """A {"volume_ref": ...} body downloads the volume to a temp path, then the
    engine restore_from_image runs; success returns {"status": "restored"}."""
    staged = mocker.AsyncMock(return_value=tmp_path / "restore-staged.qcow2")
    mocker.patch("aleph.vm.orchestrator.views.operator.download_volume_by_ref", staged)
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(aiohttp_client, mocker)

    response = await client.post(
        f"/control/machine/{vm_hash}/restore",
        json={"volume_ref": "0123456789abcdef"},
    )
    assert response.status == 200, await response.text()
    body = await response.json()
    assert body == {"status": "restored", "vm_hash": str(vm_hash)}
    staged.assert_awaited_once()
    fake_sup.restore_from_image.assert_awaited_once()
    call = fake_sup.restore_from_image.await_args
    assert call.args[0] == VmId(str(vm_hash))


@pytest.mark.asyncio
async def test_operator_restore_upload_stages_and_restores(aiohttp_client, mocker):
    """A multipart 'rootfs' upload is staged to a temp path then restored via the engine."""
    client, vm_hash, fake_sup = await _seed_authorized_backup_app(aiohttp_client, mocker)

    form = aiohttp.FormData()
    form.add_field("rootfs", b"QCOW2-UPLOAD-BYTES", filename="rootfs.qcow2")
    response = await client.post(f"/control/machine/{vm_hash}/restore", data=form)
    assert response.status == 200, await response.text()
    assert (await response.json())["status"] == "restored"
    fake_sup.restore_from_image.assert_awaited_once()


@pytest.mark.asyncio
async def test_operator_restore_invalid_image_returns_400(aiohttp_client, mocker):
    """qemu-img rejecting the staged image (InvalidBackendError) maps to 400."""
    from aleph.vm.supervisor.errors import InvalidBackendError

    client, vm_hash, fake_sup = await _seed_authorized_backup_app(
        aiohttp_client, mocker, restore_from_image=AsyncMock(side_effect=InvalidBackendError("not qcow2"))
    )
    form = aiohttp.FormData()
    form.add_field("rootfs", b"NOT-A-QCOW2", filename="rootfs.qcow2")
    response = await client.post(f"/control/machine/{vm_hash}/restore", data=form)
    assert response.status == 400, await response.text()


def test_operator_backup_endpoints_have_no_pool_references():
    """Guard: the five backup/restore endpoints (and their restore helper) must
    not read the pool. No require_vm_pool / vm_pool / .executions /
    get_execution_or_404 anywhere in their source."""
    import inspect

    from aleph.vm.orchestrator.views import operator

    targets = [
        operator.operate_backup,
        operator.operate_backup_status,
        operator.operate_backup_download,
        operator.operate_backup_delete,
        operator.operate_restore,
    ]
    if hasattr(operator, "_do_restore"):
        targets.append(operator._do_restore)
    forbidden = ["require_vm_pool", "vm_pool", ".executions", "get_execution_or_404"]
    for func in targets:
        source = inspect.getsource(func)
        for token in forbidden:
            assert token not in source, f"{func.__name__} must not reference {token!r}"


def test_operator_module_does_not_read_execution_message():
    """Owner-auth and content reads must come from the registry, not the pool execution."""
    import inspect

    from aleph.vm.orchestrator.views import operator

    source = inspect.getsource(operator)
    assert "execution.message" not in source, (
        "operator.py must not read `execution.message`; authorize from the agent "
        "registry (get_agent_record_or_404 -> record.message) instead."
    )


# ---------------------------------------------------------------------------
# recreate_network endpoint delegation (Phase 1 P1.6a)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recreate_network_delegates_to_supervisor(aiohttp_client, mocker):
    """The endpoint delegates to supervisor.recreate_network and never reads the pool."""
    mocker.patch(
        "aleph.vm.orchestrator.views.authenticate_api_request",
        new=AsyncMock(return_value=True),
    )

    # A pool whose .executions access raises: the endpoint must not touch it.
    class _ExplodingPool:
        @property
        def executions(self):
            raise AssertionError("recreate_network endpoint must not read the pool")

    app = setup_webapp(pool=_ExplodingPool())
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)

    response = await client.post("/control/network/recreate")

    assert response.status == 200, await response.text()
    assert await response.json() == _RECREATE_NETWORK_SUMMARY
    fake_sup.recreate_network.assert_awaited_once_with()


@pytest.mark.asyncio
async def test_recreate_network_partial_failure_returns_207(aiohttp_client, mocker):
    """A summary with success=False maps to HTTP 207 (partial)."""
    mocker.patch(
        "aleph.vm.orchestrator.views.authenticate_api_request",
        new=AsyncMock(return_value=True),
    )
    partial = dict(_RECREATE_NETWORK_SUMMARY, success=False, failed_count=1, failed_vms=[{"vm_hash": "x"}])

    app = setup_webapp(pool=mocker.Mock())
    fake_sup = _fake_supervisor()
    fake_sup.recreate_network = AsyncMock(return_value=partial)
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)

    response = await client.post("/control/network/recreate")

    assert response.status == 207, await response.text()
    assert await response.json() == partial


@pytest.mark.asyncio
async def test_recreate_network_internal_error_returns_500(aiohttp_client, mocker):
    """An InternalSupervisorError from the engine maps to HTTP 500."""
    from aleph.vm.supervisor.errors import InternalSupervisorError

    mocker.patch(
        "aleph.vm.orchestrator.views.authenticate_api_request",
        new=AsyncMock(return_value=True),
    )

    app = setup_webapp(pool=mocker.Mock())
    fake_sup = _fake_supervisor()
    fake_sup.recreate_network = AsyncMock(side_effect=InternalSupervisorError("nft broke"))
    app["supervisor"] = fake_sup
    client: TestClient = await aiohttp_client(app)

    response = await client.post("/control/network/recreate")

    assert response.status == 500, await response.text()
    assert (await response.json())["success"] is False
