import asyncio
import datetime
import json
import tempfile
from asyncio import Queue
from unittest import mock
from unittest.mock import MagicMock

import aiohttp
import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.pool import VmPool
from aleph.vm.storage import get_message
from aleph.vm.utils.logs import EntryDict
from aleph.vm.utils.test_helpers import (
    generate_signer_and_signed_headers_for_operation,
    patch_datetime_now,
)


@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_authorized(aiohttp_client):
    """Test that the confidential initialize endpoint rejects if the sender is not the good one. Auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    class FakeExecution:
        message = None
        is_running: bool = True
        is_confidential: bool = False

    class FakeVmPool:
        executions: dict[ItemHash, FakeExecution] = {}

        def __init__(self):
            self.executions[settings.FAKE_INSTANCE_ID] = FakeExecution()

    with mock.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="",
    ):
        with mock.patch(
            "aleph.vm.orchestrator.views.operator.is_sender_authorized",
            return_value=False,
        ) as is_sender_authorized_mock:
            app = setup_webapp()
            app["vm_pool"] = FakeVmPool()
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
    app = setup_webapp()
    app["vm_pool"] = fake_vm_pool
    client = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/confidential/initialize",
        json={"persistent_vms": []},
    )
    assert response.status == 403
    assert await response.text() == f"VM with ref {vm_hash} already running"


@pytest.mark.asyncio
async def test_operator_confidential_initialize(aiohttp_client):
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
        enable_and_start = MagicMock(return_value=True)

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
            app = setup_webapp()
            app["vm_pool"] = FakeVmPool()
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
    mock_address = "mock_address"
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )

    class FakeVmPool:
        executions = {
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
            ),
        }
        systemd_manager = mocker.Mock(restart=mocker.Mock())

    app = setup_webapp()
    pool = FakeVmPool()
    app["vm_pool"] = pool
    app["pubsub"] = FakeVmPool()
    client = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{mock_hash}/reboot",
    )
    assert response.status == 200
    assert (
        await response.text() == "Rebooted VM with ref fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    )
    assert pool.systemd_manager.restart.call_count == 1


@pytest.mark.asyncio
async def test_logs(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )

    # noinspection PyMissingConstructor
    class FakeVmPool(VmPool):
        def __init__(self):
            pass

        executions = {
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
                vm=mocker.Mock(
                    past_logs=mocker.Mock(
                        return_value=[
                            EntryDict(
                                SYSLOG_IDENTIFIER="stdout",
                                MESSAGE="logline1",
                                __REALTIME_TIMESTAMP=datetime.datetime(2020, 10, 12, 1, 2),
                            ),
                            EntryDict(
                                SYSLOG_IDENTIFIER="stdout",
                                MESSAGE="logline2",
                                __REALTIME_TIMESTAMP=datetime.datetime(2020, 10, 12, 1, 3),
                            ),
                        ]
                    )
                ),
            ),
        }
        systemd_manager = mocker.Mock(restart=mocker.Mock())

    app = setup_webapp()
    pool = FakeVmPool()
    app["vm_pool"] = pool
    app["pubsub"] = FakeVmPool()
    client = await aiohttp_client(app)
    response = await client.get(
        f"/control/machine/{mock_hash}/logs",
    )
    assert response.status == 200
    assert await response.text() == "2020-10-12T01:02:00> logline12020-10-12T01:03:00> logline2"


@pytest.mark.asyncio
async def test_websocket_logs(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    mocker.patch(
        "aleph.vm.orchestrator.views.operator.authenticate_websocket_message",
        return_value=mock_address,
    )
    fake_queue: Queue[tuple[str, str]] = asyncio.Queue()
    await fake_queue.put(("stdout", "this is a first log entry"))

    fakeVmPool = mocker.Mock(
        executions={
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
                vm=mocker.Mock(
                    get_log_queue=mocker.Mock(return_value=fake_queue),
                ),
            ),
        },
    )
    app = setup_webapp()
    app["vm_pool"] = fakeVmPool
    app["pubsub"] = None
    client = await aiohttp_client(app)
    websocket = await client.ws_connect(
        f"/control/machine/{mock_hash}/stream_logs",
    )
    await websocket.send_json({"auth": "auth is disabled"})
    response = await websocket.receive_json()
    assert response == {"status": "connected"}

    response = await websocket.receive_json()
    assert response == {"message": "this is a first log entry", "type": "stdout"}

    await fake_queue.put(("stdout", "this is a second log entry"))
    response = await websocket.receive_json()
    assert response == {"message": "this is a second log entry", "type": "stdout"}
    await websocket.close()
    assert websocket.closed


@pytest.mark.asyncio
async def test_websocket_logs_missing_auth(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"

    fake_queue: Queue[tuple[str, str]] = asyncio.Queue()
    await fake_queue.put(("stdout", "this is a first log entry"))

    fakeVmPool = mocker.Mock(
        executions={
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
                vm=mocker.Mock(
                    get_log_queue=mocker.Mock(return_value=fake_queue),
                ),
            ),
        },
    )
    app = setup_webapp()
    app["vm_pool"] = fakeVmPool
    app["pubsub"] = None
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
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"

    fake_queue: Queue[tuple[str, str]] = asyncio.Queue()
    await fake_queue.put(("stdout", "this is a first log entry"))

    fakeVmPool = mocker.Mock(
        executions={
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
                vm=mocker.Mock(
                    get_log_queue=mocker.Mock(return_value=fake_queue),
                ),
            ),
        },
    )
    app = setup_webapp()
    app["vm_pool"] = fakeVmPool
    app["pubsub"] = None
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
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"

    fake_queue: Queue[tuple[str, str]] = asyncio.Queue()
    await fake_queue.put(("stdout", "this is a first log entry"))

    fakeVmPool = mocker.Mock(
        executions={
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
                vm=mocker.Mock(
                    get_log_queue=mocker.Mock(return_value=fake_queue),
                ),
            ),
        },
    )
    app = setup_webapp()
    app["vm_pool"] = fakeVmPool
    app["pubsub"] = None
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
