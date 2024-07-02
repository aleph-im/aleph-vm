import asyncio
import datetime
import json
from asyncio import Queue

import aiohttp
import pytest
from aiohttp.test_utils import TestClient

from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.pool import VmPool
from aleph.vm.utils.logs import EntryDict
from aleph.vm.utils.test_helpers import (
    generate_signer_and_signed_headers_for_operation,
    patch_datetime_now,
)


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
    with pytest.raises(TimeoutError):
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
    assert response.type == aiohttp.WSMsgType.CLOSE
    assert websocket.closed


@pytest.mark.asyncio
async def test_websocket_logs_good_auth(aiohttp_client, mocker, patch_datetime_now):
    "Test valid authentification for websocket logs endpoint"
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/"}
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
