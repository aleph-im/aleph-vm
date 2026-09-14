"""The log stream websocket when the client hangs up mid-stream."""

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.conf import settings
from aleph.vm.storage import get_message
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    LogChunk,
    LogSource,
    VmId,
    VmInfo,
    VmStatus,
)


@pytest.mark.asyncio
async def test_a_client_leaving_mid_stream_is_not_an_error(aiohttp_client, mocker, caplog):
    """A viewer closing the log tab used to surface as a 500 with a traceback:
    the send to the gone peer raised through the handler. It is the normal
    end of a stream, so the handler logs it as such and cancels the
    supervisor's stream instead of leaving it to the garbage collector."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    mocker.patch(
        "aleph.vm.agent.views.operator.authenticate_websocket_message",
        AsyncMock(return_value=instance_message.sender),
    )

    stream_finalized = asyncio.Event()

    async def endless_logs(vm_id, include_history=False):
        try:
            for n in range(10_000):
                yield LogChunk(timestamp_ns=n, line=f"line {n}", source=LogSource.SERIAL)
                await asyncio.sleep(0.01)
        finally:
            stream_finalized.set()

    info = VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=ConfidentialMode.NONE,
        awaiting_confidential_init=False,
    )
    supervisor = MagicMock(get_vm=AsyncMock(return_value=info), stream_logs=endless_logs)
    app = setup_webapp(supervisor=supervisor)
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    client: TestClient = await aiohttp_client(app)

    caplog.set_level(logging.INFO)
    ws = await client.ws_connect(f"/control/machine/{vm_hash}/stream_logs", timeout=0.2)
    await ws.send_json({"auth": {"any": "thing"}})
    assert await ws.receive_json() == {"status": "connected"}
    assert (await ws.receive_json())["message"] == "line 0"
    # Drop the connection without reading further: the handler is still
    # mid-send when the transport goes.
    await ws.close()

    await asyncio.wait_for(stream_finalized.wait(), timeout=5)
    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert errors == []
    assert any("went away" in record.getMessage() for record in caplog.records)
