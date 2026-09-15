"""The log stream websocket when the client hangs up mid-stream."""

import itertools
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientConnectionResetError
from aiohttp.test_utils import make_mocked_request
from aleph_message.models import ItemHash

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.agent.views.operator import stream_logs
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


class HungUpWebSocket:
    """Delivers the auth message, then the peer is gone by the second log line.

    That is what aiohttp's writer raises once the transport is closing; the
    test fixtures cannot produce it, their server cancels the handler instead.
    """

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closed = False

    async def prepare(self, request) -> None:
        pass

    async def receive_json(self) -> dict:
        return {"auth": {"any": "thing"}}

    async def send_json(self, payload: dict) -> None:
        if sum(1 for sent in self.sent if "type" in sent) == 1:
            raise ClientConnectionResetError("Cannot write to closing transport")
        self.sent.append(payload)

    async def close(self) -> None:
        self.closed = True


@pytest.mark.asyncio
async def test_a_client_leaving_mid_stream_is_not_an_error(mocker, caplog):
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
    ws = HungUpWebSocket()
    mocker.patch("aleph.vm.agent.views.operator.web.WebSocketResponse", return_value=ws)

    stream_finalized = False

    async def endless_logs(vm_id, include_history=False):
        nonlocal stream_finalized
        try:
            for n in itertools.count():
                yield LogChunk(timestamp_ns=n, line=f"line {n}", source=LogSource.SERIAL)
        finally:
            stream_finalized = True

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
    request = make_mocked_request(
        "GET", f"/control/machine/{vm_hash}/stream_logs", match_info={"ref": str(vm_hash)}, app=app
    )

    caplog.set_level(logging.INFO)
    assert await stream_logs(request) is ws

    assert ws.sent == [{"status": "connected"}, {"type": "serial", "message": "line 0"}]
    assert ws.closed
    # Set before the handler returned, so by aclose, not by a later collection.
    assert stream_finalized
    errors = [record for record in caplog.records if record.levelno >= logging.ERROR]
    assert errors == []
    assert any("went away" in record.getMessage() for record in caplog.records)
