import asyncio

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from aleph.vm.guest_api.__main__ import close_http_session, create_http_session


async def _session_id(request: web.Request) -> web.Response:
    return web.Response(text=str(id(request.app["http_session"])))


async def _run_session_and_cleanup() -> tuple[str, str, bool]:
    app = web.Application()
    app.on_startup.append(create_http_session)
    app.on_cleanup.append(close_http_session)
    app.router.add_get("/session-id", _session_id)

    client = TestClient(TestServer(app))
    await client.start_server()
    session = app["http_session"]
    try:
        first = await (await client.get("/session-id")).text()
        second = await (await client.get("/session-id")).text()
        assert not session.closed
    finally:
        await client.close()
    return first, second, session.closed


def test_http_session_is_shared_and_closed_after_cleanup() -> None:
    first, second, closed = asyncio.run(_run_session_and_cleanup())
    assert first == second
    assert closed
