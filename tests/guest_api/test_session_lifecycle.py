import asyncio

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from aleph.vm.guest_api import __main__ as guest_api


async def _upstream(_: web.Request) -> web.Response:
    return web.Response(text="ok")


async def _run_two_requests(monkeypatch, upstream_url: str) -> None:
    app = guest_api.create_app("test")
    client = TestClient(TestServer(app))
    await client.start_server()

    session = app["http_session"]
    requests = []
    original_request = session.request

    def spy(*args, **kwargs):
        requests.append(session)
        return original_request(*args, **kwargs)

    session.request = spy
    monkeypatch.setattr(guest_api, "ALEPH_API_SERVER", upstream_url)
    try:
        assert (await client.get("/")).status == 200
        assert (await client.get("/")).status == 200
        assert not session.closed
    finally:
        await client.close()

    assert len(requests) == 2
    assert requests[0] is requests[1] is session
    assert session.closed


def test_requests_share_the_session_and_close_after_cleanup(monkeypatch) -> None:
    async def run() -> None:
        upstream = TestServer(web.Application())
        upstream.app.router.add_get("/", _upstream)
        await upstream.start_server()
        try:
            await _run_two_requests(monkeypatch, str(upstream.make_url("/")).rstrip("/"))
        finally:
            await upstream.close()

    asyncio.run(run())
