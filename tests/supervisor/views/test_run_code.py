import pytest
from aiohttp import ClientResponseError, web
from aiohttp.test_utils import make_mocked_request
from aiohttp.web_exceptions import HTTPBadRequest
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.views import run_code_from_path


@pytest.mark.asyncio
async def test_run_code_from_invalid_path(aiohttp_client):
    """
    Test that the run_code_from_path endpoint raises the right
    error on invalid paths.
    """
    item_hash = "invalid-item-hash"
    with pytest.raises(UnknownHashError):
        assert ItemHash(item_hash).is_storage(item_hash)

    app = web.Application()

    app.router.add_route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
    client = await aiohttp_client(app)

    invalid_hash_request: web.Request = make_mocked_request(
        "GET",
        "/vm/" + item_hash,
        match_info={
            "ref": item_hash,
            "suffix": "/some/suffix",
        },
        headers={"Host": settings.DOMAIN_NAME},
        app=app,
    )
    with pytest.raises(HTTPBadRequest):
        await run_code_from_path(invalid_hash_request)

    # Calling the view from an HTTP client should result in a Bad Request error.
    resp = await client.get("/vm/" + item_hash + "/some/suffix")
    assert resp.status == HTTPBadRequest.status_code
    text = await resp.text()
    assert text == f"Invalid message reference: {item_hash}"
    with pytest.raises(ClientResponseError):
        resp.raise_for_status()
