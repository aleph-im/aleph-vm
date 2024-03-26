import os

from aiohttp import web

from aleph.vm.orchestrator.views.authentication import authenticate_jwk

# Avoid failures linked to settings when initializing the global VmPool object
os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"

from typing import Any

import pytest


@pytest.fixture
def valid_jwk_headers(mocker):
    mocker.patch("aleph.vm.orchestrator.views.authentication.is_token_still_valid", lambda timestamp: True)
    return {
        "X-SignedPubKey": '{"payload":"7b227075626b6579223a7b22616c67223a224553323536222c22637276223a22502d323536222c22657874223a747275652c226b65795f6f7073223a5b22766572696679225d2c226b7479223a224543222c2278223a224b65763844614d7356454673365a6b4679525a4272796344564138566a334f656e49756f34743561374634222c2279223a2279597343556d715978654767673643743736794f47525873545867446444795234644f5639514c6f6b6477227d2c22616c67223a224543445341222c22646f6d61696e223a226c6f63616c686f7374222c2261646472657373223a22307833343932346566393435623933316431653932393337353535366636396365326537666535646363222c2265787069726573223a313638393337353132342e3532317d","signature":"0x58e1498a6c4f88ac1982e7147ff49405ffe1b9633e048bb74cf741abb05ce0b63bb406f3079f641ae89f597654ecd2a704d37ffbf86a28e462140033cc0eedcb1c"}',
        "X-SignedOperation": '{"time":"2023-07-14T22:14:14.132Z","signature":"96ffdbbd1704d5f6bfe4698235a0de0d2f58668deaa4371422bee26664f313f51fd483c78c34c6b317fc209779f9ddd9c45accf558e3bf881b49ad970ebf0add"}',
    }


@pytest.mark.skip(reason="TODO: Fix this test")
@pytest.mark.asyncio
async def test_valid_signature(valid_jwk_headers: dict[str, Any], mocker):
    request = mocker.AsyncMock()
    request.headers = valid_jwk_headers
    await authenticate_jwk(request)


@pytest.mark.skip(reason="TODO: Fix this test")
@pytest.mark.asyncio
async def test_invalid_signature(valid_jwk_headers: dict[str, Any], mocker):
    valid_jwk_headers["X-SignedOperation"] = (
        '{"time":"2023-07-14T22:14:14.132Z","signature":"96ffdbbd1704d5f6bfe4698235a0de0d2f58668deaa4371422bee26664f313f51fd483c78c34c6b317fc209779f9ddd9c45accf558e3bf881b49ad970ebf0ade"}'
    )
    request = mocker.AsyncMock()
    request.headers = valid_jwk_headers

    with pytest.raises(web.HTTPUnauthorized):
        await authenticate_jwk(request)


@pytest.mark.skip(reason="TODO: Fix this test")
@pytest.mark.asyncio
async def test_expired_token(valid_jwk_headers: dict[str, Any], mocker):
    mocker.patch("aleph.vm.orchestrator.views.authentication.is_token_still_valid", lambda timestamp: False)
    request = mocker.AsyncMock()
    request.headers = valid_jwk_headers

    with pytest.raises(web.HTTPUnauthorized):
        await authenticate_jwk(request)


@pytest.mark.parametrize("missing_header", ["X-SignedPubKey", "X-SignedOperation"])
@pytest.mark.asyncio
async def test_missing_headers(valid_jwk_headers: dict[str, Any], mocker, missing_header: str):
    del valid_jwk_headers[missing_header]

    request = mocker.AsyncMock()
    request.headers = valid_jwk_headers

    with pytest.raises(web.HTTPBadRequest):
        await authenticate_jwk(request)
