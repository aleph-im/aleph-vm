import datetime
import json
from typing import Any

import eth_account.messages
import pytest
from aiohttp import web
from eth_account.datastructures import SignedMessage
from jwcrypto import jwk, jws
from jwcrypto.common import base64url_decode
from jwcrypto.jwa import JWA

from aleph.vm.orchestrator.views.authentication import (
    authenticate_jwk,
    require_jwk_authentication,
)


def to_0x_hex(b: bytes) -> str:
    """
    Convert the bytes to a 0x-prefixed hex string
    """

    # force this for compat between different hexbytes versions which behave differenty
    # and conflict with other package don't allow us to have the version we want
    return "0x" + bytes.hex(b)


@pytest.mark.asyncio
async def test_require_jwk_authentication_missing_header(aiohttp_client):
    """An HTTP request to a view decorated by `@require_jwk_authentication` must return an error
    with a status code 400 and an error message in JSON when no authentication is provided.
    """
    app = web.Application()

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        return web.Response(text="ok")

    app.router.add_get("", view)
    client = await aiohttp_client(app)
    resp = await client.get("/")
    assert resp.status == 400

    r = await resp.json()
    assert {"error": "Missing X-SignedPubKey header"} == r


@pytest.mark.asyncio
async def test_require_jwk_authentication_invalid_json_bugkey(aiohttp_client):
    """An HTTP request to a view decorated by `@require_jwk_authentication`  must return an error
    with a status code 400 and an error message in JSON when the authentication key format is invalid.
    """

    app = web.Application()

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        return web.Response(text="ok")

    app.router.add_get("", view)
    client = await aiohttp_client(app)
    resp = await client.get("/", headers={"X-SignedPubKey": "invalid_json"})
    assert resp.status == 400

    r = await resp.json()
    assert {"error": "Invalid X-SignedPubKey format"} == r


@pytest.fixture
def patch_datetime_now(monkeypatch):
    """Fixture for patching the datetime.now() and datetime.utcnow() methods
    to return a fixed datetime object.
    This fixture creates a subclass of `datetime.datetime` called `mydatetime`,
    which overrides the `now()` and `utcnow()` class methods to return a fixed
    datetime object specified by `FAKE_TIME`.
    """

    class MockDateTime(datetime.datetime):
        FAKE_TIME = datetime.datetime(2010, 12, 25, 17, 5, 55)

        @classmethod
        def now(cls, tz=None, *args, **kwargs):
            return cls.FAKE_TIME.replace(tzinfo=tz)

        @classmethod
        def utcnow(cls, *args, **kwargs):
            return cls.FAKE_TIME

    monkeypatch.setattr(datetime, "datetime", MockDateTime)
    return MockDateTime


@pytest.mark.asyncio
async def test_require_jwk_authentication_expired(aiohttp_client):
    app = web.Application()
    account = eth_account.Account()
    signer_account = account.create()
    key = jwk.JWK.generate(
        kty="EC",
        crv="P-256",
        # key_ops=["verify"],
    )

    pubkey = {
        "pubkey": json.loads(key.export_public()),
        "alg": "ECDSA",
        "address": signer_account.address,
        "expires": "2023-05-02T10:44:42.754994Z",
    }
    pubkey_payload = json.dumps(pubkey).encode("utf-8").hex()
    signable_message = eth_account.messages.encode_defunct(hexstr=pubkey_payload)
    signed_message: SignedMessage = signer_account.sign_message(signable_message)
    pubkey_signature = to_0x_hex(signed_message.signature)

    pubkey_signature_header = json.dumps(
        {
            "payload": pubkey_payload,
            "signature": pubkey_signature,
        }
    )

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        return web.Response(text="ok")

    app.router.add_get("", view)
    client = await aiohttp_client(app)

    resp = await client.get("/", headers={"X-SignedPubKey": pubkey_signature_header})
    assert resp.status == 401

    r = await resp.json()
    assert {"error": "Token expired"} == r


@pytest.mark.asyncio
async def test_require_jwk_authentication_wrong_key(aiohttp_client, patch_datetime_now):
    app = web.Application()

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        return web.Response(text="ok")

    app.router.add_get("", view)
    client = await aiohttp_client(app)
    headers = {
        "X-SignedPubKey": (
            json.dumps(
                {
                    "payload": "7b227075626b6579223a207b22637276223a2022502d323536222c20226b7479223a20224543222c202278223a202273765759314e5652614a683231527834576a765f67657057772d714d436f774d76304a52353057327a7545222c202279223a2022794950424d6135474e7a49555878656c513762415a5f437776303875763448774d4c49456c656c43534473227d2c2022616c67223a20224543445341222c2022646f6d61696e223a20226c6f63616c686f7374222c202261646472657373223a2022307842323564623537643234304438353132366262364234384661633635343837323161343537343538222c202265787069726573223a2022323032332d30352d30325431303a34343a34322e3735343939345a227d",
                    "signature": "0x58e1498a6c4f88ac1982e7147ff49405ffe1b9633e048bb74cf741abb05ce0b63bb406f3079f641ae89f597654ecd2a704d37ffbf86a28e462140033cc0eedcb1c",
                }
            )
        )
    }
    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}
    headers["X-SignedOperation"] = json.dumps(
        {
            "payload": bytes.hex(json.dumps(payload).encode("utf-8")),
            "signature": "96ffdbbd1704d5f6bfe4698235a0de0d2f58668deaa4371422bee26664f313f51fd483c78c34c6b317fc209779f9ddd9c45accf558e3bf881b49ad970ebf0ade",
        }
    )

    resp = await client.get("/", headers=headers)
    assert resp.status == 401, await resp.text()

    r = await resp.json()
    assert {"error": "Invalid signature"} == r


@pytest.mark.asyncio
async def test_require_jwk_eth_signature_dont_match(aiohttp_client, patch_datetime_now):
    app = web.Application()

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        return web.Response(text="ok")

    account = eth_account.Account()
    signer_account = account.create()
    key = jwk.JWK.generate(
        kty="EC",
        crv="P-256",
        # key_ops=["verify"],
    )

    pubkey = {
        "pubkey": json.loads(key.export_public()),
        "alg": "ECDSA",
        "address": signer_account.address,
        "expires": "2023-05-02T10:44:42.754994Z",
    }
    pubkey_payload = json.dumps(pubkey).encode("utf-8").hex()
    signable_message = eth_account.messages.encode_defunct(hexstr=pubkey_payload)
    signed_message: SignedMessage = signer_account.sign_message(signable_message)
    pubkey_signature = to_0x_hex(signed_message.signature)

    app.router.add_get("", view)
    client = await aiohttp_client(app)
    headers = {
        "X-SignedPubKey": (
            json.dumps(
                {
                    "payload": pubkey_payload,
                    "signature": pubkey_signature,
                }
            )
        )
    }
    invalid_operation_payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "baddomain"}
    headers["X-SignedOperation"] = json.dumps(
        {
            "payload": bytes.hex(json.dumps(invalid_operation_payload).encode("utf-8")),
            "signature": "96ffdbbd1704d5f6bfe4698235a0de0d2f58668deaa4371422bee26664f313f51fd483c78c34c6b317fc209779f9ddd9c45accf558e3bf881b49ad970ebf0ade",
        }
    )

    resp = await client.get("/", headers=headers)
    assert resp.status == 401, await resp.text()

    r = await resp.json()
    assert {"error": "Invalid signature"} == r


@pytest.mark.asyncio
async def test_jwk():
    payload = "abc123"
    key = jwk.JWK.generate(
        kty="EC",
        crv="P-256",
    )
    pubkey = json.loads(key.export_public())
    jws_signer = jws.JWSCore(alg="ES256", key=key, payload=payload, header=None)
    signature_and_payload_json_dict = jws_signer.sign()
    signature = base64url_decode(signature_and_payload_json_dict["signature"])

    # Verify signature
    pub_jwk = jws.JWK(**pubkey)
    jws_verifier = jws.JWSCore(
        alg="ES256",
        key=pub_jwk,
        payload=payload,
        header=None,
    )
    assert jws_verifier.verify(signature=signature)


@pytest.mark.asyncio
async def test_require_jwk_authentication_good_key(aiohttp_client, patch_datetime_now):
    """An HTTP request to a view decorated by `@require_jwk_authentication`
    auth correctly a temporary key signed by a wallet and an operation signed by that key"""
    app = web.Application()

    account = eth_account.Account()
    signer_account = account.create()
    key = jwk.JWK.generate(
        kty="EC",
        crv="P-256",
        # key_ops=["verify"],
    )

    pubkey = {
        "pubkey": json.loads(key.export_public()),
        "alg": "ECDSA",
        "address": signer_account.address,
        "expires": (patch_datetime_now.FAKE_TIME + datetime.timedelta(days=1)).isoformat() + "Z",
    }
    pubkey_payload = json.dumps(pubkey).encode("utf-8").hex()
    signable_message = eth_account.messages.encode_defunct(hexstr=pubkey_payload)
    signed_message: SignedMessage = signer_account.sign_message(signable_message)
    pubkey_signature = to_0x_hex(signed_message.signature)
    pubkey_signature_header = json.dumps(
        {
            "payload": pubkey_payload,
            "signature": pubkey_signature,
        }
    )

    @require_jwk_authentication
    async def view(request, authenticated_sender):
        assert authenticated_sender == signer_account.address
        return web.Response(text="ok")

    app.router.add_get("", view)
    client = await aiohttp_client(app)

    payload = {"time": "2010-12-25T17:05:55Z", "method": "GET", "path": "/", "domain": "localhost"}

    payload_as_bytes = json.dumps(payload).encode("utf-8")
    headers = {"X-SignedPubKey": pubkey_signature_header}
    payload_signature = JWA.signing_alg("ES256").sign(key, payload_as_bytes)
    headers["X-SignedOperation"] = json.dumps(
        {
            "payload": payload_as_bytes.hex(),
            "signature": payload_signature.hex(),
        }
    )

    resp = await client.get("/", headers=headers)
    assert resp.status == 200, await resp.text()

    r = await resp.text()
    assert "ok" == r


@pytest.fixture
def valid_jwk_headers(mocker):
    mocker.patch("aleph.vm.orchestrator.views.authentication.is_token_still_valid", lambda timestamp: True)
    return {
        "X-SignedPubKey": '{"payload":"7b227075626b6579223a7b22616c67223a224553323536222c22637276223a22502d323536222c22657874223a747275652c226b65795f6f7073223a5b22766572696679225d2c226b7479223a224543222c2278223a224b65763844614d7356454673365a6b4679525a4272796344564138566a334f656e49756f34743561374634222c2279223a2279597343556d715978654767673643743736794f47525873545867446444795234644f5639514c6f6b6477227d2c22616c67223a224543445341222c22646f6d61696e223a226c6f63616c686f7374222c2261646472657373223a22307833343932346566393435623933316431653932393337353535366636396365326537666535646363222c2265787069726573223a313638393337353132342e3532317d","signature":"0x58e1498a6c4f88ac1982e7147ff49405ffe1b9633e048bb74cf741abb05ce0b63bb406f3079f641ae89f597654ecd2a704d37ffbf86a28e462140033cc0eedcb1c"}',
        "X-SignedOperation": '{"time":"2023-07-14T22:14:14.132Z","signature":"96ffdbbd1704d5f6bfe4698235a0de0d2f58668deaa4371422bee26664f313f51fd483c78c34c6b317fc209779f9ddd9c45accf558e3bf881b49ad970ebf0add"}',
    }


@pytest.mark.parametrize("missing_header", ["X-SignedPubKey", "X-SignedOperation"])
@pytest.mark.asyncio
async def test_missing_headers(valid_jwk_headers: dict[str, Any], mocker, missing_header: str):
    del valid_jwk_headers[missing_header]

    request = mocker.AsyncMock()
    request.headers = valid_jwk_headers

    with pytest.raises(web.HTTPBadRequest):
        await authenticate_jwk(request)
