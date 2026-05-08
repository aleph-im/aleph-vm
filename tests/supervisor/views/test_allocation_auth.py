"""Unit tests for src/aleph/vm/orchestrator/views/allocation_auth.py."""

import json
import time as time_module
from hashlib import sha256

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError

from aleph.vm.conf import Settings, settings


def test_authorized_signers_default_empty():
    """By default, no signers are authorized — the new path is effectively disabled."""
    assert settings.AUTHORIZED_ALLOCATION_SIGNERS == []


def test_signature_max_age_default():
    """Default time window is 5 minutes (300 seconds)."""
    assert settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS == 300


def test_invalid_signer_address_rejected():
    """Non-hex-address entries fail validation."""
    with pytest.raises(ValidationError):
        Settings(AUTHORIZED_ALLOCATION_SIGNERS=["not-an-address"])


def test_non_checksum_signer_address_rejected():
    """Lowercase / non-checksummed addresses fail validation (catches typos early)."""
    # Valid hex but not in EIP-55 mixed case.
    with pytest.raises(ValidationError):
        Settings(AUTHORIZED_ALLOCATION_SIGNERS=["0xdac17f958d2ee523a2206206994597c13d831ec7"])


def test_checksummed_signer_address_accepted():
    """Properly checksummed addresses pass."""
    settings_inst = Settings(AUTHORIZED_ALLOCATION_SIGNERS=["0xdAC17F958D2ee523a2206206994597C13D831ec7"])
    assert settings_inst.AUTHORIZED_ALLOCATION_SIGNERS == ["0xdAC17F958D2ee523a2206206994597C13D831ec7"]


@pytest.fixture
def signing_account():
    """Generate a fresh ETH account for signing test requests."""
    return Account.create()


@pytest.fixture
def authorize_signer(signing_account, monkeypatch):
    """Add the signing account to AUTHORIZED_ALLOCATION_SIGNERS for the test."""
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [signing_account.address])
    return signing_account


@pytest.fixture(autouse=True)
def reset_iat_cache():
    """Clear the monotonic-iat dict between tests (added in Task 5)."""
    # Imported lazily because the symbol doesn't exist until Task 5.
    try:
        from aleph.vm.orchestrator.views.allocation_auth import _last_accepted_iat

        _last_accepted_iat.clear()
        yield
        _last_accepted_iat.clear()
    except ImportError:
        yield


def make_signed_payload(*, method="POST", path="/control/allocations", body=b"", iat=None) -> bytes:
    """Build the canonical JSON bytes that get signed."""
    payload = {
        "method": method,
        "path": path,
        "body_sha256": sha256(body).hexdigest(),
        "iat": iat if iat is not None else int(time_module.time()),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def make_auth_header(account, payload_bytes: bytes) -> str:
    """Sign payload_bytes with `account` and produce the full Authorization value."""
    signed = account.sign_message(encode_defunct(payload_bytes))
    return f"Aleph-EIP191-V1 sig={signed.signature.hex()},payload={payload_bytes.hex()}"


@pytest.fixture
def mock_request(mocker):
    """Build a minimal fake aiohttp request supporting `await request.read()`."""

    def factory(*, method="POST", path="/control/allocations", headers=None, body=b""):
        request = mocker.Mock()
        request.method = method
        request.path = path
        request.headers = headers or {}
        request.read = mocker.AsyncMock(return_value=body)
        request.remote = "127.0.0.1"
        return request

    return factory


def test_parse_auth_params_valid():
    from aleph.vm.orchestrator.views.allocation_auth import _parse_auth_params

    params = _parse_auth_params("Aleph-EIP191-V1 sig=0xdead,payload=0xbeef")
    assert params == {"sig": "0xdead", "payload": "0xbeef"}


def test_parse_auth_params_extra_whitespace_tolerated():
    from aleph.vm.orchestrator.views.allocation_auth import _parse_auth_params

    params = _parse_auth_params("Aleph-EIP191-V1   sig=0xdead, payload=0xbeef")
    assert params == {"sig": "0xdead", "payload": "0xbeef"}


@pytest.mark.parametrize(
    "header",
    [
        "Aleph-EIP191-V1",  # no params
        "Aleph-EIP191-V1 sig=0xdead",  # missing payload
        "Aleph-EIP191-V1 payload=0xbeef",  # missing sig
        "Aleph-EIP191-V1 sigonly",  # not a key=value pair
        "Aleph-EIP191-V1 sig=,payload=0xbeef",  # empty value
        "Bearer abc",  # wrong scheme
    ],
)
def test_parse_auth_params_malformed(header):
    from aleph.vm.orchestrator.views.allocation_auth import _parse_auth_params

    with pytest.raises(ValueError):
        _parse_auth_params(header)


@pytest.mark.asyncio
async def test_verify_aleph_signature_valid_request(mock_request, authorize_signer):
    from aleph.vm.orchestrator.views.allocation_auth import (
        _last_accepted_iat,
        _verify_aleph_signature,
    )

    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(
        method="POST",
        path="/control/allocations",
        headers={"Authorization": auth},
        body=b"{}",
    )

    assert await _verify_aleph_signature(request, auth) is True
    assert authorize_signer.address.lower() in {k.lower() for k in _last_accepted_iat}


@pytest.mark.asyncio
async def test_verify_rejects_non_integer_iat(mock_request, authorize_signer):
    """A signed payload with a non-integer iat (e.g., float or string) is rejected."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    # Hand-craft a payload with a string iat — must be signed with the same bytes
    # to bypass earlier checks and reach the type guard.
    bad_payload = json.dumps(
        {
            "method": "POST",
            "path": "/control/allocations",
            "body_sha256": sha256(b"{}").hexdigest(),
            "iat": "1700000000",
        },  # ← string, not int
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    auth = make_auth_header(authorize_signer, bad_payload)
    request = mock_request(
        method="POST",
        path="/control/allocations",
        headers={"Authorization": auth},
        body=b"{}",
    )

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_boolean_iat(mock_request, authorize_signer):
    """A boolean iat (which is technically int subclass) is rejected too."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    bad_payload = json.dumps(
        {
            "method": "POST",
            "path": "/control/allocations",
            "body_sha256": sha256(b"{}").hexdigest(),
            "iat": True,
        },  # ← boolean
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    auth = make_auth_header(authorize_signer, bad_payload)
    request = mock_request(
        method="POST",
        path="/control/allocations",
        headers={"Authorization": auth},
        body=b"{}",
    )

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_stale_iat(mock_request, authorize_signer):
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    stale = int(time_module.time()) - 600  # 10 minutes ago, default window is 5
    payload_bytes = make_signed_payload(body=b"{}", iat=stale)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_far_future_iat(mock_request, authorize_signer):
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    future = int(time_module.time()) + 600
    payload_bytes = make_signed_payload(body=b"{}", iat=future)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_method_mismatch(mock_request, authorize_signer):
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    # Request says GET but payload is signed for POST.
    request = mock_request(method="GET", path="/control/allocations", headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_path_mismatch(mock_request, authorize_signer):
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(method="POST", path="/control/migrate", headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_unauthorized_signer(mock_request, monkeypatch):
    """Signer not in the authorized list is rejected."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [])
    rogue = Account.create()
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(rogue, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_tampered_payload(mock_request, authorize_signer):
    """If the payload bytes are altered after signing, recovery yields a
    different address that isn't authorized."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    payload_bytes = make_signed_payload(body=b"{}")
    signed = authorize_signer.sign_message(encode_defunct(payload_bytes))
    # Tamper with payload after signing — flip one byte of iat.
    tampered = json.loads(payload_bytes)
    tampered["iat"] = tampered["iat"] + 1
    tampered_bytes = json.dumps(tampered, sort_keys=True, separators=(",", ":")).encode()

    auth = f"Aleph-EIP191-V1 sig={signed.signature.hex()},payload={tampered_bytes.hex()}"
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_body_mismatch(mock_request, authorize_signer):
    """Signed body_sha256 doesn't match the actual body bytes → reject."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    # Signer signs for body=b"original".
    payload_bytes = make_signed_payload(body=b"original")
    auth = make_auth_header(authorize_signer, payload_bytes)
    # Request actually carries a different body.
    request = mock_request(headers={"Authorization": auth}, body=b"tampered")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_replay(mock_request, authorize_signer):
    """Replaying a captured request (same iat) is rejected by monotonic-iat."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)

    request1 = mock_request(headers={"Authorization": auth}, body=b"{}")
    request2 = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request1, auth) is True
    assert await _verify_aleph_signature(request2, auth) is False  # same iat


@pytest.mark.asyncio
async def test_verify_accepts_strictly_increasing_iat(mock_request, authorize_signer):
    """A subsequent request with a strictly greater iat is accepted."""
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    iat1 = int(time_module.time())
    payload1 = make_signed_payload(body=b"{}", iat=iat1)
    auth1 = make_auth_header(authorize_signer, payload1)

    payload2 = make_signed_payload(body=b"{}", iat=iat1 + 1)
    auth2 = make_auth_header(authorize_signer, payload2)

    assert await _verify_aleph_signature(mock_request(headers={"Authorization": auth1}, body=b"{}"), auth1) is True
    assert await _verify_aleph_signature(mock_request(headers={"Authorization": auth2}, body=b"{}"), auth2) is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "auth",
    [
        "Aleph-EIP191-V1 sig=notHex,payload=0xbeef",  # invalid hex in sig
        "Aleph-EIP191-V1 sig=0xdead,payload=notHex",  # invalid hex in payload
        "Aleph-EIP191-V1 sig=0xdead,payload=0xbeef",  # payload not JSON
    ],
)
async def test_verify_rejects_malformed_header(mock_request, authorize_signer, auth):  # noqa: ARG001 (authorize_signer is a fixture)
    from aleph.vm.orchestrator.views.allocation_auth import _verify_aleph_signature

    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_dispatcher_routes_to_signature_path(mock_request, authorize_signer, mocker):
    from aleph.vm.orchestrator.views import allocation_auth

    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    spy = mocker.spy(allocation_auth, "_verify_aleph_signature")
    assert await allocation_auth.authenticate_api_request(request) is True
    spy.assert_called_once()


@pytest.mark.asyncio
async def test_dispatcher_invalid_signature_does_not_fall_back(mock_request, mocker):
    """Garbage Aleph-EIP191-V1 + valid X-Auth-Signature → reject. The signature
    path is authoritative once chosen."""
    from aleph.vm.orchestrator.views import allocation_auth

    request = mock_request(
        headers={
            "Authorization": "Aleph-EIP191-V1 sig=0xdead,payload=0xbeef",
            "X-Auth-Signature": "test",  # would be valid via the legacy path
        },
        body=b"{}",
    )
    spy_legacy = mocker.spy(allocation_auth, "_verify_legacy_token")
    assert await allocation_auth.authenticate_api_request(request) is False
    spy_legacy.assert_not_called()


@pytest.mark.asyncio
async def test_dispatcher_falls_back_to_legacy_with_warning(mock_request, caplog, monkeypatch):
    """No Aleph-EIP191-V1, valid legacy token → accept + warning logged."""
    from aleph.vm.orchestrator.views import allocation_auth

    monkeypatch.setattr(
        settings,
        "ALLOCATION_TOKEN_HASH",
        sha256(b"test").hexdigest(),
    )
    request = mock_request(headers={"X-Auth-Signature": "test"}, body=b"{}")

    with caplog.at_level("WARNING"):
        assert await allocation_auth.authenticate_api_request(request) is True
    assert any("legacy token path" in r.message for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatcher_no_auth_headers(mock_request):
    from aleph.vm.orchestrator.views import allocation_auth

    request = mock_request(headers={}, body=b"{}")
    assert await allocation_auth.authenticate_api_request(request) is False


@pytest.mark.asyncio
async def test_dispatcher_empty_legacy_token_returns_false(mock_request, monkeypatch):
    """X-Auth-Signature: '' (header present but empty) → False, not a raise.

    Otherwise the response message would differ from other rejections,
    leaking dispatch-path info.
    """
    from aleph.vm.orchestrator.views import allocation_auth

    monkeypatch.setattr(
        settings,
        "ALLOCATION_TOKEN_HASH",
        sha256(b"test").hexdigest(),
    )
    request = mock_request(headers={"X-Auth-Signature": ""}, body=b"{}")
    assert await allocation_auth.authenticate_api_request(request) is False


@pytest.mark.asyncio
async def test_dispatcher_unknown_scheme_does_not_fall_back(mock_request, mocker, monkeypatch):
    """Authorization with an unknown scheme + valid legacy → reject. The
    Authorization header's mere presence is authoritative."""
    from aleph.vm.orchestrator.views import allocation_auth

    monkeypatch.setattr(
        settings,
        "ALLOCATION_TOKEN_HASH",
        sha256(b"test").hexdigest(),
    )
    request = mock_request(
        headers={
            "Authorization": "Bearer abc",
            "X-Auth-Signature": "test",  # would be valid via legacy
        },
        body=b"{}",
    )
    spy_legacy = mocker.spy(allocation_auth, "_verify_legacy_token")
    assert await allocation_auth.authenticate_api_request(request) is False
    spy_legacy.assert_not_called()


@pytest.mark.asyncio
async def test_dispatcher_eip191_scheme_without_params_does_not_fall_back(mock_request, mocker, monkeypatch):
    """Authorization: 'Aleph-EIP191-V1' (no trailing space, no params)
    + valid legacy → reject. Misconfigured client must not be rescued
    by legacy fallback."""
    from aleph.vm.orchestrator.views import allocation_auth

    monkeypatch.setattr(
        settings,
        "ALLOCATION_TOKEN_HASH",
        sha256(b"test").hexdigest(),
    )
    request = mock_request(
        headers={
            "Authorization": "Aleph-EIP191-V1",  # missing the params
            "X-Auth-Signature": "test",
        },
        body=b"{}",
    )
    spy_legacy = mocker.spy(allocation_auth, "_verify_legacy_token")
    assert await allocation_auth.authenticate_api_request(request) is False
    spy_legacy.assert_not_called()
