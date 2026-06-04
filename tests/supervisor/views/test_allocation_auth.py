"""Unit tests for src/aleph/vm/orchestrator/views/allocation_auth.py."""

import asyncio
import json
import time as time_module
import types
from hashlib import sha256

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct
from pydantic import ValidationError

from aleph.vm.conf import Settings, settings
from aleph.vm.orchestrator.views import allocation_auth
from aleph.vm.orchestrator.views.allocation_auth import (
    MAX_SIGNED_REQUEST_BODY_BYTES,
    _accepted_payloads,
    _parse_auth_params,
    _verify_aleph_signature,
    log_allocation_auth_config,
)


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
def reset_replay_cache():
    """Clear the accepted-payloads dict between tests for isolation."""
    _accepted_payloads.clear()
    yield
    _accepted_payloads.clear()


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


def _freeze_time(monkeypatch, fixed_now: float) -> None:
    """Pin `allocation_auth.time.time()` to `fixed_now` for this test.

    Swaps just the local `time` reference inside allocation_auth's namespace
    — the real `time` module stays untouched, so pytest's own timing and
    other modules' `time.time()` calls are unaffected.
    """
    monkeypatch.setattr(allocation_auth, "time", types.SimpleNamespace(time=lambda: fixed_now))


@pytest.fixture
def mock_request(mocker):
    """Build a minimal fake aiohttp request supporting `await request.read()`."""

    def factory(*, method="POST", path="/control/allocations", headers=None, body=b"", content_length=None):
        request = mocker.Mock()
        request.method = method
        request.path = path
        request.headers = headers or {}
        request.read = mocker.AsyncMock(return_value=body)
        # Match aiohttp's behavior: Content-Length defaults to body length
        # unless the caller wants to exercise the cap or chunked-encoding paths.
        request.content_length = content_length if content_length is not None else len(body)
        # No query string by default; tests covering H2 override this.
        request.query_string = ""
        request.remote = "127.0.0.1"
        return request

    return factory


def test_parse_auth_params_valid():
    params = _parse_auth_params("Aleph-EIP191-V1 sig=0xdead,payload=0xbeef")
    assert params == {"sig": "0xdead", "payload": "0xbeef"}


def test_parse_auth_params_extra_whitespace_tolerated():
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
    with pytest.raises(ValueError):
        _parse_auth_params(header)


@pytest.mark.asyncio
async def test_verify_aleph_signature_valid_request(mock_request, authorize_signer):
    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(
        method="POST",
        path="/control/allocations",
        headers={"Authorization": auth},
        body=b"{}",
    )

    assert await _verify_aleph_signature(request, auth) is True
    assert authorize_signer.address.lower() in {k.lower() for k in _accepted_payloads}


@pytest.mark.asyncio
async def test_verify_rejects_non_integer_iat(mock_request, authorize_signer):
    """A signed payload with a non-integer iat (e.g., float or string) is rejected."""
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
    stale = int(time_module.time()) - 600  # 10 minutes ago, default window is 5
    payload_bytes = make_signed_payload(body=b"{}", iat=stale)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_far_future_iat(mock_request, authorize_signer):
    future = int(time_module.time()) + 600
    payload_bytes = make_signed_payload(body=b"{}", iat=future)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_method_mismatch(mock_request, authorize_signer):
    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    # Request says GET but payload is signed for POST.
    request = mock_request(method="GET", path="/control/allocations", headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_path_mismatch(mock_request, authorize_signer):
    payload_bytes = make_signed_payload(method="POST", path="/control/allocations", body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(method="POST", path="/control/migrate", headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_unauthorized_signer(mock_request, monkeypatch):
    """Signer not in the authorized list is rejected."""
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
    # Signer signs for body=b"original".
    payload_bytes = make_signed_payload(body=b"original")
    auth = make_auth_header(authorize_signer, payload_bytes)
    # Request actually carries a different body.
    request = mock_request(headers={"Authorization": auth}, body=b"tampered")

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_rejects_replay(mock_request, authorize_signer):
    """Replaying a captured request (byte-identical payload) is rejected."""
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)

    request1 = mock_request(headers={"Authorization": auth}, body=b"{}")
    request2 = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request1, auth) is True
    assert await _verify_aleph_signature(request2, auth) is False  # same iat


@pytest.mark.asyncio
async def test_verify_accepts_strictly_increasing_iat(mock_request, authorize_signer):
    """A subsequent request with a strictly greater iat is accepted."""
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
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_dispatcher_routes_to_signature_path(mock_request, authorize_signer, mocker):
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
async def test_dispatcher_falls_back_to_legacy_silently(mock_request, caplog, monkeypatch):
    """No Aleph-EIP191-V1, valid legacy token → accept WITHOUT per-request log.

    The deprecation notice is emitted once at boot via
    `log_allocation_auth_config`; logging on every request would flood logs.
    """
    monkeypatch.setattr(
        settings,
        "ALLOCATION_TOKEN_HASH",
        sha256(b"test").hexdigest(),
    )
    request = mock_request(headers={"X-Auth-Signature": "test"}, body=b"{}")

    with caplog.at_level("WARNING"):
        assert await allocation_auth.authenticate_api_request(request) is True
    assert not any("legacy" in r.message.lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_dispatcher_no_auth_headers(mock_request):
    request = mock_request(headers={}, body=b"{}")
    assert await allocation_auth.authenticate_api_request(request) is False


@pytest.mark.asyncio
async def test_dispatcher_empty_legacy_token_returns_false(mock_request, monkeypatch):
    """X-Auth-Signature: '' (header present but empty) → False, not a raise.

    Otherwise the response message would differ from other rejections,
    leaking dispatch-path info.
    """
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


# --- C1: concurrent iat check+update must not race ---


@pytest.mark.asyncio
async def test_verify_concurrent_same_iat_rejects_one(authorize_signer, mocker):
    """Two concurrent verifications with the same captured signed payload:
    exactly one must succeed. Without the asyncio.Lock around the seen-set
    check+record, both observe the payload as unseen and both succeed — a
    concurrent duplicate slips through.

    Forces an interleave by making `request.read()` yield control.
    """
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)

    async def slow_read():
        # Yield, then return body — guarantees both tasks reach the await
        # point before either completes, so the post-await iat critical
        # section is what serializes them.
        await asyncio.sleep(0)
        return b"{}"

    def make_req():
        request = mocker.Mock()
        request.method = "POST"
        request.path = "/control/allocations"
        request.headers = {"Authorization": auth}
        request.content_length = len(b"{}")
        request.query_string = ""
        request.read = slow_read
        request.remote = "127.0.0.1"
        return request

    results = await asyncio.gather(
        _verify_aleph_signature(make_req(), auth),
        _verify_aleph_signature(make_req(), auth),
    )
    assert sum(results) == 1, f"Exactly one of two same-iat verifications must succeed, got {results}"


# --- C2: body size cap ---


@pytest.mark.asyncio
async def test_verify_rejects_oversized_body(mock_request, authorize_signer):
    """Content-Length over the cap → reject without reading the body."""
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(
        headers={"Authorization": auth},
        body=b"{}",
        content_length=MAX_SIGNED_REQUEST_BODY_BYTES + 1,
    )

    assert await _verify_aleph_signature(request, auth) is False
    # Body must not be read once the cap rejects.
    request.read.assert_not_called()


@pytest.mark.asyncio
async def test_verify_rejects_missing_content_length(mock_request, authorize_signer):
    """Content-Length is None (chunked encoding) → reject. Scheduler clients
    always send length-delimited JSON; chunked uploads here are suspicious."""
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(
        headers={"Authorization": auth},
        body=b"{}",
    )
    request.content_length = None  # explicit None overrides the auto-set length

    assert await _verify_aleph_signature(request, auth) is False
    request.read.assert_not_called()


# --- H1: scheme name is case-insensitive (RFC 7235 §2.1) ---


def test_parse_auth_params_lowercase_scheme_accepted():
    """Lowercase scheme `aleph-eip191-v1` must parse — auth-scheme tokens
    are case-insensitive per RFC 7235."""
    params = _parse_auth_params("aleph-eip191-v1 sig=0xdead,payload=0xbeef")
    assert params == {"sig": "0xdead", "payload": "0xbeef"}


def test_parse_auth_params_uppercase_scheme_accepted():
    params = _parse_auth_params("ALEPH-EIP191-V1 sig=0xdead,payload=0xbeef")
    assert params == {"sig": "0xdead", "payload": "0xbeef"}


@pytest.mark.asyncio
async def test_dispatcher_accepts_lowercase_scheme(mock_request, authorize_signer):
    """End-to-end: a client lowercasing the scheme is accepted."""
    payload_bytes = make_signed_payload(body=b"{}")
    signed = authorize_signer.sign_message(encode_defunct(payload_bytes))
    auth = f"aleph-eip191-v1 sig={signed.signature.hex()},payload={payload_bytes.hex()}"
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await allocation_auth.authenticate_api_request(request) is True


# --- H2: query strings are forbidden on signed endpoints ---


@pytest.mark.asyncio
async def test_verify_rejects_request_with_query_string(mock_request, authorize_signer):
    """A request whose URL carries a query string is rejected.

    Rationale: the signed payload binds method + path but not the query
    string. Rather than extend the wire format, signed endpoints forbid
    query strings entirely. A scheduler that accidentally appends one
    must be told via 401 rather than silently authenticate with an
    unbinding query in play.
    """
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    # Simulate aiohttp's `query_string` attribute.
    request.query_string = "foo=bar"

    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_accepts_request_with_empty_query_string(mock_request, authorize_signer):
    """An empty query string (the common case) does not block verification."""
    payload_bytes = make_signed_payload(body=b"{}")
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    request.query_string = ""

    assert await _verify_aleph_signature(request, auth) is True


# --- H3: unknown auth-params rejected ---


def test_parse_auth_params_rejects_unknown_param():
    """`Aleph-EIP191-V1 sig=…,payload=…,extra=poison` is rejected.

    The verifier promises to bind everything it accepts. Silently ignoring
    extras would break that promise the day a new param is added without
    updating the verifier."""
    with pytest.raises(ValueError, match="Unknown auth-param"):
        _parse_auth_params("Aleph-EIP191-V1 sig=0xdead,payload=0xbeef,extra=0xc0ffee")


@pytest.mark.asyncio
async def test_verify_rejects_unknown_auth_param(mock_request, authorize_signer):
    """End-to-end: an extra auth-param yields a 401 even with a valid sig+payload."""
    payload_bytes = make_signed_payload(body=b"{}")
    signed = authorize_signer.sign_message(encode_defunct(payload_bytes))
    auth = f"Aleph-EIP191-V1 sig={signed.signature.hex()}," f"payload={payload_bytes.hex()},extra=poison"
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    assert await _verify_aleph_signature(request, auth) is False


# --- M1: verification failures log at WARNING ---


@pytest.mark.asyncio
async def test_verify_failure_logs_at_warning(mock_request, caplog):
    """A failed verification emits a WARNING (not DEBUG) so operators
    triaging a misconfigured scheduler don't need debug logging globally."""
    auth = "Aleph-EIP191-V1 sig=notHex,payload=0xbeef"
    request = mock_request(headers={"Authorization": auth}, body=b"{}")

    with caplog.at_level("WARNING", logger="aleph.vm.orchestrator.views.allocation_auth"):
        assert await _verify_aleph_signature(request, auth) is False
    assert any("Aleph-EIP191-V1 verification failed" in r.message for r in caplog.records)


# --- M2: boot-time auth-config summary ---


def test_log_allocation_auth_config_signature_path_only(caplog, monkeypatch):
    """Signers configured, legacy hash cleared → INFO summary, no warning."""
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", ["0xdAC17F958D2ee523a2206206994597C13D831ec7"])
    monkeypatch.setattr(settings, "ALLOCATION_TOKEN_HASH", "")

    with caplog.at_level("INFO", logger="aleph.vm.orchestrator.views.allocation_auth"):
        log_allocation_auth_config()
    assert any("Aleph-EIP191-V1 enabled" in r.message for r in caplog.records)
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert not any("legacy" in r.message.lower() for r in warnings)


def test_log_allocation_auth_config_both_enabled_warns(caplog, monkeypatch):
    """Signers + legacy hash → both messages, including a warning to remove legacy."""
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", ["0xdAC17F958D2ee523a2206206994597C13D831ec7"])
    monkeypatch.setattr(settings, "ALLOCATION_TOKEN_HASH", sha256(b"test").hexdigest())

    with caplog.at_level("INFO", logger="aleph.vm.orchestrator.views.allocation_auth"):
        log_allocation_auth_config()
    warnings = [r.message for r in caplog.records if r.levelname == "WARNING"]
    assert any("legacy X-Auth-Signature path is still enabled" in m for m in warnings)


def test_log_allocation_auth_config_legacy_only_warns(caplog, monkeypatch):
    """No signers, legacy hash only → warning prompts operator to migrate."""
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [])
    monkeypatch.setattr(settings, "ALLOCATION_TOKEN_HASH", sha256(b"test").hexdigest())

    with caplog.at_level("WARNING", logger="aleph.vm.orchestrator.views.allocation_auth"):
        log_allocation_auth_config()
    assert any("only the legacy X-Auth-Signature path is configured" in r.message for r in caplog.records)


def test_log_allocation_auth_config_nothing_configured_warns(caplog, monkeypatch):
    """No signers and no legacy hash → warning that all scheduler calls will 401."""
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [])
    monkeypatch.setattr(settings, "ALLOCATION_TOKEN_HASH", "")

    with caplog.at_level("WARNING", logger="aleph.vm.orchestrator.views.allocation_auth"):
        log_allocation_auth_config()
    assert any("no auth method configured" in r.message for r in caplog.records)


# --- M3: iat window boundary behavior ---


@pytest.mark.asyncio
async def test_verify_iat_equal_to_now_accepted(monkeypatch, mock_request, authorize_signer):
    """iat == now (delta 0) → accepted. Sanity baseline."""
    fixed_now = 1_700_000_000.0
    _freeze_time(monkeypatch, fixed_now)
    payload_bytes = make_signed_payload(body=b"{}", iat=int(fixed_now))
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is True


@pytest.mark.asyncio
async def test_verify_iat_at_lower_boundary_accepted(monkeypatch, mock_request, authorize_signer):
    """iat == now - max_age (exactly at the edge) → accepted.

    Pins down that the comparison is `abs(...) > max_age` (strict), not
    `>=`. A future maintainer flipping this would silently shrink the
    window by 1 second and break clients that sign with their own clock.
    """
    fixed_now = 1_700_000_000.0
    _freeze_time(monkeypatch, fixed_now)
    iat = int(fixed_now) - settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS
    payload_bytes = make_signed_payload(body=b"{}", iat=iat)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is True


@pytest.mark.asyncio
async def test_verify_iat_just_past_lower_boundary_rejected(monkeypatch, mock_request, authorize_signer):
    """iat == now - max_age - 1 → rejected (one second over the edge)."""
    fixed_now = 1_700_000_000.0
    _freeze_time(monkeypatch, fixed_now)
    iat = int(fixed_now) - settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS - 1
    payload_bytes = make_signed_payload(body=b"{}", iat=iat)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is False


@pytest.mark.asyncio
async def test_verify_iat_at_upper_boundary_accepted(monkeypatch, mock_request, authorize_signer):
    """iat == now + max_age (clock-skew on the far side) → accepted."""
    fixed_now = 1_700_000_000.0
    _freeze_time(monkeypatch, fixed_now)
    iat = int(fixed_now) + settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS
    payload_bytes = make_signed_payload(body=b"{}", iat=iat)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is True


@pytest.mark.asyncio
async def test_verify_iat_just_past_upper_boundary_rejected(monkeypatch, mock_request, authorize_signer):
    """iat == now + max_age + 1 → rejected."""
    fixed_now = 1_700_000_000.0
    _freeze_time(monkeypatch, fixed_now)
    iat = int(fixed_now) + settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS + 1
    payload_bytes = make_signed_payload(body=b"{}", iat=iat)
    auth = make_auth_header(authorize_signer, payload_bytes)
    request = mock_request(headers={"Authorization": auth}, body=b"{}")
    assert await _verify_aleph_signature(request, auth) is False


# --- M5: same-second distinct requests must not collide ---


@pytest.mark.asyncio
async def test_verify_accepts_same_iat_across_endpoints(mock_request, authorize_signer):
    """Two distinct requests signed in the same wall-clock second both pass.

    Regression: the replay check used a per-signer monotonic-iat floor, so a
    POST followed <1s later by a status GET (different method+path but the
    same integer-second iat) was rejected — a de-facto global rate limit of
    one request per signer per second across all endpoints. Replay
    protection must only reject byte-identical resubmissions; the payload
    already binds method, path and body.
    """
    iat = int(time_module.time())

    payload_post = make_signed_payload(method="POST", path="/control/machine/x/migration/export", body=b"{}", iat=iat)
    auth_post = make_auth_header(authorize_signer, payload_post)
    request_post = mock_request(
        method="POST",
        path="/control/machine/x/migration/export",
        headers={"Authorization": auth_post},
        body=b"{}",
    )
    assert await _verify_aleph_signature(request_post, auth_post) is True

    payload_get = make_signed_payload(method="GET", path="/control/machine/x/migration/export/status", iat=iat)
    auth_get = make_auth_header(authorize_signer, payload_get)
    request_get = mock_request(
        method="GET",
        path="/control/machine/x/migration/export/status",
        headers={"Authorization": auth_get},
    )
    assert await _verify_aleph_signature(request_get, auth_get) is True


@pytest.mark.asyncio
async def test_verify_accepts_same_iat_distinct_bodies_same_endpoint(mock_request, authorize_signer):
    """Two distinct POSTs to the same path within the same second both pass.

    E.g. the scheduler allocating two VMs back-to-back: same method+path,
    same integer-second iat, different bodies. Not replays of each other —
    `body_sha256` differs — so both must be accepted.
    """
    iat = int(time_module.time())
    for body in (b'{"persistent_vms": ["a"]}', b'{"persistent_vms": ["b"]}'):
        payload_bytes = make_signed_payload(body=body, iat=iat)
        auth = make_auth_header(authorize_signer, payload_bytes)
        request = mock_request(headers={"Authorization": auth}, body=body)
        assert await _verify_aleph_signature(request, auth) is True


# --- M6: seen-set memory is bounded by the acceptance window ---


@pytest.mark.asyncio
async def test_accepted_payloads_pruned_after_window(monkeypatch, mock_request, authorize_signer):
    """Entries older than the acceptance window are evicted on the next accept.

    Once a payload's iat is stale enough that the absolute window would
    reject a resubmission outright, keeping its hash adds nothing — pruning
    bounds the seen-set to the signer's request rate over the window.
    """
    t0 = 1_700_000_000.0
    _freeze_time(monkeypatch, t0)
    payload_old = make_signed_payload(body=b"{}", iat=int(t0))
    auth_old = make_auth_header(authorize_signer, payload_old)
    request_old = mock_request(headers={"Authorization": auth_old}, body=b"{}")
    assert await _verify_aleph_signature(request_old, auth_old) is True

    signer_key = authorize_signer.address.lower()
    assert sha256(payload_old).hexdigest() in _accepted_payloads[signer_key]

    # Advance past the window; the next accepted request triggers pruning.
    t1 = t0 + settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS + 1
    _freeze_time(monkeypatch, t1)
    payload_new = make_signed_payload(body=b"{}", iat=int(t1))
    auth_new = make_auth_header(authorize_signer, payload_new)
    request_new = mock_request(headers={"Authorization": auth_new}, body=b"{}")
    assert await _verify_aleph_signature(request_new, auth_new) is True

    assert _accepted_payloads[signer_key] == {sha256(payload_new).hexdigest(): int(t1)}


# --- M4: per-signer dedup (no cross-signer interference) ---


@pytest.mark.asyncio
async def test_verify_per_signer_dedup_is_independent(mock_request, monkeypatch):
    """Two authorized signers maintain independent seen-sets.

    Two signers can legitimately produce byte-identical payloads (same
    method, path, body and second). A future "optimization" using a single
    global payload-hash set would reject the second signer's request as a
    "replay" of the first's; this test pins down the per-signer keying.
    """
    signer_a = Account.create()
    signer_b = Account.create()
    monkeypatch.setattr(settings, "AUTHORIZED_ALLOCATION_SIGNERS", [signer_a.address, signer_b.address])

    # Identical payload bytes, signed independently by A and B.
    payload_bytes = make_signed_payload(body=b"{}", iat=int(time_module.time()))

    auth_a = make_auth_header(signer_a, payload_bytes)
    request_a = mock_request(headers={"Authorization": auth_a}, body=b"{}")
    assert await _verify_aleph_signature(request_a, auth_a) is True

    # Signer B's own signature over the same bytes → accepted; A's entry
    # doesn't apply to B.
    auth_b = make_auth_header(signer_b, payload_bytes)
    request_b = mock_request(headers={"Authorization": auth_b}, body=b"{}")
    assert await _verify_aleph_signature(request_b, auth_b) is True

    # Replaying A's exact request is still rejected — for A.
    request_a2 = mock_request(headers={"Authorization": auth_a}, body=b"{}")
    assert await _verify_aleph_signature(request_a2, auth_a) is False
