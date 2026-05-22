"""Authentication for scheduler-only control endpoints.

Currently the scheduler authenticates with a shared bearer token whose
SHA-256 hash is configured on the supervisor as
:data:`aleph.vm.conf.settings.ALLOCATION_TOKEN_HASH`. This module hosts
the verifier and the decorator so they can be evolved (signature-based
auth, key rotation, etc.) without touching the views package's `__init__`.
"""

import asyncio
import functools
import json
import logging
import time
from hashlib import sha256

from aiohttp import web
from eth_account import Account
from eth_account.messages import encode_defunct

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)

ALEPH_EIP191_V1_SCHEME = "Aleph-EIP191-V1"

# Defense-in-depth cap on the size of a signed request body. aiohttp's
# Application has a default `client_max_size` of 1 MiB, but the auth verifier
# must not rely on it: an operator who raises that ceiling for unrelated
# reasons would unknowingly expand the DoS surface here. Scheduler control
# requests are short JSON; 1 MiB is plenty.
MAX_SIGNED_REQUEST_BODY_BYTES = 1 * 1024 * 1024


ALLOWED_AUTH_PARAMS = frozenset({"sig", "payload"})


def _parse_auth_params(auth_header: str) -> dict[str, str]:
    """Parse `Aleph-EIP191-V1 key=val,key=val` into a dict.

    Raises ValueError if the scheme is wrong, the params are missing or
    malformed, the required keys (`sig`, `payload`) are absent, or any
    unknown param is present. Rejecting unknowns keeps the auth contract
    tight: the verifier promises to bind everything it accepts, so silently
    ignoring extras would break that promise the moment a new param is added
    without updating the verifier. The scheme name is compared
    case-insensitively per RFC 7235 §2.1.
    """
    scheme, _, params_str = auth_header.partition(" ")
    if scheme.casefold() != ALEPH_EIP191_V1_SCHEME.casefold():
        msg = f"Unsupported auth scheme: {scheme!r}"
        raise ValueError(msg)
    params_str = params_str.strip()
    if not params_str:
        msg = "Auth header has no parameters"
        raise ValueError(msg)

    params: dict[str, str] = {}
    for pair in params_str.split(","):
        key, sep, value = pair.strip().partition("=")
        if not sep or not value:
            msg = f"Malformed auth-param: {pair!r}"
            raise ValueError(msg)
        params[key] = value

    missing = ALLOWED_AUTH_PARAMS - params.keys()
    if missing:
        msg = f"Missing required auth-param(s): {sorted(missing)}"
        raise ValueError(msg)
    unknown = params.keys() - ALLOWED_AUTH_PARAMS
    if unknown:
        msg = f"Unknown auth-param(s): {sorted(unknown)}"
        raise ValueError(msg)

    return params


_last_accepted_iat: dict[str, int] = {}
"""Per-signer floor on accepted `iat` values. Module-level state, in-memory
only; doesn't survive supervisor restarts (the absolute time window covers
the post-restart gap). Single-process only: a multi-worker supervisor would
let a captured request be replayed against a sibling worker."""

_iat_lock: asyncio.Lock | None = None
"""Serializes the read-check-write on `_last_accepted_iat`. Without this,
two concurrent verifications for the same signer can both observe the old
floor and both write, letting a same-iat replay slip through. Lazily
initialized so module import doesn't require a running event loop."""

PAYLOAD_REQUIRED_FIELDS = ("method", "path", "body_sha256", "iat")


async def _accept_iat_if_fresh(signer_key: str, iat: int) -> bool:
    """Atomically check `iat > last accepted for this signer` and update.

    Returns True iff the iat strictly exceeds the floor and the floor was
    advanced. The lock prevents two concurrent verifications for the same
    signer from both observing the old floor and both succeeding.
    """
    global _iat_lock  # noqa: PLW0603 — lazy singleton; deferred to first call so import doesn't need a running loop
    if _iat_lock is None:
        _iat_lock = asyncio.Lock()
    async with _iat_lock:
        previous = _last_accepted_iat.get(signer_key, float("-inf"))
        if iat <= previous:
            return False
        _last_accepted_iat[signer_key] = iat
        return True


async def _verify_aleph_signature(request: web.Request, auth_header: str) -> bool:
    """Verify a request bearing an `Authorization: Aleph-EIP191-V1 ...` header.

    Returns True iff the signature is valid, recovers an authorized signer,
    binds the request, and beats the per-signer monotonic-iat floor. All
    failure modes return False (the dispatcher decides the response shape).

    Side effect: calls `await request.read()`, which buffers the body into
    aiohttp's request cache. Downstream handlers using `request.json()` or
    `request.read()` get the same bytes; handlers streaming via
    `request.content.iter_chunked()` would get an empty stream.
    """
    try:
        params = _parse_auth_params(auth_header)
        payload_bytes = bytes.fromhex(params["payload"].removeprefix("0x"))
        payload = json.loads(payload_bytes)
        for field in PAYLOAD_REQUIRED_FIELDS:
            if field not in payload:
                msg = f"Missing payload field: {field!r}"
                raise ValueError(msg)

        iat = payload["iat"]
        if not isinstance(iat, int) or isinstance(iat, bool):
            # bool is a subclass of int in Python — exclude explicitly.
            msg = f"iat must be a JSON integer, got {type(iat).__name__}"
            raise ValueError(msg)

        # Cheap rejections first.
        now = time.time()
        max_age = settings.ALLOCATION_SIGNATURE_MAX_AGE_SECONDS
        stale = abs(iat - now) > max_age
        # Path matching is exact: aiohttp routes `/foo` and `/foo/` distinctly,
        # so signers must use the exact path the route will receive.
        method_path_mismatch = payload["method"] != request.method or payload["path"] != request.path
        # The signed payload binds method + path only — not the query string.
        # Rather than extend the wire format, forbid query strings on signed
        # endpoints: callers control them, attackers do too, and silent
        # under-binding is the worst of both worlds.
        has_query = bool(request.query_string)
        if stale or method_path_mismatch or has_query:
            return False

        # Crypto: recover signer and check authorization.
        sig_hex = params["sig"].removeprefix("0x")
        recovered = Account.recover_message(
            encode_defunct(payload_bytes),
            signature=bytes.fromhex(sig_hex),
        )
        authorized = {a.lower() for a in settings.AUTHORIZED_ALLOCATION_SIGNERS}
        if recovered.lower() not in authorized:
            return False

        # Bound body memory BEFORE reading — refuses to buffer an oversized
        # body just to discover the hash doesn't match. Missing Content-Length
        # (chunked encoding) is rejected: scheduler clients always send
        # length-delimited JSON.
        content_length = request.content_length
        if content_length is None or content_length > MAX_SIGNED_REQUEST_BODY_BYTES:
            return False

        # Body hash binding.
        body = await request.read()
        if sha256(body).hexdigest() != payload["body_sha256"]:
            return False

        # Monotonic-iat replay protection. The check-and-update MUST be
        # atomic; without it, two concurrent requests with the same signer
        # can both succeed. Done last so we don't bump the floor for a
        # request that would otherwise fail downstream.
        return await _accept_iat_if_fresh(recovered.lower(), iat)
    except Exception as exc:  # broad catch intentional — auth verifier MUST NOT raise
        # Signature recovery, hex decoding, JSON parsing, and field type
        # coercion all raise different exception types. For an auth verifier,
        # "any unexpected input → reject" is the correct posture; raising
        # would 500 the request instead of 401-ing it. Logged at WARNING so
        # operators don't need to enable debug logging globally to triage a
        # misconfigured scheduler.
        logger.warning("Aleph-EIP191-V1 verification failed: %s", exc)
        return False


def _verify_legacy_token(request: web.Request) -> bool:
    """Authenticate via SHA-256(X-Auth-Signature) == ALLOCATION_TOKEN_HASH.

    DEPRECATED: scheduled for removal once all schedulers have migrated to
    Aleph-EIP191-V1. See AUTHORIZED_ALLOCATION_SIGNERS.
    """
    signature: bytes = request.headers.get("X-Auth-Signature", "").encode()
    if not signature:
        return False
    return sha256(signature).hexdigest() == settings.ALLOCATION_TOKEN_HASH


async def authenticate_api_request(request: web.Request) -> bool:
    """Dispatch between Aleph-EIP191-V1 (new) and legacy X-Auth-Signature.

    The presence of an `Authorization` header (any value) is authoritative —
    a malformed/invalid signature is rejected, with no fallback to the
    legacy `X-Auth-Signature` path. The scheme name is matched
    case-insensitively (RFC 7235 §2.1). Deprecation of the legacy path is
    surfaced once at supervisor boot via `log_allocation_auth_config`, not
    per-request, to keep production logs readable.
    """
    auth = request.headers.get("Authorization", "")
    if auth:
        scheme, sep, _ = auth.partition(" ")
        if not sep or scheme.casefold() != ALEPH_EIP191_V1_SCHEME.casefold():
            return False
        return await _verify_aleph_signature(request, auth)
    if "X-Auth-Signature" in request.headers:
        return _verify_legacy_token(request)
    return False


def log_allocation_auth_config() -> None:
    """Emit a one-shot warning at supervisor boot if the legacy token path is
    the only auth method configured. Operators see the deprecation notice
    exactly once per process lifetime — not flooded per-request."""
    has_signers = bool(settings.AUTHORIZED_ALLOCATION_SIGNERS)
    has_legacy = bool(settings.ALLOCATION_TOKEN_HASH)
    if has_signers:
        logger.info(
            "Allocation auth: Aleph-EIP191-V1 enabled with %d authorized signer(s)",
            len(settings.AUTHORIZED_ALLOCATION_SIGNERS),
        )
        if has_legacy:
            logger.warning(
                "Allocation auth: legacy X-Auth-Signature path is still enabled "
                "(ALLOCATION_TOKEN_HASH is set). Remove it once all schedulers "
                "have migrated to Aleph-EIP191-V1.",
            )
    elif has_legacy:
        logger.warning(
            "Allocation auth: only the legacy X-Auth-Signature path is configured. "
            "Set AUTHORIZED_ALLOCATION_SIGNERS to enable Aleph-EIP191-V1 (recommended).",
        )
    else:
        logger.warning(
            "Allocation auth: no auth method configured — all scheduler " "endpoints will reject requests with 401.",
        )


def requires_allocation_auth(handler):
    """Decorator: reject the request with 401 unless the auth check passes.

    Accepts either `Authorization: Aleph-EIP191-V1 ...` or the legacy
    `X-Auth-Signature` token. Apply BELOW any CORS decorator so OPTIONS
    preflights pass through unauthenticated.
    """

    @functools.wraps(handler)
    async def wrapper(request: web.Request) -> web.StreamResponse:
        if not await authenticate_api_request(request):
            return web.HTTPUnauthorized(text="Authentication token received is invalid")
        return await handler(request)

    return wrapper
