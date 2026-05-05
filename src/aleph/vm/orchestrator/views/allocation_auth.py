"""Authentication for scheduler-only control endpoints.

Currently the scheduler authenticates with a shared bearer token whose
SHA-256 hash is configured on the supervisor as
:data:`aleph.vm.conf.settings.ALLOCATION_TOKEN_HASH`. This module hosts
the verifier and the decorator so they can be evolved (signature-based
auth, key rotation, etc.) without touching the views package's `__init__`.
"""

from hashlib import sha256

from aiohttp import web

from aleph.vm.conf import settings


def authenticate_api_request(request: web.Request) -> bool:
    """Authenticate an API request to update the VM allocations."""
    signature: bytes = request.headers.get("X-Auth-Signature", "").encode()

    if not signature:
        raise web.HTTPUnauthorized(text="Authentication token is missing")

    # Use a simple authentication method: the hash of the signature should match the value in the settings
    return sha256(signature).hexdigest() == settings.ALLOCATION_TOKEN_HASH


def requires_allocation_auth(handler):
    """Decorator: reject the request with 401 unless the X-Auth-Signature header matches.

    Wraps :func:`authenticate_api_request` so endpoints don't have to repeat the
    three-line check. Apply BELOW any CORS decorator so OPTIONS preflights pass
    through unauthenticated.
    """
    import functools

    @functools.wraps(handler)
    async def wrapper(request: web.Request) -> web.StreamResponse:
        if not authenticate_api_request(request):
            return web.HTTPUnauthorized(text="Authentication token received is invalid")
        return await handler(request)

    return wrapper
