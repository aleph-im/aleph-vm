import asyncio
import functools
import json
import logging
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Union

import aiohttp.web_exceptions
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from eth_account import Account
from eth_account.messages import encode_defunct
from jwskate import Jwk
from pydantic import root_validator, validator
from pydantic.main import BaseModel

from aleph.vm.models import VmExecution
from aleph.vm.pool import VmPool

logger = logging.getLogger(__name__)


def is_token_still_valid(timestamp):
    """
    Checks if a token has exprired based on its timestamp
    """
    timestamp = int(timestamp)
    current_datetime = datetime.now(tz=timezone.utc)
    target_datetime = datetime.fromtimestamp(timestamp, tz=timezone.utc)

    return target_datetime > current_datetime


def verify_wallet_signature(signature, message, address):
    """
    Verifies a signature issued by a wallet
    """
    enc_msg = encode_defunct(hexstr=message)
    # Todo: Catch exception
    #     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/root/aleph-vm-remote/src/aleph/vm/orchestrator/views/operator.py", line 40, in verify_wallet_signature
    # computed_address = Account.recover_message(enc_msg, signature=signature)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_utils/decorators.py", line 20, in _wrapper
    # return self.method(objtype, *args, **kwargs)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_account/account.py", line 463, in recover_message
    # return cast(ChecksumAddress, self._recover_hash(message_hash, vrs, signature))
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_utils/decorators.py", line 20, in _wrapper
    # return self.method(objtype, *args, **kwargs)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_account/account.py", line 481, in _recover_hash
    # signature_bytes_standard = to_standard_signature_bytes(signature_bytes)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_account/_utils/signing.py", line 105, in to_standard_signature_bytes
    # standard_v = to_standard_v(v)
    # ^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_account/_utils/signing.py", line 110, in to_standard_v
    # (_chain, chain_naive_v) = extract_chain_id(enhanced_v)
    # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    # File "/opt/aleph-vm/eth_account/_utils/signing.py", line 96, in extract_chain_id
    # raise ValueError("v %r is invalid, must be one of: 0, 1, 27, 28, 35+")
    # ValueError: v %r is invalid, must be one of: 0, 1, 27, 28, 35+
    computed_address = Account.recover_message(enc_msg, signature=signature)
    return computed_address.lower() == address.lower()


class SignedPubKeyPayload(BaseModel):
    """This payload is signed by the wallet of the user to authorize an ephemeral key to act on his behalf."""

    pubkey: dict[str, Any]
    # {'pubkey': {'alg': 'ES256', 'crv': 'P-256', 'ext': True, 'key_ops': ['verify'], 'kty': 'EC',
    #  'x': '4blJBYpltvQLFgRvLE-2H7dsMr5O0ImHkgOnjUbG2AU', 'y': '5VHnq_hUSogZBbVgsXMs0CjrVfMy4Pa3Uv2BEBqfrN4'}
    # alg: Literal["ECDSA"]
    domain: str
    address: str
    expires: float  # timestamp  # TODO: move to ISO 8601

    @property
    def json_web_key(self) -> Jwk:
        """Return the ephemeral public key as Json Web Key"""
        return Jwk(self.pubkey)


class SignedPubKeyHeader(BaseModel):
    signature: bytes
    payload: bytes

    @validator("signature")
    def signature_must_be_hex(cls, v: bytes) -> bytes:
        """Convert the signature from hexadecimal to bytes"""
        v = v.strip(b"0x")
        return bytes.fromhex(v.decode())

    @validator("payload")
    def payload_must_be_hex(cls, v: bytes) -> bytes:
        """Convert the payload from hexadecimal to bytes"""
        return bytes.fromhex(v.decode())

    @root_validator(pre=False, skip_on_failure=True)
    def check_expiry(cls, values):
        """Check that the token has not expired"""
        payload: bytes = values["payload"]
        content = SignedPubKeyPayload.parse_raw(payload)
        if not is_token_still_valid(content.expires):
            msg = "Token expired"
            raise ValueError(msg)
        return values

    @root_validator(pre=False, skip_on_failure=True)
    def check_signature(cls, values):
        """Check that the signature is valid"""
        signature: bytes = values["signature"]
        payload: bytes = values["payload"]
        content = SignedPubKeyPayload.parse_raw(payload)
        if not verify_wallet_signature(signature, payload.hex(), content.address):
            msg = "Invalid signature"
            raise ValueError(msg)
        return values

    @property
    def content(self) -> SignedPubKeyPayload:
        """Return the content of the header"""
        return SignedPubKeyPayload.parse_raw(self.payload)


class SignedOperation(BaseModel):
    """This payload is signed by the ephemeral key authorized above."""

    signature: bytes
    payload: bytes

    @validator("signature")
    def signature_must_be_hex(cls, v) -> bytes:
        """Convert the signature from hexadecimal to bytes"""
        v = v.strip(b"0x")
        return bytes.fromhex(v.decode())

    @validator("payload")
    def payload_must_be_hex(cls, v) -> bytes:
        """Convert the payload from hexadecimal to bytes"""
        return bytes.fromhex(v.decode())


class SignedOperationPayload(BaseModel):
    time: datetime
    method: Union[Literal["POST"], Literal["GET"]]
    path: str
    # body_sha256: str  # disabled since there is no body


def get_signed_pubkey(request: web.Request) -> SignedPubKeyHeader:
    """Get the ephemeral public key that is signed by the wallet from the request headers."""
    signed_pubkey_header = request.headers.get("X-SignedPubKey")
    if not signed_pubkey_header:
        raise web.HTTPBadRequest(reason="Missing X-SignedPubKey header")

    try:
        return SignedPubKeyHeader.parse_raw(signed_pubkey_header)
    except KeyError as error:
        logger.debug(f"Missing X-SignedPubKey header: {error}")
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey fields") from error
    except json.JSONDecodeError as error:
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey format") from error
    except ValueError as error:
        if error.args == ("Token expired",):
            raise web.HTTPUnauthorized(reason="Token expired") from error
        elif error.args == ("Invalid signature",):
            raise web.HTTPUnauthorized(reason="Invalid signature") from error
        else:
            raise error


def get_signed_operation(request: web.Request) -> SignedOperation:
    """Get the signed operation public key that is signed by the ephemeral key from the request headers."""
    try:
        signed_operation = request.headers["X-SignedOperation"]
        return SignedOperation.parse_raw(signed_operation)
    except KeyError as error:
        raise web.HTTPBadRequest(reason="Missing X-SignedOperation header") from error
    except json.JSONDecodeError as error:
        raise web.HTTPBadRequest(reason="Invalid X-SignedOperation format") from error


async def authenticate_jwk(request: web.Request) -> str:
    signed_pubkey = get_signed_pubkey(request)
    signed_operation = get_signed_operation(request)

    if signed_pubkey.content.json_web_key.verify(
        data=signed_operation.payload,
        signature=signed_operation.signature,
        alg="ES256",
    ):
        logger.debug("Signature verified")
        return signed_pubkey.content.address
    else:
        raise web.HTTPUnauthorized(reason="Signature could not verified")


def require_jwk_authentication(handler: Callable[[web.Request], Awaitable[web.StreamResponse]]):
    @functools.wraps(handler)
    async def wrapper(request):
        try:
            authenticated_sender: str = await authenticate_jwk(request)
        except web.HTTPException as e:
            return web.json_response(data={"error": e.reason}, status=e.status)

        # TODO: Check if the request.host must be in an authorized list ?

        response = await handler(request, authenticated_sender)
        # Allow browser clients to access the body of the response
        response.headers.update({"Access-Control-Allow-Origin": request.headers.get("Origin", "")})
        return response

    return wrapper


def get_itemhash_or_400(match_info: UrlMappingMatchInfo) -> ItemHash:
    try:
        ref = match_info["ref"]
    except KeyError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'") from error
    try:
        return ItemHash(ref)
    except UnknownHashError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'") from error


def get_execution_or_404(ref: ItemHash, pool: VmPool) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error."""
    execution = pool.executions.get(ref)
    if execution:
        return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")


@require_jwk_authentication
async def stream_logs(request: web.Request, authenticated_sender: str):
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.vm is None:
        raise web.HTTPBadRequest(body=f"VM {vm_hash} is not running")

    if execution.message.address != authenticated_sender:
        logger.debug(f"Unauthorized sender {authenticated_sender} for {vm_hash}")
        return web.Response(status=401, body="Unauthorized sender")

    queue: asyncio.Queue = asyncio.Queue()
    try:
        ws = web.WebSocketResponse()
        try:
            await ws.prepare(request)

            execution.vm.fvm.log_queues.append(queue)

            while True:
                log_type, message = await queue.get()
                assert log_type in ("stdout", "stderr")

                await ws.send_json({"type": log_type, "message": message.decode()})
        finally:
            await ws.close()
    finally:
        execution.vm.fvm.log_queues.remove(queue)
        queue.empty()


@require_jwk_authentication
async def operate_expire(request: web.Request, authenticated_sender: str):
    """Stop the virtual machine, smoothly if possible.

    A timeout may be specified to delay the action."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    timeout = float(ItemHash(request.match_info["timeout"]))
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.message.address != authenticated_sender:
        logger.debug(f"Unauthorized sender {authenticated_sender} for {vm_hash}")
        return web.Response(status=401, body="Unauthorized sender")

    logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
    await execution.expire(timeout=timeout)
    execution.persistent = False

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash, pool=pool)

    # TODO: Check if this should be execution.message.address or execution.message.content.address?
    if execution.message.address != authenticated_sender:
        logger.debug(f"Unauthorized sender {authenticated_sender} for {vm_hash}")
        return web.Response(status=401, body="Unauthorized sender")

    if execution.is_running:
        logger.info(f"Stopping {execution.vm_hash}")
        await execution.stop()
        execution.persistent = False
        return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
    else:
        return web.Response(status=200, body="Already stopped, nothing to do")


@require_jwk_authentication
async def operate_reboot(request: web.Request, authenticated_sender: str):
    """
    Reboots the virtual machine, smoothly if possible.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.message.address != authenticated_sender:
        logger.debug(f"Unauthorized sender {authenticated_sender} for {vm_hash}")
        return web.Response(status=401, body="Unauthorized sender")

    # TODO: implement this endpoint
    logger.info(f"Rebooting {execution.vm_hash}")
    return web.Response(status=200, body=f"Rebooted {execution.vm_hash}")


@require_jwk_authentication
async def operate_erase(request: web.Request, authenticated_sender: str):
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.message.address != authenticated_sender:
        logger.debug(f"Unauthorized sender {authenticated_sender} for {vm_hash}")
        return web.Response(status=401, body="Unauthorized sender")

    logger.info(f"Erasing {execution.vm_hash}")

    # Stop the VM
    await execution.stop()
    execution.persistent = False

    # Delete all data
    if execution.resources is not None:
        for volume in execution.resources.volumes:
            if not volume.read_only:
                logger.info(f"Deleting volume {volume.path_on_host}")
                volume.path_on_host.unlink()

    return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
