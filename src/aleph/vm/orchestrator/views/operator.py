import asyncio
import functools
import json
import logging
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import Callable, Literal, Dict, Any, Union

import aiohttp.web_exceptions
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from eth_account import Account
from eth_account.messages import encode_defunct
from jwskate import Jwk
from pydantic.main import BaseModel

from ...models import VmExecution
from ...pool import VmPool

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
    computed_address = Account.recover_message(enc_msg, signature=signature)

    return computed_address.lower() == address.lower()


def get_json_from_hex(str: str):
    """
    Converts a hex string to a json object
    """
    return json.loads(bytes.fromhex(str).decode("utf-8"))


class SignedPubKeyHeader(BaseModel):
    signature: str  # hexadecimal
    payload: str  # hexadecimal of SignedPubKeyPayload


class SignedPubKeyPayload(BaseModel):
    """This payload is signed by the wallet of the user to authorize an ephemeral key to act on his behalf."""
    # pubkey: Jwk
    pubkey: Dict[str, Any]
    # {'pubkey': {'alg': 'ES256', 'crv': 'P-256', 'ext': True, 'key_ops': ['verify'], 'kty': 'EC', 'x': '4blJBYpltvQLFgRvLE-2H7dsMr5O0ImHkgOnjUbG2AU', 'y': '5VHnq_hUSogZBbVgsXMs0CjrVfMy4Pa3Uv2BEBqfrN4'}
    # alg: Literal["ECDSA"]
    domain: str
    address: str
    expires: float  # timestamp  # TODO: move to ISO 8601


class SignedOperation(BaseModel):
    """This payload is signed by the ephemeral key authorized above."""
    signature: str  # hexadecimal
    payload: str  # hexadecimal of SignedOperationPayload


class SignedOperationPayload(BaseModel):
    time: datetime
    method: Union[Literal["POST"], Literal["GET"]]
    path: str
    # body_sha256: str  # disabled since there is no body


async def authenticate_jwk(request: web.Request) -> str:
    # The ephemeral public key that is signed by the wallet.
    signed_pubkey = request.headers.get("X-SignedPubKey")
    if not signed_pubkey:
        raise web.HTTPBadRequest(reason="Missing X-SignedPubKey header")

    # Check that the header is a valid JSON object and deserialize it
    try:
        pubkey_dict = json.loads(signed_pubkey)
        pubkey_body = SignedPubKeyHeader.parse_obj(pubkey_dict)
    except (json.JSONDecodeError, KeyError):
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey format")

    # Deserialize the payload from the header
    try:
        json_payload = SignedPubKeyPayload.parse_obj(get_json_from_hex(pubkey_body.payload))
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Not valid JSON payload")

    wallet_address: str = json_payload.address

    if not verify_wallet_signature(pubkey_body.signature, pubkey_body.payload, wallet_address):
        raise web.HTTPUnauthorized(reason="Invalid signature")

    expires = json_payload.expires
    if not expires or not is_token_still_valid(expires):
        raise web.HTTPUnauthorized(reason="Token expired")

    signed_operation = request.headers.get("X-SignedOperation")
    if not signed_operation:
        raise web.HTTPBadRequest(reason="Missing X-SignedOperation header")

    json_web_key = Jwk(json_payload.pubkey)
    try:
        payload_json = json.loads(signed_operation)
        request_object = SignedOperation.parse_obj(payload_json)
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Could not decode X-SignedOperation")

    if json_web_key.verify(
        data=bytes.fromhex(request_object.payload),
        signature=bytes.fromhex(request_object.signature),
        alg="ES256",
    ):
        logger.debug("Signature verified")
        return wallet_address
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
    except KeyError:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'")
    try:
        return ItemHash(ref)
    except UnknownHashError:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'")


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
