import asyncio
import functools
import json
import logging
from collections.abc import Awaitable
from datetime import datetime, timedelta, timezone
from typing import Callable

import aiohttp.web_exceptions
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from eth_account import Account
from eth_account.messages import encode_defunct
from jwskate import Jwk

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


async def authenticate_jwk(request: web.Request):
    signed_keypair = request.headers.get("X-SignedPubKey")
    if not signed_keypair:
        raise web.HTTPBadRequest(reason="Missing X-SignedPubKey header")

    try:
        keypair_dict = json.loads(signed_keypair)
        payload = keypair_dict.get("payload")
        signature = keypair_dict.get("signature")
    except (json.JSONDecodeError, KeyError):
        raise web.HTTPBadRequest(reason="Invalid X-SignedPubKey format")

    try:
        json_payload = get_json_from_hex(payload)
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(reason="")

    if not verify_wallet_signature(signature, payload, json_payload.get("address")):
        raise web.HTTPUnauthorized(reason="Invalid signature")

    expires = json_payload.get("expires")
    if not expires or not is_token_still_valid(expires):
        raise web.HTTPUnauthorized(reason="Token expired")

    signed_operation = request.headers.get("X-SignedOperation")
    if not signed_operation:
        raise web.HTTPBadRequest(reason="Missing X-SignedOperation header")

    json_web_key = Jwk(json_payload.get("pubkey"))
    try:
        payload = json.loads(signed_operation)
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(reason="Could not decode X-SignedOperation")

    # The signature is not part of the signed payload, remove it
    payload_signature = payload.pop("signature")
    signed_payload = json.dumps(payload, separators=(",", ":")).encode("utf-8")

    if json_web_key.verify(
        data=signed_payload,
        signature=bytes.fromhex(payload_signature),
        alg="ES256",
    ):
        logger.debug("Signature verified")
    else:
        raise web.HTTPUnauthorized(reason="Signature could not verified")


def require_jwk_authentication(handler: Callable[[web.Request], Awaitable[web.StreamResponse]]):
    @functools.wraps(handler)
    async def wrapper(request):
        try:
            await authenticate_jwk(request)
        except web.HTTPException as e:
            return web.json_response(data={"error": e.reason}, status=e.status)

        return await handler(request)

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
async def stream_logs(request: web.Request):
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.vm is None:
        raise web.HTTPBadRequest(body=f"VM {vm_hash} is not running")

    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
    try:
        ws = web.WebSocketResponse()
        try:
            await ws.prepare(request)

            # Limit the number of queues per VM
            if len(execution.vm.fvm.log_queues) > 20:
                logger.warning("Too many log queues, dropping the oldest one")
                execution.vm.fvm.log_queues.pop(0)

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
async def operate_expire(request: web.Request):
    """Stop the virtual machine, smoothly if possible.

    A timeout may be specified to delay the action."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    timeout = float(ItemHash(request.match_info["timeout"]))
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
    await execution.expire(timeout=timeout)
    execution.persistent = False

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@require_jwk_authentication
async def operate_stop(request: web.Request):
    """Stop the virtual machine, smoothly if possible."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.is_running:
        logger.info(f"Stopping {execution.vm_hash}")
        await execution.stop()
        execution.persistent = False
        return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
    else:
        return web.Response(status=200, body="Already stopped, nothing to do")


@require_jwk_authentication
async def operate_reboot(request: web.Request):
    """
    Reboots the virtual machine, smoothly if possible.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    # TODO: implement this endpoint
    logger.info(f"Rebooting {execution.vm_hash}")
    return web.Response(status=200, body=f"Rebooted {execution.vm_hash}")


@require_jwk_authentication
async def operate_erase(request: web.Request):
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

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
