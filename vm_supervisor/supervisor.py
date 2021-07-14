"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import asyncio
import binascii
import copy
import json
import logging
import math
import time
from base64 import b32decode, b16encode
from typing import Awaitable, Dict, Any, Optional, Tuple, AsyncIterable

import aiodns
import aiohttp
import msgpack
from aiohttp import web, ClientResponseError, ClientConnectorError
from aiohttp.web_exceptions import HTTPNotFound, HTTPServiceUnavailable, HTTPBadRequest, \
    HTTPInternalServerError
from msgpack import UnpackValueError
from yarl import URL

import pydantic
from aleph_message.models import ProgramMessage, Message, BaseMessage
from firecracker.microvm import MicroVMFailedInit
from .conf import settings
from .models import VmHash, VmExecution
from .pool import VmPool
from .pubsub import PubSub
from .storage import get_message, get_latest_amend
from .vm.firecracker_microvm import ResourceDownloadError, VmSetupError

logger = logging.getLogger(__name__)
pool = VmPool()


async def index(request: web.Request):
    assert request.method == "GET"
    return web.Response(text="Server: Aleph VM Supervisor")


async def try_get_message(ref: str) -> ProgramMessage:
    # Get the message or raise an aiohttp HTTP error
    try:
        return await get_message(ref)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(reason="Hash not found")
        else:
            raise


async def get_latest_ref(item_hash: str) -> str:
    try:
        return await get_latest_amend(item_hash)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(reason="Hash not found")
        else:
            raise


async def update_with_latest_ref(obj):
    """
    Update the reference `ref` inplace if a newer version is available.

    Useful to update references in parallel with asyncio.gather.
    """
    if hasattr(obj, 'use_latest') and obj.use_latest:
        obj.ref = await get_latest_ref(obj.ref)
    else:
        return obj


async def update_message(message: ProgramMessage):
    # Load amends
    await asyncio.gather(
        update_with_latest_ref(message.content.runtime),
        update_with_latest_ref(message.content.code),
        update_with_latest_ref(message.content.data),
        *(
            update_with_latest_ref(volume)
            for volume in (message.content.volumes or [])
        ),
    )


async def load_updated_message(ref: VmHash) -> Tuple[ProgramMessage, ProgramMessage]:
    original_message = await try_get_message(ref)
    message = copy.deepcopy(original_message)
    await update_message(message)
    pool.message_cache[ref] = message
    return message, original_message


async def build_asgi_scope(path: str, request: web.Request) -> Dict[str, Any]:
    # ASGI mandates lowercase header names
    headers = tuple((name.lower(), value)
                    for name, value in request.raw_headers)
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": headers,
        "body": await request.read()
    }


async def run_code(vm_hash: VmHash, path: str, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    execution: VmExecution = await pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        message, original_message = await load_updated_message(vm_hash)

        try:
            execution = await pool.create_a_vm(vm_hash=vm_hash, program=message.content,
                                               original=original_message.content)
        except ResourceDownloadError as error:
            logger.exception(error)
            raise HTTPBadRequest(reason="Code, runtime or data not available")
        except VmSetupError as error:
            logger.exception(error)
            raise HTTPInternalServerError(reason="Error during program initialisation")
        except MicroVMFailedInit as error:
            logger.exception(error)
            raise HTTPInternalServerError(reason="Error during runtime initialisation")

    logger.debug(f"Using vm={execution.vm.vm_id}")

    scope: Dict = await build_asgi_scope(path, request)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.vm.run_code(scope=scope)
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=500,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        headers = {key.decode(): value.decode()
                   for key, value in result['headers']['headers']}

        return web.Response(
            status=result['headers']['status'],
            body=result["body"]["body"],
            headers=headers,
        )
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=request.app['pubsub'])
            execution.stop_after_timeout(timeout=settings.REUSE_TIMEOUT)
        else:
            await execution.stop()


def run_code_from_path(request: web.Request) -> Awaitable[web.Response]:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref: VmHash = request.match_info["ref"]
    return run_code(message_ref, path, request)


def b32_to_b16(hash: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = hash.upper() + "=" * (56 - len(hash))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def get_ref_from_dns(domain):
    resolver = aiodns.DNSResolver()
    record = await resolver.query(domain, 'TXT')
    return record[0].text


async def run_code_from_hostname(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a hostname

    The first component of the hostname is used as identifier of the message defining the
    Aleph VM function.

    Since hostname labels are limited to 63 characters and hex(sha256(...)) has a length of 64,
    we expect the hash to be encoded in base32 instead of hexadecimal. Padding is added
    automatically.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref_base32 = request.host.split(".")[0]
    if settings.FAKE_DATA:
        message_ref = "TEST_HASH"
    else:
        try:
            message_ref = b32_to_b16(message_ref_base32).decode()
            logger.debug(f"Using base32 message id from hostname to obtain '{message_ref}")
        except binascii.Error:
            try:
                message_ref = await get_ref_from_dns(domain=f"_aleph-id.{request.host}")
                logger.debug(f"Using DNS TXT record to obtain '{message_ref}'")
            except aiodns.error.DNSError:
                raise HTTPNotFound(reason="Invalid message reference")

    return await run_code(message_ref, path, request)


async def subscribe_via_ws(url) -> AsyncIterable[BaseMessage]:
    logger.debug("subscribe_via_ws()")
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url) as ws:
            logger.debug(f"Websocket connected on {url}")
            async for msg in ws:
                logger.debug(f"Websocket received data...")
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    # Patch data format to match HTTP GET format
                    data["_id"] = {"$oid": data["_id"]}
                    try:
                        yield Message(**data)
                    except pydantic.error_wrappers.ValidationError as error:
                        print(error.json())
                        print(error.raw_errors)
                        raise
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break


async def watch_for_messages(dispatcher: PubSub):
    """Watch for new Aleph messages"""
    logger.debug("watch_for_messages()")
    url = URL(f"{settings.API_SERVER}/api/ws0/messages"
              ).with_query({"startDate": math.floor(time.time())})

    async for message in subscribe_via_ws(url):
        logger.info(f"Websocket received message: {message.item_hash}")
        ref = message.content.ref if hasattr(message.content, 'ref') else message.item_hash
        await dispatcher.publish(key=ref, value=message)


async def start_watch_for_messages_task(app: web.Application):
    logger.debug("start_watch_for_messages_task()")
    pubsub = PubSub()
    app['pubsub'] = pubsub
    app['messages_listener'] = asyncio.create_task(watch_for_messages(pubsub))


async def stop_watch_for_messages_task(app: web.Application):
    app['messages_listener'].cancel()
    await app['messages_listener']


app = web.Application()

app.add_routes([web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path)])
app.add_routes([web.route("*", "/{suffix:.*}", run_code_from_hostname)])


def run():
    """Run the VM Supervisor."""
    settings.check()
    app.on_startup.append(start_watch_for_messages_task)
    app.on_cleanup.append(stop_watch_for_messages_task)
    web.run_app(app, port=settings.SUPERVISOR_PORT)
