import json
import logging
import re
from pathlib import Path

import aiohttp
import redis.asyncio as redis_async
import redis.exceptions as redis_exceptions
import sentry_sdk
from aiohttp import web
from setproctitle import setproctitle

from aleph.vm.conf import settings
from aleph.vm.version import get_version_from_apt, get_version_from_git

logger = logging.getLogger(__name__)

ALEPH_API_SERVER = "https://official.aleph.cloud"
ALEPH_VM_CONNECTOR = "http://localhost:4021"
CACHE_EXPIRES_AFTER = 7 * 24 * 3600  # Seconds
REDIS_ADDRESS = "redis://localhost"

_redis: redis_async.Redis | None = None


async def get_redis(address: str = REDIS_ADDRESS) -> redis_async.Redis:
    global _redis
    # Ensure the redis connection is still up before returning it
    if _redis:
        try:
            await _redis.ping()
        except redis_exceptions.ConnectionError:
            _redis = None
    if not _redis:
        _redis = redis_async.from_url(address)

    return _redis


async def proxy(request: web.Request):
    tail: str = request.match_info.get("tail") or ""
    path: str = tail.lstrip("/")
    query_string = request.rel_url.query_string
    url = f"{ALEPH_API_SERVER}/{path}?{query_string}"

    async with aiohttp.ClientSession() as session:
        async with session.request(method=request.method, url=url) as response:
            data = await response.read()
            return web.Response(body=data, status=response.status, content_type=response.content_type)


async def repost(request: web.Request):
    logger.debug("REPOST")
    data_raw = await request.json()
    topic, message = data_raw["topic"], json.loads(data_raw["data"])

    content = json.loads(message["item_content"])
    content["address"] = "VM on executor"
    message["item_content"] = json.dumps(content)

    new_data = {"topic": topic, "data": json.dumps(message)}

    path = request.path
    if request.rel_url.query_string:
        query_string = request.rel_url.query_string
        url = f"{ALEPH_VM_CONNECTOR}{path}?{query_string}"
    else:
        url = f"{ALEPH_VM_CONNECTOR}{path}"

    async with aiohttp.ClientSession() as session:
        async with session.post(url=url, json=new_data) as response:
            data = await response.read()
            return web.Response(body=data, status=response.status, content_type=response.content_type)


# async def decrypt_secret(request: web.Request):
#     Not implemented...


async def properties(request: web.Request):
    logger.debug("Forwarding signing properties")
    _ = request

    url = f"{ALEPH_VM_CONNECTOR}/properties"
    async with aiohttp.ClientSession() as session:
        async with session.get(url=url) as response:
            data = await response.read()
            return web.Response(body=data, status=response.status, content_type=response.content_type)


async def sign(request: web.Request):
    vm_hash = request.app["meta_vm_hash"]
    message = await request.json()

    # Ensure that the hash of the VM is used as sending address
    content = json.loads(message["item_content"])
    if content["address"] != vm_hash:
        raise web.HTTPBadRequest(reason="Message address does not match VM item_hash")

    logger.info("Forwarding signing request to VM Connector")

    url = f"{ALEPH_VM_CONNECTOR}/sign"
    async with aiohttp.ClientSession() as session:
        async with session.post(url=url, json=message) as response:
            signed_message = await response.read()
            return web.Response(
                body=signed_message,
                status=response.status,
                content_type=response.content_type,
            )


async def get_from_cache(request: web.Request):
    prefix: str = request.app["meta_vm_hash"]
    key: str | None = request.match_info.get("key")
    if not (key and re.match(r"^\w+$", key)):
        return web.HTTPBadRequest(text="Invalid key")

    redis: redis_async.Redis = await get_redis()
    body = await redis.get(f"{prefix}:{key}")
    if body:
        return web.Response(body=body, status=200)
    else:
        return web.Response(text="No such key in cache", status=404)


async def put_in_cache(request: web.Request):
    prefix: str = request.app["meta_vm_hash"]
    key: str | None = request.match_info.get("key")
    if not (key and re.match(r"^\w+$", key)):
        return web.HTTPBadRequest(text="Invalid key")

    value: bytes = await request.read()

    redis: redis_async.Redis = await get_redis()
    return web.json_response(await redis.set(f"{prefix}:{key}", value, ex=CACHE_EXPIRES_AFTER))


async def delete_from_cache(request: web.Request):
    prefix: str = request.app["meta_vm_hash"]
    key: str | None = request.match_info.get("key")
    if not (key and re.match(r"^\w+$", key)):
        return web.HTTPBadRequest(text="Invalid key")

    redis: redis_async.Redis = await get_redis()
    result = await redis.delete(f"{prefix}:{key}")
    return web.json_response(result)


async def list_keys_from_cache(request: web.Request):
    prefix: str = request.app["meta_vm_hash"]
    pattern: str = request.rel_url.query.get("pattern", "*")
    if not re.match(r"^[\w?*^\-]+$", pattern):
        return web.HTTPBadRequest(text="Invalid key")

    redis: redis_async.Redis = await get_redis()
    result = await redis.keys(f"{prefix}:{pattern}")
    keys = [key.decode()[len(prefix) + 1 :] for key in result]
    return web.json_response(keys)


def run_guest_api(
    unix_socket_path: Path,
    vm_hash: str | None = None,
    sentry_dsn: str | None = None,
    server_name: str | None = None,
):
    # This function runs in a separate process, requiring to reinitialize the Sentry SDK
    if sentry_sdk and sentry_dsn:
        sentry_sdk.init(
            dsn=sentry_dsn,
            server_name=server_name,
            # Set traces_sample_rate to 1.0 to capture 100%
            # of transactions for performance monitoring.
            # We recommend adjusting this value in production.
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
        )
        sentry_sdk.set_context(
            "version",
            {
                "git": get_version_from_git(),
                "apt": get_version_from_apt(),
            },
        )

    setproctitle(f"aleph-vm guest_api on {unix_socket_path}")
    app = web.Application()
    app["meta_vm_hash"] = vm_hash or "_"

    app.router.add_route(method="GET", path="/properties", handler=properties)
    app.router.add_route(method="POST", path="/sign", handler=sign)

    app.router.add_route(method="GET", path="/cache/", handler=list_keys_from_cache)
    app.router.add_route(method="GET", path="/cache/{key:.*}", handler=get_from_cache)
    app.router.add_route(method="PUT", path="/cache/{key:.*}", handler=put_in_cache)
    app.router.add_route(method="DELETE", path="/cache/{key:.*}", handler=delete_from_cache)

    app.router.add_route(method="GET", path="/{tail:.*}", handler=proxy)
    app.router.add_route(method="HEAD", path="/{tail:.*}", handler=proxy)
    app.router.add_route(method="OPTIONS", path="/{tail:.*}", handler=proxy)

    app.router.add_route(method="POST", path="/api/v0/ipfs/pubsub/pub", handler=repost)
    app.router.add_route(method="POST", path="/api/v0/p2p/pubsub/pub", handler=repost)

    # web.run_app(app=app, port=9000)
    web.run_app(app=app, path=str(unix_socket_path))


if __name__ == "__main__":
    run_guest_api(Path("/tmp/guest-api"), vm_hash="vm")
