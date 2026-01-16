import asyncio
import json
import logging
import os
import socket
import subprocess
import sys
from datetime import datetime, timezone
from os import listdir
from pathlib import Path
from typing import Any

import aiohttp
from aleph_message.models import (
    MessagesResponse,
    PostMessage,
    ProgramMessage,
    StoreMessage,
)
from aleph_message.status import MessageStatus
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pip._internal.operations.freeze import freeze
from pydantic import BaseModel
from starlette.responses import JSONResponse

from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.chains.remote import RemoteAccount
from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import StorageEnum
from aleph.sdk.vm.app import AlephApp
from aleph.sdk.vm.cache import VmCache

logger = logging.getLogger(__name__)
logger.debug("imports done")

http_app = FastAPI()
app = AlephApp(http_app=http_app)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize cache on startup event to avoid running loop errors
cache: VmCache | None = None

startup_lifespan_executed: bool = False

ALEPH_API_HOSTS: list[str] = [
    "https://official.aleph.cloud",
    "https://api.aleph.im",
]


@app.on_event("startup")
async def startup_event() -> None:
    global startup_lifespan_executed, cache
    startup_lifespan_executed = True
    cache = VmCache()


@app.get("/")
async def index() -> dict[str, Any]:
    if os.path.exists("/opt/venv"):
        opt_venv = list(listdir("/opt/venv"))
    else:
        opt_venv = []
    return {
        "Example": "example_fastapi",
        "endpoints": [
            # Features
            "/lifespan",
            "/environ",
            "/state/increment",
            "/wait-for/{delay}",
            # Local cache
            "/cache/get/{key}",
            "/cache/set/{key}/{value}",
            "/cache/remove/{key}",
            "/cache/keys",
            # Networking
            "/dns",
            "/ip/address",
            "/ip/4",
            "/ip/6",
            "/internet",
            # Error handling
            "/raise",
            "/crash",
            # Aleph.im
            "/messages",
            "/get_a_message",
            "/post_a_message",
            "/post_a_message_local_account",
            "/post_a_file",
            "/sign_a_message",
            # Platform properties
            "/platform/os",
            "/platform/python",
            "/platform/pip-freeze",
        ],
        "files_in_volumes": {
            "/opt/venv": opt_venv,
        },
    }


@app.get("/lifespan")
async def check_lifespan():
    """
    Check that ASGI lifespan startup signal has been received
    """
    return {"Lifespan": startup_lifespan_executed}


@app.get("/environ")
async def environ() -> dict[str, str]:
    """List environment variables"""
    return dict(os.environ)


async def get_aleph_messages(api_host: str, message_filter: MessageFilter):
    async with AlephHttpClient(api_server=api_host) as client:
        data = await client.get_messages(message_filter=message_filter)
        return data.dict()


@app.get("/messages")
async def read_aleph_messages() -> dict[str, MessagesResponse]:
    """Read data from Aleph using the Aleph Client library."""
    message_filter = MessageFilter(hashes=["f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e"])

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {
        asyncio.create_task(get_aleph_messages(host, message_filter)) for host in ALEPH_API_HOSTS
    }

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        result = done.pop().result()

        if result.get("messages", None):
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return {"Messages": result}
        else:
            failures.append(result)
            continue

    # No Aleph API Host was reachable
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


@app.get("/dns")
async def resolve_dns_hostname():
    """Check if DNS resolution is working."""
    hostname = "example.org"
    ipv4: str | None = None
    ipv6: str | None = None

    info = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
    if not info:
        logger.error("DNS resolution failed")

    # Iterate over the results to find the IPv4 and IPv6 addresses they may not all be present.
    # The function returns a list of 5-tuples with the following structure:
    # (family, type, proto, canonname, sockaddr)
    for info_tuple in info:
        if info_tuple[0] == socket.AF_INET:
            ipv4 = info_tuple[4][0]
        elif info_tuple[0] == socket.AF_INET6:
            ipv6 = info_tuple[4][0]

    if ipv4 and not ipv6:
        logger.warning(f"DNS resolution for {hostname} returned only an IPv4 address")
    elif ipv6 and not ipv4:
        logger.warning(f"DNS resolution for {hostname} returned only an IPv6 address")

    result = {"ipv4": ipv4, "ipv6": ipv6}
    status_code = 200 if len(info) > 1 else 503
    return JSONResponse(content=result, status_code=status_code)


@app.get("/ip/address")
async def ip_address():
    """Fetch the ip addresses of the virtual machine."""
    output = subprocess.check_output(["ip", "addr"], shell=False)
    return PlainTextResponse(content=output)


@app.get("/ip/4")
async def connect_ipv4():
    """Connect to some DNS services using their IPv4 address.
    The webserver on that address can return a 404 error, and it is normal, so we accept that response code.
    """
    ipv4_hosts: list[str] = [
        "https://208.67.222.222",  # OpenDNS service
        "https://9.9.9.9",  # Quad9 VPN service
        "https://94.140.14.14",  # AdGuard DNS service
    ]
    timeout_seconds = 5

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {
        asyncio.create_task(check_url(host, timeout_seconds, socket_family=socket.AF_INET, accept_404=True))
        for host in ipv4_hosts
    }

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        result = done.pop().result()

        if result["result"]:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return result
        else:
            failures.append(result)
            continue

    # No IPv6 URL was reachable, return the collected failure reasons
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


@app.get("/ip/6")
async def connect_ipv6():
    """Connect to some DNS services using their IPv6 address.
    The webserver on that address can return a 404 error, and it is normal, so we accept that response code.
    """
    ipv6_hosts: list[str] = [
        "https://[2620:0:ccc::2]",  # OpenDNS service
        "https://[2620:fe::fe]",  # Quad9 DNS service
        "https://[2606:4700:4700::1111]",  # CloudFlare DNS service
    ]
    timeout_seconds = 5

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {
        asyncio.create_task(check_url(host, timeout_seconds, socket_family=socket.AF_INET6, accept_404=True))
        for host in ipv6_hosts
    }

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        result = done.pop().result()

        if result["result"]:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return result
        else:
            failures.append(result)
            continue

    # No IPv6 URL was reachable, return the collected failure reasons
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


async def check_url(
    internet_host: str, timeout_seconds: int = 5, socket_family=socket.AF_INET, accept_404: bool = False
):
    """Check the connectivity of a single URL."""
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    tcp_connector = aiohttp.TCPConnector(family=socket_family)
    async with aiohttp.ClientSession(timeout=timeout, connector=tcp_connector) as session:
        try:
            async with session.get(internet_host) as resp:
                if 200 <= resp.status < 300:
                    return {"result": True, "headers": resp.headers, "url": internet_host}

                if resp.status == 404 and accept_404:
                    return {"result": True, "headers": resp.headers, "url": internet_host}

                reason = f"HTTP Status {resp.status}"
                logger.warning(f"Session connection for host {internet_host} failed with status {resp.status}")
                return {"result": False, "url": internet_host, "reason": reason}
        except (aiohttp.ClientConnectionError, TimeoutError) as e:
            reason = f"{type(e).__name__}"
            logger.warning(f"Session connection for host {internet_host} failed ({reason})")
            return {"result": False, "url": internet_host, "reason": reason}
        except Exception as e:
            # Catch other errors not related to timeouts like DNS errors, SSL certificates, etc.
            reason = f"Unexpected error: {type(e).__name__}"
            logger.error(f"Unexpected error for host {internet_host}: {e}", exc_info=True)
            return {"result": False, "url": internet_host, "reason": reason}


@app.get("/internet")
async def read_internet():
    """Check Internet connectivity of the system, requiring IP connectivity, domain resolution and HTTPS/TLS."""
    internet_hosts: list[str] = [
        "https://aleph.im/",
        "https://ethereum.org/en/",
        "https://ipfs.io/",
    ]
    timeout_seconds = 5

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {asyncio.create_task(check_url(host, timeout_seconds)) for host in internet_hosts}

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        result = done.pop().result()

        if result["result"]:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return result
        else:
            failures.append(result)
            continue

    # No URL was reachable, return the collected failure reasons
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


@app.get("/get_a_message")
async def get_a_message():
    """Get a message from the Aleph.im network"""
    item_hash = "3fc0aa9569da840c43e7bd2033c3c580abb46b007527d6d20f2d4e98e867f7af"
    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {asyncio.create_task(get_aleph_message(host, item_hash)) for host in ALEPH_API_HOSTS}

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        result = done.pop().result()

        if result.get("item_hash", None):
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return result
        else:
            failures.append(result)
            continue

    # No Aleph API Host was reachable
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


async def get_aleph_message(api_host: str, item_hash: str):
    try:
        async with AlephHttpClient(api_server=api_host) as client:
            message = await client.get_message(
                item_hash=item_hash,
                message_type=ProgramMessage,
            )
            return message.dict()
    except Exception as e:
        reason = f"Unexpected error: {type(e).__name__}"
        logger.error(f"Unexpected error for host {api_host}: {e}", exc_info=True)
        return {"result": False, "reason": reason}


@app.post("/post_a_message")
async def post_with_remote_account():
    """Post a message on the Aleph.im network using the remote account of the host."""
    failures = []
    try:
        account = await RemoteAccount.from_crypto_host(host="http://localhost", unix_socket="/tmp/socat-socket")

        # Create a list of tasks to check the URLs in parallel
        tasks: set[asyncio.Task] = {
            asyncio.create_task(send_post_aleph_message(host, account)) for host in ALEPH_API_HOSTS
        }

        # While no tasks have completed, keep waiting for the next one to finish
        while tasks:
            done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            message, status = done.pop().result()

            if status == MessageStatus.PROCESSED:
                # The task was successful, cancel the remaining tasks and return the result
                for task in tasks:
                    task.cancel()
                return {
                    "message": message,
                }
            else:
                failures.append(message)
                continue
    except aiohttp.client_exceptions.UnixClientConnectorError:
        failures.append({"error": "Could not connect to the remote account"})

    # No API Host was reachable
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


@app.post("/post_a_message_local_account")
async def post_with_local_account():
    """Post a message on the Aleph.im network using a local private key."""
    from aleph.sdk.chains.ethereum import get_fallback_account

    account = get_fallback_account()

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {asyncio.create_task(send_post_aleph_message(host, account)) for host in ALEPH_API_HOSTS}

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        message, status = done.pop().result()

        if status == MessageStatus.PROCESSED:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return {
                "message": message,
            }
        else:
            failures.append(message)
            continue

    # No API Host was reachable
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


async def send_post_aleph_message(api_host: str, account: RemoteAccount | ETHAccount):
    """Post a message on the Aleph.im network using a local or the remote account of the host."""
    try:
        content = {
            "date": datetime.now(tz=timezone.utc).isoformat(),
            "test": True,
            "answer": 42,
            "something": "interesting",
        }
        async with AuthenticatedAlephHttpClient(
            account=account,
            api_server=api_host,
        ) as client:
            message: PostMessage
            status: MessageStatus
            return await client.create_post(
                post_content=content,
                post_type="test",
                ref=None,
                channel="TEST",
                inline=True,
                storage_engine=StorageEnum.storage,
                sync=True,
            )
    except aiohttp.client_exceptions.UnixClientConnectorError as e:
        reason = f"{type(e).__name__}"
        logger.error(f"Connection error for host {api_host} with account {account}: {e}", exc_info=True)
        return {"result": False, "reason": reason}, MessageStatus.REJECTED
    except Exception as e:
        reason = f"Unexpected error: {type(e).__name__}"
        logger.error(f"Unexpected error for host {api_host} with account {account}: {e}", exc_info=True)
        return {"result": False, "reason": reason}, MessageStatus.REJECTED


@app.post("/post_a_file")
async def post_a_file():
    from aleph.sdk.chains.ethereum import get_fallback_account

    account = get_fallback_account()
    file_path = Path(__file__).absolute()

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {
        asyncio.create_task(send_store_aleph_message(host, account, file_path)) for host in ALEPH_API_HOSTS
    }

    failures = []

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        message, status = done.pop().result()

        if status == MessageStatus.PROCESSED:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return {
                "message": message,
            }
        else:
            failures.append(message)
            continue

    # No API Host was reachable
    return JSONResponse(status_code=503, content={"result": False, "failures": failures})


async def send_store_aleph_message(api_host: str, account: ETHAccount, file_path: Path):
    """Store a file on the Aleph.im network using a local account."""
    try:
        async with AuthenticatedAlephHttpClient(
            account=account,
            api_server=api_host,
        ) as client:
            message: StoreMessage
            status: MessageStatus
            return await client.create_store(
                file_path=file_path,
                ref=None,
                channel="TEST",
                storage_engine=StorageEnum.storage,
                sync=True,
            )
    except aiohttp.client_exceptions.UnixClientConnectorError as e:
        reason = f"{type(e).__name__}"
        logger.error(f"Connection error for host {api_host} with account {account}: {e}", exc_info=True)
        return {"result": False, "reason": reason}, MessageStatus.REJECTED
    except Exception as e:
        reason = f"Unexpected error: {type(e).__name__}"
        logger.error(f"Unexpected error for host {api_host} with account {account}: {e}", exc_info=True)
        return {"result": False, "reason": reason}, MessageStatus.REJECTED


@app.get("/sign_a_message")
async def sign_a_message():
    """Sign a message using a locally managed account within the virtual machine."""
    # FIXME: Broken, fixing this depends on https://github.com/aleph-im/aleph-sdk-python/pull/120
    from aleph.sdk.chains.ethereum import get_fallback_account

    account = get_fallback_account()
    message = {"hello": "world", "chain": "ETH", "type": "POST", "item_hash": "0x000"}
    signed_message = await account.sign_message(message)
    return {"message": signed_message}


@app.get("/cache/get/{key}")
async def get_from_cache(key: str):
    """Get data in the VM cache"""
    if cache is None:
        return JSONResponse(status_code=503, content={"error": "Cache not initialized"})
    return await cache.get(key)


@app.get("/cache/set/{key}/{value}")
async def store_in_cache(key: str, value: str):
    """Store data in the VM cache"""
    if cache is None:
        return JSONResponse(status_code=503, content={"error": "Cache not initialized"})
    return await cache.set(key, value)


@app.get("/cache/remove/{key}")
async def remove_from_cache(key: str):
    """Store data in the VM cache"""
    if cache is None:
        return JSONResponse(status_code=503, content={"error": "Cache not initialized"})
    result = await cache.delete(key)
    return result == 1


@app.get("/cache/keys")
async def keys_from_cache(pattern: str = "*"):
    """List keys from the VM cache"""
    if cache is None:
        return JSONResponse(status_code=503, content={"error": "Cache not initialized"})
    return await cache.keys(pattern)


@app.get("/state/increment")
async def increment() -> dict[str, int]:
    path = "/var/lib/example/storage.json"
    try:
        with open(path) as fd:
            data = json.load(fd)
        data["counter"] += 1
    except FileNotFoundError:
        data = {"counter": 0}
    with open(path, "w") as fd:
        json.dump(data, fd)
    return data


class Data(BaseModel):
    text: str
    number: int


@app.post("/post")
async def receive_post(data: Data) -> str:
    return str(data)


class CustomError(Exception):
    pass


@app.get("/raise")
def raise_error() -> None:
    """Raises an error to check that the init handles it properly without crashing"""
    error_message = "Whoops"
    raise CustomError(error_message)


@app.get("/crash")
def crash() -> None:
    """Crash the entire VM in order to check that the supervisor can handle it"""
    sys.exit(1)


filters = [
    {
        # "sender": "0xB31B787AdA86c6067701d4C0A250c89C7f1f29A5",
        "channel": "TEST"
    }
]


@app.get("/platform/os")
def platform_os() -> PlainTextResponse:
    return PlainTextResponse(content=Path("/etc/os-release").read_text())


@app.get("/platform/python")
def platform_python() -> PlainTextResponse:
    return PlainTextResponse(content=sys.version)


@app.get("/platform/pip-freeze")
def platform_pip_freeze() -> list[str]:
    return list(freeze())


@app.event(filters=filters)
async def aleph_event(event) -> dict[str, str]:
    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {asyncio.create_task(get_aleph_json(host)) for host in ALEPH_API_HOSTS}

    # While no tasks have completed, keep waiting for the next one to finish
    while tasks:
        done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        status = done.pop().result()

        if status:
            # The task was successful, cancel the remaining tasks and return the result
            for task in tasks:
                task.cancel()
            return {"result": "Good"}
        else:
            continue

    return {"result": "Bad"}


async def get_aleph_json(api_host: str) -> bool:
    try:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
            async with session.get(f"{api_host}/api/v0/info/public.json") as resp:
                resp.raise_for_status()
                return True
    except Exception:
        return False
