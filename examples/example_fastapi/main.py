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
from typing import Any, Optional

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
from pydantic import BaseModel, HttpUrl
from starlette.responses import JSONResponse

from aleph.sdk.chains.ethereum import get_fallback_account
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
cache = VmCache()

startup_lifespan_executed: bool = False


@app.on_event("startup")
async def startup_event() -> None:
    global startup_lifespan_executed
    startup_lifespan_executed = True


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


@app.get("/messages")
async def read_aleph_messages() -> dict[str, MessagesResponse]:
    """Read data from Aleph using the Aleph Client library."""
    async with AlephHttpClient() as client:
        message_filter = MessageFilter(hashes=["f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e"])
        data = await client.get_messages(message_filter=message_filter)
    return {"Messages": data}


@app.get("/dns")
async def resolve_dns_hostname():
    """Check if DNS resolution is working."""
    hostname = "example.org"
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None

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
    """Connect to the Quad9 VPN provider using their IPv4 address."""
    ipv4_host = "9.9.9.9"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ipv4_host, 53))
        return {"result": True}
    except socket.timeout:
        logger.warning(f"Socket connection for host {ipv4_host} failed")
        return {"result": False}


@app.get("/ip/6")
async def connect_ipv6():
    """Connect to the Quad9 VPN provider using their IPv6 address.
    The webserver on that address returns a 404 error, so we accept that response code.
    """
    ipv6_host = "https://[2620:fe::fe]"
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
        try:
            async with session.get(ipv6_host) as resp:
                # We expect this endpoint to return a 404 error
                if resp.status != 404:
                    resp.raise_for_status()
                return {"result": True, "headers": resp.headers}
        except TimeoutError:
            logger.warning(f"Session connection to host {ipv6_host} timed out")
            return {"result": False, "reason": "Timeout"}
        except aiohttp.ClientConnectionError as error:
            logger.warning(f"Client connection to host {ipv6_host} failed: {error}")
            # Get a string that describes the error
            return {"result": False, "reason": str(error.args[0])}


async def check_url(internet_host: HttpUrl, timeout_seconds: int = 5):
    """Check the connectivity of a single URL."""
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
        try:
            async with session.get(internet_host) as resp:
                resp.raise_for_status()
                return {"result": resp.status, "headers": resp.headers, "url": internet_host}
        except (aiohttp.ClientConnectionError, TimeoutError):
            logger.warning(f"Session connection for host {internet_host} failed")
            return {"result": False, "url": internet_host}


@app.get("/internet")
async def read_internet():
    """Check Internet connectivity of the system, requiring IP connectivity, domain resolution and HTTPS/TLS."""
    internet_hosts: list[HttpUrl] = [
        HttpUrl(url="https://aleph.im/", scheme="https"),
        HttpUrl(url="https://ethereum.org", scheme="https"),
        HttpUrl(url="https://ipfs.io/", scheme="https"),
    ]
    timeout_seconds = 5

    # Create a list of tasks to check the URLs in parallel
    tasks: set[asyncio.Task] = {asyncio.create_task(check_url(host, timeout_seconds)) for host in internet_hosts}

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
            continue

    # No URL was reachable
    return {"result": False}


@app.get("/get_a_message")
async def get_a_message():
    """Get a message from the Aleph.im network"""
    item_hash = "3fc0aa9569da840c43e7bd2033c3c580abb46b007527d6d20f2d4e98e867f7af"
    async with AlephHttpClient() as client:
        message = await client.get_message(
            item_hash=item_hash,
            message_type=ProgramMessage,
        )
        return message.dict()


@app.post("/post_a_message")
async def post_with_remote_account():
    """Post a message on the Aleph.im network using the remote account of the host."""
    try:
        account = await RemoteAccount.from_crypto_host(host="http://localhost", unix_socket="/tmp/socat-socket")

        content = {
            "date": datetime.now(tz=timezone.utc).isoformat(),
            "test": True,
            "answer": 42,
            "something": "interesting",
        }
        async with AuthenticatedAlephHttpClient(
            account=account,
        ) as client:
            message: PostMessage
            status: MessageStatus
            message, status = await client.create_post(
                post_content=content,
                post_type="test",
                ref=None,
                channel="TEST",
                inline=True,
                storage_engine=StorageEnum.storage,
                sync=True,
            )
            if status != MessageStatus.PROCESSED:
                return JSONResponse(status_code=500, content={"error": status})
        return {
            "message": message,
        }
    except aiohttp.client_exceptions.UnixClientConnectorError:
        return JSONResponse(status_code=500, content={"error": "Could not connect to the remote account"})


@app.post("/post_a_message_local_account")
async def post_with_local_account():
    """Post a message on the Aleph.im network using a local private key."""

    account = get_fallback_account()

    content = {
        "date": datetime.now(tz=timezone.utc).isoformat(),
        "test": True,
        "answer": 42,
        "something": "interesting",
    }
    async with AuthenticatedAlephHttpClient(
        account=account,
        api_server="https://api2.aleph.im",
        allow_unix_sockets=False,
    ) as client:
        message: PostMessage
        status: MessageStatus
        message, status = await client.create_post(
            post_content=content,
            post_type="test",
            ref=None,
            channel="TEST",
            inline=True,
            storage_engine=StorageEnum.storage,
            sync=True,
        )
        if status != MessageStatus.PROCESSED:
            return JSONResponse(status_code=500, content={"error": status})
    return {
        "message": message,
    }


@app.post("/post_a_file")
async def post_a_file():
    account = get_fallback_account()
    file_path = Path(__file__).absolute()
    async with AuthenticatedAlephHttpClient(
        account=account,
    ) as client:
        message: StoreMessage
        status: MessageStatus
        message, status = await client.create_store(
            file_path=file_path,
            ref=None,
            channel="TEST",
            storage_engine=StorageEnum.storage,
            sync=True,
        )
        if status != MessageStatus.PROCESSED:
            return JSONResponse(status_code=500, content={"error": status})
    return {
        "message": message,
    }


@app.get("/sign_a_message")
async def sign_a_message():
    """Sign a message using a locally managed account within the virtual machine."""
    # FIXME: Broken, fixing this depends on https://github.com/aleph-im/aleph-sdk-python/pull/120
    account = get_fallback_account()
    message = {"hello": "world", "chain": "ETH"}
    signed_message = await account.sign_message(message)
    return {"message": signed_message}


@app.get("/cache/get/{key}")
async def get_from_cache(key: str):
    """Get data in the VM cache"""
    return await cache.get(key)


@app.get("/cache/set/{key}/{value}")
async def store_in_cache(key: str, value: str):
    """Store data in the VM cache"""
    return await cache.set(key, value)


@app.get("/cache/remove/{key}")
async def remove_from_cache(key: str):
    """Store data in the VM cache"""
    result = await cache.delete(key)
    return result == 1


@app.get("/cache/keys")
async def keys_from_cache(pattern: str = "*"):
    """List keys from the VM cache"""
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
    print("aleph_event", event)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
        async with session.get("https://official.aleph.cloud/api/v0/info/public.json") as resp:
            print("RESP", resp)
            resp.raise_for_status()
    return {"result": "Good"}
