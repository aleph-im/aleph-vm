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
from typing import TYPE_CHECKING, Any, Callable

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

from aleph.sdk.chains.remote import RemoteAccount
from aleph.sdk.client import AlephHttpClient, AuthenticatedAlephHttpClient
from aleph.sdk.query.filters import MessageFilter
from aleph.sdk.types import StorageEnum
from aleph.sdk.vm.app import AlephApp
from aleph.sdk.vm.cache import VmCache

if TYPE_CHECKING:
    from aleph.sdk.vm.cache import VmCache


logger = logging.getLogger(__name__)
logger.debug("imports done")

# API Failover code - commented out for testing
ALEPH_API_HOSTS: list[str] = [
    "https://official.aleph.cloud",
    "https://api.aleph.im",
]

DEFAULT_TIMEOUT_SECONDS = 10


class APIFailoverError(Exception):
    """Raised when all API endpoints fail."""

    pass


async def _safe_request_with_timeout(
    host: str,
    request_func: Callable[[str], Any],
    timeout_seconds: float,
) -> dict[str, Any]:
    """Safely execute a request function with timeout and error handling."""
    try:
        result = await asyncio.wait_for(
            request_func(host),
            timeout=timeout_seconds,
        )
        return {"host": host, "result": result}
    except asyncio.TimeoutError as e:
        logger.warning(f"Request to {host} timed out after {timeout_seconds}s")
        return {"host": host, "error": e}
    except aiohttp.ClientError as e:
        logger.warning(f"Client error connecting to {host}: {e}")
        return {"host": host, "error": e}
    except Exception as e:
        logger.error(f"Unexpected error connecting to {host}: {e}", exc_info=True)
        return {"host": host, "error": e}


async def try_api_hosts(
    api_hosts: list[str],
    request_func: Callable[[str], Any],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    success_check: Callable[[Any], bool] | None = None,
) -> Any:
    """Try multiple API hosts in parallel and return the first successful result."""
    if not api_hosts:
        raise APIFailoverError("No API hosts provided")

    # Create tasks for all API hosts with individual timeouts
    tasks: set[asyncio.Task] = set()
    for host in api_hosts:
        try:
            task = asyncio.create_task(
                _safe_request_with_timeout(
                    host=host,
                    request_func=request_func,
                    timeout_seconds=timeout_seconds,
                )
            )
            tasks.add(task)
        except Exception as e:
            logger.warning(f"Failed to create task for host {host}: {e}")
            continue

    if not tasks:
        raise APIFailoverError("Failed to create any API request tasks")

    errors: list[tuple[str, Exception]] = []

    try:
        # Wait for tasks to complete one by one
        while tasks:
            done, tasks = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

            for task in done:
                try:
                    result = await task
                    host = result.get("host", "unknown")

                    # Check if this is an error result
                    if "error" in result:
                        error = result["error"]
                        logger.warning(f"API request to {host} failed: {error}")
                        errors.append((host, error))
                        continue

                    # Extract the actual result
                    actual_result = result.get("result")

                    # Validate the result if a success check is provided
                    if success_check and not success_check(actual_result):
                        logger.warning(f"API request to {host} returned invalid result")
                        errors.append((host, ValueError("Invalid result from API")))
                        continue

                    # Success! Cancel remaining tasks and return
                    logger.info(f"Successfully connected to API host: {host}")
                    for remaining_task in tasks:
                        remaining_task.cancel()
                        try:
                            await remaining_task
                        except asyncio.CancelledError:
                            pass

                    return actual_result

                except asyncio.CancelledError:
                    continue
                except Exception as e:
                    logger.error(f"Unexpected error processing task result: {e}", exc_info=True)
                    errors.append(("unknown", e))
                    continue

    finally:
        # Ensure all tasks are cancelled
        for task in tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

    # If we get here, all hosts failed
    error_summary = "; ".join([f"{host}: {str(error)}" for host, error in errors])
    raise APIFailoverError(f"All API hosts failed. Errors: {error_summary}")


async def try_url_check(
    urls: list[str],
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    socket_family: int | None = None,
) -> dict[str, Any]:
    """Check multiple URLs in parallel and return the first successful connection."""

    async def check_single_url(url: str) -> dict[str, Any]:
        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        connector_kwargs = {}
        if socket_family is not None:
            connector_kwargs["family"] = socket_family

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(**connector_kwargs),
            timeout=timeout,
        ) as session:
            async with session.get(url) as resp:
                # Accept 404 as success for some endpoints (like Quad9)
                if resp.status in (200, 404):
                    return {"result": True, "status": resp.status, "url": url, "headers": dict(resp.headers)}
                else:
                    resp.raise_for_status()
                    return {"result": True, "status": resp.status, "url": url, "headers": dict(resp.headers)}

    try:
        result = await try_api_hosts(
            api_hosts=urls,
            request_func=check_single_url,
            timeout_seconds=timeout_seconds,
            success_check=lambda r: r.get("result") is True,
        )
        return result
    except APIFailoverError as e:
        logger.warning(f"All URL checks failed: {e}")
        return {"result": False, "reason": str(e)}
    except Exception as e:
        logger.error(f"Unexpected error in URL check: {e}", exc_info=True)
        return {"result": False, "reason": str(e)}


http_app = FastAPI()
app = AlephApp(http_app=http_app)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize cache as None - will be created during startup event
cache: VmCache | None = None
startup_lifespan_executed: bool = False

cache = VmCache()


@app.on_event("startup")
async def startup_event() -> None:
    global startup_lifespan_executed
    startup_lifespan_executed = True


def get_cache():
    """Get or create the cache instance on-demand (lazy import + lazy initialization)."""
    global cache
    if cache is None:
        try:
            cache = VmCache()
            logger.info("Cache initialized on-demand")
        except Exception as e:
            logger.warning(f"Failed to initialize cache: {e}")
            # Don't retry - return None so endpoint can handle it
    return cache


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
    """Connect to the Quad9 VPN provider using their IPv4 address."""
    ipv4_host = "9.9.9.9"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ipv4_host, 53))
        return {"result": True}
    except TimeoutError:
        logger.warning(f"Socket connection for host {ipv4_host} failed")
        return {"result": False}


@app.get("/ip/6")
async def connect_ipv6():
    """Connect to IPv6 DNS providers using their IPv6 addresses.
    Tests IPv6 connectivity by trying multiple providers in parallel.
    """
    ipv6_hosts: list[str] = [
        "https://[2620:fe::fe]",  # Quad9 DNS service
        "https://[2606:4700:4700::1111]",  # Cloudflare DNS service
    ]
    return await try_url_check(urls=ipv6_hosts, timeout_seconds=5, socket_family=socket.AF_INET6)


async def check_url(internet_host: str, timeout_seconds: int = 5, socket_family=socket.AF_INET):
    """Check the connectivity of a single URL."""
    timeout = aiohttp.ClientTimeout(total=timeout_seconds)
    tcp_connector = aiohttp.TCPConnector(family=socket_family)
    async with aiohttp.ClientSession(timeout=timeout, connector=tcp_connector) as session:
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
    internet_hosts: list[str] = [
        "https://aleph.im/",
        "https://ethereum.org/en/",
        "https://ipfs.io/",
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
    """Get a message from the Aleph.im network."""
    item_hash = "3fc0aa9569da840c43e7bd2033c3c580abb46b007527d6d20f2d4e98e867f7af"

    async def fetch_message(api_host: str):
        """Fetch a message from a specific API host."""
        async with AlephHttpClient(api_server=api_host) as client:
            message = await client.get_message(
                item_hash=item_hash,
                message_type=ProgramMessage,
            )
            return message.dict()

    try:
        result = await try_api_hosts(
            api_hosts=ALEPH_API_HOSTS,
            request_func=fetch_message,
            timeout_seconds=10,
        )
        return result
    except APIFailoverError as e:
        logger.error(f"Failed to fetch message from all API hosts: {e}")
        return JSONResponse(status_code=503, content={"error": "All API hosts unavailable", "details": str(e)})


@app.post("/post_a_message")
async def post_with_remote_account():
    """Post a message on the Aleph.im network using the remote account of the host."""
    try:
        account = await RemoteAccount.from_crypto_host(host="http://localhost", unix_socket="/tmp/socat-socket")
    except aiohttp.client_exceptions.UnixClientConnectorError:
        return JSONResponse(status_code=500, content={"error": "Could not connect to the remote account"})
    except Exception as e:
        logger.error(f"Failed to create remote account: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": f"Failed to create account: {str(e)}"})

    async def post_message(api_host: str) -> tuple[PostMessage, MessageStatus]:
        """Post a message to a specific API host."""
        content = {
            "date": datetime.now(tz=timezone.utc).isoformat(),
            "test": True,
            "answer": 42,
            "something": "interesting",
        }
        async with AuthenticatedAlephHttpClient(account=account, api_server=api_host) as client:
            message, status = await client.create_post(
                post_content=content,
                post_type="test",
                ref=None,
                channel="TEST",
                inline=True,
                storage_engine=StorageEnum.storage,
                sync=True,
            )

            return message, status

    try:
        message, status = await try_api_hosts(
            api_hosts=ALEPH_API_HOSTS,
            request_func=post_message,
            timeout_seconds=15,
            success_check=lambda result: result[1] == MessageStatus.PROCESSED,
        )
        if status != MessageStatus.PROCESSED:
            return JSONResponse(status_code=500, content={"error": f"Message status: {status}"})
        return {"message": message}
    except APIFailoverError as e:
        logger.error(f"Failed to post message to all API hosts: {e}")
        return JSONResponse(status_code=503, content={"error": "All API hosts unavailable", "details": str(e)})


@app.post("/post_a_message_local_account")
async def post_with_local_account():
    """Post a message on the Aleph.im network using a local private key."""
    from aleph.sdk.chains.ethereum import get_fallback_account

    try:
        account = get_fallback_account()
    except Exception as e:
        logger.error(f"Failed to get fallback account: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": f"Failed to create account: {str(e)}"})

    async def post_message(api_host: str) -> tuple[PostMessage, MessageStatus]:
        """Post a message to a specific API host."""
        content = {
            "date": datetime.now(tz=timezone.utc).isoformat(),
            "test": True,
            "answer": 42,
            "something": "interesting",
        }
        async with AuthenticatedAlephHttpClient(
            account=account, api_server=api_host, allow_unix_sockets=False
        ) as client:
            message, status = await client.create_post(
                post_content=content,
                post_type="test",
                ref=None,
                channel="TEST",
                inline=True,
                storage_engine=StorageEnum.storage,
                sync=True,
            )
            return message, status

    try:
        message, status = await try_api_hosts(
            api_hosts=ALEPH_API_HOSTS,
            request_func=post_message,
            timeout_seconds=15,
            success_check=lambda result: result[1] == MessageStatus.PROCESSED,
        )
        if status != MessageStatus.PROCESSED:
            return JSONResponse(status_code=500, content={"error": f"Message status: {status}"})
        return {"message": message}
    except APIFailoverError as e:
        logger.error(f"Failed to post message to all API hosts: {e}")
        return JSONResponse(status_code=503, content={"error": "All API hosts unavailable", "details": str(e)})


@app.post("/post_a_file")
async def post_a_file():
    """Store a file on the Aleph.im network using a local account."""
    from aleph.sdk.chains.ethereum import get_fallback_account

    """ OLD
    account = get_fallback_account()
    file_path = Path(__file__).absolute()

    async with AuthenticatedAlephHttpClient(account=account) as client:
        message, status = await client.create_store(
            file_path=file_path,
            ref=None,
            channel="TEST",
            storage_engine=StorageEnum.storage,
            sync=True,
        )

    if status != MessageStatus.PROCESSED:
        return JSONResponse(status_code=500, content={"error": f"Message status: {status}"})

    return {"message": message}
    """
    try:
        account = get_fallback_account()
    except Exception as e:
        logger.error(f"Failed to get fallback account: {e}", exc_info=True)
        return JSONResponse(status_code=500, content={"error": f"Failed to create account: {str(e)}"})

    file_path = Path(__file__).absolute()

    async def store_file(api_host: str) -> tuple[StoreMessage, MessageStatus]:
        """Store a file on a specific API host."""
        async with AuthenticatedAlephHttpClient(account=account, api_server=api_host) as client:
            message, status = await client.create_store(
                file_path=file_path,
                ref=None,
                channel="TEST",
                storage_engine=StorageEnum.storage,
                sync=True,
            )
            return message, status

    try:
        message, status = await try_api_hosts(
            api_hosts=ALEPH_API_HOSTS,
            request_func=store_file,
            timeout_seconds=20,
            success_check=lambda result: result[1] == MessageStatus.PROCESSED,
        )
        if status != MessageStatus.PROCESSED:
            return JSONResponse(status_code=500, content={"error": f"Message status: {status}"})
        return {"message": message}
    except APIFailoverError as e:
        logger.error(f"Failed to store file to all API hosts: {e}")
        return JSONResponse(status_code=503, content={"error": "All API hosts unavailable", "details": str(e)})


@app.get("/sign_a_message")
async def sign_a_message():
    """Sign a message using a locally managed account within the virtual machine."""
    # FIXME: Broken, fixing this depends on https://github.com/aleph-im/aleph-sdk-python/pull/120
    from aleph.sdk.chains.ethereum import get_fallback_account

    account = get_fallback_account()
    message = {"hello": "world", "chain": "ETH"}
    signed_message = await account.sign_message(message)
    return {"message": signed_message}


@app.get("/cache/get/{key}")
async def get_from_cache(key: str):
    """Get data in the VM cache"""
    cache_instance = get_cache()
    if cache_instance is None:
        return JSONResponse(status_code=503, content={"error": "Cache not available"})
    return await cache_instance.get(key)


@app.get("/cache/set/{key}/{value}")
async def store_in_cache(key: str, value: str):
    """Store data in the VM cache"""
    cache_instance = get_cache()
    if cache_instance is None:
        return JSONResponse(status_code=503, content={"error": "Cache not available"})
    return await cache_instance.set(key, value)


@app.get("/cache/remove/{key}")
async def remove_from_cache(key: str):
    """Store data in the VM cache"""
    cache_instance = get_cache()
    if cache_instance is None:
        return JSONResponse(status_code=503, content={"error": "Cache not available"})
    result = await cache_instance.delete(key)
    return result == 1


@app.get("/cache/keys")
async def keys_from_cache(pattern: str = "*"):
    """List keys from the VM cache"""
    cache_instance = get_cache()
    if cache_instance is None:
        return JSONResponse(status_code=503, content={"error": "Cache not available"})
    return await cache_instance.keys(pattern)


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
    """Handle Aleph events."""
    logger.info(f"Received aleph_event: {event}")

    async def check_api_info(api_host: str) -> bool:
        """Check if API info endpoint is accessible."""
        try:
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
                async with session.get(f"{api_host}/api/v0/info/public.json") as resp:
                    resp.raise_for_status()
                    return True
        except Exception as e:
            logger.warning(f"Failed to check API info at {api_host}: {e}")
            return False

    try:
        await try_api_hosts(
            api_hosts=ALEPH_API_HOSTS,
            request_func=check_api_info,
            timeout_seconds=5,
            success_check=lambda result: result is True,
        )
        return {"result": "Good"}
    except APIFailoverError as e:
        logger.error(f"All API hosts failed for event handling: {e}")
        return {"result": "Bad", "error": str(e)}
