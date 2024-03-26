import json
import logging
import os
import socket
import subprocess
import sys
from datetime import datetime
from os import listdir
from pathlib import Path
from typing import Dict, Optional

import aiohttp
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pip._internal.operations.freeze import freeze
from pydantic import BaseModel
from starlette.responses import JSONResponse

# FIXME: This import fails to work in a VM when using pytest
# from aleph.sdk.chains.remote import RemoteAccount
from aleph.sdk.client import AlephClient, AuthenticatedAlephClient
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
async def startup_event():
    global startup_lifespan_executed
    startup_lifespan_executed = True


@app.get("/")
async def index():
    if os.path.exists("/opt/venv"):
        opt_venv = list(listdir("/opt/venv"))
    else:
        opt_venv = []
    return {
        "Example": "example_fastapi",
        "endpoints": [
            "/environ",
            "/messages",
            "/dns",
            "ip/address",
            "/ip/4",
            "/ip/6",
            "/internet",
            "/post_a_message",
            "/state/increment",
            "/wait-for/{delay}",
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
async def environ() -> Dict[str, str]:
    """List environment variables"""
    return dict(os.environ)


@app.get("/messages")
async def read_aleph_messages():
    """Read data from Aleph using the Aleph Client library."""
    async with AlephClient() as client:
        data = await client.get_messages(hashes=["f246f873c3e0f637a15c566e7a465d2ecbb83eaa024d54ccb8fb566b549a929e"])
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
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect(("9.9.9.9", 53))
    return {"result": True}


@app.get("/ip/6")
async def connect_ipv6():
    """Connect to the Quad9 VPN provider using their IPv6 address.
    The webserver on that address returns a 404 error, so we accept that response code.
    """
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
        async with session.get("https://[2620:fe::fe]") as resp:
            # We expect this endpoint to return a 404 error
            if resp.status != 404:
                resp.raise_for_status()
            return {"result": True, "headers": resp.headers}


@app.get("/internet")
async def read_internet():
    """Connect the aleph.im official website to check Internet connectivity."""
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
        async with session.get("https://aleph.im/") as resp:
            resp.raise_for_status()
            return {"result": resp.status, "headers": resp.headers}


@app.get("/post_a_message")
async def post_a_message():
    """Post a message on the Aleph network"""

    account = await RemoteAccount.from_crypto_host(host="http://localhost", unix_socket="/tmp/socat-socket")

    content = {
        "date": datetime.utcnow().isoformat(),
        "test": True,
        "answer": 42,
        "something": "interesting",
    }
    async with AuthenticatedAlephClient(
        account=account,
    ) as client:
        response = await client.create_post(
            post_content=content,
            post_type="test",
            ref=None,
            channel="TEST",
            inline=True,
            storage_engine=StorageEnum.storage,
        )
    return {
        "response": response,
    }


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
async def increment():
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
async def receive_post(data: Data):
    return str(data)


class CustomError(Exception):
    pass


@app.get("/raise")
def raise_error():
    """Raises an error to check that the init handles it properly without crashing"""
    raise CustomError("Whoops")


@app.get("/crash")
def crash():
    """Crash the entire VM in order to check that the supervisor can handle it"""
    sys.exit(1)


filters = [
    {
        # "sender": "0xB31B787AdA86c6067701d4C0A250c89C7f1f29A5",
        "channel": "TEST"
    }
]


@app.get("/platform/os")
def platform_os():
    return PlainTextResponse(content=Path("/etc/os-release").read_text())


@app.get("/platform/python")
def platform_python():
    return PlainTextResponse(content=sys.version)


@app.get("/platform/pip-freeze")
def platform_pip_freeze():
    return list(freeze())


@app.event(filters=filters)
async def aleph_event(event):
    print("aleph_event", event)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector()) as session:
        async with session.get("https://official.aleph.cloud/api/v0/info/public.json") as resp:
            print("RESP", resp)
            resp.raise_for_status()
    return {"result": "Good"}
