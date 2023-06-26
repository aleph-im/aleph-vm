#!/usr/bin/python3 -OO
import base64
import logging
from pathlib import Path

logging.basicConfig(
    level=logging.DEBUG,
    format="%(relativeCreated)4f |V %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

logger.debug("Imports starting")

import asyncio
import ctypes
import os
import socket
import subprocess
import sys
import traceback
from contextlib import redirect_stdout
from dataclasses import dataclass, field
from enum import Enum
from io import StringIO
from os import system
from shutil import make_archive
from typing import Any, AsyncIterable, Dict, List, NewType, Optional, Tuple, Union

import aiohttp
import msgpack

logger.debug("Imports finished")

ASGIApplication = NewType("ASGIApplication", Any)


class Encoding(str, Enum):
    plain = "plain"
    zip = "zip"
    squashfs = "squashfs"


class Interface(str, Enum):
    asgi = "asgi"
    executable = "executable"


class ShutdownException(Exception):
    pass


@dataclass
class Volume:
    mount: str
    device: str
    read_only: bool


@dataclass
class ConfigurationPayload:
    input_data: bytes
    interface: Interface
    vm_hash: str
    code: bytes = None
    encoding: Encoding = None
    entrypoint: str = None
    ip: Optional[str] = None
    route: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None


@dataclass
class RunCodePayload:
    scope: Dict


# Open a socket to receive instructions from the host
s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.bind((socket.VMADDR_CID_ANY, 52))
s.listen()

# Send the host that we are ready
s0 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s0.connect((2, 52))
s0.close()

# Configure aleph-client to use the guest API
os.environ["ALEPH_API_HOST"] = "http://localhost"
os.environ["ALEPH_API_UNIX_SOCKET"] = "/tmp/socat-socket"
os.environ["ALEPH_REMOTE_CRYPTO_HOST"] = "http://localhost"
os.environ["ALEPH_REMOTE_CRYPTO_UNIX_SOCKET"] = "/tmp/socat-socket"

logger.debug("init1.py is launching")


def setup_hostname(hostname: str):
    os.environ["ALEPH_ADDRESS_TO_USE"] = hostname
    system(f"hostname {hostname}")


def setup_variables(variables: Optional[Dict[str, str]]):
    if variables is None:
        return
    for key, value in variables.items():
        os.environ[key] = value


def setup_network(
    ip: Optional[str], route: Optional[str], dns_servers: Optional[List[str]] = None
):
    """Setup the system with info from the host."""
    dns_servers = dns_servers or []
    if not os.path.exists("/sys/class/net/eth0"):
        logger.info("No network interface eth0")
        return

    if not ip:
        logger.info("No network IP")
        return

    logger.debug("Setting up networking")
    system("ip addr add 127.0.0.1/8 dev lo brd + scope host")
    system("ip addr add ::1/128 dev lo")
    system("ip link set lo up")
    if "/" in ip:
        # Forward compatibility with future supervisors that pass the mask with the IP.
        system(f"ip addr add {ip} dev eth0")
    else:
        logger.warning(
            "Not passing the mask with the IP is deprecated and will be unsupported"
        )
        system(f"ip addr add {ip}/24 dev eth0")
    system("ip link set eth0 up")

    if route:
        system(f"ip route add default via {route} dev eth0")
        logger.debug(f"IP and route set: {ip} via {route}")
    else:
        logger.warning("IP set with no network route")

    with open("/etc/resolv.conf", "wb") as resolvconf_fd:
        for server in dns_servers:
            resolvconf_fd.write(f"nameserver {server}\n".encode())


def setup_input_data(input_data: bytes):
    logger.debug("Extracting data")
    if input_data:
        # Unzip in /data
        if not os.path.exists("/opt/input.zip"):
            open("/opt/input.zip", "wb").write(input_data)
            os.makedirs("/data", exist_ok=True)
            os.system("unzip -q /opt/input.zip -d /data")


def setup_volumes(volumes: List[Volume]):
    for volume in volumes:
        logger.debug(f"Mounting /dev/{volume.device} on {volume.mount}")
        os.makedirs(volume.mount, exist_ok=True)
        if volume.read_only:
            system(f"mount -t squashfs -o ro /dev/{volume.device} {volume.mount}")
        else:
            system(f"mount -o rw /dev/{volume.device} {volume.mount}")

    system("mount")


def setup_code_asgi(
    code: bytes, encoding: Encoding, entrypoint: str
) -> ASGIApplication:
    # Allow importing packages from /opt/packages
    sys.path.append("/opt/packages")

    logger.debug("Extracting code")
    app: ASGIApplication
    if encoding == Encoding.squashfs:
        sys.path.append("/opt/code")
        module_name, app_name = entrypoint.split(":", 1)
        logger.debug("import module")
        module = __import__(module_name)
        for level in module_name.split(".")[1:]:
            module = getattr(module, level)
        app = getattr(module, app_name)
    elif encoding == Encoding.zip:
        # Unzip in /opt and import the entrypoint from there
        if not os.path.exists("/opt/archive.zip"):
            open("/opt/archive.zip", "wb").write(code)
            logger.debug("Run unzip")
            os.system("unzip -q /opt/archive.zip -d /opt")
        sys.path.append("/opt")
        module_name, app_name = entrypoint.split(":", 1)
        logger.debug("import module")
        module = __import__(module_name)
        for level in module_name.split(".")[1:]:
            module = getattr(module, level)
        app = getattr(module, app_name)
    elif encoding == Encoding.plain:
        # Execute the code and extract the entrypoint
        locals: Dict[str, Any] = {}
        exec(code, globals(), locals)
        app = locals[entrypoint]
    else:
        raise ValueError(f"Unknown encoding '{encoding}'")
    return app


def setup_code_executable(
    code: bytes, encoding: Encoding, entrypoint: str
) -> subprocess.Popen:
    logger.debug("Extracting code")
    if encoding == Encoding.squashfs:
        path = f"/opt/code/{entrypoint}"
        if not os.path.isfile(path):
            os.system("find /opt/code/")
            raise FileNotFoundError(f"No such file: {path}")
        os.system(f"chmod +x {path}")
    elif encoding == Encoding.zip:
        open("/opt/archive.zip", "wb").write(code)
        logger.debug("Run unzip")
        os.makedirs("/opt/code", exist_ok=True)
        os.system("unzip /opt/archive.zip -d /opt/code")
        path = f"/opt/code/{entrypoint}"
        if not os.path.isfile(path):
            os.system("find /opt/code")
            raise FileNotFoundError(f"No such file: {path}")
        os.system(f"chmod +x {path}")
    elif encoding == Encoding.plain:
        os.makedirs("/opt/code", exist_ok=True)
        path = f"/opt/code/executable {entrypoint}"
        open(path, "wb").write(code)
        os.system(f"chmod +x {path}")
    else:
        raise ValueError(f"Unknown encoding '{encoding}'. This should never happen.")

    process = subprocess.Popen(path)
    return process


def setup_code(
    code: Optional[bytes],
    encoding: Optional[Encoding],
    entrypoint: Optional[str],
    interface: Interface,
) -> Union[ASGIApplication, subprocess.Popen]:
    if interface == Interface.asgi:
        return setup_code_asgi(code=code, encoding=encoding, entrypoint=entrypoint)
    elif interface == Interface.executable:
        return setup_code_executable(
            code=code, encoding=encoding, entrypoint=entrypoint
        )
    else:
        raise ValueError("Invalid interface. This should never happen.")


async def run_python_code_http(
    application: ASGIApplication, scope: dict
) -> Tuple[Dict, Dict, str, Optional[bytes]]:
    logger.debug("Running code")
    with StringIO() as buf, redirect_stdout(buf):
        # Execute in the same process, saves ~20ms than a subprocess

        # The body should not be part of the ASGI scope itself
        body: bytes = scope.pop("body")

        async def receive():
            type_ = (
                "http.request"
                if scope["type"] in ("http", "websocket")
                else "aleph.message"
            )
            return {"type": type_, "body": body, "more_body": False}

        send_queue: asyncio.Queue = asyncio.Queue()

        async def send(dico):
            await send_queue.put(dico)

        # TODO: Better error handling
        logger.debug("Awaiting application...")
        await application(scope, receive, send)

        logger.debug("Waiting for headers")
        headers: Dict
        if scope["type"] == "http":
            headers = await send_queue.get()
        else:
            headers = {}

        logger.debug("Waiting for body")
        body: Dict = await send_queue.get()

        logger.debug("Waiting for buffer")
        output = buf.getvalue()

        logger.debug(f"Headers {headers}")
        logger.debug(f"Body {body}")
        logger.debug(f"Output {output}")

    logger.debug("Getting output data")
    output_data: bytes
    if os.path.isdir("/data") and os.listdir("/data"):
        make_archive("/opt/output", "zip", "/data")
        with open("/opt/output.zip", "rb") as output_zipfile:
            output_data = output_zipfile.read()
    else:
        output_data = b""

    logger.debug("Returning result")
    return headers, body, output, output_data


async def make_request(session, scope):
    async with session.request(
        scope["method"],
        url="http://localhost:8080{}".format(scope["path"]),
        params=scope["query_string"],
        headers=[(a.decode("utf-8"), b.decode("utf-8")) for a, b in scope["headers"]],
        data=scope.get("body", None),
    ) as resp:
        headers = {
            "headers": [
                (a.encode("utf-8"), b.encode("utf-8")) for a, b in resp.headers.items()
            ],
            "status": resp.status,
        }
        body = {"body": await resp.content.read()}
    return headers, body


def show_loading():
    body = {
        "body": Path("/root/loading.html").read_text()
    }
    headers = {
        "headers": [
            [b'Content-Type', b'text/html'],
            [b'Connection', b'keep-alive'],
            [b'Keep-Alive', b'timeout=5'],
            [b'Transfer-Encoding', b'chunked']
        ],
        "status": 503,
    }
    return headers, body


async def run_executable_http(scope: dict) -> Tuple[Dict, Dict, str, Optional[bytes]]:
    logger.debug("Calling localhost")

    tries = 0
    headers = None
    body = None

    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not body:
            try:
                tries += 1
                headers, body = await make_request(session, scope)
            except aiohttp.ClientConnectorError:
                if tries > 20:
                    headers, body = show_loading()
                await asyncio.sleep(0.05)

    output = ""  # Process stdout is not captured per request
    output_data = None
    logger.debug("Returning result")
    return headers, body, output, output_data


async def process_instruction(
    instruction: bytes,
    interface: Interface,
    application: Union[ASGIApplication, subprocess.Popen],
) -> AsyncIterable[bytes]:
    if instruction == b"halt":
        logger.info("Received halt command")
        system("sync")
        logger.debug("Filesystems synced")
        if isinstance(application, subprocess.Popen):
            application.terminate()
            logger.debug("Application terminated")
            # application.communicate()
        else:
            # Close the cached session in aleph_client:
            from aleph_client.asynchronous import get_fallback_session

            session: aiohttp.ClientSession = get_fallback_session()
            await session.close()
            logger.debug("Aiohttp cached session closed")
        yield b"STOP\n"
        logger.debug("Supervisor informed of halt")
        raise ShutdownException
    elif instruction.startswith(b"!"):
        # Execute shell commands in the form `!ls /`
        msg = instruction[1:].decode()
        try:
            process_output = subprocess.check_output(
                msg, stderr=subprocess.STDOUT, shell=True
            )
            yield process_output
        except subprocess.CalledProcessError as error:
            yield str(error).encode() + b"\n" + error.output
    else:
        # Python
        logger.debug("msgpack.loads (")
        msg_ = msgpack.loads(instruction, raw=False)
        logger.debug("msgpack.loads )")
        payload = RunCodePayload(**msg_)

        output: Optional[str] = None
        try:
            headers: Dict
            body: Dict
            output_data: Optional[bytes]

            if interface == Interface.asgi:
                headers, body, output, output_data = await run_python_code_http(
                    application=application, scope=payload.scope
                )
            elif interface == Interface.executable:
                headers, body, output, output_data = await run_executable_http(
                    scope=payload.scope
                )
            else:
                raise ValueError("Unknown interface. This should never happen")

            result = {
                "headers": headers,
                "body": body,
                "output": output,
                "output_data": output_data,
            }
            yield msgpack.dumps(result, use_bin_type=True)
        except Exception as error:
            yield msgpack.dumps(
                {
                    "error": str(error),
                    "traceback": str(traceback.format_exc()),
                    "output": output,
                }
            )


def receive_data_length(client) -> int:
    """Receive the length of the data to follow."""
    buffer = b""
    for _ in range(9):
        byte = client.recv(1)
        if byte == b"\n":
            break
        else:
            buffer += byte
    return int(buffer)


def load_configuration(data: bytes) -> ConfigurationPayload:
    msg_ = msgpack.loads(data, raw=False)
    msg_["volumes"] = [Volume(**volume_dict) for volume_dict in msg_.get("volumes")]
    return ConfigurationPayload(**msg_)


def receive_config(client) -> ConfigurationPayload:
    length = receive_data_length(client)
    data = b""
    while len(data) < length:
        data += client.recv(1024 * 1024)
    return load_configuration(data)


def setup_system(config: ConfigurationPayload):
    # Linux host names are limited to 63 characters. We therefore use the base32 representation
    # of the item_hash instead of its common base16 representation.
    item_hash_binary: bytes = base64.b16decode(config.vm_hash.encode().upper())
    hostname = base64.b32encode(item_hash_binary).decode().strip("=").lower()
    setup_hostname(hostname)

    setup_variables(config.variables)
    setup_volumes(config.volumes)
    setup_network(config.ip, config.route, config.dns_servers)
    setup_input_data(config.input_data)
    logger.debug("Setup finished")


def umount_volumes(volumes: List[Volume]):
    "Umount user related filesystems"
    system("sync")
    for volume in volumes:
        logger.debug(f"Umounting /dev/{volume.device} on {volume.mount}")
        system(f"umount {volume.mount}")


async def main() -> None:
    client, addr = s.accept()

    logger.debug("Receiving setup...")
    config = receive_config(client)
    setup_system(config)

    try:
        app: Union[ASGIApplication, subprocess.Popen] = setup_code(
            config.code, config.encoding, config.entrypoint, config.interface
        )
        client.send(msgpack.dumps({"success": True}))
    except Exception as error:
        client.send(
            msgpack.dumps(
                {
                    "success": False,
                    "error": str(error),
                    "traceback": str(traceback.format_exc()),
                }
            )
        )
        logger.exception("Program could not be started")
        raise

    class ServerReference:
        "Reference used to close the server from within `handle_instruction"
        server: asyncio.AbstractServer

    server_reference = ServerReference()

    async def handle_instruction(reader, writer):
        data = await reader.read(1000_1000)  # Max 1 Mo

        logger.debug("Init received msg")
        if logger.level <= logging.DEBUG:
            data_to_print = f"{data[:500]}..." if len(data) > 500 else data
            logger.debug(f"<<<\n\n{data_to_print}\n\n>>>")

        try:
            async for result in process_instruction(
                instruction=data, interface=config.interface, application=app
            ):
                writer.write(result)
                await writer.drain()

                logger.debug("Instruction processed")
        except ShutdownException:
            logger.info("Initiating shutdown")
            writer.write(b"STOPZ\n")
            await writer.drain()
            logger.debug("Shutdown confirmed to supervisor")
            server_reference.server.close()
            logger.debug("Supervisor socket server closed")
        finally:
            writer.close()

    server = await asyncio.start_server(handle_instruction, sock=s)
    server_reference.server = server

    addr = server.sockets[0].getsockname()
    print(f"Serving on {addr}")

    try:
        async with server:
            await server.serve_forever()
    except asyncio.CancelledError:
        logger.debug("Server was properly cancelled")
    finally:
        logger.warning("System shutdown")
        server.close()
        logger.debug("Server closed")
        umount_volumes(config.volumes)
        logger.debug("User volumes unmounted")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncio.run(main())

    logger.info("Unmounting system filesystems")
    system("umount /dev/shm")
    system("umount /dev/pts")
    system("umount -a")

    logger.info("Sending reboot syscall")
    # Send reboot syscall, see man page
    # https://man7.org/linux/man-pages/man2/reboot.2.html
    libc = ctypes.CDLL(None)
    libc.syscall(169, 0xFEE1DEAD, 672274793, 0x4321FEDC, None)
    # The exit should not happen due to system halt.
    sys.exit(0)
