#!/usr/bin/python3 -OO

import logging
logging.basicConfig(
    level=logging.DEBUG,
    format="%(relativeCreated)4f |V %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

logger.debug("Imports starting")

import asyncio
import os
import socket
import subprocess
import sys
import traceback
from contextlib import redirect_stdout
from dataclasses import dataclass
from io import StringIO
from os import system
from shutil import make_archive
from typing import Optional, Dict, Any, Tuple, Iterator, List, NewType

import msgpack

logger.debug("Imports finished")

ASGIApplication = NewType('AsgiApplication', Any)


class Encoding:
    plain = "plain"
    zip = "zip"


@dataclass
class ConfigurationPayload:
    ip: Optional[str]
    route: Optional[str]
    dns_servers: List[str]
    code: bytes
    encoding: Encoding
    entrypoint: str
    input_data: bytes


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
os.environ["ALEPH_API_UNIX_SOCKET"] = "/tmp/socat-socket"

logger.debug("init1.py is launching")


def setup_network(ip: Optional[str], route: Optional[str], dns_servers: List[str] = []):
    """Setup the system with info from the host."""
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
    system(f"ip addr add {ip}/24 dev eth0")
    system("ip link set eth0 up")

    if route:
        system(f"ip route add default via {route} dev eth0")
        logger.debug("IP and route set")
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
            os.system("unzip /opt/input.zip -d /data")


def setup_code(code: bytes, encoding: Encoding, entrypoint: str) -> ASGIApplication:
    logger.debug("Extracting code")
    if encoding == Encoding.zip:
        # Unzip in /opt and import the entrypoint from there
        if not os.path.exists("/opt/archive.zip"):
            open("/opt/archive.zip", "wb").write(code)
            logger.debug("Run unzip")
            os.system("unzip /opt/archive.zip -d /opt")
        sys.path.append("/opt")
        module_name, app_name = entrypoint.split(":", 1)
        logger.debug("import module")
        module = __import__(module_name)
        app: ASGIApplication = getattr(module, app_name)
    elif encoding == Encoding.plain:
        # Execute the code and extract the entrypoint
        locals: Dict[str, Any] = {}
        exec(code, globals(), locals)
        app: ASGIApplication = locals[entrypoint]
    else:
        raise ValueError(f"Unknown encoding '{encoding}'")
    return app


async def run_python_code_http(application: ASGIApplication, scope: dict
                               ) ->  Tuple[Dict, Dict, str, Optional[bytes]]:

    logger.debug("Running code")
    with StringIO() as buf, redirect_stdout(buf):
        # Execute in the same process, saves ~20ms than a subprocess
        async def receive():
            pass

        send_queue: asyncio.Queue = asyncio.Queue()

        async def send(dico):
            await send_queue.put(dico)

        # TODO: Better error handling
        await application(scope, receive, send)
        headers: Dict = await send_queue.get()
        body: Dict = await send_queue.get()
        output = buf.getvalue()

    logger.debug("Getting output data")
    output_data: bytes
    if os.path.isdir('/data') and os.listdir('/data'):
        make_archive("/opt/output", 'zip', "/data")
        with open("/opt/output.zip", "rb") as output_zipfile:
            output_data = output_zipfile.read()
    else:
        output_data = b''

    logger.debug("Returning result")
    return headers, body, output, output_data


def process_instruction(instruction: bytes, application: ASGIApplication) -> Iterator[bytes]:
    if instruction == b"halt":
        system("sync")
        yield b"STOP\n"
        sys.exit()
    elif instruction.startswith(b"!"):
        # Execute shell commands in the form `!ls /`
        msg = instruction[1:].decode()
        try:
            process_output = subprocess.check_output(msg, stderr=subprocess.STDOUT, shell=True)
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

            headers, body, output, output_data = asyncio.get_event_loop().run_until_complete(
                run_python_code_http(application=application, scope=payload.scope)
            )
            result = {
                "headers": headers,
                "body": body,
                "output": output,
                "output_data": output_data,
            }
            yield msgpack.dumps(result, use_bin_type=True)
        except Exception as error:
            yield msgpack.dumps({
                "error": str(error),
                "traceback": str(traceback.format_exc()),
                "output": output
            })


def main():
    client, addr = s.accept()
    data = client.recv(1000_1000)
    msg_ = msgpack.loads(data, raw=False)

    payload = ConfigurationPayload(**msg_)
    setup_network(payload.ip, payload.route, payload.dns_servers)
    setup_input_data(payload.input_data)
    app: ASGIApplication = setup_code(payload.code, payload.encoding, payload.entrypoint)

    while True:
        client, addr = s.accept()
        data = client.recv(1000_1000)  # Max 1 Mo
        logger.debug("CID: {} port:{} data: {}".format(addr[0], addr[1], len(data)))

        logger.debug("Init received msg")
        if logger.level <= logging.DEBUG:
            data_to_print = f"{data[:500]}..." if len(data) > 500 else data
            logger.debug(f"<<<\n\n{data_to_print}\n\n>>>")

        for result in process_instruction(instruction=data, application=app):
            client.send(result)

        logger.debug("...DONE")
        client.close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    main()
