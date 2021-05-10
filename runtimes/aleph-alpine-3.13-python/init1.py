#!/usr/bin/python3

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
from typing import Optional, Dict, Any, Tuple, Iterator

import msgpack


class Encoding:
    plain = "plain"
    zip = "zip"


@dataclass
class RunCodePayload:
    code: bytes
    input_data: Optional[bytes]
    entrypoint: str
    encoding: str
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

print("init1.py is launching")


async def run_python_code_http(code: bytes, input_data: Optional[bytes],
                               entrypoint: str, encoding: str, scope: dict
                               ) ->  Tuple[Dict, Dict, str, Optional[bytes]]:
    if encoding == Encoding.zip:
        # Unzip in /opt and import the entrypoint from there
        open("/opt/archive.zip", "wb").write(code)
        os.system("unzip /opt/archive.zip -d /opt")
        sys.path.append("/opt")
        module_name, app_name = entrypoint.split(":", 1)
        module = __import__(module_name)
        app = getattr(module, app_name)
    elif encoding == Encoding.plain:
        # Execute the code and extract the entrypoint
        locals: Dict[str, Any] = {}
        exec(code, globals(), locals)
        app = locals[entrypoint]
    else:
        raise ValueError(f"Unknown encoding '{encoding}'")

    if input_data:
        # Unzip in /data
        open("/opt/input.zip", "wb").write(input_data)
        os.makedirs("/data", exist_ok=True)
        os.system("unzip /opt/input.zip -d /data")

    with StringIO() as buf, redirect_stdout(buf):
        # Execute in the same process, saves ~20ms than a subprocess
        async def receive():
            pass

        send_queue: asyncio.Queue = asyncio.Queue()

        async def send(dico):
            await send_queue.put(dico)

        # TODO: Better error handling
        await app(scope, receive, send)
        headers: Dict = await send_queue.get()
        body: Dict = await send_queue.get()
        output = buf.getvalue()

    os.makedirs("/data", exist_ok=True)
    open('/data/hello.txt', 'w').write("Hello !")

    output_data: bytes
    if os.listdir('/data'):
        make_archive("/opt/output", 'zip', "/data")
        with open("/opt/output.zip", "rb") as output_zipfile:
            output_data = output_zipfile.read()
    else:
        output_data = b''

    return headers, body, output, output_data


def process_instruction(instruction: bytes) -> Iterator[bytes]:
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
        msg_ = msgpack.loads(instruction, raw=False)
        payload = RunCodePayload(**msg_)

        try:
            headers: Dict
            body: Dict
            output: str
            output_data: Optional[bytes]

            headers, body, output, output_data = asyncio.get_event_loop().run_until_complete(
                run_python_code_http(
                    payload.code, input_data=payload.input_data,
                    entrypoint=payload.entrypoint, encoding=payload.encoding, scope=payload.scope
                )
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
    while True:
        client, addr = s.accept()
        data = client.recv(1000_1000)  # Max 1 Mo
        print("CID: {} port:{} data: {}".format(addr[0], addr[1], len(data)))

        print("Init received msg <<<\n\n", data, "\n\n>>>")
        for result in process_instruction(instruction=data):
            client.send(result)

        print("...DONE")
        client.close()


if __name__ == '__main__':
    main()
