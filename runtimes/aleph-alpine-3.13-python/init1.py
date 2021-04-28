#!/usr/bin/python3
import asyncio
import json
import os
import socket
import subprocess
import sys
import traceback
from base64 import b64decode
from contextlib import redirect_stdout
from io import StringIO
from os import system
from shutil import make_archive
from typing import Optional, Dict, Any, Tuple

import msgpack

s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s.bind((socket.VMADDR_CID_ANY, 52))
s.listen()

# Send we are ready
s0 = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
s0.connect((2, 52))
s0.close()

print("INIT1 READY")


class Encoding:
    plain = "plain"
    zip = "zip"


async def run_python_code_http(code: str, input_data: Optional[str],
                               entrypoint: str, encoding: str, scope: dict
                               ) ->  Tuple[Dict, Dict, str, Optional[bytes]]:
    if encoding == Encoding.zip:
        # Unzip in /opt and import the entrypoint from there
        decoded: bytes = b64decode(code)
        open("/opt/archive.zip", "wb").write(decoded)
        del decoded
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
        decoded_data: bytes = b64decode(code)
        open("/opt/input.zip", "wb").write(decoded_data)
        del decoded_data
        os.makedirs("/data", exist_ok=True)
        os.system("unzip /opt/input.zip -d /data")

    with StringIO() as buf, redirect_stdout(buf):
        # Execute in the same process, saves ~20ms than a subprocess
        async def receive():
            pass

        send_queue: asyncio.Queue = asyncio.Queue()

        async def send(dico):
            await send_queue.put(dico)

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


while True:
    client, addr = s.accept()
    data = client.recv(1000_1000)  # Max 1 Mo
    print("CID: {} port:{} data: {}".format(addr[0], addr[1], data.decode()))

    msg = data.decode().strip()
    del data

    print("msg", [msg])
    if msg == "halt":
        system("sync")
        client.send(b"STOP\n")
        sys.exit()
    elif msg.startswith("!"):
        # Shell
        msg = msg[1:]
        try:
            process_output = subprocess.check_output(msg, stderr=subprocess.STDOUT, shell=True)
            client.send(process_output)
        except subprocess.CalledProcessError as error:
            client.send(str(error).encode() + b"\n" + error.output)
    else:
        # Python
        msg_ = json.loads(msg)
        code = msg_["code"]
        input_data = msg_.get("input_data")
        entrypoint = msg_["entrypoint"]
        scope = msg_["scope"]
        encoding = msg_["encoding"]
        try:
            headers: Dict
            body: Dict
            output: str
            output_data: Optional[bytes]

            headers, body, output, output_data = asyncio.get_event_loop().run_until_complete(
                run_python_code_http(
                    code, input_data=input_data,
                    entrypoint=entrypoint, encoding=encoding, scope=scope
                )
            )
            result = {
                "headers": headers,
                "body": body,
                "output": output,
                "output_data": output_data,
            }
            client.send(msgpack.packb(result, use_bin_type=True))
        except Exception as error:
            client.send(str(error).encode() + str(traceback.format_exc()).encode())

    print("...DONE")
    client.close()
