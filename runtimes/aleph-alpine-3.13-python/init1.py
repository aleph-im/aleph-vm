#!/usr/bin/python3
import asyncio
import json
import os
import socket
import subprocess
import sys
import traceback
from base64 import b64decode
from os import system
from io import StringIO
from contextlib import redirect_stdout

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


async def run_python_code_http(code: str, entrypoint: str, encoding: str, scope: dict):
    if encoding == Encoding.zip:
        # Unzip in /opt and import the entrypoint from there
        decoded: bytes = b64decode(code)
        open("/opt/archive.zip", "wb").write(decoded)
        os.system("unzip /opt/archive.zip -d /opt")
        sys.path.append("/opt")
        module_name, app_name = entrypoint.split(":", 1)
        module = __import__(module_name)
        app = getattr(module, app_name)
    elif encoding == Encoding.plain:
        # Execute the code and extract the entrypoint
        locals = {}
        exec(code, globals(), locals)
        app = locals[entrypoint]
    else:
        raise ValueError(f"Unknown encoding '{encoding}'")

    with StringIO() as buf, redirect_stdout(buf):
        # Execute in the same process, saves ~20ms than a subprocess
        async def receive():
            pass

        send_queue = asyncio.Queue()

        async def send(dico):
            await send_queue.put(dico)

        await app(scope, receive, send)
        headers = await send_queue.get()
        body = await send_queue.get()
        output = buf.getvalue()
    return headers, body, output


while True:
    client, addr = s.accept()
    data = client.recv(1000_1000)  # Max 1 Mo
    print("CID: {} port:{} data: {}".format(addr[0], addr[1], data))

    msg = data.decode().strip()

    print("msg", [msg])
    if msg == "halt":
        system("sync")
        client.send(b"STOP\n")
        sys.exit()
    elif msg.startswith("!"):
        # Shell
        msg = msg[1:]
        try:
            output = subprocess.check_output(msg, stderr=subprocess.STDOUT, shell=True)
            client.send(output)
        except subprocess.CalledProcessError as error:
            client.send(str(error).encode() + b"\n" + error.output)
    else:
        # Python
        msg_ = json.loads(msg)
        code = msg_["code"]
        entrypoint = msg_["entrypoint"]
        scope = msg_["scope"]
        encoding = msg_["encoding"]
        try:
            headers, body, output = asyncio.get_event_loop().run_until_complete(
                run_python_code_http(
                    code, entrypoint=entrypoint, encoding=encoding, scope=scope
                )
            )
            client.send(body["body"])
        except Exception as error:
            client.send(str(error).encode() + str(traceback.format_exc()).encode())

    print("...DONE")
    client.close()
