import asyncio
import os
import sys
import termios
import tty

import websockets

WS_URL = "ws://localhost:4020/control/machine/{ref}/serial"
EXIT_SEQUENCE = b"\x1d"  # Ctrl-]


async def client():
    old_settings = termios.tcgetattr(sys.stdin)
    ws_url = WS_URL.format(ref="decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


    try:
        async with websockets.connect(ws_url) as ws:
            print("[Connected] Use Ctrl-] to disconnect ", file=sys.stderr)
            tty.setraw(sys.stdin.fileno())  # Set terminal to raw mode

            async def send_input():
                while True:
                    data = await asyncio.get_event_loop().run_in_executor(None, os.read, sys.stdin.fileno(), 1)
                    if not data:
                        break
                    if data == EXIT_SEQUENCE:
                        print("\n[Exit sequence received — quitting]", file=sys.stderr)
                        break
                    if data == b"\r":
                        data = b"\r\n"
                    await ws.send(data)

            async def receive_output():
                async for message in ws:
                    if isinstance(message, bytes):
                        os.write(sys.stdout.fileno(), message)
                    else:
                        os.write(sys.stdout.fileno(), message.encode())

            task_send = asyncio.create_task(send_input())
            task_recv = asyncio.create_task(receive_output())

            done, pending = await asyncio.wait([task_send, task_recv], return_when=asyncio.FIRST_COMPLETED)

            for task in pending:
                task.cancel()
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)  # Restore terminal
        print("\n[Disconnected]", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(client())
