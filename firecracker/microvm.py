import asyncio
import base64
import json
import logging
import os.path
from enum import Enum
from functools import lru_cache
from os import getuid
from pathlib import Path
from pwd import getpwnam

import aiohttp
from aiohttp import ClientResponse

logger = logging.getLogger(__name__)

class Encoding(str, Enum):
    plain = 'plain'
    zip = 'zip'

VSOCK_PATH = '/tmp/v.sock'


# extend the json.JSONEncoder class to support bytes
class JSONBytesEncoder(json.JSONEncoder):

    # overload method default
    def default(self, obj):

        # Match all the types you want to handle in your converter
        if isinstance(obj, bytes):
            return obj.decode()
        return json.JSONEncoder.default(self, obj)


def system(command):
    logger.debug(command)
    return os.system(command)


async def setfacl():
    user = getuid()
    cmd = f"sudo setfacl -m u:{user}:rw /dev/kvm"
    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await proc.communicate()

    if proc.returncode == 0:
        return
    logger.error(f'[{cmd!r} exited with {[proc.returncode]}]')
    if stdout:
        logger.error(f'[stdout]\n{stdout.decode()}')
    if stderr:
        logger.error(f'[stderr]\n{stderr.decode()}')


class MicroVM:
    vm_id: int
    use_jailer: bool
    firecracker_bin_path: str
    jailer_bin_path: str
    proc: asyncio.subprocess.Process = None

    @property
    def jailer_path(self):
        firecracker_bin_name = os.path.basename(self.firecracker_bin_path)
        return f"/srv/jailer/{firecracker_bin_name}/{self.vm_id}/root"

    @property
    def socket_path(self):
        if self.use_jailer:
            return f"{self.jailer_path}/run/firecracker.socket"
        else:
            return f"/tmp/firecracker-{self.vm_id}.socket"

    @property
    def vsock_path(self):
        if self.use_jailer:
            return f"{self.jailer_path}{VSOCK_PATH}"
        else:
            return f"{VSOCK_PATH}"

    def __init__(self, vm_id: int, firecracker_bin_path: str,
                 use_jailer: bool=True, jailer_bin_path: str = None):
        self.vm_id = vm_id
        self.use_jailer = use_jailer
        self.firecracker_bin_path = firecracker_bin_path
        self.jailer_bin_path = jailer_bin_path

    @lru_cache()
    def get_session(self) -> aiohttp.ClientSession:
        conn = aiohttp.UnixConnector(path=self.socket_path)
        return aiohttp.ClientSession(connector=conn)

    def cleanup_jailer(self):
        system(f"rm -fr {self.jailer_path}")

        # system(f"rm -fr {self.jailer_path}/run/")
        # system(f"rm -fr {self.jailer_path}/dev/")
        # system(f"rm -fr {self.jailer_path}/opt/")
        #
        # if os.path.exists(path=self.vsock_path):
        #     os.remove(path=self.vsock_path)
        #
        system(f"mkdir -p {self.jailer_path}/tmp/")
        system(f"chown jailman:jailman {self.jailer_path}/tmp/")
        #
        system(f"mkdir -p {self.jailer_path}/opt")

        # system(f"cp disks/rootfs.ext4 {self.jailer_path}/opt")
        # system(f"cp hello-vmlinux.bin {self.jailer_path}/opt")

    async def start(self) -> asyncio.subprocess.Process:
        if self.use_jailer:
            return await self.start_jailed_firecracker()
        else:
            return await self.start_firecracker()

    async def start_firecracker(self) -> asyncio.subprocess.Process:
        logger.debug(' '.join((self.firecracker_bin_path, "--api-sock", self.socket_path)))
        if os.path.exists(VSOCK_PATH):
            os.remove(VSOCK_PATH)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)
        self.proc = await asyncio.create_subprocess_exec(
            self.firecracker_bin_path, "--api-sock", self.socket_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self.proc

    async def start_jailed_firecracker(self) -> asyncio.subprocess.Process:
        uid = str(getpwnam('jailman').pw_uid)
        gid = str(getpwnam('jailman').pw_gid)
        logger.debug(' '.join((self.jailer_bin_path,
                               "--id", str(self.vm_id),
                               "--exec-file", self.firecracker_bin_path,
                               "--uid", uid, "--gid", gid)))
        self.proc = await asyncio.create_subprocess_exec(
            self.jailer_bin_path,
            "--id", str(self.vm_id), "--exec-file", self.firecracker_bin_path,
            "--uid", uid, "--gid", gid,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self.proc

    async def socket_is_ready(self, delay=0.01):
        while not os.path.exists(self.socket_path):
            await asyncio.sleep(delay)

    async def set_boot_source(self, kernel_image_path: str, enable_console: bool = False):
        if self.use_jailer:
            kernel_filename = Path(kernel_image_path).name
            jailer_kernel_image_path = f"/opt/{kernel_filename}"
            os.link(kernel_image_path, f"{self.jailer_path}{jailer_kernel_image_path}")
            kernel_image_path = jailer_kernel_image_path

        console = "console=ttyS0" if enable_console else ""
        data = {
            "kernel_image_path": kernel_image_path,
            # Add console=ttyS0 for debugging, but it makes the boot twice slower
            "boot_args": f"{console} reboot=k panic=1 pci=off ro noapic nomodules random.trust_cpu=on",
        }
        session = self.get_session()
        response: ClientResponse = await session.put(
            'http://localhost/boot-source',
            json=data)
        response.raise_for_status()

    async def set_rootfs(self, path_on_host: str):
        if self.use_jailer:
            rootfs_filename = Path(path_on_host).name
            jailer_path_on_host = f"/opt/{rootfs_filename}"
            os.link(path_on_host, f"{self.jailer_path}/{jailer_path_on_host}")
            path_on_host = jailer_path_on_host

        data = {
            "drive_id": "rootfs",
            "path_on_host": path_on_host,
            "is_root_device": True,
            "is_read_only": True,
        }
        session = self.get_session()
        response = await session.put('http://localhost/drives/rootfs',
                                     json=data)
        response.raise_for_status()

    async def set_vsock(self):
        data = {
            "vsock_id": "1",
            "guest_cid": 3,
            "uds_path": VSOCK_PATH,
        }
        session = self.get_session()
        response = await session.put('http://localhost/vsock',
                                     json=data)
        response.raise_for_status()

    async def set_network(self):
        """Configure the host network with a tap interface to the VM.
        """
        name = f"tap{self.vm_id}"

        system(f"ip tuntap add {name} mode tap")
        system(f"ip addr add 172.{self.vm_id // 256}.{self.vm_id % 256}.1/24 dev {name}")
        system(f"ip link set {name} up")
        system('sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"')
        # TODO: Don't fill iptables with duplicate rules; purge rules on delete
        system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
        system("iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT")
        system(f"iptables -A FORWARD -i {name} -o eth0 -j ACCEPT")

        data = {
            "iface_id": "eth0",
            "guest_mac": f"AA:FC:00:00:00:01",
            "host_dev_name": name,
        }
        session = self.get_session()
        response = await session.put('http://localhost/network-interfaces/eth0',
                                     json=data)
        logger.debug(response)
        logger.debug(await response.text())
        response.raise_for_status()

    async def start_instance(self):
        data = {
            "action_type": "InstanceStart",
        }
        session = self.get_session()
        response = await session.put('http://localhost/actions',
                                     json=data)
        response.raise_for_status()
        logger.debug(response)
        logger.debug(await response.text())

    async def print_logs(self):
        while not self.proc:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            stdout = await self.proc.stdout.readline()
            if stdout:
                print(stdout.decode().strip())
            else:
                await asyncio.sleep(0.001)


    async def wait_for_init(self):
        """Wait for a connection from the init in the VM"""
        logger.debug("Waiting for init...")
        queue = asyncio.Queue()

        async def unix_client_connected(*_):
            await queue.put(True)

        await asyncio.start_unix_server(unix_client_connected, path=f"{self.vsock_path}_52")
        os.system(f"chown jailman:jailman {self.vsock_path}_52")
        await queue.get()
        logger.debug("...signal from init received")

    async def run_code(self, code: bytes, entrypoint: str,
                       encoding: str = 'plain', scope: dict = None):
        scope = scope or {}
        reader, writer = await asyncio.open_unix_connection(path=self.vsock_path)

        if encoding == Encoding.zip:
            code = base64.b64encode(code).decode()
        elif encoding == Encoding.plain:
            code = code.decode()
        else:
            raise ValueError(f"Unknown encoding '{encoding}'")

        msg = {
            'code': code,
            'entrypoint': entrypoint,
            'encoding': encoding,
            'scope': scope,
        }
        writer.write(('CONNECT 52\n' + JSONBytesEncoder().encode(msg) + '\n').encode())
        await writer.drain()

        ack = await reader.readline()
        logger.debug(f'ack={ack.decode()}')
        response = await reader.read()
        logger.debug(f'response= <<<\n{response.decode()}>>>')
        writer.close()
        await writer.wait_closed()
        return response

    async def stop(self):
        if self.proc:
            self.proc.terminate()
            self.proc.kill()
        await self.get_session().close()
        self.get_session.cache_clear()

        name = f"tap{self.vm_id}"
        system(f"ip tuntap del {name} mode tap")

    def __del__(self):
        loop = asyncio.get_running_loop()
        loop.create_task(self.stop())
