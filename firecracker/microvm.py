import asyncio
import json
import logging
import os.path
import string
from asyncio import Task
from os import getuid
from pathlib import Path
from pwd import getpwnam
from tempfile import NamedTemporaryFile
from typing import Optional, Tuple, List

from .config import FirecrackerConfig
from .models import FilePath
from .config import Drive

logger = logging.getLogger(__name__)

VSOCK_PATH = "/tmp/v.sock"


class MicroVMFailedInit(Exception):
    pass


# extend the json.JSONEncoder class to support bytes
class JSONBytesEncoder(json.JSONEncoder):

    # overload method default
    def default(self, obj):

        # Match all the types you want to handle in your converter
        if isinstance(obj, bytes):
            return obj.decode()
        return json.JSONEncoder.default(self, obj)


def system(command):
    logger.debug(f"shell {command}")
    return os.system(command)


async def setfacl():
    user = getuid()
    cmd = f"sudo setfacl -m u:{user}:rw /dev/kvm"
    proc = await asyncio.create_subprocess_shell(
        cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()

    if proc.returncode == 0:
        return
    logger.error(f"[{cmd!r} exited with {[proc.returncode]}]")
    if stdout:
        logger.error(f"[stdout]\n{stdout.decode()}")
    if stderr:
        logger.error(f"[stderr]\n{stderr.decode()}")


class MicroVM:
    vm_id: int
    use_jailer: bool
    firecracker_bin_path: str
    jailer_bin_path: Optional[str]
    proc: Optional[asyncio.subprocess.Process] = None
    network_tap: Optional[str] = None
    network_interface: Optional[str] = None
    stdout_task: Optional[Task] = None
    stderr_task: Optional[Task] = None
    config_file = None
    drives: List[Drive] = None
    init_timeout: float

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

    @property
    def guest_ip(self):
        return f"172.{self.vm_id // 256}.{self.vm_id % 256}.2"

    @property
    def host_ip(self):
        return f"172.{self.vm_id // 256}.{self.vm_id % 256}.1"

    def __init__(
        self,
        vm_id: int,
        firecracker_bin_path: str,
        use_jailer: bool = True,
        jailer_bin_path: Optional[str] = None,
        init_timeout: float = 5.,
    ):
        self.vm_id = vm_id
        self.use_jailer = use_jailer
        self.firecracker_bin_path = firecracker_bin_path
        self.jailer_bin_path = jailer_bin_path
        self.drives = []
        self.init_timeout = init_timeout

    def prepare_jailer(self):
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

    async def start(self, config: FirecrackerConfig) -> asyncio.subprocess.Process:
        if self.use_jailer:
            return await self.start_jailed_firecracker(config)
        else:
            return await self.start_firecracker(config)

    async def start_firecracker(self, config: FirecrackerConfig) -> asyncio.subprocess.Process:

        if os.path.exists(VSOCK_PATH):
            os.remove(VSOCK_PATH)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        config_file = NamedTemporaryFile()
        config_file.write(config.json(by_alias=True, exclude_none=True, indent=4).encode())
        config_file.flush()
        self.config_file = config_file
        print(self.config_file)

        logger.debug(
            " ".join((self.firecracker_bin_path, "--api-sock", self.socket_path,
                      "--config-file", config_file.name))
        )

        self.proc = await asyncio.create_subprocess_exec(
            self.firecracker_bin_path,
            "--api-sock",
            self.socket_path,
            "--config-file",
            config_file.name,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self.proc

    async def start_jailed_firecracker(self, config: FirecrackerConfig) -> asyncio.subprocess.Process:
        if not self.jailer_bin_path:
            raise ValueError("Jailer binary path is missing")
        uid = str(getpwnam("jailman").pw_uid)
        gid = str(getpwnam("jailman").pw_gid)

        # config_file = NamedTemporaryFile(dir=f"{self.jailer_path}/tmp/", suffix='.json')
        config_file = open(f"{self.jailer_path}/tmp/config.json", 'wb')
        config_file.write(config.json(by_alias=True, exclude_none=True, indent=4).encode())
        config_file.flush()
        os.chmod(config_file.name, 0o644)
        self.config_file = config_file

        logger.debug(
            " ".join(
                (
                    self.jailer_bin_path,
                    "--id",
                    str(self.vm_id),
                    "--exec-file",
                    self.firecracker_bin_path,
                    "--uid",
                    uid,
                    "--gid",
                    gid,
                    "--",
                    "--config-file",
                    "/tmp/" + os.path.basename(config_file.name),
                )
            )
        )

        self.proc = await asyncio.create_subprocess_exec(
            self.jailer_bin_path,
            "--id",
            str(self.vm_id),
            "--exec-file",
            self.firecracker_bin_path,
            "--uid",
            uid,
            "--gid",
            gid,
            "--",
            "--config-file",
            "/tmp/" + os.path.basename(config_file.name),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self.proc

    def enable_kernel(self, kernel_image_path: str) -> str:
        """Make a kernel available to the VM.

        Creates a symlink to the kernel file if jailer is in use.
        """
        if self.use_jailer:
            kernel_filename = Path(kernel_image_path).name
            jailer_kernel_image_path = f"/opt/{kernel_filename}"
            os.link(kernel_image_path, f"{self.jailer_path}{jailer_kernel_image_path}")
            kernel_image_path = jailer_kernel_image_path
        return kernel_image_path

    def enable_rootfs(self, path_on_host: str) -> str:
        """Make a rootfs available to the VM.

        Creates a symlink to the rootfs file if jailer is in use.
        """
        if self.use_jailer:
            rootfs_filename = Path(path_on_host).name
            jailer_path_on_host = f"/opt/{rootfs_filename}"
            os.link(path_on_host, f"{self.jailer_path}/{jailer_path_on_host}")
            return jailer_path_on_host
        else:
            return path_on_host

    @staticmethod
    def compute_device_name(index: int) -> str:
        return f"vd{string.ascii_lowercase[index + 1]}"

    def enable_drive(self, drive_path: str, read_only: bool = True) -> Drive:
        """Make a volume available to the VM.

        Creates a symlink to the volume file if jailer is in use.
        """
        index = len(self.drives)
        device_name = self.compute_device_name(index)
        if self.use_jailer:
            drive_filename = Path(drive_path).name
            jailer_path_on_host = f"/opt/{drive_filename}"
            os.link(drive_path, f"{self.jailer_path}/{jailer_path_on_host}")
            drive_path = jailer_path_on_host

        drive = Drive(
            drive_id=device_name,
            path_on_host=FilePath(drive_path),
            is_root_device=False,
            is_read_only=read_only,
        )
        self.drives.append(drive)
        return drive

    async def create_network_interface(self, interface: str = "eth0") -> str:
        logger.debug("Create network interface")

        assert self.network_interface is None  # Only one is supported at the moment
        assert self.network_tap is None

        self.network_interface = interface

        host_dev_name = f"vmtap{self.vm_id}"
        self.network_tap = host_dev_name

        system(f"ip tuntap add {host_dev_name} mode tap")
        system(
            f"ip addr add {self.host_ip}/24 dev {host_dev_name}"
        )
        system(f"ip link set {host_dev_name} up")
        system('sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"')
        # TODO: Don't fill iptables with duplicate rules; purge rules on delete
        system(f"iptables -t nat -A POSTROUTING -o {interface} -j MASQUERADE")
        system(
            "iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
        )
        system(f"iptables -A FORWARD -i {host_dev_name} -o {interface} -j ACCEPT")

        return host_dev_name

    async def print_logs(self):
        while not self.proc:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            stdout = await self.proc.stdout.readline()
            if stdout:
                print(stdout.decode().strip())
            else:
                await asyncio.sleep(0.001)

    async def print_logs_stderr(self):
        while not self.proc:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            stdout = await self.proc.stderr.readline()
            if stdout:
                print(stdout.decode().strip())
            else:
                await asyncio.sleep(0.001)

    def start_printing_logs(self) -> Tuple[Task, Task]:
        loop = asyncio.get_running_loop()
        self.stdout_task = loop.create_task(self.print_logs())
        self.stderr_task = loop.create_task(self.print_logs_stderr())
        return self.stdout_task, self.stderr_task

    async def wait_for_init(self):
        """Wait for a connection from the init in the VM"""
        logger.debug("Waiting for init...")
        queue = asyncio.Queue()

        async def unix_client_connected(*_):
            await queue.put(True)

        await asyncio.start_unix_server(
            unix_client_connected, path=f"{self.vsock_path}_52"
        )
        os.system(f"chown jailman:jailman {self.vsock_path}_52")
        try:
            await asyncio.wait_for(queue.get(), timeout=self.init_timeout)
            logger.debug("...signal from init received")
        except asyncio.TimeoutError:
            logger.warning("Never received signal from init")
            raise MicroVMFailedInit()

    async def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.kill()
            except ProcessLookupError:
                pass
            self.proc = None

    async def teardown(self):
        """Stop the VM, cleanup network interface and remove data directory."""
        await self.stop()

        if self.stdout_task:
            self.stdout_task.cancel()
        if self.stderr_task:
            self.stderr_task.cancel()

        if self.network_tap:
            await asyncio.sleep(0.01)  # Used to prevent `ioctl(TUNSETIFF): Device or resource busy`
            logger.debug(f"Removing interface {self.network_tap}")
            system(f"ip tuntap del {self.network_tap} mode tap")
            logger.debug("Removing iptables rules")
            system(f"iptables -t nat -D POSTROUTING -o {self.network_interface} -j MASQUERADE")
            system(
                "iptables -D FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            )
            system(
                f"iptables -D FORWARD -i {self.network_tap} -o {self.network_interface} -j ACCEPT"
            )

        logger.debug("Removing files")
        system(f"rm -fr {self.jailer_path}")


    def __del__(self):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.teardown())
        except RuntimeError as error:
            if error.args == ('no running event loop',):
                return
            else:
                raise
