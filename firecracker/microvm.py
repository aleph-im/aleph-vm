import asyncio
import json
import logging
import os.path
import shutil
import string
from asyncio import Task
from asyncio.base_events import Server
from dataclasses import dataclass
from os import getuid
from pathlib import Path
from pwd import getpwnam
from tempfile import NamedTemporaryFile
from typing import Any, Dict, List, Optional, Tuple

import msgpack

from .config import Drive, FirecrackerConfig

logger = logging.getLogger(__name__)

VSOCK_PATH = "/tmp/v.sock"
JAILER_BASE_DIRECTORY = "/var/lib/aleph/vm/jailer"
DEVICE_BASE_DIRECTORY = "/dev/mapper"


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
    logger.warning(f"[{cmd!r} exited with {[proc.returncode]}]")
    if stdout:
        logger.warning(f"[stdout]\n{stdout.decode()}")
    if stderr:
        logger.warning(f"[stderr]\n{stderr.decode()}")


@dataclass
class RuntimeConfiguration:
    version: str

    def supports_ipv6(self) -> bool:
        return self.version != "1.0.0"


class MicroVM:
    vm_id: int
    use_jailer: bool
    firecracker_bin_path: Path
    jailer_bin_path: Optional[Path]
    proc: Optional[asyncio.subprocess.Process] = None
    stdout_task: Optional[Task] = None
    stderr_task: Optional[Task] = None
    log_queues: List
    config_file_path: Optional[Path] = None
    drives: List[Drive]
    init_timeout: float
    mounted_rootfs: Optional[Path] = None
    _unix_socket: Server

    @property
    def namespace_path(self):
        firecracker_bin_name = os.path.basename(self.firecracker_bin_path)
        return f"{JAILER_BASE_DIRECTORY}/{firecracker_bin_name}/{self.vm_id}"

    @property
    def jailer_path(self):
        return os.path.join(self.namespace_path, "root")

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

    def __init__(
        self,
        vm_id: int,
        firecracker_bin_path: Path,
        use_jailer: bool = True,
        jailer_bin_path: Optional[Path] = None,
        init_timeout: float = 5.0,
    ):
        self.vm_id = vm_id
        self.use_jailer = use_jailer
        self.firecracker_bin_path = firecracker_bin_path
        self.jailer_bin_path = jailer_bin_path
        self.drives = []
        self.init_timeout = init_timeout
        self.runtime_config = None
        self.log_queues: List[asyncio.Queue] = []

    def to_dict(self):
        return {
            "jailer_path": self.jailer_path,
            "socket_path": self.socket_path,
            "vsock_path": self.vsock_path,
            **self.__dict__,
        }

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
        system(f"mkdir -p {self.jailer_path}/dev/mapper")

        # system(f"cp disks/rootfs.ext4 {self.jailer_path}/opt")
        # system(f"cp hello-vmlinux.bin {self.jailer_path}/opt")

    async def start(self, config: FirecrackerConfig) -> asyncio.subprocess.Process:
        if self.use_jailer:
            return await self.start_jailed_firecracker(config)
        else:
            return await self.start_firecracker(config)

    async def start_firecracker(
        self, config: FirecrackerConfig
    ) -> asyncio.subprocess.Process:

        if os.path.exists(VSOCK_PATH):
            os.remove(VSOCK_PATH)
        if os.path.exists(self.socket_path):
            os.remove(self.socket_path)

        with NamedTemporaryFile(delete=False) as config_file:
            config_file.write(
                config.json(by_alias=True, exclude_none=True, indent=4).encode()
            )
            config_file.flush()
            os.chmod(config_file.name, 0o644)
            self.config_file_path = Path(config_file.name)

        logger.debug(
            " ".join(
                (
                    str(self.firecracker_bin_path),
                    "--api-sock",
                    str(self.socket_path),
                    "--config-file",
                    config_file.name,
                )
            )
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

    async def start_jailed_firecracker(
        self, config: FirecrackerConfig
    ) -> asyncio.subprocess.Process:
        if not self.jailer_bin_path:
            raise ValueError("Jailer binary path is missing")
        uid = str(getpwnam("jailman").pw_uid)
        gid = str(getpwnam("jailman").pw_gid)

        with open(f"{self.jailer_path}/tmp/config.json", "wb") as config_file:
            config_file.write(
                config.json(by_alias=True, exclude_none=True, indent=4).encode()
            )
            config_file.flush()
            os.chmod(config_file.name, 0o644)
            self.config_file_path = Path(config_file.name)

        logger.debug(
            " ".join(
                (
                    str(self.jailer_bin_path),
                    "--id",
                    str(self.vm_id),
                    "--exec-file",
                    str(self.firecracker_bin_path),
                    "--uid",
                    uid,
                    "--gid",
                    gid,
                    "--chroot-base-dir",
                    JAILER_BASE_DIRECTORY,
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
            "--chroot-base-dir",
            JAILER_BASE_DIRECTORY,
            "--",
            "--config-file",
            "/tmp/" + os.path.basename(config_file.name),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return self.proc

    def enable_kernel(self, kernel_image_path: Path) -> Path:
        """Make a kernel available to the VM.

        Creates a symlink to the kernel file if jailer is in use.
        """
        if self.use_jailer:
            kernel_filename = kernel_image_path.name
            jailer_kernel_image_path = f"/opt/{kernel_filename}"
            kernel_image_path.link_to(f"{self.jailer_path}{jailer_kernel_image_path}")
            return Path(jailer_kernel_image_path)
        else:
            return kernel_image_path

    def enable_rootfs(self, path_on_host: Path) -> Path:
        if path_on_host.is_file():
            return self.enable_file_rootfs(path_on_host)
        elif path_on_host.is_block_device():
            return self.enable_device_mapper_rootfs(path_on_host)
        else:
            raise ValueError(f"Not a file or a block device: {path_on_host}")

    def enable_file_rootfs(self, path_on_host: Path) -> Path:
        """Make a rootfs available to the VM.

        Creates a symlink to the rootfs file if jailer is in use.
        """
        if self.use_jailer:
            rootfs_filename = Path(path_on_host).name
            jailer_path_on_host = f"/opt/{rootfs_filename}"
            os.link(path_on_host, f"{self.jailer_path}/{jailer_path_on_host}")
            return Path(jailer_path_on_host)
        else:
            return path_on_host

    def enable_device_mapper_rootfs(self, path_on_host: Path) -> Path:
        """Mount a rootfs to the VM."""
        self.mounted_rootfs = path_on_host
        if not self.use_jailer:
            return path_on_host

        rootfs_filename = path_on_host.name
        device_jailer_path = Path(DEVICE_BASE_DIRECTORY) / rootfs_filename
        final_path = Path(self.jailer_path) / str(device_jailer_path).strip("/")
        if not final_path.is_block_device():
            jailer_device_vm_path = Path(f"{self.jailer_path}/{DEVICE_BASE_DIRECTORY}")
            jailer_device_vm_path.mkdir(exist_ok=True, parents=True)
            rootfs_device = path_on_host.resolve()
            # Copy the /dev/dm-{device_id} special block file that is the real mapping destination on Jailer
            system(f"cp -vap {rootfs_device} {self.jailer_path}/dev/")
            path_to_mount = jailer_device_vm_path / rootfs_filename
            if not path_to_mount.is_symlink():
                path_to_mount.symlink_to(rootfs_device)
            system(f"chown -Rh jailman:jailman {self.jailer_path}/dev")

        return device_jailer_path

    @staticmethod
    def compute_device_name(index: int) -> str:
        return f"vd{string.ascii_lowercase[index + 1]}"

    def enable_drive(self, drive_path: Path, read_only: bool = True) -> Drive:
        """Make a volume available to the VM.

        Creates a symlink to the volume file if jailer is in use.
        """
        index = len(self.drives)
        device_name = self.compute_device_name(index)

        if self.use_jailer:
            drive_filename = drive_path.name
            jailer_path_on_host = f"/opt/{drive_filename}"
            drive_path.link_to(f"{self.jailer_path}/{jailer_path_on_host}")
            drive_path = Path(jailer_path_on_host)

        drive = Drive(
            drive_id=device_name,
            path_on_host=drive_path,
            is_root_device=False,
            is_read_only=read_only,
        )
        self.drives.append(drive)
        return drive

    async def print_logs(self):
        while not self.proc:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            stdout = await self.proc.stdout.readline()
            for queue in self.log_queues:
                await queue.put(('stdout', stdout))
            if stdout:
                print(stdout.decode().strip())
            else:
                await asyncio.sleep(0.001)

    async def print_logs_stderr(self):
        while not self.proc:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            stderr = await self.proc.stderr.readline()
            for queue in self.log_queues:
                await queue.put(('stderr', stderr))
            if stderr:
                print(stderr.decode().strip())
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

        async def unix_client_connected(
            reader: asyncio.StreamReader, _writer: asyncio.StreamWriter
        ):
            data = await reader.read(1_000_000)
            if data:
                config_dict: Dict[str, Any] = msgpack.loads(data)
                runtime_config = RuntimeConfiguration(version=config_dict["version"])
            else:
                # Older runtimes do not send a config. Use a default.
                runtime_config = RuntimeConfiguration(version="1.0.0")

            logger.debug("Runtime version: %s", runtime_config)
            await queue.put(runtime_config)

        self._unix_socket = await asyncio.start_unix_server(
            unix_client_connected, path=f"{self.vsock_path}_52"
        )
        system(f"chown jailman:jailman {self.vsock_path}_52")
        try:
            self.runtime_config = await asyncio.wait_for(
                queue.get(), timeout=self.init_timeout
            )
            logger.debug("...signal from init received")
        except asyncio.TimeoutError:
            logger.warning("Never received signal from init")
            raise MicroVMFailedInit()

    async def shutdown(self) -> None:
        logger.debug(f"Shutdown vm={self.vm_id}")
        try:
            reader, writer = await asyncio.open_unix_connection(path=self.vsock_path)
        except (
            FileNotFoundError,
            ConnectionResetError,
            ConnectionRefusedError,
        ) as error:
            logger.warning(
                f"VM={self.vm_id} cannot receive shutdown signal: {error.args}"
            )
            return

        try:
            payload = b"halt"
            writer.write(b"CONNECT 52\n" + payload)

            await writer.drain()

            ack: bytes = await reader.readline()
            logger.debug(f"ack={ack.decode()}")

            msg: bytes = await reader.readline()
            logger.debug(f"msg={msg!r}")

            msg2: bytes = await reader.readline()
            logger.debug(f"msg2={msg2!r}")

            if msg2 != b"STOPZ\n":
                logger.warning(f"Unexpected response from VM: {msg2[:20]!r}")
        except ConnectionResetError as error:
            logger.warning(
                f"ConnectionResetError in shutdown of {self.vm_id}: {error.args}"
            )

    async def stop(self):
        if self.proc:
            logger.debug("Stopping firecracker process")
            try:
                self.proc.terminate()
                self.proc.kill()
            except ProcessLookupError:
                logger.debug(f"Firecracker process pid={self.proc.pid} not found")
            self.proc = None
        else:
            logger.debug("No firecracker process to stop")

    async def teardown(self):
        """Stop the VM, cleanup network interface and remove data directory."""
        try:
            await asyncio.wait_for(self.shutdown(), timeout=5)
        except asyncio.TimeoutError:
            logger.exception(f"Timeout during VM shutdown vm={self.vm_id}")
        logger.debug("Waiting for one second for the process to shutdown")
        await asyncio.sleep(1)
        await self.stop()

        if self.stdout_task:
            self.stdout_task.cancel()
        if self.stderr_task:
            self.stderr_task.cancel()

        if self.mounted_rootfs:
            logger.debug("Waiting for one second for the VM to shutdown")
            await asyncio.sleep(1)
            root_fs = self.mounted_rootfs.name
            system(f"dmsetup remove {root_fs}")
            if self.use_jailer:
                shutil.rmtree(self.jailer_path)

        if self._unix_socket:
            logger.debug("Closing unix socket")
            self._unix_socket.close()
            await self._unix_socket.wait_closed()

        logger.debug("Removing files")
        if self.config_file_path:
            self.config_file_path.unlink(missing_ok=True)
        system(f"rm -fr {self.namespace_path}")

    def __del__(self):
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.teardown())
        except RuntimeError as error:
            if error.args == ("no running event loop",):
                return
            else:
                raise
