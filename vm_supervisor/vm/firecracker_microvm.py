import asyncio
import dataclasses
import logging
from dataclasses import dataclass
from multiprocessing import Process, set_start_method
from os import system
from os.path import isfile, exists
from typing import Optional, Dict

import msgpack

from firecracker.microvm import MicroVM, setfacl
from guest_api.__main__ import run_guest_api
from ..conf import settings
from ..models import FunctionMessage, FilePath
from ..storage import get_code_path, get_runtime_path, get_data_path

logger = logging.getLogger(__name__)
set_start_method("spawn")


@dataclass
class ConfigurationPayload:
    ip: Optional[str]
    route: Optional[str]

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


@dataclass
class RunCodePayload:
    code: bytes
    input_data: bytes
    entrypoint: str
    encoding: str
    scope: Dict

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


class AlephFirecrackerResources:

    message: FunctionMessage

    kernel_image_path: FilePath
    code_path: FilePath
    rootfs_path: FilePath
    data_path: Optional[FilePath]

    def __init__(self, message: FunctionMessage):
        self.message = message

    async def download_kernel(self):
        # Assumes kernel is already present on the host
        self.kernel_image_path = settings.LINUX_PATH
        assert isfile(self.kernel_image_path)

    async def download_code(self):
        code_ref: str = self.message.content.code.ref
        self.code_path = await get_code_path(code_ref)
        assert isfile(self.code_path)

    async def download_runtime(self):
        runtime_ref: str = self.message.content.runtime.ref
        self.rootfs_path = await get_runtime_path(runtime_ref)
        assert isfile(self.rootfs_path)

    async def download_data(self):
        if self.message.content.data:
            data_ref: str = self.message.content.data.ref
            self.data_path = await get_data_path(data_ref)
            assert isfile(self.data_path)
        else:
            self.data_path = None

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_code(),
            self.download_runtime(),
            self.download_data(),
        )


class AlephFirecrackerVM:
    vm_id: int
    resources: AlephFirecrackerResources
    enable_console: bool
    enable_networking: bool
    fvm: MicroVM
    guest_api_process: Process

    def __init__(
        self,
        vm_id: int,
        resources: AlephFirecrackerResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
    ):
        self.vm_id = vm_id
        self.resources = resources
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console

    async def setup(self):
        logger.debug("setup started")
        await setfacl()
        fvm = MicroVM(
            vm_id=self.vm_id,
            firecracker_bin_path=settings.FIRECRACKER_PATH,
            use_jailer=settings.USE_JAILER,
            jailer_bin_path=settings.JAILER_PATH,
        )
        fvm.prepare_jailer()
        await fvm.start()
        await fvm.socket_is_ready()
        await fvm.set_boot_source(
            self.resources.kernel_image_path,
            enable_console=self.enable_console,
        )
        await fvm.set_rootfs(self.resources.rootfs_path)
        await fvm.set_vsock()
        if self.enable_networking:
            await fvm.set_network()
        logger.debug("setup done")
        self.fvm = fvm

    async def start(self):
        logger.debug(f"starting vm {self.vm_id}")
        if not self.fvm:
            raise ValueError("No VM found. Call setup() before start()")

        fvm = self.fvm

        if self.enable_console:
            fvm.start_printing_logs()

        await asyncio.gather(
            fvm.start_instance(),
            fvm.wait_for_init(),
        )
        logger.debug(f"started fvm {self.vm_id}")

    async def configure(self):
        """Configure the VM by sending configuration info to it's init"""
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)
        payload = ConfigurationPayload(
            ip=self.fvm.guest_ip if self.enable_networking else None,
            route=self.fvm.host_ip if self.enable_console else None,
        )
        writer.write(b"CONNECT 52\n" + payload.as_msgpack())
        await writer.drain()

    async def start_guest_api(self):
        logger.debug(f"starting guest API for {self.vm_id}")
        vsock_path = f"{self.fvm.vsock_path}_53"
        self.guest_api_process = Process(target=run_guest_api, args=(vsock_path,))
        self.guest_api_process.start()
        while not exists(vsock_path):
            await asyncio.sleep(0.01)
        system(f"chown jailman:jailman {vsock_path}")
        logger.debug(f"started guest API for {self.vm_id}")

    async def stop_guest_api(self):
        self.guest_api_process.terminate()

    async def teardown(self):
        await self.fvm.teardown()
        await self.stop_guest_api()

    async def run_code(
        self,
        code: bytes,
        entrypoint: str,
        input_data: bytes = b"",
        encoding: str = "plain",
        scope: dict = None,
    ):
        logger.debug("running code")
        scope = scope or {}
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)

        payload = RunCodePayload(
            code=code,
            input_data=input_data,
            entrypoint=entrypoint,
            encoding=encoding,
            scope=scope,
        )

        writer.write(b"CONNECT 52\n" + payload.as_msgpack())
        await writer.drain()

        ack: bytes = await reader.readline()
        logger.debug(f"ack={ack.decode()}")

        logger.debug("waiting for VM response")
        response: bytes = await reader.read()

        logger.debug("cleaning VM resources")
        writer.close()
        await writer.wait_closed()
        return response
