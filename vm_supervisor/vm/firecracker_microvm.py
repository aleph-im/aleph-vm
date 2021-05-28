import asyncio
import dataclasses
import logging
from dataclasses import dataclass
from enum import Enum
from multiprocessing import Process, set_start_method
from os import system
from os.path import isfile, exists
from typing import Optional, Dict, List

import msgpack
from aiohttp import ClientResponseError

from aleph_message.models import ProgramContent
from aleph_message.models.program import MachineResources
from firecracker.microvm import MicroVM, setfacl, Encoding
from guest_api.__main__ import run_guest_api
from ..conf import settings
from ..models import FilePath
from ..storage import get_code_path, get_runtime_path, get_data_path

logger = logging.getLogger(__name__)
set_start_method("spawn")


def load_file_content(path: FilePath) -> bytes:
    if path:
        with open(path, "rb") as fd:
            return fd.read()
    else:
        return b""


class ResourceDownloadError(ClientResponseError):
    """An error occurred while downloading a VM resource file"""

    def __init__(self, error: ClientResponseError):
        super().__init__(
            request_info=error.request_info,
            history=error.history,
            status=error.status,
            message=error.message,
            headers=error.headers,
        )


class Interface(str, Enum):
    asgi = "asgi"
    executable = "executable"


@dataclass
class ConfigurationPayload:
    ip: Optional[str]
    route: Optional[str]
    dns_servers: List[str]
    code: bytes
    encoding: str
    entrypoint: str
    input_data: bytes
    interface: Interface

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


@dataclass
class ConfigurationResponse:
    success: bool
    error: Optional[str] = None
    traceback: Optional[str] = None


@dataclass
class RunCodePayload:
    scope: Dict

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


class AlephFirecrackerResources:

    message_content: ProgramContent

    kernel_image_path: FilePath
    code_path: FilePath
    code_encoding: Encoding
    code_entrypoint: str
    rootfs_path: FilePath
    data_path: Optional[FilePath]

    def __init__(self, message_content: ProgramContent):
        self.message_content = message_content
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint

    async def download_kernel(self):
        # Assumes kernel is already present on the host
        self.kernel_image_path = settings.LINUX_PATH
        assert isfile(self.kernel_image_path)

    async def download_code(self):
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert isfile(self.code_path)

    async def download_runtime(self):
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert isfile(self.rootfs_path)

    async def download_data(self):
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                self.data_path = await get_data_path(data_ref)
            except ClientResponseError as error:
                raise ResourceDownloadError(error)
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


class VmSetupError(Exception):
    pass


class AlephFirecrackerVM:
    vm_id: int
    resources: AlephFirecrackerResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    fvm: MicroVM
    guest_api_process: Process

    def __init__(
        self,
        vm_id: int,
        resources: AlephFirecrackerResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources()
    ):
        self.vm_id = vm_id
        self.resources = resources
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console
        self.hardware_resources = hardware_resources

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
        await fvm.set_resources(vcpus=self.hardware_resources.vcpus,
                                memory=self.hardware_resources.memory)
        if self.enable_networking:
            await fvm.set_network(interface=settings.NETWORK_INTERFACE)
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

        code: bytes = load_file_content(self.resources.code_path)
        input_data: bytes = load_file_content(self.resources.data_path)

        interface = Interface.asgi if ":" in self.resources.code_entrypoint \
            else Interface.executable

        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)
        payload = ConfigurationPayload(
            ip=self.fvm.guest_ip if self.enable_networking else None,
            route=self.fvm.host_ip if self.enable_console else None,
            dns_servers=settings.DNS_NAMESERVERS,
            code=code,
            encoding=self.resources.code_encoding,
            entrypoint=self.resources.code_entrypoint,
            input_data=input_data,
            interface=interface,
        )
        writer.write(b"CONNECT 52\n" + payload.as_msgpack())
        await writer.drain()

        await reader.readline()  # Ignore the acknowledgement from the socket
        response_raw = await reader.read(1000_000)
        response = ConfigurationResponse(
            **msgpack.loads(response_raw, raw=False))
        if response.success is False:
            raise VmSetupError(response.error)

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
        scope: dict = None,
    ):
        logger.debug("running code")
        scope = scope or {}
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)

        payload = RunCodePayload(scope=scope)

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
