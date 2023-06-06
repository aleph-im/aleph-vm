import asyncio
import dataclasses
import logging
import os.path
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing import Process, set_start_method
from os.path import exists, isfile
from pathlib import Path
from typing import Dict, List, Optional

import msgpack

try:
    import psutil as psutil
except ImportError:
    psutil = None
from aiohttp import ClientResponseError
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import MachineResources

from firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from firecracker.microvm import MicroVM, setfacl
from guest_api.__main__ import run_guest_api

from ..conf import settings
from ..models import InstanceContent
from ..network.firewall import teardown_nftables_for_vm
from ..network.interfaces import TapInterface
from ..storage import get_code_path, get_data_path, get_runtime_path, get_volume_path, create_devmapper

logger = logging.getLogger(__name__)
set_start_method("spawn")


def load_file_content(path: Path) -> bytes:
    if path:
        with open(path, "rb") as fd:
            return fd.read()
    else:
        return b""


class FileTooLargeError(Exception):
    pass


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
class Volume:
    mount: str
    device: str
    read_only: bool


@dataclass
class HostVolume:
    mount: str
    path_on_host: Path
    read_only: bool


@dataclass
class InstanceConfiguration:
    interface: Interface
    vm_hash: str
    ip: Optional[str] = None
    route: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None

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


class AlephInstanceResources:

    message_content: InstanceContent

    kernel_image_path: Path
    rootfs_path: Path
    volumes: List[HostVolume]
    volume_paths: Dict[str, Path]
    namespace: str

    def __init__(self, message_content: InstanceContent, namespace: str):
        self.message_content = message_content
        self.namespace = namespace

    def to_dict(self):
        return self.__dict__

    async def download_kernel(self):
        # Assumes kernel is already present on the host
        self.kernel_image_path = Path(settings.LINUX_PATH)
        assert isfile(self.kernel_image_path)

    async def download_runtime(self):
        if hasattr(self.message_content, "rootfs"):
            self.rootfs_path = await create_devmapper(self.message_content.rootfs, self.namespace)
            assert self.rootfs_path.is_block_device(), f"Runtime not found on {self.rootfs_path}"
        else:
            runtime_ref: str = self.message_content.runtime.ref
            try:
                self.rootfs_path = await get_runtime_path(runtime_ref)
            except ClientResponseError as error:
                raise ResourceDownloadError(error)
            assert isfile(self.rootfs_path), f"Runtime not found on {self.rootfs_path}"

    async def download_volumes(self):
        volumes = []
        # TODO: Download in parallel
        for volume in self.message_content.volumes:
            volumes.append(
                HostVolume(
                    mount=volume.mount,
                    path_on_host=(
                        await get_volume_path(volume=volume, namespace=self.namespace)
                    ),
                    read_only=volume.is_read_only(),
                )
            )
        self.volumes = volumes

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_volumes(),
        )


class VmSetupError(Exception):
    pass


class VmInitNotConnected(Exception):
    pass


class AlephFirecrackerInstance:
    vm_id: int
    vm_hash: str
    resources: AlephInstanceResources
    enable_console: bool
    enable_networking: bool
    is_instance: bool
    hardware_resources: MachineResources
    fvm: Optional[MicroVM] = None
    tap_interface: Optional[TapInterface] = None

    def __init__(
        self,
        vm_id: int,
        vm_hash: str,
        resources: AlephInstanceResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        self.vm_id = vm_id
        self.vm_hash = vm_hash
        self.resources = resources
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console
        self.hardware_resources = hardware_resources
        self.tap_interface = tap_interface

    def to_dict(self):
        if self.fvm.proc and psutil:
            try:
                p = psutil.Process(self.fvm.proc.pid)
                pid_info = {
                    "status": p.status(),
                    "create_time": p.create_time(),
                    "cpu_times": p.cpu_times(),
                    "cpu_percent": p.cpu_percent(),
                    "memory_info": p.memory_info(),
                    "io_counters": p.io_counters(),
                    "open_files": p.open_files(),
                    "connections": p.connections(),
                    "num_threads": p.num_threads(),
                    "num_ctx_switches": p.num_ctx_switches(),
                }
            except psutil.NoSuchProcess:
                logger.warning("Cannot read process metrics (process not found)")
                pid_info = None
        else:
            pid_info = None

        return {
            "process": pid_info,
            **self.__dict__,
        }

    async def setup(self):
        logger.debug("instance setup started")
        await setfacl()

        fvm = MicroVM(
            vm_id=self.vm_id,
            firecracker_bin_path=settings.FIRECRACKER_PATH,
            use_jailer=settings.USE_JAILER,
            jailer_bin_path=settings.JAILER_PATH,
            init_timeout=settings.INIT_TIMEOUT,
        )
        fvm.prepare_jailer()

        config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(
                    fvm.enable_kernel(self.resources.kernel_image_path)
                ),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=self.is_instance),
            ),
            drives=[
                Drive(
                    drive_id="rootfs",
                    path_on_host=fvm.mount_rootfs(self.resources.rootfs_path),
                    is_root_device=True,
                    is_read_only=False,
                ),
            ]
            + [
                fvm.enable_drive(volume.path_on_host, read_only=volume.read_only)
                for volume in self.resources.volumes
            ],
            machine_config=MachineConfig(
                vcpu_count=self.hardware_resources.vcpus,
                mem_size_mib=self.hardware_resources.memory,
            ),
            vsock=Vsock(),
            network_interfaces=[
                NetworkInterface(
                    iface_id="eth0", host_dev_name=self.tap_interface.device_name
                )
            ]
            if self.enable_networking
            else [],
        )

        logger.debug(config.json(by_alias=True, exclude_none=True, indent=4))

        try:
            await fvm.start(config)
            logger.debug("instance setup done")
            self.fvm = fvm
        except Exception:
            await fvm.teardown()
            teardown_nftables_for_vm(self.vm_id)
            await self.tap_interface.delete()
            raise

    async def start(self):
        logger.debug(f"starting instance {self.vm_id}")
        if not self.fvm:
            raise ValueError("No VM found. Call setup() before start()")

        fvm = self.fvm

        if self.enable_console:
            fvm.start_printing_logs()

        await fvm.wait_for_init()
        logger.debug(f"started fvm {self.vm_id}")

    async def configure(self):
        """Configure the VM by sending configuration info to it's init"""
        interface = Interface.executable

        volumes: List[Volume]
        volumes = [
            Volume(
                mount=volume.mount,
                device=self.fvm.drives[index].drive_id,
                read_only=volume.read_only,
            )
            for index, volume in enumerate(self.resources.volumes)
        ]

        # The ip and route should not contain the network mask in order to maintain
        # compatibility with the existing runtimes.
        ip = self.tap_interface.guest_ip.with_prefixlen.split("/", 1)[0]
        route = str(self.tap_interface.host_ip).split("/", 1)[0]

        config = InstanceConfiguration(
            ip=ip if self.enable_networking else None,
            route=route if self.enable_networking else None,
            dns_servers=settings.DNS_NAMESERVERS,
            interface=interface,
            vm_hash=self.vm_hash,
            volumes=volumes,
            variables=self.resources.message_content.variables,
        )


        if response.success is False:
            logger.exception(response.traceback)
            raise VmSetupError(response.error)

    async def teardown(self):
        if self.fvm:
            await self.fvm.teardown()
            teardown_nftables_for_vm(self.vm_id)
            await self.tap_interface.delete()
