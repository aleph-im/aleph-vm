"""
This module contains abstract class for executables (programs and instances) running inside Firecracker MicroVMs.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from multiprocessing import Process, set_start_method
from os.path import exists, isfile
from pathlib import Path
from typing import Generic, Optional, TypeVar

from aiohttp import ClientResponseError
from aleph_message.models import ExecutableContent, ItemHash
from aleph_message.models.execution.environment import MachineResources

from aleph.vm.conf import settings
from aleph.vm.controllers.configuration import (
    Configuration,
    VMConfiguration,
    save_controller_configuration,
)
from aleph.vm.controllers.firecracker.snapshots import CompressedDiskVolumeSnapshot
from aleph.vm.controllers.interface import AlephVmControllerInterface
from aleph.vm.guest_api.__main__ import run_guest_api
from aleph.vm.hypervisors.firecracker.microvm import FirecrackerConfig, MicroVM
from aleph.vm.network.firewall import teardown_nftables_for_vm
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import chown_to_jailman, get_volume_path

try:
    import psutil  # type: ignore [no-redef]
except ImportError:
    psutil = None  # type: ignore [assignment]

logger = logging.getLogger(__name__)

try:
    set_start_method("spawn")
except RuntimeError as error:
    if error.args == ("context has already been set",):
        logger.info("Start method has already been set")
        pass
    else:
        raise error


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
class BaseConfiguration:
    vm_hash: ItemHash
    ip: Optional[str] = None
    route: Optional[str] = None
    dns_servers: list[str] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)
    variables: Optional[dict[str, str]] = None


@dataclass
class ConfigurationResponse:
    success: bool
    error: Optional[str] = None
    traceback: Optional[str] = None


class AlephFirecrackerResources:
    """Resources required to start a Firecracker VM"""

    message_content: ExecutableContent

    kernel_image_path: Path
    rootfs_path: Path
    volumes: list[HostVolume]
    namespace: str

    def __init__(self, message_content: ExecutableContent, namespace: str):
        self.message_content = message_content
        self.namespace = namespace

    def to_dict(self):
        return self.__dict__

    async def download_kernel(self):
        # Assumes kernel is already present on the host
        self.kernel_image_path = Path(settings.LINUX_PATH)
        assert isfile(self.kernel_image_path)

    async def download_volumes(self):
        volumes = []
        # TODO: Download in parallel
        for volume in self.message_content.volumes:
            volumes.append(
                HostVolume(
                    mount=volume.mount,
                    path_on_host=(await get_volume_path(volume=volume, namespace=self.namespace)),
                    read_only=volume.is_read_only(),
                )
            )
        self.volumes = volumes

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_volumes(),
        )


class VmSetupError(Exception):
    pass


class VmInitNotConnectedError(Exception):
    pass


ConfigurationType = TypeVar("ConfigurationType")


class AlephFirecrackerExecutable(Generic[ConfigurationType], AlephVmControllerInterface):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephFirecrackerResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    tap_interface: Optional[TapInterface] = None
    fvm: MicroVM
    vm_configuration: Optional[ConfigurationType]
    guest_api_process: Optional[Process] = None
    is_instance: bool
    persistent: bool
    _firecracker_config: Optional[FirecrackerConfig] = None
    controller_configuration: Optional[Configuration] = None
    support_snapshot: bool

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephFirecrackerResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: Optional[MachineResources] = None,
        tap_interface: Optional[TapInterface] = None,
        persistent: bool = False,
    ):
        self.vm_id = vm_id
        self.vm_hash = vm_hash
        self.resources = resources
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        self.hardware_resources = hardware_resources or MachineResources()
        self.tap_interface = tap_interface
        self.persistent = persistent

        self.fvm = MicroVM(
            vm_id=self.vm_id,
            firecracker_bin_path=settings.FIRECRACKER_PATH,
            jailer_base_directory=settings.JAILER_BASE_DIR,
            use_jailer=settings.USE_JAILER,
            jailer_bin_path=settings.JAILER_PATH,
            init_timeout=settings.INIT_TIMEOUT,
        )
        self.fvm.prepare_jailer()

        # These properties are set later in the setup and configuration.
        self.vm_configuration = None
        self.guest_api_process = None
        self._firecracker_config = None

    def to_dict(self):
        """Dict representation of the virtual machine. Used to record resource usage and for JSON serialization."""
        if self.fvm.proc and psutil:
            # The firecracker process is still running and process information can be obtained from `psutil`.
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
        # self._firecracker_config = FirecrackerConfig(...)
        raise NotImplementedError()

    async def start(self):
        logger.debug(f"Starting VM={self.vm_id}")

        if not self.fvm:
            msg = "No VM found. Call setup() before start()"
            raise ValueError(msg)

        if self.is_instance or self.persistent:
            msg = "VM should be started using SystemD Manager class"
            raise ValueError(msg)

        try:
            firecracker_config_path = await self.fvm.save_configuration_file(self._firecracker_config)
            await self.fvm.start(firecracker_config_path)
            logger.debug("setup done")
        except Exception:
            # Stop the VM and clear network interfaces in case any error prevented the start of the virtual machine.
            logger.error("VM startup failed, cleaning up network")
            await self.fvm.teardown()
            teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
            raise

        if self.enable_console:
            self.fvm.start_printing_logs()

        await self.wait_for_init()
        logger.debug(f"started fvm {self.vm_id}")
        await self.load_configuration()

    async def wait_for_init(self) -> None:
        """Wait for the init process of the virtual machine to be ready.
        May be empty."""
        return

    async def configure(self):
        """Configure the VM by saving controller service configuration"""
        if self.persistent:
            firecracker_config_path = await self.fvm.save_configuration_file(self._firecracker_config)
            vm_configuration = VMConfiguration(
                firecracker_bin_path=self.fvm.firecracker_bin_path,
                use_jailer=self.fvm.use_jailer,
                jailer_bin_path=self.fvm.jailer_bin_path,
                init_timeout=self.fvm.init_timeout,
                config_file_path=firecracker_config_path,
            )

            configuration = Configuration(
                vm_id=self.vm_id,
                settings=settings,
                vm_configuration=vm_configuration,
            )

            save_controller_configuration(self.vm_hash, configuration)

    async def load_configuration(self):
        """Load configuration settings for programs."""
        return

    async def start_guest_api(self):
        logger.debug(f"starting guest API for {self.vm_id}")
        vsock_path = f"{self.fvm.vsock_path}_53"
        vm_hash = self.vm_hash
        self.guest_api_process = Process(
            target=run_guest_api,
            args=(vsock_path, vm_hash, settings.SENTRY_DSN, settings.DOMAIN_NAME),
        )
        self.guest_api_process.start()
        while not exists(vsock_path):
            await asyncio.sleep(0.01)
        await chown_to_jailman(Path(vsock_path))
        logger.debug(f"started guest API for {self.vm_id}")

    async def stop_guest_api(self):
        if self.guest_api_process and self.guest_api_process._popen:
            self.guest_api_process.terminate()

    async def teardown(self):
        if self.fvm:
            await self.fvm.teardown()
            teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
        await self.stop_guest_api()

    async def create_snapshot(self) -> CompressedDiskVolumeSnapshot:
        raise NotImplementedError()

    def get_log_queue(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        # Limit the number of queues per VM

        if len(self.fvm.log_queues) > 20:
            logger.warning("Too many log queues, dropping the oldest one")
            self.fvm.log_queues.pop(0)
        self.fvm.log_queues.append(queue)
        return queue

    def unregister_queue(self, queue: asyncio.Queue):
        if queue in self.fvm.log_queues:
            self.fvm.log_queues.remove(queue)
        queue.empty()
