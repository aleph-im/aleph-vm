import asyncio
import json
import logging
import shutil
import sys
from asyncio import Task
from asyncio.subprocess import Process
from typing import Callable, Dict, Generic, Optional, Tuple, TypeVar, Union, TypedDict

import psutil
import qmp
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.volume import PersistentVolume, VolumePersistence
from systemd import journal

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    AlephFirecrackerResources,
    VmSetupError,
)
from aleph.vm.controllers.interface import AlephVmControllerInterface
from aleph.vm.controllers.qemu.cloudinit import CloudInitMixin
from aleph.vm.network.firewall import teardown_nftables_for_vm
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import get_rootfs_base_path
from aleph.vm.utils import HostNotFoundError, ping, run_in_subprocess

logger = logging.getLogger(__name__)


class AlephQemuResources(AlephFirecrackerResources):
    async def download_all(self):
        volume = self.message_content.rootfs
        parent_image_path = await get_rootfs_base_path(volume.parent.ref)
        self.rootfs_path = await self.make_writable_volume(parent_image_path, volume)
        return

    async def make_writable_volume(self, parent_image_path, volume: Union[PersistentVolume, RootfsVolume]):
        """Create a new qcow2 image file based on the passed one, that we give to the VM to write onto"""
        qemu_img_path = shutil.which("qemu-img")
        volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"

        # detect the image format
        out_json = await run_in_subprocess([qemu_img_path, "info", str(parent_image_path), "--output=json"])
        out = json.loads(out_json)
        parent_format = out.get("format", None)
        if parent_format is None:
            raise VmSetupError(f"Failed to detect format for {volume}: {out_json}")
        if parent_format not in ("qcow2", "raw"):
            raise VmSetupError(f"Format {parent_format} for {volume} unhandled by QEMU hypervisor")

        dest_path = settings.PERSISTENT_VOLUMES_DIR / self.namespace / f"{volume_name}.qcow2"
        # Do not override if user asked for host persistance.
        if dest_path.exists() and volume.persistence == VolumePersistence.host:
            return dest_path

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        size_in_bytes = int(volume.size_mib * 1024 * 1024)

        await run_in_subprocess(
            [
                qemu_img_path,
                "create",
                "-f",  # Format
                "qcow2",
                "-F",
                parent_format,
                "-b",
                str(parent_image_path),
                str(dest_path),
                str(size_in_bytes),
            ]
        )
        return dest_path


ConfigurationType = TypeVar("ConfigurationType")


class EntryDict(TypedDict):
    SYSLOG_IDENTIFIER: str
    MESSAGE: str


def make_logs_queue(stdout_identifier, stderr_identifier, skip_past=True) -> Tuple[asyncio.Queue, Callable[[], None]]:
    """Create a queue which streams the logs for the process.

    @param stdout_identifier: journald identifier for process stdout
    @param stderr_identifier: journald identifier for process stderr
    @param skip_past: Skip past history.
    @return: queue and function to cancel the queue.

    The consumer is required to call the queue cancel function when it's done consuming the queue.

    Works by creating a journald reader, and using `add_reader` to call a callback when
    data is available for reading.
    In the callback we check the message type and fill the queue accordingly

    For more information refer to the sd-journal(3) manpage
    and systemd.journal module documentation.
    """
    r = journal.Reader()
    r.add_match(SYSLOG_IDENTIFIER=stdout_identifier)
    r.add_match(SYSLOG_IDENTIFIER=stderr_identifier)
    queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

    def _ready_for_read():
        change_type = r.process()  # reset fd status
        if change_type != journal.APPEND:
            return
        entry: EntryDict
        for entry in r:
            log_type = "stdout" if entry["SYSLOG_IDENTIFIER"] == stdout_identifier else "stderr"
            msg = entry["MESSAGE"]
            asyncio.create_task(queue.put((log_type, msg)))

    if skip_past:
        r.seek_tail()

    loop = asyncio.get_event_loop()
    loop.add_reader(r.fileno(), _ready_for_read)

    def do_cancel():
        loop.remove_reader(r.fileno())
        r.close()

    return queue, do_cancel


class AlephQemuInstance(Generic[ConfigurationType], CloudInitMixin, AlephVmControllerInterface):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    tap_interface: Optional[TapInterface] = None
    vm_configuration: Optional[ConfigurationType]
    is_instance: bool
    qemu_process: Optional[Process]
    support_snapshot = False
    qmp_socket_path = None
    _queue_cancellers: Dict[asyncio.Queue, Callable] = {}

    def __repr__(self):
        return f"<AlephQemuInstance {self.vm_id}>"

    def __str__(self):
        return f"vm-{self.vm_id}"

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephQemuResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        self.vm_id = vm_id
        self.vm_hash = vm_hash
        self.resources = resources
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        self.hardware_resources = hardware_resources
        self.tap_interface = tap_interface

    def to_dict(self):
        """Dict representation of the virtual machine. Used to record resource usage and for JSON serialization."""
        if self.qemu_process and psutil:
            # The firecracker process is still running and process information can be obtained from `psutil`.
            try:
                p = psutil.Process(self.qemu_process.pid)
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
                logger.warning("Cannot read process metrics (process %s not found)", self.qemu_process)
                pid_info = None
        else:
            pid_info = None

        return {
            "process": pid_info,
            **self.__dict__,
        }

    async def setup(self):
        pass

    @property
    def _journal_stdout_name(self) -> str:
        return f"vm-{self.vm_hash}-stdout"

    @property
    def _journal_stderr_name(self) -> str:
        return f"vm-{self.vm_hash}-stderr"

    async def start(self):
        logger.debug(f"Starting Qemu: {self} ")
        # Based on the command
        #  qemu-system-x86_64 -enable-kvm -m 2048 -net nic,model=virtio
        # -net tap,ifname=tap0,script=no,downscript=no -drive file=alpine.qcow2,media=disk,if=virtio -nographic

        qemu_path = shutil.which("qemu-system-x86_64")
        image_path = self.resources.rootfs_path
        vcpu_count = self.hardware_resources.vcpus
        mem_size_mib = self.hardware_resources.memory
        mem_size_mb = int(mem_size_mib / 1024 / 1024 * 1000 * 1000)
        # hardware_resources.published ports -> not implemented at the moment
        # hardware_resources.seconds -> only for microvm

        monitor_socket_path = settings.EXECUTION_ROOT / (str(self.vm_id) + "-monitor.socket")
        self.qmp_socket_path = qmp_socket_path = settings.EXECUTION_ROOT / (str(self.vm_id) + "-qmp.socket")

        args = [
            qemu_path,
            "-enable-kvm",
            "-nodefaults",
            "-m",
            str(mem_size_mb),
            "-smp",
            str(vcpu_count),
            # Disable floppy
            "-fda",
            "",
            # "-snapshot",  # Do not save anything to disk
            "-drive",
            f"file={image_path},media=disk,if=virtio",
            # To debug you can pass gtk or curses instead
            "-display",
            "none",
            "--no-reboot",  # Rebooting from inside the VM shuts down the machine
            # Listen for commands on this socket
            "-monitor",
            f"unix:{monitor_socket_path},server,nowait",
            # Listen for commands on this socket (QMP protocol in json). Supervisor use it to send shutdown or start
            # command
            "-qmp",
            f"unix:{qmp_socket_path},server,nowait",
            # Tell to put the output to std fd, so we can include them in the log
            "-serial",
            "stdio",
            # Uncomment for debug
            # "-serial", "telnet:localhost:4321,server,nowait",
        ]
        if self.tap_interface:
            interface_name = self.tap_interface.device_name
            # script=no, downscript=no tell qemu not to try to set up the network itself
            args += ["-net", "nic,model=virtio", "-net", f"tap,ifname={interface_name},script=no,downscript=no"]

        cloud_init_drive = await self._create_cloud_init_drive()
        if cloud_init_drive:
            args += ["-cdrom", f"{cloud_init_drive.path_on_host}"]

        try:
            print(*args)

            journal_stdout = journal.stream(self._journal_stdout_name)
            journal_stderr = journal.stream(self._journal_stderr_name)
            self.qemu_process = proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=journal_stdout,
                stderr=journal_stderr,
            )

            logger.debug(f"setup done {self}, {proc}")

            async def handle_termination(proc: Process):
                await proc.wait()
                logger.info(f"{self} Process terminated with {proc.returncode} : {str(args)}")

            loop = asyncio.get_running_loop()
            loop.create_task(handle_termination(proc))
        except Exception:
            # Stop the VM and clear network interfaces in case any error prevented the start of the virtual machine.
            logger.error("VM startup failed, cleaning up network")
            if self.enable_networking:
                teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
            raise

        if self.enable_console:
            self.print_logs()

        await self.wait_for_init()
        logger.debug(f"started qemu vm {self} on {self.get_ip()}")

    async def wait_for_init(self) -> None:
        """Wait for the init process of the instance to be ready."""
        assert self.enable_networking and self.tap_interface, f"Network not enabled for VM {self.vm_id}"

        ip = self.get_ip()
        if not ip:
            msg = "Host IP not available"
            raise ValueError(msg)

        ip = ip.split("/", 1)[0]

        attempts = 30
        timeout_seconds = 2.0

        for attempt in range(attempts):
            try:
                await ping(ip, packets=1, timeout=timeout_seconds)
                return
            except HostNotFoundError:
                if attempt < (attempts - 1):
                    continue
                else:
                    raise

    async def configure(self):
        """Nothing to configure, we do the configuration via cloud init"""
        pass

    async def start_guest_api(self):
        pass

    async def stop_guest_api(self):
        pass

    print_task: Optional[Task] = None
    log_queues: list[asyncio.Queue] = []

    async def teardown(self):
        if self.print_task:
            self.print_task.cancel()
        self._shutdown()

        if self.enable_networking:
            teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
        await self.stop_guest_api()

    def print_logs(self) -> None:
        """Print logs to our output for debugging"""
        queue = self.get_log_queue()

        async def print_logs():
            try:
                while True:
                    log_type, message = await queue.get()
                    fd = sys.stderr if log_type == "stderr" else sys.stdout
                    print(self, message, file=fd)
            finally:
                self.unregister_queue(queue)

        loop = asyncio.get_running_loop()
        self.print_task = loop.create_task(print_logs(), name=f"{self}-print-logs")

    def _get_qmpclient(self) -> Optional[qmp.QEMUMonitorProtocol]:
        if not (self.qmp_socket_path and self.qmp_socket_path.exists()):
            return None
        client = qmp.QEMUMonitorProtocol(str(self.qmp_socket_path))
        client.connect()
        return client

    def _shutdown(self):
        client = self._get_qmpclient()
        if client:
            resp = client.command("system_powerdown")
            if not resp == {}:
                logger.warning("unexpected answer from VM", resp)
            client.close()
        self.qmp_socket_path = None

    def get_log_queue(self) -> asyncio.Queue:
        queue, canceller = make_logs_queue(self._journal_stdout_name, self._journal_stderr_name)
        self._queue_cancellers[queue] = canceller
        # Limit the number of queues per VM
        if len(self.log_queues) > 20:
            logger.warning("Too many log queues, dropping the oldest one")
            self.unregister_queue(self.log_queues[1])
        self.log_queues.append(queue)
        return queue

    def unregister_queue(self, queue: asyncio.Queue) -> None:
        if queue in self.log_queues:
            self._queue_cancellers[queue]()
            del self._queue_cancellers[queue]
            self.log_queues.remove(queue)
        queue.empty()
