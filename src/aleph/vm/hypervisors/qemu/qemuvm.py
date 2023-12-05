import asyncio
import sys
from asyncio import Task
from asyncio.subprocess import Process

from aleph.vm.controllers.qemu.instance import logger


class QemuVM(object):
    qemu_bin_path: str
    cloud_init_drive_path: str | None
    image_path: str
    monitor_socket_path: str
    qmp_socket_path: str
    vcpu_count: int
    mem_size_mb: int
    interface_name: str

    def __init__(self, config):
        self.qemu_bin_path = config.qemu_bin_path
        self.cloud_init_drive_path = config.cloud_init_drive_path
        self.image_path = config.image_path
        self.monitor_socket_path = config.monitor_socket_path
        self.qmp_socket_path = config.qmp_socket_path
        self.vcpu_count = config.vcpu_count
        self.mem_size_mb = config.mem_size_mb
        self.interface_name = config.interface_name

    def prepare_start(self):
        pass

    async def start(
        self,
    ) -> None:
        # Based on the command
        #  qemu-system-x86_64 -enable-kvm -m 2048 -net nic,model=virtio
        # -net tap,ifname=tap0,script=no,downscript=no -drive file=alpine.qcow2,media=disk,if=virtio -nographic
        # hardware_resources.published ports -> not implemented at the moment
        # hardware_resources.seconds -> only for microvm
        args = [
            self.qemu_bin_path,
            "-enable-kvm",
            "-nodefaults",
            "-m",
            str(self.mem_size_mb),
            "-smp",
            str(self.vcpu_count),
            "-drive",
            f"file={self.image_path},media=disk,if=virtio",
            # To debug you can pass gtk or curses instead
            "-display",
            "none",
            "--no-reboot",  # Rebooting from inside the VM shuts down the machine
            # Listen for commands on this socket
            "-monitor",
            f"unix:{self.monitor_socket_path},server,nowait",
            # Listen for commands on this socket (QMP protocol in json). Supervisor use it to send shutdown or start
            # command
            "-qmp",
            f"unix:{self.qmp_socket_path},server,nowait",
            # Tell to put the output to std fd, so we can include them in the log
            "-serial",
            "stdio",
            # Uncomment for debug
            # "-serial", "telnet:localhost:4321,server,nowait",
            # "-snapshot",  # Do not save anything to disk
        ]
        if self.interface_name:
            # script=no, downscript=no tell qemu not to try to set up the network itself
            args += ["-net", "nic,model=virtio", "-net", f"tap,ifname={self.interface_name},script=no,downscript=no"]

        if self.cloud_init_drive_path:
            args += ["-cdrom", f"{self.cloud_init_drive_path}"]
        try:
            print(*args)
            self.qemu_process = proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            logger.debug(f"setup done {self}, {proc}")

            async def handle_termination(proc: Process):
                await proc.wait()
                logger.info(f"{self} Process terminated with {proc.returncode} : {str(args)}")

            loop = asyncio.get_running_loop()
            loop.create_task(handle_termination(proc))
            logger.debug(f"started qemu vm {self} on {self.get_ip()}")
        except Exception:
            raise

    log_queues: list[asyncio.Queue] = []

    async def _process_stderr(self):
        while not self.qemu_process:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            line = await self.qemu_process.stderr.readline()
            if not line:  # FD is closed nothing more will come
                print(self, "EOF")
                return
            for queue in self.log_queues:
                await queue.put(("stderr", line))
            print(self, line.decode().strip(), file=sys.stderr)

    def start_printing_logs(self) -> tuple[Task, Task]:
        """Start two tasks to process the stdout and stderr

        It will stream their content to queues registered on self.log_queues
        It will also print them"""

        loop = asyncio.get_running_loop()
        self.stdout_task = loop.create_task(self._process_stdout())
        self.stderr_task = loop.create_task(self._process_stderr())
        return self.stdout_task, self.stderr_task

    async def _process_stdout(self):
        while not self.qemu_process:
            await asyncio.sleep(0.01)  # Todo: Use signal here
        while True:
            line = await self.qemu_process.stdout.readline()
            if not line:  # FD is closed nothing more will come
                print(self, "EOF")
                return
            for queue in self.log_queues:
                await queue.put(("stdout", line))
            print(self, line.decode().strip())
