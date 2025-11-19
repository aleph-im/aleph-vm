import asyncio
from asyncio.subprocess import Process
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, TextIO

import qmp
from systemd import journal

from aleph.vm.controllers.configuration import QemuGPU, QemuVMConfiguration
from aleph.vm.controllers.qemu.instance import logger


@dataclass
class HostVolume:
    path_on_host: Path
    read_only: bool


class QemuVM:
    qemu_bin_path: str
    cloud_init_drive_path: str | None
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    vcpu_count: int
    mem_size_mb: int
    interface_name: str
    qemu_process: Process | None = None
    host_volumes: list[HostVolume]
    gpus: list[QemuGPU]
    journal_stdout: TextIO | None
    journal_stderr: TextIO | None

    def __repr__(self) -> str:
        if self.qemu_process:
            return f"<QemuVM: {self.qemu_process.pid}>"
        else:
            return "<QemuVM: not running>"

    def __init__(self, vm_hash, config: QemuVMConfiguration):
        self.qemu_bin_path = config.qemu_bin_path
        self.cloud_init_drive_path = config.cloud_init_drive_path
        self.image_path = config.image_path
        self.monitor_socket_path = config.monitor_socket_path
        self.qmp_socket_path = config.qmp_socket_path
        self.vcpu_count = config.vcpu_count
        self.mem_size_mb = config.mem_size_mb
        self.interface_name = config.interface_name
        self.vm_hash = vm_hash

        self.host_volumes = [
            HostVolume(
                path_on_host=volume.path_on_host,
                read_only=volume.read_only,
            )
            for volume in config.host_volumes
        ]
        self.gpus = config.gpus

    @property
    def _journal_stdout_name(self) -> str:
        return f"vm-{self.vm_hash}-stdout"

    @property
    def _journal_stderr_name(self) -> str:
        return f"vm-{self.vm_hash}-stderr"

    def prepare_start(self):
        pass

    async def start(
        self,
    ) -> Process:
        # Based on the command
        #  qemu-system-x86_64 -enable-kvm -m 2048 -net nic,model=virtio
        # -net tap,ifname=tap0,script=no,downscript=no -drive file=alpine.qcow2,media=disk,if=virtio -nographic

        self.journal_stdout: BinaryIO = journal.stream(self._journal_stdout_name)
        self.journal_stderr: BinaryIO = journal.stream(self._journal_stderr_name)
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
            # "--no-reboot",  # Rebooting from inside the VM shuts down the machine
            # Disable --no-reboot so user can reboot from inside the VM. see ALEPH-472
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
            # nographics. Seems redundant with -serial stdio but without it the boot process is not displayed on stdout
            "-nographic",
            # Boot
            # order=c only first hard drive
            # reboot-timeout in combination with -no-reboot, makes it so qemu stop if there is no bootable device
            "-boot",
            "order=c,reboot-timeout=1",
            # Uncomment for debug
            # "-serial", "telnet:localhost:4321,server,nowait",
            # "-snapshot",  # Do not save anything to disk
        ]
        if self.interface_name:
            # script=no, downscript=no tell qemu not to try to set up the network itself
            args += ["-net", "nic,model=virtio", "-net", f"tap,ifname={self.interface_name},script=no,downscript=no"]

        if self.cloud_init_drive_path:
            args += ["-cdrom", f"{self.cloud_init_drive_path}"]

        args += self._get_host_volumes_args()
        args += self._get_gpu_args()
        print(*args)

        self.qemu_process = proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=self.journal_stdout,
            stderr=self.journal_stderr,
        )

        print(
            f"Started QemuVm {self}, {proc}. Log available with: journalctl -t  {self._journal_stdout_name} -t {self._journal_stderr_name}"
        )
        return proc

    def _get_host_volumes_args(self):
        args = []
        for volume in self.host_volumes:
            args += [
                "-drive",
                f"file={volume.path_on_host},format=raw,readonly={'on' if volume.read_only else 'off'},media=disk,if=virtio",
            ]
        return args

    def _get_gpu_args(self):
        args = [
            # Use host-phys-bits-limit argument for GPU support. TODO: Investigate how to get the correct bits size
            "-cpu",
            "host,host-phys-bits-limit=0x28",
        ]
        for gpu in self.gpus:
            device_args = f"vfio-pci,host={gpu.pci_host},multifunction=on,rombar=0"

            # Only add x-vga=on parameter if the GPU supports it
            if gpu.supports_x_vga:
                device_args += ",x-vga=on"

            args += [
                "-device",
                device_args,
            ]
        return args

    def _get_qmpclient(self) -> qmp.QEMUMonitorProtocol | None:
        if not (self.qmp_socket_path and self.qmp_socket_path.exists()):
            return None
        client = qmp.QEMUMonitorProtocol(str(self.qmp_socket_path))
        client.connect()
        return client

    def send_shutdown_message(self):
        print("sending shutdown message to vm")
        client = self._get_qmpclient()
        if client:
            resp = client.command("system_powerdown")
            if not resp == {}:
                logger.warning("unexpected answer from VM", resp)
            print("shutdown message sent")
            client.close()

    async def stop(self):
        """Stop the VM."""
        self.send_shutdown_message()

        if self.journal_stdout and self.journal_stdout != asyncio.subprocess.DEVNULL:
            self.journal_stdout.close()
        if self.journal_stderr and self.journal_stderr != asyncio.subprocess.DEVNULL:
            self.journal_stderr.close()
