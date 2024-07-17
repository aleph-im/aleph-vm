import asyncio
from asyncio.subprocess import Process
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, TextIO

import qmp
from systemd import journal

from aleph.vm.controllers.configuration import QemuVMConfiguration
from aleph.vm.controllers.qemu.instance import logger


@dataclass
class HostVolume:
    path_on_host: Path
    read_only: bool


class QemuVM:
    qemu_bin_path: str
    cloud_init_drive_path: Optional[str]
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    vcpu_count: int
    mem_size_mb: int
    interface_name: str
    qemu_process: Optional[Process] = None
    host_volumes: list[HostVolume]

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

        journal_stdout: TextIO = journal.stream(self._journal_stdout_name)
        journal_stderr: TextIO = journal.stream(self._journal_stderr_name)
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
        for volume in self.host_volumes:
            args += [
                "-drive",
                f"file={volume.path_on_host},format=raw,readonly={'on' if volume.read_only else 'off'},media=disk,if=virtio",
            ]
        if self.interface_name:
            # script=no, downscript=no tell qemu not to try to set up the network itself
            args += ["-net", "nic,model=virtio", "-net", f"tap,ifname={self.interface_name},script=no,downscript=no"]

        if self.cloud_init_drive_path:
            args += ["-cdrom", f"{self.cloud_init_drive_path}"]
        print(*args)

        self.qemu_process = proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=journal_stdout,
            stderr=journal_stderr,
        )

        print(
            f"Started QemuVm {self}, {proc}. Log available with: journalctl -t  {self._journal_stdout_name} -t {self._journal_stderr_name}"
        )
        return proc

    def _get_qmpclient(self) -> Optional[qmp.QEMUMonitorProtocol]:
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
