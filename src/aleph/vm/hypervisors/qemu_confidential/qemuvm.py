import asyncio
from asyncio.subprocess import Process
from pathlib import Path
from typing import TextIO

from aleph_message.models.execution.environment import AMDSEVPolicy
from cpuid.features import secure_encryption_info
from systemd import journal

from aleph.vm.controllers.configuration import QemuConfidentialVMConfiguration
from aleph.vm.controllers.qemu.instance import logger
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM


class QemuConfidentialVM(QemuVM):

    sev_policy: str = hex(AMDSEVPolicy.NO_DBG)
    sev_dh_cert_file: Path  # "vm_godh.b64"
    sev_session_file: Path  # "vm_session.b64"

    def __repr__(self) -> str:
        if self.qemu_process:
            return f"<QemuConfidentialVM: {self.qemu_process.pid}>"
        else:
            return "<QemuConfidentialVM: not running>"

    def __init__(self, vm_hash, config: QemuConfidentialVMConfiguration):
        super().__init__(vm_hash, config)
        self.qemu_bin_path = config.qemu_bin_path
        self.cloud_init_drive_path = config.cloud_init_drive_path
        self.image_path = config.image_path
        self.monitor_socket_path = config.monitor_socket_path
        self.qmp_socket_path = config.qmp_socket_path
        self.vcpu_count = config.vcpu_count
        self.mem_size_mb = config.mem_size_mb
        self.interface_name = config.interface_name
        self.log_queues: list[asyncio.Queue] = []
        self.ovmf_path: Path = config.ovmf_path
        self.sev_session_file = config.sev_session_file
        self.sev_dh_cert_file = config.sev_dh_cert_file
        self.sev_policy = hex(config.sev_policy)

    def prepare_start(self):
        pass

    async def start(
        self,
    ) -> Process:
        # Based on the command
        #  qemu-system-x86_64 -enable-kvm -m 2048 -net nic,model=virtio
        # -net tap,ifname=tap0,script=no,downscript=no -drive file=alpine.qcow2,media=disk,if=virtio -nographic
        # hardware_resources.published ports -> not implemented at the moment
        # hardware_resources.seconds -> only for microvm
        journal_stdout: TextIO = journal.stream(self._journal_stdout_name)
        journal_stderr: TextIO = journal.stream(self._journal_stderr_name)

        # TODO : ensure this is ok at launch
        sev_info = secure_encryption_info()
        if sev_info is None:
            raise ValueError("Not running on an AMD SEV platform?")
        godh = self.sev_dh_cert_file
        launch_blob = self.sev_session_file

        if not (godh.is_file() and launch_blob.is_file()):
            raise FileNotFoundError("Missing guest owner certificates, cannot start the VM.`")
        args = [
            self.qemu_bin_path,
            "-enable-kvm",
            "-nodefaults",
            "-m",
            str(self.mem_size_mb),
            "-smp",
            str(self.vcpu_count),
            "-drive",
            f"if=pflash,format=raw,unit=0,file={self.ovmf_path},readonly=on",
            "-drive",
            f"file={self.image_path},media=disk,if=virtio,format=qcow2",
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
            "-nographic",
            "-serial",
            "stdio",
            "--no-reboot",  # Rebooting from inside the VM shuts down the machine
            "-S",
            # Confidential options
            "-object",
            f"sev-guest,id=sev0,policy={self.sev_policy},cbitpos={sev_info.c_bit_position},"
            f"reduced-phys-bits={sev_info.phys_addr_reduction},"
            f"dh-cert-file={godh},session-file={launch_blob}",
            "-machine",
            "confidential-guest-support=sev0",
            # Linux kernel 6.9 added a control on the RDRAND function to ensure that the random numbers generation
            # works well, on Qemu emulation for confidential computing the CPU model us faked and this makes control
            # raise an error and prevent boot. Passing the argument --cpu host instruct the VM to use the same CPU
            # model than the host thus the VM's kernel knows which method is used to get random numbers (Intel and
            # AMD have different methods) and properly boot.
            "-cpu",
            "host",
            # Uncomment following for debug
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
