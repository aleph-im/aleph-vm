from typing import List, Optional

from firecracker.models import FilePath
from pydantic import BaseModel, PositiveInt

VSOCK_PATH = "/tmp/v.sock"


class BootSource(BaseModel):
    kernel_image_path: FilePath = FilePath("vmlinux.bin")
    boot_args: str = (
        "console=ttyS0 reboot=k panic=1 pci=off "
        "ro noapic nomodules random.trust_cpu=on"
    )

    @staticmethod
    def args(enable_console: bool = True):
        default = "reboot=k panic=1 pci=off ro noapic nomodules random.trust_cpu=on"
        if enable_console:
            return "console=ttyS0 " + default
        else:
            return default


class Drive(BaseModel):
    drive_id: str = "rootfs"
    path_on_host: FilePath = FilePath("./runtimes/aleph-alpine-3.13-python/rootfs.ext4")
    is_root_device: bool = True
    is_read_only: bool = True


class MachineConfig(BaseModel):
    vcpu_count: PositiveInt = 1
    mem_size_mib: PositiveInt = 128
    smt: bool = False


class Vsock(BaseModel):
    vsock_id: str = "1"
    guest_cid: PositiveInt = 3
    uds_path: str = VSOCK_PATH


class NetworkInterface(BaseModel):
    iface_id: str = "eth0"
    guest_mac: str = "AA:FC:00:00:00:01"
    host_dev_name: str


class FirecrackerConfig(BaseModel):
    boot_source: BootSource
    drives: List[Drive]
    machine_config: MachineConfig
    vsock: Optional[Vsock]
    network_interfaces: Optional[List[NetworkInterface]]

    class Config:
        allow_population_by_field_name = True
        alias_generator = lambda x: x.replace("_", "-")
