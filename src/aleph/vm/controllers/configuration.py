from enum import Enum
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel

from aleph.vm.conf import Settings


class VMConfiguration(BaseModel):
    use_jailer: bool
    firecracker_bin_path: Path
    jailer_bin_path: Path
    config_file_path: Path
    init_timeout: float


class QemuVMConfiguration(BaseModel):
    qemu_bin_path: str
    cloud_init_drive_path: Optional[str]
    image_path: str
    monitor_socket_path: str
    qmp_socket_path: str
    vcpu_count: int
    mem_size_mb: int
    interface_name: Optional[str]


class HypervisorType(str, Enum):
    qemu = "qemu"
    firecracker = "firecracker"


class Configuration(BaseModel):
    vm_id: int
    settings: Settings
    vm_configuration: Union[QemuVMConfiguration, VMConfiguration]
    hypervisor: HypervisorType = HypervisorType.firecracker
