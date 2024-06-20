import logging
from enum import Enum
from pathlib import Path
from typing import Optional, Union

from pydantic import BaseModel

from aleph.vm.conf import Settings, settings

logger = logging.getLogger(__name__)


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
    monitor_socket_path: Path
    qmp_socket_path: Path
    vcpu_count: int
    mem_size_mb: int
    interface_name: Optional[str]


class HypervisorType(str, Enum):
    qemu = "qemu"
    firecracker = "firecracker"


class Configuration(BaseModel):
    vm_id: int
    vm_hash: str
    settings: Settings
    vm_configuration: Union[QemuVMConfiguration, VMConfiguration]
    hypervisor: HypervisorType = HypervisorType.firecracker


def save_controller_configuration(vm_hash: str, configuration: Configuration) -> Path:
    """Save VM configuration to be used by the controller service"""
    config_file_path = Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-controller.json")
    with config_file_path.open("w") as controller_config_file:
        controller_config_file.write(
            configuration.json(
                by_alias=True, exclude_none=True, indent=4, exclude={"settings": {"USE_DEVELOPER_SSH_KEYS"}}
            )
        )
    config_file_path.chmod(0o644)
    return config_file_path
