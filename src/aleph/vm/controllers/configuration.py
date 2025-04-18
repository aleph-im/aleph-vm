import logging
from enum import Enum
from pathlib import Path

from pydantic import BaseModel

from aleph.vm.conf import Settings, settings

logger = logging.getLogger(__name__)


class VMConfiguration(BaseModel):
    use_jailer: bool
    firecracker_bin_path: Path
    jailer_bin_path: Path
    config_file_path: Path
    init_timeout: float


class QemuVMHostVolume(BaseModel):
    mount: str
    path_on_host: Path
    read_only: bool


class QemuGPU(BaseModel):
    pci_host: str
    supports_x_vga: bool = True  # Default to True for backward compatibility


class QemuVMConfiguration(BaseModel):
    qemu_bin_path: str
    cloud_init_drive_path: str | None = None
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    vcpu_count: int
    mem_size_mb: int
    interface_name: str | None = None
    host_volumes: list[QemuVMHostVolume]
    gpus: list[QemuGPU]


class QemuConfidentialVMConfiguration(BaseModel):
    qemu_bin_path: str
    cloud_init_drive_path: str | None = None
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    vcpu_count: int
    mem_size_mb: int
    interface_name: str | None = None
    host_volumes: list[QemuVMHostVolume]
    gpus: list[QemuGPU]
    ovmf_path: Path
    sev_session_file: Path
    sev_dh_cert_file: Path
    sev_policy: int


class HypervisorType(str, Enum):
    qemu = "qemu"
    firecracker = "firecracker"


class Configuration(BaseModel):
    vm_id: int
    vm_hash: str
    settings: Settings
    vm_configuration: QemuConfidentialVMConfiguration | QemuVMConfiguration | VMConfiguration
    hypervisor: HypervisorType = HypervisorType.firecracker


def save_controller_configuration(vm_hash: str, configuration: Configuration) -> Path:
    """Save VM configuration to be used by the controller service"""
    config_file_path = Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-controller.json")
    with config_file_path.open("w") as controller_config_file:
        controller_config_file.write(
            configuration.model_dump_json(
                by_alias=True, exclude_none=True, indent=4, exclude={"settings": {"USE_DEVELOPER_SSH_KEYS"}}
            )
        )
    config_file_path.chmod(0o644)
    return config_file_path
