import logging
from enum import Enum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer

from aleph.vm.conf import Settings, settings
from aleph.vm.sizes import MiB

logger = logging.getLogger(__name__)


def _coerce_mib(value: object) -> MiB:
    if isinstance(value, MiB):
        return value
    if not isinstance(value, (int, float, str)):
        raise TypeError(f"Cannot coerce {type(value)!r} to MiB")
    return MiB(int(value))


# A memory size that serializes to/from a plain integer number of MiB.
MemSizeMib = Annotated[
    MiB,
    BeforeValidator(_coerce_mib),
    PlainSerializer(lambda m: m.count, return_type=int),
]


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
    model_config = ConfigDict(arbitrary_types_allowed=True)

    qemu_bin_path: str
    cloud_init_drive_path: str | None = None
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    qga_socket_path: Path | None = None
    vcpu_count: int
    mem_size_mb: MemSizeMib
    interface_name: str | None = None
    host_volumes: list[QemuVMHostVolume]
    gpus: list[QemuGPU]


class QemuConfidentialVMConfiguration(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    qemu_bin_path: str
    cloud_init_drive_path: str | None = None
    image_path: str
    monitor_socket_path: Path
    qmp_socket_path: Path
    qga_socket_path: Path | None = None
    vcpu_count: int
    mem_size_mb: MemSizeMib
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


def get_controller_configuration_path(vm_hash: str) -> Path:
    """Get the path to the controller configuration file for a VM."""
    return Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-controller.json")


def load_controller_configuration(vm_hash: str) -> Configuration | None:
    """Load VM configuration from the controller service configuration file.

    :param vm_hash: The VM hash identifying the configuration file
    :return: The Configuration object, or None if the file doesn't exist
    """
    config_file_path = get_controller_configuration_path(vm_hash)

    if not config_file_path.exists():
        logger.warning(f"Controller configuration file not found for {vm_hash}")
        return None

    with config_file_path.open("r") as f:
        return Configuration.model_validate_json(f.read())


def save_controller_configuration(vm_hash: str, configuration: Configuration) -> Path:
    """Save VM configuration to be used by the controller service"""
    config_file_path = get_controller_configuration_path(vm_hash)
    with config_file_path.open("w") as controller_config_file:
        controller_config_file.write(
            configuration.model_dump_json(
                by_alias=True, exclude_none=True, indent=4, exclude={"settings": {"USE_DEVELOPER_SSH_KEYS"}}
            )
        )
    config_file_path.chmod(0o644)
    return config_file_path


def remove_controller_configuration(vm_hash: str) -> None:
    """Remove the on-disk artifacts that define a VM across supervisor
    restarts: the controller configuration and the cloud-init seed.

    Delete-path only. A merely stopped persistent VM must keep these files;
    they are what reattach (load_persistent_executions) and StartVm read.
    """
    get_controller_configuration_path(vm_hash).unlink(missing_ok=True)
    # Written by build_cloud_init_drive / create_cloud_init_drive_image.
    Path(f"{settings.EXECUTION_ROOT}/cloud-init-{vm_hash}.img").unlink(missing_ok=True)
