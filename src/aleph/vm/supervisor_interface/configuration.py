import logging
from enum import Enum
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer

from aleph.vm.conf import IPv6AllocationPolicy, settings
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


class ControllerSettings(BaseModel):
    """The slice of node settings a VM controller actually needs.

    Controller configs used to embed a FULL Settings dump, which coupled the
    on-disk format to every one of the ~200 settings: any rename or removal
    broke parsing of configs written by the previous version and crash-looped
    the supervisor daemon on upgrade (the 1.13.0 CONNECTIVITY_DNS_HOSTNAME
    incident). Only the fields below were ever read controller-side
    (supervisor/controllers/__main__.py); nothing else belongs here.

    Validation is deliberately lax in both directions:
    - ``extra="ignore"``: configs written by older versions carry the full
      dump; the surplus keys are ignored on read. No file migration needed.
    - ``from_attributes=True``: writers pass the live Settings object and
      pydantic extracts just this slice.
    - Defaults mirror conf.py so a key absent from an old dump (or removed
      from a future one) falls back instead of failing.
    Known keys with invalid values still fail loudly."""

    model_config = ConfigDict(extra="ignore", from_attributes=True)

    JAILER_BASE_DIR: Path | None = None
    NETWORK_INTERFACE: str | None = None
    IPV4_ADDRESS_POOL: str = "172.16.0.0/12"
    IPV4_NETWORK_PREFIX_LENGTH: int = 24
    IPV6_ADDRESS_POOL: str = "fc00:1:2:3::/64"
    IPV6_ALLOCATION_POLICY: IPv6AllocationPolicy = IPv6AllocationPolicy.static
    IPV6_SUBNET_PREFIX: int = 124
    IPV6_FORWARDING_ENABLED: bool = True
    USE_NDP_PROXY: bool = True


class Configuration(BaseModel):
    vm_id: int
    vm_hash: str
    settings: ControllerSettings
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
    # qemu does not unlink its UNIX control sockets on exit; once the VM
    # is deleted they are dead files (a relaunch would bind over them).
    for socket_kind in ("monitor", "qmp", "qga"):
        Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-{socket_kind}.socket").unlink(missing_ok=True)
