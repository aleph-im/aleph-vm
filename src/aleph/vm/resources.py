import subprocess
from enum import Enum
from typing import Optional

from aleph_message.models import HashableModel
from pydantic import BaseModel, ConfigDict, Field

from aleph.vm.orchestrator.utils import get_compatible_gpus


class HostGPU(BaseModel):
    """Host GPU properties detail."""

    pci_host: str = Field(description="GPU PCI host address")
    supports_x_vga: bool = Field(description="Whether the GPU supports x-vga QEMU parameter", default=True)

    model_config = ConfigDict(extra="forbid")


class GpuDeviceClass(str, Enum):
    """GPU device class. Look at https://admin.pci-ids.ucw.cz/read/PD/03"""

    VGA_COMPATIBLE_CONTROLLER = "0300"
    _3D_CONTROLLER = "0302"


class GpuDevice(HashableModel):
    """GPU properties."""

    vendor: str = Field(description="GPU vendor name")
    model: str | None = Field(description="GPU model name on Aleph Network", default=None)
    device_name: str = Field(description="GPU vendor card name")
    device_class: GpuDeviceClass = Field(
        description="GPU device class. Look at https://admin.pci-ids.ucw.cz/read/PD/03"
    )
    pci_host: str = Field(description="Host PCI bus for this device")
    device_id: str = Field(description="GPU vendor & device ids")
    compatible: bool = Field(description="GPU compatibility with Aleph Network", default=False)

    @property
    def has_x_vga_support(self) -> bool:
        """
        Determine if the GPU supports x-vga based on its device class.

        VGA compatible controllers (0300) support x-vga
        3D controllers (0302) do not support x-vga
        """
        return self.device_class == GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER

    model_config = ConfigDict(extra="forbid")


class CompatibleGPU(BaseModel):
    """Compatible GPU properties detail."""

    vendor: str = Field(description="GPU vendor name")
    model: str = Field(description="GPU model name")
    name: str = Field(description="GPU full name")
    device_id: str = Field(description="GPU device id code including vendor_id and model_id")


def is_gpu_device_class(device_class: str) -> bool:
    try:
        GpuDeviceClass(device_class)
        return True
    except ValueError:
        return False


def get_gpu_model(device_id: str) -> bool | None:
    """Returns a GPU model name if it's found from the compatible ones."""
    model_gpu_set = {gpu["device_id"]: gpu["model"] for gpu in get_compatible_gpus()}
    try:
        return model_gpu_set[device_id]
    except KeyError:
        return None


def is_gpu_compatible(device_id: str) -> bool:
    """Checks if a GPU is compatible based on vendor and model IDs."""
    compatible_gpu_set = {gpu["device_id"] for gpu in get_compatible_gpus()}
    return device_id in compatible_gpu_set


def get_vendor_name(vendor_id: str) -> str:
    match vendor_id:
        case "10de":
            return "NVIDIA"
        case "1002":
            return "AMD"
        case "8086":
            return "Intel"
        case _:
            raise ValueError("Device vendor not compatible")


def is_kernel_enabled_gpu(pci_host: str) -> bool:
    # Get detailed info about Kernel drivers used by this device.
    # Needs to use specifically only the kernel driver vfio-pci to be compatible for QEmu virtualization
    result = subprocess.run(["lspci", "-s", pci_host, "-nnk"], capture_output=True, text=True, check=True)
    details = result.stdout.split("\n")
    if "\tKernel driver in use: vfio-pci" in details:
        return True

    return False


def parse_gpu_device_info(line: str) -> GpuDevice | None:
    """Parse GPU device info from a line of lspci output."""

    pci_host, device = line.split(' "', maxsplit=1)

    if not is_kernel_enabled_gpu(pci_host):
        return None

    device_class, device_vendor, device_info = device.split('" "', maxsplit=2)
    device_class = device_class.split("[", maxsplit=1)[1][:-1]

    if not is_gpu_device_class(device_class):
        return None

    device_class = GpuDeviceClass(device_class)

    vendor, vendor_id = device_vendor.rsplit(" [", maxsplit=1)
    vendor_id = vendor_id[:-1]
    vendor_name = get_vendor_name(vendor_id)
    device_name = device_info.split('"', maxsplit=1)[0]
    device_name, model_id = device_name.rsplit(" [", maxsplit=1)
    model_id = model_id[:-1]
    device_id = f"{vendor_id}:{model_id}"
    model = get_gpu_model(device_id=device_id)
    compatible = is_gpu_compatible(device_id=device_id)

    return GpuDevice(
        pci_host=pci_host,
        vendor=vendor_name,
        model=model,
        device_name=device_name,
        device_class=device_class,
        device_id=device_id,
        compatible=compatible,
    )


def get_gpu_devices() -> list[GpuDevice]:
    """Get GPU info using lspci command."""

    result = subprocess.run(["lspci", "-mmnnn"], capture_output=True, text=True, check=True)
    output = result.stdout
    gpu_devices = list(
        {device for line in output.split("\n") if line and (device := parse_gpu_device_info(line)) is not None}
    )
    return gpu_devices if gpu_devices else []
