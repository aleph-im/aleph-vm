import subprocess
from enum import Enum
from typing import List, Optional

from aleph_message.models import HashableModel
from pydantic import BaseModel, Extra, Field


class HostGPU(BaseModel):
    """Host GPU properties detail."""

    pci_host: str = Field(description="GPU PCI host address")

    class Config:
        extra = Extra.forbid


class GpuDeviceClass(str, Enum):
    """GPU device class. Look at https://admin.pci-ids.ucw.cz/read/PD/03"""

    VGA_COMPATIBLE_CONTROLLER = "0300"
    _3D_CONTROLLER = "0302"


class GpuDevice(HashableModel):
    """GPU properties."""

    vendor: str = Field(description="GPU vendor name")
    device_name: str = Field(description="GPU vendor card name")
    device_class: GpuDeviceClass = Field(
        description="GPU device class. Look at https://admin.pci-ids.ucw.cz/read/PD/03"
    )
    pci_host: str = Field(description="Host PCI bus for this device")
    device_id: str = Field(description="GPU vendor & device ids")

    class Config:
        extra = Extra.forbid


def is_gpu_device_class(device_class: str) -> bool:
    try:
        GpuDeviceClass(device_class)
        return True
    except ValueError:
        return False


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


def parse_gpu_device_info(line: str) -> Optional[GpuDevice]:
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

    return GpuDevice(
        pci_host=pci_host,
        vendor=vendor_name,
        device_name=device_name,
        device_class=device_class,
        device_id=device_id,
    )


def get_gpu_devices() -> Optional[List[GpuDevice]]:
    """Get GPU info using lspci command."""

    result = subprocess.run(["lspci", "-mmnnn"], capture_output=True, text=True, check=True)
    gpu_devices = list(
        {device for line in result.stdout.split("\n") if line and (device := parse_gpu_device_info(line)) is not None}
    )
    return gpu_devices if gpu_devices else None
