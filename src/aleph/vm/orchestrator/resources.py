import math
import subprocess
from datetime import datetime, timezone
from enum import Enum
from functools import lru_cache
from typing import List, Literal, Optional

import cpuinfo
import psutil
from aiohttp import web
from aleph_message.models import ItemHash
from aleph_message.models.abstract import HashableModel
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel, Extra, Field

from aleph.vm.conf import settings
from aleph.vm.sevclient import SevClient
from aleph.vm.utils import (
    check_amd_sev_es_supported,
    check_amd_sev_snp_supported,
    check_amd_sev_supported,
    cors_allow_all,
)


class Period(BaseModel):
    datetime: datetime


class LoadAverage(BaseModel):
    load1: float
    load5: float
    load15: float

    @classmethod
    def from_psutil(cls, psutil_loadavg: tuple[float, float, float]):
        return cls(
            load1=psutil_loadavg[0],
            load5=psutil_loadavg[1],
            load15=psutil_loadavg[2],
        )


class CoreFrequencies(BaseModel):
    min: float
    max: float

    @classmethod
    def from_psutil(cls, psutil_freq: psutil._common.scpufreq):
        min_ = psutil_freq.min or psutil_freq.current
        max_ = psutil_freq.max or psutil_freq.current
        return cls(min=min_, max=max_)


class CpuUsage(BaseModel):
    count: int
    load_average: LoadAverage
    core_frequencies: CoreFrequencies


class MemoryUsage(BaseModel):
    total_kB: int
    available_kB: int


class DiskUsage(BaseModel):
    total_kB: int
    available_kB: int


class UsagePeriod(BaseModel):
    start_timestamp: datetime
    duration_seconds: float


class GpuDeviceClass(str, Enum):
    VGA_COMPATIBLE_CONTROLLER = "0300"
    _3D_CONTROLLER = "0302"


class GpuProperties(BaseModel):
    """GPU properties."""

    vendor: str = Field(description="GPU vendor name")
    device_name: str = Field(description="GPU vendor card name")
    device_class: GpuDeviceClass = Field(
        description="GPU device class. Look at https://admin.pci-ids.ucw.cz/read/PD/03"
    )
    device_id: str = Field(description="GPU vendor & device ids")

    class Config:
        extra = Extra.forbid


def is_gpu_device_class(device_class: str) -> bool:
    try:
        GpuDeviceClass(device_class)
        return True
    except ValueError:
        return False


class MachineProperties(BaseModel):
    cpu: CpuProperties
    gpu: Optional[List[GpuProperties]]


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
    active: bool = True


def parse_gpu_device_info(line) -> Optional[GpuProperties]:
    """Parse GPU device info from a line of lspci output."""

    device = line.split(' "', maxsplit=1)[1]
    device_class, device_vendor, device_info = device.split('" "', maxsplit=2)
    device_class = device_class.split("[", maxsplit=1)[1][:-1]
    vendor, vendor_id = device_vendor.split(" [", maxsplit=1)
    device_name = device_info.split('"', maxsplit=1)[0]
    device_name, model_id = device_name.split(" [", maxsplit=1)
    device_id = f"{vendor_id[:-1]}:{model_id[:-1]}"

    return (
        GpuProperties(
            vendor=vendor,
            device_name=device_name,
            device_class=device_class,
            device_id=device_id,
        )
        if is_gpu_device_class(device_class)
        else None
    )


def get_gpu_info() -> Optional[List[GpuProperties]]:
    """Get GPU info using lspci command."""

    result = subprocess.run(["lspci", "-mmnnn"], capture_output=True, text=True, check=True)
    gpu_devices = list(
        {device for line in result.stdout.split("\n") if line and (device := parse_gpu_device_info(line)) is not None}
    )
    return gpu_devices if gpu_devices else None


@lru_cache
def get_machine_properties() -> MachineProperties:
    """Fetch machine properties such as architecture, CPU vendor, ...
    These should not change while the supervisor is running.

    In the future, some properties may have to be fetched from within a VM.
    """
    cpu_info = cpuinfo.get_cpu_info()  # Slow
    gpu_info = get_gpu_info()
    return MachineProperties(
        cpu=CpuProperties(
            architecture=cpu_info.get("raw_arch_string", cpu_info.get("arch_string_raw")),
            vendor=cpu_info.get("vendor_id", cpu_info.get("vendor_id_raw")),
            features=list(
                filter(
                    None,
                    (
                        "sev" if check_amd_sev_supported() else None,
                        "sev_es" if check_amd_sev_es_supported() else None,
                        "sev_snp" if check_amd_sev_snp_supported() else None,
                    ),
                )
            ),
        ),
        gpu=gpu_info,
    )


@cors_allow_all
async def about_system_usage(_: web.Request):
    """Public endpoint to expose information about the system usage."""
    period_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    usage: MachineUsage = MachineUsage(
        cpu=CpuUsage(
            count=psutil.cpu_count(),
            load_average=LoadAverage.from_psutil(psutil.getloadavg()),
            core_frequencies=CoreFrequencies.from_psutil(psutil.cpu_freq()),
        ),
        mem=MemoryUsage(
            total_kB=math.ceil(psutil.virtual_memory().total / 1000),
            available_kB=math.floor(psutil.virtual_memory().available / 1000),
        ),
        disk=DiskUsage(
            total_kB=psutil.disk_usage(str(settings.PERSISTENT_VOLUMES_DIR)).total // 1000,
            available_kB=psutil.disk_usage(str(settings.PERSISTENT_VOLUMES_DIR)).free // 1000,
        ),
        period=UsagePeriod(
            start_timestamp=period_start,
            duration_seconds=60,
        ),
        properties=get_machine_properties(),
    )

    return web.json_response(text=usage.json(exclude_none=True))


@cors_allow_all
async def about_certificates(request: web.Request):
    """Public endpoint to expose platform certificates for confidential computing."""

    if not settings.ENABLE_CONFIDENTIAL_COMPUTING:
        return web.HTTPBadRequest(reason="Confidential computing setting not enabled on that server")

    sev_client: SevClient = request.app["sev_client"]

    return web.FileResponse(await sev_client.get_certificates())


class Allocation(BaseModel):
    """An allocation is the set of resources that are currently allocated on this orchestrator.
    It contains the item_hashes of all persistent VMs, instances, on-demand VMs and jobs.
    """

    persistent_vms: set[ItemHash] = Field(default_factory=set)
    instances: set[ItemHash] = Field(default_factory=set)
    on_demand_vms: set[ItemHash] | None = None
    jobs: set[ItemHash] | None = None


class VMNotification(BaseModel):
    """A notification to the orchestrator that a VM has been created or destroyed.
    This is typically sent by a user that just created a VM in order to quickly ensure the creation of the VM.
    """

    instance: ItemHash
