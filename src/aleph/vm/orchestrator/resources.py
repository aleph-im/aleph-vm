import math
from datetime import datetime, timezone
from typing import Optional

import psutil
from aiohttp import web
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel, Field

from aleph.vm.conf import settings
from aleph.vm.orchestrator.machine import (
    get_cpu_info,
    get_hardware_info,
    get_memory_info,
)
from aleph.vm.pool import VmPool
from aleph.vm.resources import GpuDevice
from aleph.vm.sevclient import SevClient
from aleph.vm.utils import (
    async_cache,
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


class MachineProperties(BaseModel):
    cpu: CpuProperties


class GpuProperties(BaseModel):
    devices: list[GpuDevice] | None = None
    available_devices: list[GpuDevice] | None = None


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
    gpu: GpuProperties
    active: bool = True


class ExtendedCpuProperties(CpuProperties):
    """CPU properties."""

    model: Optional[str] = Field(default=None, description="CPU model")
    frequency: Optional[str] = Field(default=None, description="CPU frequency")
    count: Optional[str] = Field(default=None, description="CPU count")


class MemoryProperties(BaseModel):
    """MEMORY properties."""

    size: Optional[str] = Field(default=None, description="Memory size")
    units: Optional[str] = Field(default=None, description="Memory size units")
    type: Optional[str] = Field(default=None, description="Memory type")
    clock: Optional[str] = Field(default=None, description="Memory clock")
    clock_units: Optional[str] = Field(default=None, description="Memory clock units")


class MachineCapability(BaseModel):
    cpu: ExtendedCpuProperties
    memory: MemoryProperties


def get_machine_gpus(request: web.Request) -> GpuProperties:
    pool: VmPool = request.app["vm_pool"]
    gpus = pool.gpus
    available_gpus = pool.get_available_gpus()

    return GpuProperties(
        devices=gpus,
        available_devices=available_gpus,
    )


machine_properties_cached = None


@async_cache
async def get_machine_properties() -> MachineProperties:
    """Fetch machine properties such as architecture, CPU vendor, ...
    These should not change while the supervisor is running.

    In the future, some properties may have to be fetched from within a VM.
    """
    hw = await get_hardware_info()
    cpu_info = get_cpu_info(hw)
    return MachineProperties(
        cpu=CpuProperties(
            architecture=cpu_info["architecture"],
            vendor=cpu_info["vendor"],
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
    )


@async_cache
async def get_machine_capability() -> MachineCapability:
    hw = await get_hardware_info()
    cpu_info = get_cpu_info(hw)
    mem_info = get_memory_info(hw)

    return MachineCapability(
        cpu=ExtendedCpuProperties(
            architecture=cpu_info["architecture"],
            vendor=cpu_info["vendor"],
            model=cpu_info["model"],
            frequency=cpu_info["frequency"],
            count=cpu_info["count"],
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
        memory=MemoryProperties(
            size=mem_info["size"],
            units=mem_info["units"],
            type=mem_info["type"],
            clock=mem_info["clock"],
        ),
    )


@cors_allow_all
async def about_system_usage(request: web.Request):
    """Public endpoint to expose information about the system usage."""
    period_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    machine_properties = get_machine_properties()
    pool = request.app["vm_pool"]

    machine_properties = await get_machine_properties()
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
            available_kB=pool.calculate_available_disk() // 1000,
            # available_kB=psutil.disk_usage(str(settings.PERSISTENT_VOLUMES_DIR)).free // 1000,
        ),
        period=UsagePeriod(
            start_timestamp=period_start,
            duration_seconds=60,
        ),
        properties=machine_properties,
        gpu=get_machine_gpus(request),
    )

    return web.json_response(text=usage.model_dump_json(exclude_none=True))


@cors_allow_all
async def about_certificates(request: web.Request):
    """Public endpoint to expose platform certificates for confidential computing."""

    if not settings.ENABLE_CONFIDENTIAL_COMPUTING:
        return web.HTTPServiceUnavailable(text="Confidential computing setting not enabled on that server")

    sev_client: SevClient = request.app["sev_client"]

    return web.FileResponse(await sev_client.get_certificates())


async def about_capability(_: web.Request):
    """Public endpoint to expose information about the CRN capability."""

    capability: MachineCapability = await get_machine_capability()
    return web.json_response(text=capability.json(exclude_none=False))


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
