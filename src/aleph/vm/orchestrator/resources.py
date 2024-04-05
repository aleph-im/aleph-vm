import math
from datetime import datetime, timezone
from functools import lru_cache
from typing import Optional

import psutil
from aiohttp import web
from aleph.vm.conf import settings
from aleph.vm.orchestrator.machine import get_cpu_info, get_memory_info
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel, Field


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


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod
    properties: MachineProperties
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


@lru_cache
def get_machine_properties() -> MachineProperties:
    """Fetch machine properties such as architecture, CPU vendor, ...
    These should not change while the supervisor is running.

    In the future, some properties may have to be fetched from within a VM.
    """

    cpu_info = get_cpu_info()
    return MachineProperties(
        cpu=CpuProperties(
            architecture=cpu_info["architecture"],
            vendor=cpu_info["vendor"],
        ),
    )


@lru_cache
def get_machine_capability() -> MachineCapability:
    cpu_info = get_cpu_info()
    mem_info = get_memory_info()

    return MachineCapability(
        cpu=ExtendedCpuProperties(
            architecture=cpu_info["architecture"],
            vendor=cpu_info["vendor"],
            model=cpu_info["model"],
            frequency=cpu_info["frequency"],
            count=cpu_info["count"],
        ),
        memory=MemoryProperties(
            size=mem_info["size"],
            units=mem_info["units"],
            type=mem_info["type"],
            clock=mem_info["clock"],
            clock_units=mem_info["clock_units"],
        ),
    )


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
    return web.json_response(text=usage.json(exclude_none=True), headers={"Access-Control-Allow-Origin:": "*"})


async def about_capability(_: web.Request):
    """Public endpoint to expose information about the CRN capability."""

    capability: MachineCapability = get_machine_capability()
    return web.json_response(text=capability.json(exclude_none=False), headers={"Access-Control-Allow-Origin:": "*"})


class Allocation(BaseModel):
    """An allocation is the set of resources that are currently allocated on this orchestrator.
    It contains the item_hashes of all persistent VMs, instances, on-demand VMs and jobs.
    """

    persistent_vms: set[str] = Field(default_factory=set)
    instances: set[str] = Field(default_factory=set)
    on_demand_vms: Optional[set[str]] = None
    jobs: Optional[set[str]] = None


class VMNotification(BaseModel):
    """A notification to the orchestrator that a VM has been created or destroyed.
    This is typically sent by a user that just created a VM in order to quickly ensure the creation of the VM.
    """

    instance: ItemHash
