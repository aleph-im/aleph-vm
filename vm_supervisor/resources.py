from datetime import datetime, timezone
from typing import Tuple

import psutil
from aiohttp import web
from pydantic import BaseModel

from .conf import settings


class Period(BaseModel):
    datetime: datetime


class LoadAverage(BaseModel):
    load1: float
    load5: float
    load15: float

    @classmethod
    def from_psutil(cls, psutil_loadavg: Tuple[float, float, float]):
        return cls(load1=psutil_loadavg[0],
                   load5=psutil_loadavg[1],
                   load15=psutil_loadavg[2],
                   )


class CoreFrequencies(BaseModel):
    min: float
    max: float

    @classmethod
    def from_psutil(cls, psutil_freq: psutil._common.scpufreq):
        min = psutil_freq.min or psutil_freq.current
        max = psutil_freq.max or psutil_freq.current
        return cls(min=min, max=max)


class CpuUsage(BaseModel):
    count: int
    load_average: LoadAverage
    core_frequencies: CoreFrequencies


class MemoryUsage(BaseModel):
    total_kB: int
    available_kB: int

    @property
    def available_MB(self) -> float:
        return self.available_kB / 1000


class DiskUsage(BaseModel):
    total_kB: int
    available_kB: int

    @property
    def available_MB(self) -> float:
        return self.available_kB / 1000


class UsagePeriod(BaseModel):
    start_timestamp: datetime
    duration_seconds: float

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat(),
        }


class MachineUsage(BaseModel):
    cpu: CpuUsage
    mem: MemoryUsage
    disk: DiskUsage
    period: UsagePeriod


async def about_system_usage(request: web.Request):
    period_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)

    usage: MachineUsage = MachineUsage(
        cpu=CpuUsage(
            count=psutil.cpu_count(),
            load_average=LoadAverage.from_psutil(psutil.getloadavg()),
            core_frequencies=CoreFrequencies.from_psutil(psutil.cpu_freq()),
        ),
        mem=MemoryUsage(
            total_kB=psutil.virtual_memory().total / 1000,
            available_kB=psutil.virtual_memory().available / 1000,
        ),
        disk=DiskUsage(
            total_kB=psutil.disk_usage(settings.PERSISTENT_VOLUMES_DIR).total
            // 1000,  # 10 GB,
            available_kB=psutil.disk_usage(settings.PERSISTENT_VOLUMES_DIR).free
            // 1000,  # 9 GB
        ),
        period=UsagePeriod(
            start_timestamp=period_start,
            duration_seconds=60,
        ),
    )
    return web.json_response(
        text=usage.json(),
    )
