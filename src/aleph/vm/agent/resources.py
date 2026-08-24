import math
from datetime import datetime, timezone

import psutil
from aiohttp import web
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import CpuProperties
from pydantic import BaseModel, Field

from aleph.vm.agent.aggregate import get_compatible_gpus, update_aggregate_settings
from aleph.vm.agent.machine import get_cpu_info, get_hardware_info, get_memory_info
from aleph.vm.agent.vcpu_probe import get_supported_snp_vcpu_types
from aleph.vm.conf import settings
from aleph.vm.resources import GpuDevice
from aleph.vm.sevclient import SevClient
from aleph.vm.storage_pools import pools_disk_usage
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


class SevSnpProperties(BaseModel):
    supported_vcpu_types: list[str] = Field(
        description="QEMU SNP guest CPU models this host can launch (e.g. EPYC-v4). "
        "The scheduler matches v-program launch-measurement vcpu_type against this list."
    )


class TeeProperties(BaseModel):
    """TEE launch capability, keyed by platform so TDX and friends slot in later."""

    sev_snp: SevSnpProperties | None = None


class MachineProperties(BaseModel):
    cpu: CpuProperties
    tee: TeeProperties | None = None


class AnnotatedGpuDevice(GpuDevice):
    """A host GPU annotated with what the network says about it.

    The supervisor reports raw hardware (GpuDevice); the network-derived
    fields are the agent's to add, from the settings aggregate's
    compatible_gpus whitelist."""

    model: str | None = Field(description="GPU model name on Aleph Network", default=None)
    compatible: bool = Field(description="GPU compatibility with Aleph Network", default=False)


class GpuProperties(BaseModel):
    devices: list[AnnotatedGpuDevice] | None = None
    available_devices: list[AnnotatedGpuDevice] | None = None


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

    model: str | None = Field(default=None, description="CPU model")
    frequency: int | None = Field(default=None, description="CPU frequency")
    count: int | None = Field(default=None, description="CPU count")


class MemoryProperties(BaseModel):
    """MEMORY properties."""

    size: int | None = Field(default=None, description="Memory size")
    units: str | None = Field(default=None, description="Memory size units")
    type: str | None = Field(default=None, description="Memory type")
    clock: int | None = Field(default=None, description="Memory clock")
    clock_units: str | None = Field(default=None, description="Memory clock units")


class MachineCapability(BaseModel):
    cpu: ExtendedCpuProperties
    memory: MemoryProperties
    tee: TeeProperties | None = None


async def _gpus_from_host_info(host_info) -> GpuProperties:
    """Rebuild the rich GPU inventory from the supervisor's HostInfo.

    GetHostInfo carries raw GpuDevice fields as plain dicts (gpu_inventory /
    available_gpus): the supervisor never talks to the network, so the
    network annotation (AnnotatedGpuDevice: `model`, `compatible`) is
    applied here from the settings aggregate.
    """
    await update_aggregate_settings()
    network_models = {gpu.device_id: gpu.model for gpu in get_compatible_gpus()}

    def annotate(gpu: dict) -> AnnotatedGpuDevice:
        return AnnotatedGpuDevice.model_validate(
            gpu
            | {
                "model": network_models.get(gpu["device_id"]),
                "compatible": gpu["device_id"] in network_models,
            }
        )

    return GpuProperties(
        devices=[annotate(gpu) for gpu in host_info.gpu_inventory],
        available_devices=[annotate(gpu) for gpu in host_info.available_gpus],
    )


async def _get_tee_properties() -> TeeProperties | None:
    """TEE launch capability, absent when there is nothing provable to advertise."""
    snp_vcpu_types = await get_supported_snp_vcpu_types()
    if not snp_vcpu_types:
        return None
    return TeeProperties(sev_snp=SevSnpProperties(supported_vcpu_types=snp_vcpu_types))


@async_cache
async def _get_static_machine_properties() -> MachineProperties:
    """The part of the machine properties that cannot change while the agent
    runs: architecture, vendor and the SEV feature flags. Cached because
    ``get_hardware_info`` shells out.

    ``tee`` is deliberately left ``None`` here and filled in per call by
    ``get_machine_properties``: it depends on the QEMU probe, which can fail
    transiently and then recover, and caching it alongside the static facts
    would freeze a failed probe's empty advertisement for the life of the
    process.
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
        tee=None,
    )


async def get_machine_properties() -> MachineProperties:
    """Fetch machine properties such as architecture, CPU vendor, ...

    The static part is cached; the TEE block is re-evaluated on every call so
    that a probe which failed once and has since recovered is advertised
    again. Cheap once the probe has succeeded, since the probe keeps its own
    result.

    In the future, some properties may have to be fetched from within a VM.
    """
    static = await _get_static_machine_properties()
    return static.model_copy(update={"tee": await _get_tee_properties()})


@async_cache
async def _get_static_machine_capability() -> MachineCapability:
    """The part of the machine capability that cannot change while the agent
    runs. Cached because ``get_hardware_info`` shells out. ``tee`` is left
    ``None`` and filled in per call by ``get_machine_capability``, for the
    same reason as ``_get_static_machine_properties``.
    """
    hw = await get_hardware_info()
    cpu_info = get_cpu_info(hw)
    mem_info = get_memory_info(hw)

    return MachineCapability(
        cpu=ExtendedCpuProperties(
            architecture=cpu_info["architecture"],
            vendor=cpu_info["vendor"],
            model=cpu_info["model"],
            frequency=(cpu_info["frequency"]),
            count=(cpu_info["count"]),
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
        tee=None,
    )


async def get_machine_capability() -> MachineCapability:
    """What ``/about/capability`` reports. Static part cached, TEE block
    re-evaluated per call so a recovered probe is advertised again."""
    static = await _get_static_machine_capability()
    return static.model_copy(update={"tee": await _get_tee_properties()})


def _disk_usage_from_pools(host_info) -> DiskUsage:
    """Aggregate capacity across every volume pool (same-filesystem pools
    counted once). Usage-aware available disk comes from the supervisor's
    HostInfo; a gRPC supervisor that has not implemented it yet reports 0."""
    total_bytes, free_bytes = pools_disk_usage()
    return DiskUsage(
        total_kB=total_bytes // 1000,
        available_kB=(host_info.available_disk_bytes // 1000 if host_info.available_disk_bytes else free_bytes // 1000),
    )


@cors_allow_all
async def about_system_usage(request: web.Request):
    """Public endpoint to expose information about the system usage."""
    period_start = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    host_info = await request.app["supervisor"].get_host_info()

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
        disk=_disk_usage_from_pools(host_info),
        period=UsagePeriod(
            start_timestamp=period_start,
            duration_seconds=60,
        ),
        properties=machine_properties,
        gpu=await _gpus_from_host_info(host_info),
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
    # V-PROGRAM messages (verifiable SEV-SNP programs), scheduler-designated
    v_programs: set[ItemHash] = Field(default_factory=set)


class VMNotification(BaseModel):
    """A notification to the orchestrator that a VM has been created or destroyed.
    This is typically sent by a user that just created a VM in order to quickly ensure the creation of the VM.
    """

    instance: ItemHash
