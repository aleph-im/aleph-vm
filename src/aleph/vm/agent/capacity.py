"""Agent-side resource admission: capacity policy and the GPU reservation ledger.

The instance/program distinction, the two-bucket memory accounting, the vCPU
overcommit factor and user-scoped GPU holds are client policy: the supervisor
only enforces mechanism invariants (physical memory, no GPU double-attach).
The agent is the supervisor's single client, so this in-memory ledger is
consistent by construction.

Committed memory/vCPU figures come from the agent's own registry (records are
created at create and forgotten at delete); GPU inventory and current
attachments come from the supervisor's HostInfo.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psutil
from aleph_message.models import ExecutableContent, ItemHash
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import GpuDevice, InsufficientResourcesError
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.types import GpuSpec, PciAddress

logger = logging.getLogger(__name__)

RESERVATION_TTL_SECONDS = 60


@dataclass(frozen=True)
class ResourceRequirements:
    """Resources an Aleph message asks for, reduced to scalars plus GPU kinds.

    Agent-internal: built from the message before any download, consumed by
    :meth:`CapacityManager.check_capacity` and the GPU ledger."""

    vcpus: int
    memory_mib: int
    disk_mib: int
    is_instance: bool
    gpu_device_ids: list[str] = field(default_factory=list)


def requirements_from_message(content: ExecutableContent) -> ResourceRequirements:
    """Extract the resources a message requests into a message-free DTO."""
    is_instance = isinstance(content, InstanceContent)
    disk_mib = 0
    if isinstance(content, InstanceContent) and content.rootfs:
        disk_mib += content.rootfs.size_mib
    for volume in content.volumes or []:
        disk_mib += getattr(volume, "size_mib", 0) or 0
    return ResourceRequirements(
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        disk_mib=disk_mib,
        is_instance=is_instance,
        gpu_device_ids=requested_gpu_ids(content),
    )


def requested_gpu_ids(content: ExecutableContent) -> list[str]:
    """The vendor:device ids of the GPUs a message requests."""
    requested = content.requirements.gpu if content.requirements and content.requirements.gpu else []
    return [gpu.device_id for gpu in requested]


@dataclass
class GpuHold:
    """A user's hold on one concrete host card, expiring after
    RESERVATION_TTL_SECONDS."""

    user: str
    expiration: datetime

    def is_expired(self) -> bool:
        return datetime.now(tz=timezone.utc) > self.expiration


class CapacityManager:
    """Admission policy and GPU reservation ledger for one agent process.

    Holds are keyed by the concrete host card (pci_host); expired entries are
    dropped lazily. One instance lives in the agent app state (app["capacity"])
    alongside the registry, shared by the reserve endpoint and the create
    paths.
    """

    def __init__(self, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
        self.supervisor = supervisor
        self.registry = registry
        self.holds: dict[str, GpuHold] = {}
        self._lock = asyncio.Lock()

    def check_capacity(
        self,
        *,
        memory_mib: int,
        vcpus: int,
        disk_mib: int,
        is_instance: bool,
        exclude_vm_hash: ItemHash | None = None,
    ) -> None:
        """Raise InsufficientResourcesError if these requirements exceed the host caps.

        Two-bucket memory accounting: instances share
        physical - HOST_MEMORY_RESERVED_MIB - PROGRAM_MEMORY_RESERVED_MIB,
        programs share PROGRAM_MEMORY_RESERVED_MIB. vCPUs are capped at
        physical cores times VCPU_OVERCOMMIT_FACTOR. Disk is only checked for
        disk_mib > 0 (the reserve path; the create path passes 0).

        ``exclude_vm_hash`` skips that VM's own registry record from the
        committed sums: the create paths record the VM before admission (the
        early owner record, or a leftover record on a recreate), and its own
        record must not count against its own request.
        """
        required_memory_mib = memory_mib
        required_vcpus = vcpus
        required_disk_mib = disk_mib

        committed_instance_memory_mib = 0
        committed_program_memory_mib = 0
        committed_vcpus = 0
        for vm_hash, record in tuple(self.registry.items()):
            if exclude_vm_hash is not None and vm_hash == exclude_vm_hash:
                continue
            resources = record.message.resources
            memory = resources.memory
            record_vcpus = resources.vcpus
            if not memory and not record_vcpus:
                continue
            if isinstance(record.message, InstanceContent):
                committed_instance_memory_mib += memory
            else:
                committed_program_memory_mib += memory
            committed_vcpus += record_vcpus

        physical_memory_mib = psutil.virtual_memory().total // (1024 * 1024)
        physical_cores = psutil.cpu_count() or 1
        host_reserved_mib = settings.HOST_MEMORY_RESERVED_MIB
        program_reserved_mib = settings.PROGRAM_MEMORY_RESERVED_MIB

        instance_memory_cap_mib = max(physical_memory_mib - host_reserved_mib - program_reserved_mib, 0)
        program_memory_cap_mib = program_reserved_mib

        # vCPU overcommit: CPU time is safe to oversubscribe because the
        # kernel scheduler time-slices it, so the cap is the physical core
        # count multiplied by the configured factor (e.g. 4 vCPUs per core
        # with VCPU_OVERCOMMIT_FACTOR=4.0).
        vcpu_cap = int(physical_cores * settings.VCPU_OVERCOMMIT_FACTOR)

        if is_instance:
            bucket_name = "instance"
            committed_memory_mib = committed_instance_memory_mib
            memory_cap_mib = instance_memory_cap_mib
        else:
            bucket_name = "program"
            committed_memory_mib = committed_program_memory_mib
            memory_cap_mib = program_memory_cap_mib

        available_disk_mib = self._available_disk_bytes() // (1024 * 1024)

        errors: list[str] = []

        if committed_memory_mib + required_memory_mib > memory_cap_mib:
            errors.append(
                f"Memory ({bucket_name} bucket): "
                f"required {required_memory_mib} MiB, "
                f"committed {committed_memory_mib} MiB, "
                f"cap {memory_cap_mib} MiB "
                f"(physical {physical_memory_mib} MiB, "
                f"host_reserved {host_reserved_mib} MiB, "
                f"program_reserved {program_reserved_mib} MiB)"
            )

        if committed_vcpus + required_vcpus > vcpu_cap:
            errors.append(
                f"vCPUs: required {required_vcpus}, "
                f"committed {committed_vcpus}, "
                f"cap {vcpu_cap} "
                f"(physical {physical_cores} x factor {settings.VCPU_OVERCOMMIT_FACTOR})"
            )

        if required_disk_mib > 0 and required_disk_mib > available_disk_mib:
            errors.append(f"Disk: required {required_disk_mib} MiB, " f"available {available_disk_mib} MiB")

        if errors:
            detail = "Insufficient capacity to create VM. " + "; ".join(errors)
            available_memory_mib = max(memory_cap_mib - committed_memory_mib, 0)
            available_vcpus = max(vcpu_cap - committed_vcpus, 0)
            raise InsufficientResourcesError(
                detail,
                required={
                    "vcpus": required_vcpus,
                    "memory_mib": required_memory_mib,
                    "disk_mib": required_disk_mib,
                },
                available={
                    "vcpus": available_vcpus,
                    "memory_mib": available_memory_mib,
                    "disk_mib": available_disk_mib,
                },
            )

    @staticmethod
    def _available_disk_bytes() -> int:
        """Disk available for new VMs, in bytes.

        Free space under PERSISTENT_VOLUMES_DIR, the same figure the pool's
        calculate_available_disk reports: the reserved-but-unused delta it
        added per execution is 0 for every spec-built VM (spec disks carry no
        size). The directory is created by the supervisor's setup; if it does
        not exist (yet), report 0 rather than failing admission outright.
        """
        try:
            return max(shutil.disk_usage(str(settings.PERSISTENT_VOLUMES_DIR)).free, 0)
        except OSError:
            logger.warning("PERSISTENT_VOLUMES_DIR %s not accessible, reporting 0", settings.PERSISTENT_VOLUMES_DIR)
            return 0

    async def _available_gpus(self) -> list[GpuDevice]:
        """Host cards not attached to any VM, per the supervisor's HostInfo."""
        host_info = await self.supervisor.get_host_info()
        return [GpuDevice.model_validate(gpu) for gpu in host_info.available_gpus]

    def _get_valid_hold(self, pci_host: str) -> GpuHold | None:
        hold = self.holds.get(pci_host)
        if hold is not None and hold.is_expired():
            del self.holds[pci_host]
            return None
        return hold

    async def reserve_gpus(self, requested_device_ids: list[str], user: str) -> datetime:
        """Hold one available card per requested device_id for ``user``.

        Atomic: cards are resolved first and committed to the ledger only once
        every request is matched, so a partial request leaves no stray holds.
        A card held by ANOTHER user is skipped; the user's own hold is
        refreshed. Returns the hold expiry.
        """
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(seconds=RESERVATION_TTL_SECONDS)
        if not requested_device_ids:
            return expiration_date
        async with self._lock:
            available_gpus = await self._available_gpus()
            resolved = self._match_requests(available_gpus, requested_device_ids, user, consume_own_hold=False)
            for gpu in resolved:
                self.holds[gpu.pci_host] = GpuHold(user=user, expiration=expiration_date)
        return expiration_date

    async def resolve_gpus(self, requested_device_ids: list[str], owner: str) -> list[GpuSpec]:
        """Resolve GPU requests to concrete host cards for the create path.

        Matches each device_id against the supervisor's available cards,
        skipping cards held by ANOTHER user and consuming ``owner``'s own
        holds (the card is taken and its hold dropped). Returns resolved
        GpuSpec entries (pci_host set) ready to go on a CreateVmSpec.

        Raises:
            InsufficientResourcesError: a requested device_id has no available
                host card free of another user's hold.
        """
        if not requested_device_ids:
            return []
        async with self._lock:
            available_gpus = await self._available_gpus()
            resolved = self._match_requests(available_gpus, requested_device_ids, owner, consume_own_hold=True)
        return [
            GpuSpec(
                pci_host=PciAddress(gpu.pci_host),
                supports_x_vga=gpu.has_x_vga_support,
            )
            for gpu in resolved
        ]

    def _match_requests(
        self,
        available_gpus: list[GpuDevice],
        requested_device_ids: list[str],
        user: str,
        *,
        consume_own_hold: bool,
    ) -> list[GpuDevice]:
        """Match each requested device_id to a distinct available card.

        ``available_gpus`` is consumed in place. Called under ``self._lock``.
        """
        unheld_available = list(available_gpus)
        resolved: list[GpuDevice] = []
        for device_id in requested_device_ids:
            for gpu in available_gpus:
                if gpu.device_id != device_id:
                    continue
                hold = self._get_valid_hold(gpu.pci_host)
                if hold is not None and hold.user != user:
                    # Held by another user: not available to this one.
                    continue
                if hold is not None and consume_own_hold:
                    del self.holds[gpu.pci_host]
                available_gpus.remove(gpu)
                resolved.append(gpu)
                break
            else:  # for-else: no match for this request
                detail = f"No available GPU matching device_id {device_id!r}"
                logger.warning(detail)
                raise InsufficientResourcesError(
                    detail,
                    required={"gpu_device_id": device_id},
                    available={"gpus": [gpu.device_id for gpu in unheld_available]},
                )
        return resolved
