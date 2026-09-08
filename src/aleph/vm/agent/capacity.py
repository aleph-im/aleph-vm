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
from collections.abc import Collection
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import psutil
from aleph_message.models import ExecutableContent, ItemHash, VerifiableProgramContent
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm import storage_pools
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
    max_volume_mib: int = 0
    is_instance: bool = False
    gpu_device_ids: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class AdmissionVerdict:
    """One candidate's admission answer.

    ``code`` and ``detail`` are safe to hand back to the scheduler; the full
    error text stays in the logs.
    """

    vm_hash: ItemHash
    accepted: bool
    code: str = ""
    detail: str = ""


def is_instance_bucket(content: ExecutableContent) -> bool:
    """Whether this content is admitted against the instance memory bucket.

    A V-PROGRAM is a full SNP VM and belongs with the instances even though it
    is not an InstanceContent. Bucketing one as a program would both starve the
    small program bucket and hide its memory from instance admission, so the
    rule lives here instead of being restated wherever a bucket is picked.
    """
    return isinstance(content, (InstanceContent, VerifiableProgramContent))


def requirements_from_message(content: ExecutableContent) -> ResourceRequirements:
    """Extract the resources a message requests into a message-free DTO."""
    is_instance = isinstance(content, InstanceContent)
    volume_sizes_mib: list[int] = []
    if isinstance(content, InstanceContent) and content.rootfs:
        volume_sizes_mib.append(content.rootfs.size_mib)
    for volume in content.volumes or []:
        volume_sizes_mib.append(getattr(volume, "size_mib", 0) or 0)
    return ResourceRequirements(
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        disk_mib=sum(volume_sizes_mib),
        max_volume_mib=max(volume_sizes_mib, default=0),
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
        max_volume_mib: int = 0,
        is_instance: bool,
        exclude_vm_hash: ItemHash | None = None,
    ) -> None:
        """Raise InsufficientResourcesError if these requirements exceed the host caps.

        Two-bucket memory accounting: instances share
        physical - HOST_MEMORY_RESERVED_MIB - PROGRAM_MEMORY_RESERVED_MIB,
        programs share PROGRAM_MEMORY_RESERVED_MIB. vCPUs are capped at
        physical cores times VCPU_OVERCOMMIT_FACTOR. Disk is checked whenever
        disk_mib > 0: the create paths pass the message's volume total when
        they admit a VM, and 0 in the re-checks they run once the images are
        downloaded, which are about the images rather than the volumes.

        ``exclude_vm_hash`` skips that VM's own registry record from the
        committed sums: the create paths record the VM before admission (the
        early owner record, or a leftover record on a recreate), and its own
        record must not count against its own request.
        """
        committed_instance_memory_mib, committed_program_memory_mib, committed_vcpus = self._committed_resources(
            () if exclude_vm_hash is None else (exclude_vm_hash,)
        )
        self._check_against(
            memory_mib=memory_mib,
            vcpus=vcpus,
            disk_mib=disk_mib,
            max_volume_mib=max_volume_mib,
            is_instance=is_instance,
            committed_instance_memory_mib=committed_instance_memory_mib,
            committed_program_memory_mib=committed_program_memory_mib,
            committed_vcpus=committed_vcpus,
        )

    def _check_against(
        self,
        *,
        memory_mib: int,
        vcpus: int,
        disk_mib: int,
        max_volume_mib: int,
        is_instance: bool,
        committed_instance_memory_mib: int,
        committed_program_memory_mib: int,
        committed_vcpus: int,
        committed_disk_mib: int = 0,
    ) -> None:
        """The admission arithmetic, against caller-supplied commitments.

        Split out so simulate() can judge a candidate against sums it is
        accumulating itself, while check_capacity keeps judging against the
        registry as it stands. One implementation, so an advisory answer can
        never be stronger or weaker than the enforced one.
        """
        required_memory_mib = memory_mib
        required_vcpus = vcpus
        required_disk_mib = disk_mib

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

        # Free space is a live figure, not a committed sum, so a batch caller
        # passes what it has already promised to the candidates before this one.
        available_disk_mib = max(self._available_disk_bytes() // (1024 * 1024) - committed_disk_mib, 0)

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

        max_volume_error = self._check_max_volume(max_volume_mib)
        if max_volume_error:
            errors.append(max_volume_error)

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

    def simulate(
        self,
        candidates: list[tuple[ItemHash, ResourceRequirements, bool]],
        *,
        releasing: frozenset[ItemHash] = frozenset(),
        available_gpus: list[GpuDevice] | None = None,
    ) -> list[AdmissionVerdict]:
        """Judge a whole plan at once.

        Cumulative: each accepted candidate is committed before the next is
        judged, so three VMs that only fit twice get two yeses and one no. This
        covers memory, vCPUs and aggregate disk. Disk needs the accumulator
        because free space is read live and no record of it exists until the
        volumes are actually written. Aggregate only: the per-volume check asks
        whether the roomiest pool could hold the largest volume, and which pool
        a volume lands on is a placement decision nothing models here.

        A candidate's own registry record never counts against it. A hash can
        already be recorded here and still be a candidate: a recreate, or an
        owner record left by a create that failed part way. Counting both the
        record and the request would make the VM refuse itself, so the record
        is discounted the way check_capacity's exclude_vm_hash does it.

        Release-aware: hashes the plan is about to stop are subtracted from the
        committed sums, so "allocate C, delete B" admits C against B's memory.
        Their disk is not credited back: nothing has been deleted yet, so the
        space is genuinely still occupied, and guessing otherwise would make
        the advisory answer stronger than the enforced one.

        Side-effect free: nothing here reserves or holds anything, which is
        what makes it safe for the speculative capacity-check endpoint.

        GPUs are judged from ``available_gpus``, the host's unattached cards,
        which the caller reads from the supervisor because that read is async
        and this call is not. Matching is cumulative like the rest: two
        candidates wanting the only card of a kind get one yes. A card under a
        live hold counts as taken, since the hold is some user's pending
        create.

        Without ``available_gpus`` there is no inventory to judge against, so a
        candidate that asks for a card is refused rather than admitted on
        memory alone. An advisory yes must never be read as one that covered
        the GPU.

        Releases are not credited back for cards either, and for the same
        reason as disk: the inventory is the cards not currently attached, so a
        card still held by a VM the plan stops is absent from it. "Stop B,
        allocate C onto B's card" is answered no even though doing it in that
        order would work.

        The third element of a candidate is the caller's memory-bucket choice,
        NOT ResourceRequirements.is_instance. The two disagree for V-PROGRAMs:
        requirements_from_message reports is_instance=False (the content is not
        an InstanceContent) while a V-PROGRAM is committed to the instance
        bucket, which is what _committed_resources and _admit both do. Pass
        is_instance_bucket(content) rather than restating the rule.
        """
        candidate_hashes = {vm_hash for vm_hash, _, _ in candidates}
        committed_instance, committed_program, committed_vcpus = self._committed_resources(candidate_hashes)
        for vm_hash in releasing:
            if vm_hash in candidate_hashes:
                # Already discounted above. Subtracting again would credit the
                # same VM twice and admit against memory nobody freed.
                continue
            freed = self._record_commitment(vm_hash)
            if freed is None:
                continue
            committed_instance -= freed[0]
            committed_program -= freed[1]
            committed_vcpus -= freed[2]
        # A registry inconsistency must not make admission more permissive than
        # an empty node.
        committed_instance = max(committed_instance, 0)
        committed_program = max(committed_program, 0)
        committed_vcpus = max(committed_vcpus, 0)

        gpu_pool = None if available_gpus is None else self._unheld_gpus(available_gpus)

        verdicts: list[AdmissionVerdict] = []
        committed_disk = 0
        for vm_hash, requirements, is_instance in candidates:
            refusal: tuple[str, str] | None = None
            try:
                self._check_against(
                    memory_mib=requirements.memory_mib,
                    vcpus=requirements.vcpus,
                    disk_mib=requirements.disk_mib,
                    max_volume_mib=requirements.max_volume_mib,
                    is_instance=is_instance,
                    committed_instance_memory_mib=committed_instance,
                    committed_program_memory_mib=committed_program,
                    committed_vcpus=committed_vcpus,
                    committed_disk_mib=committed_disk,
                )
            except InsufficientResourcesError as error:
                logger.info("Plan candidate %s refused: %s", vm_hash, error)
                refusal = ("insufficient_capacity", "not enough capacity on this CRN")
            if refusal is None:
                # Last, and only once the candidate has cleared everything
                # else: taking cards is what makes the pool cumulative, so a
                # candidate refused on memory must not walk off with them.
                gpu_refusal = self._take_gpus(requirements.gpu_device_ids, gpu_pool)
                if gpu_refusal is not None:
                    logger.info("Plan candidate %s refused: %s", vm_hash, gpu_refusal)
                    refusal = ("gpu_unavailable", "no available GPU matches this request")
            if refusal is not None:
                verdicts.append(AdmissionVerdict(vm_hash, False, *refusal))
                # Discounting the record was a bet that the request would
                # replace it. It did not: whatever is recorded here is still
                # here, so it has to weigh on the rest of the batch again.
                # Unless the plan is stopping it anyway, in which case the
                # release already accounts for it.
                kept = None if vm_hash in releasing else self._record_commitment(vm_hash)
                if kept is not None:
                    committed_instance += kept[0]
                    committed_program += kept[1]
                    committed_vcpus += kept[2]
                continue
            if is_instance:
                committed_instance += requirements.memory_mib
            else:
                committed_program += requirements.memory_mib
            committed_vcpus += requirements.vcpus
            committed_disk += requirements.disk_mib
            verdicts.append(AdmissionVerdict(vm_hash, True))
        return verdicts

    def _record_commitment(self, vm_hash: ItemHash) -> tuple[int, int, int] | None:
        """What this VM's registry record adds to (instance, program, vcpus).

        None when there is no record, or one with no resources to speak of.
        """
        record = self.registry.get(vm_hash)
        if record is None or not record.message.resources:
            return None
        resources = record.message.resources
        if is_instance_bucket(record.message):
            return resources.memory, 0, resources.vcpus
        return 0, resources.memory, resources.vcpus

    def _unheld_gpus(self, available_gpus: list[GpuDevice]) -> list[GpuDevice]:
        """The cards a plan may count on: unattached and not under a live hold.

        A hold is some user's pending create, so a held card is treated as
        taken. Read-only on purpose: unlike _get_valid_hold this leaves expired
        entries in the ledger, because simulate mutates nothing.
        """
        return [gpu for gpu in available_gpus if (hold := self.holds.get(gpu.pci_host)) is None or hold.is_expired()]

    @staticmethod
    def _take_gpus(device_ids: list[str], pool: list[GpuDevice] | None) -> str | None:
        """Consume one card per requested id from ``pool``. None if it fits.

        All or nothing, like reserve_gpus: a candidate that cannot get every
        card it asked for takes none, so it does not strand cards a later
        candidate could have used.
        """
        if not device_ids:
            return None
        if pool is None:
            return "GPU availability was not checked for this plan"
        taken: list[GpuDevice] = []
        for device_id in device_ids:
            for gpu in pool:
                if gpu.device_id == device_id and gpu not in taken:
                    taken.append(gpu)
                    break
            else:
                return f"No available GPU matching device_id {device_id!r}"
        for gpu in taken:
            pool.remove(gpu)
        return None

    def _committed_resources(self, excluded: Collection[ItemHash]) -> tuple[int, int, int]:
        """(committed_instance_memory_mib, committed_program_memory_mib,
        committed_vcpus) summed over the registry, skipping the records of
        ``excluded`` (see ``check_capacity`` and ``simulate``)."""
        committed_instance_memory_mib = 0
        committed_program_memory_mib = 0
        committed_vcpus = 0
        for vm_hash, record in tuple(self.registry.items()):
            if vm_hash in excluded:
                continue
            resources = record.message.resources
            memory = resources.memory
            record_vcpus = resources.vcpus
            if not memory and not record_vcpus:
                continue
            if is_instance_bucket(record.message):
                committed_instance_memory_mib += memory
            else:
                committed_program_memory_mib += memory
            committed_vcpus += record_vcpus
        return committed_instance_memory_mib, committed_program_memory_mib, committed_vcpus

    @staticmethod
    def _check_max_volume(max_volume_mib: int) -> str | None:
        """None when ``max_volume_mib`` fits the roomiest eligible pool, else
        an error string describing the shortfall. No pool holds a volume
        split across disks, so this catches a request the aggregate free
        figure alone would wrongly admit."""
        if max_volume_mib <= 0:
            return None
        roomiest_mib = storage_pools.roomiest_pool_free_bytes() // (1024 * 1024)
        if max_volume_mib <= roomiest_mib:
            return None
        return f"Disk (largest single volume): required {max_volume_mib} MiB, roomiest pool has {roomiest_mib} MiB"

    @staticmethod
    def _available_disk_bytes() -> int:
        """Disk available for new VMs across every volume pool, in bytes.

        Aggregate free space with same-filesystem pools counted once, the
        same figure the pool's calculate_available_disk reports: the
        reserved-but-unused delta it adds per execution is 0 for every
        spec-built VM (spec disks carry no size). Unreachable pools (missing
        dir, dead disk) contribute 0 rather than failing admission outright.
        """
        return max(storage_pools.pools_disk_usage()[1], 0)

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
                    available={"gpus": [gpu.device_id for gpu in available_gpus]},
                )
        return resolved
