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
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil
from aleph_message.models import ExecutableContent, ItemHash, VerifiableProgramContent
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm import storage_pools
from aleph.vm.agent.vm.purge import ROOTFS_STEM, _checked_namespace
from aleph.vm.agent.vm.reclaimable import (
    MARKER_NAME,
    file_size_bytes,
    reclaimable_bytes,
)
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


# The filename suffixes a volume's file carries in ``{pool}/{vm_hash}/``. A
# QEMU boot disk is the qcow2 ``downloader._make_writable_volume`` creates; a
# Firecracker one is the ``.btrfs`` device-mapper base of
# ``storage.create_devmapper``. An extra persistent volume is an ``.ext4``
# (``storage.get_volume_path``), a ``.btrfs`` when it has a parent, or a qcow2
# when it goes through the writable-volume path.
BOOT_DISK_SUFFIXES = (".qcow2", ".btrfs")
VOLUME_SUFFIXES = (".ext4", ".btrfs", ".qcow2")


@dataclass(frozen=True)
class DeclaredVolume:
    """One volume a message asks the node to allocate.

    ``filenames`` are the names the volume's file can carry inside
    ``{pool}/{vm_hash}/``: a stem ("rootfs" for the boot disk, the volume's
    name for an extra persistent volume, see ``purge.ROOTFS_STEM`` and the
    naming convention it documents) joined to each suffix that kind of volume
    can take. The suffix is part of the match because a stem alone is not
    unique: ``rootfs.qcow2`` and ``rootfs.ext4`` can sit side by side in one
    directory and belong to different volumes.

    Both spellings of a name are listed because ``storage.get_volume_path``
    sanitizes a name that is not already ``[\\w\\-_/]+`` while
    ``downloader._make_writable_volume`` does not.
    """

    filenames: tuple[str, ...]
    size_mib: int


@dataclass(frozen=True)
class HeldVolume:
    """An existing file that already backs a declared volume.

    ``size_bytes`` is what the file allocates on disk, capped at the size the
    volume declares: a file cannot discount more than the message asks for.
    """

    path: Path
    size_bytes: int

    @property
    def pool_path(self) -> Path:
        """The pool holding the file (``{pool}/{vm_hash}/{name.ext}``)."""
        return self.path.parent.parent


def _volume_stems(name: str) -> tuple[str, ...]:
    """The filename stems a declared volume's file can carry on disk."""
    sanitized = name if re.match(r"^[\w\-_/]+$", name) else re.sub(r"[^\w\-_]", "_", name)
    return (name,) if sanitized == name else (name, sanitized)


def _volume_filenames(stems: tuple[str, ...], suffixes: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(f"{stem}{suffix}" for stem in stems for suffix in suffixes)


def declared_volumes(content: ExecutableContent) -> list[DeclaredVolume]:
    """The per-VM volumes a message asks the node to allocate.

    Every entry of ``content.volumes`` is listed, in message order, plus the
    boot disk of an instance. A volume that owns no file in the VM's directory
    carries no filenames and so can never discount anything: an immutable
    volume resolves to a shared cache entry rather than to a file this VM
    owns, and it declares no size either, so it adds nothing to the total.

    A persistent volume named "rootfs" does not claim the "rootfs" stem when
    the message also declares a boot disk: that stem belongs to the boot disk,
    and letting both claim it would discount one file twice.
    """
    volumes: list[DeclaredVolume] = []
    boot_disk = content.rootfs if isinstance(content, InstanceContent) else None
    if boot_disk:
        volumes.append(
            DeclaredVolume(
                filenames=_volume_filenames((ROOTFS_STEM,), BOOT_DISK_SUFFIXES),
                size_mib=boot_disk.size_mib,
            )
        )
    for volume in content.volumes or []:
        size_mib = getattr(volume, "size_mib", 0) or 0
        name = getattr(volume, "name", "") or ""
        stems = _volume_stems(name) if name else ()
        if boot_disk:
            stems = tuple(stem for stem in stems if stem != ROOTFS_STEM)
        volumes.append(DeclaredVolume(filenames=_volume_filenames(stems, VOLUME_SUFFIXES), size_mib=size_mib))
    return volumes


def requirements_from_message(
    content: ExecutableContent, volumes: list[DeclaredVolume] | None = None
) -> ResourceRequirements:
    """Extract the resources a message requests into a message-free DTO.

    ``volumes`` is ``declared_volumes(content)``, which a caller that already
    has that list (``check_message``) passes in rather than deriving it twice.

    A V-PROGRAM is a full SEV-SNP VM, not a Firecracker program, so it is
    bucketed as an instance even though it is not an InstanceContent. That
    matches ``CapacityManager._committed_resources``, which already counts it
    against the instance bucket: bucketing it as a program here would both
    starve the small program bucket and hide its memory from instance
    admission (silent over-commit).
    """
    volume_sizes_mib = [volume.size_mib for volume in (declared_volumes(content) if volumes is None else volumes)]
    return ResourceRequirements(
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        disk_mib=sum(volume_sizes_mib),
        max_volume_mib=max(volume_sizes_mib, default=0),
        is_instance=isinstance(content, InstanceContent | VerifiableProgramContent),
        gpu_device_ids=requested_gpu_ids(content),
    )


def existing_volume_files(vm_hash: ItemHash | str) -> dict[str, Path]:
    """``{filename: path}`` of the VM's existing volume files, on every pool.

    Keyed by the whole name, suffix included: ``rootfs.qcow2`` and
    ``rootfs.ext4`` share a stem but are two different volumes, and keying by
    stem would let one shadow the other and be credited in its place.

    The namespace is validated before it reaches a path join, like every
    other caller of ``iter_namespace_dirs``: ``pool.path / namespace`` is a
    bare join, so an unchecked hash lets "../.." resolve and be counted as
    space the VM already holds, and an inflated discount relaxes admission.

    Symlinks and the marker are skipped, and pools are walked in order with
    the first match winning, so the result does not depend on iteration luck.
    """
    namespace = _checked_namespace(vm_hash)
    files: dict[str, Path] = {}
    for directory in storage_pools.iter_namespace_dirs(namespace):
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            logger.warning("Volume directory %s not readable, not discounting it", directory)
            continue
        for entry in entries:
            if entry.name == MARKER_NAME or entry.is_symlink() or not entry.is_file():
                continue
            files.setdefault(entry.name, entry)
    return files


def held_volumes(vm_hash: ItemHash | str, volumes: list[DeclaredVolume]) -> list[HeldVolume | None]:
    """What the VM already holds for each declared volume, positionally.

    The discount is per declared volume, never per directory: a file that
    backs no declared volume (a volume the updated message renamed or
    dropped, left behind on a node the VM is re-scheduled to) discounts
    nothing. Summing the directory instead would let such a leftover cancel
    the space a genuinely new volume still needs, turning the disk check off
    for exactly the create that needs it.

    A matched file is consumed, so one file discounts at most one volume.
    Two declared volumes can name the same file (two spellings of one name,
    one of which storage sanitizes into the other), and a file the node holds
    once cannot pay for two volumes it is about to allocate.

    Each hit is capped at the size its volume declares, so a file that grew
    past its declaration cannot credit the difference either.
    """
    existing = existing_volume_files(vm_hash)
    held: list[HeldVolume | None] = []
    for volume in volumes:
        filename = next((name for name in volume.filenames if name in existing), None)
        if filename is None:
            held.append(None)
            continue
        path = existing.pop(filename)
        size_bytes = min(file_size_bytes(path), volume.size_mib * 1024 * 1024)
        held.append(HeldVolume(path=path, size_bytes=size_bytes))
    return held


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

    def check_message(self, content: ExecutableContent, *, exclude_vm_hash: ItemHash | None = None) -> None:
        """Admission from the message alone, before a byte is allocated.

        The single admission path of every create path: the sizes come from
        the message (rootfs and volume ``size_mib``), so a host with no room
        refuses before the downloader runs rather than after it has already
        written the volumes. Judging disk after the build would measure space
        this very VM has just taken, which is why there is no second check.

        What the VM already holds for each volume the message declares is
        subtracted, so an existing VM is never refused for space it already
        occupies. This matters for a RECREATE and for an adoption:
        ``creating()`` adopts the retained directory on entry, which drops its
        ``.reclaimable`` marker, so those bytes stop counting as free in
        ``_available_disk_bytes`` at the very moment the VM asks for them
        again.

        The discount is matched volume by volume (see ``held_volumes``), never
        summed over the directory: a leftover file from a volume the message
        no longer declares must not pay for a new one, and a file that backs
        one declared volume must not pay for a second one too.
        """
        volumes = declared_volumes(content)
        held = held_volumes(exclude_vm_hash, volumes) if exclude_vm_hash is not None else [None] * len(volumes)
        declared_mib = sum(volume.size_mib for volume in volumes)
        held_mib = sum(hit.size_bytes for hit in held if hit is not None) // (1024 * 1024)
        # The largest declared volume decides the per-pool check, and it is
        # judged at its declared size: shrinking that figure by what is held
        # elsewhere would let a discount from one volume excuse the placement
        # of another. What the VM already holds *for that volume* is instead
        # credited to the pool its file sits on, which is the only pool that
        # would have to find room for it again.
        largest = max(range(len(volumes)), key=lambda index: volumes[index].size_mib, default=None)
        requirements = requirements_from_message(content, volumes)
        self.check_capacity(
            memory_mib=requirements.memory_mib,
            vcpus=requirements.vcpus,
            disk_mib=max(declared_mib - held_mib, 0),
            max_volume_mib=volumes[largest].size_mib if largest is not None else 0,
            max_volume_credit=held[largest] if largest is not None else None,
            is_instance=requirements.is_instance,
            exclude_vm_hash=exclude_vm_hash,
        )

    def check_capacity(
        self,
        *,
        memory_mib: int,
        vcpus: int,
        disk_mib: int,
        max_volume_mib: int = 0,
        max_volume_credit: HeldVolume | None = None,
        is_instance: bool,
        exclude_vm_hash: ItemHash | None = None,
    ) -> None:
        """Raise InsufficientResourcesError if these requirements exceed the host caps.

        Two-bucket memory accounting: instances share
        physical - HOST_MEMORY_RESERVED_MIB - PROGRAM_MEMORY_RESERVED_MIB,
        programs share PROGRAM_MEMORY_RESERVED_MIB. vCPUs are capped at
        physical cores times VCPU_OVERCOMMIT_FACTOR. Disk is only checked for
        disk_mib > 0, so a caller with nothing left to allocate (a recreate
        whose volumes are all on disk already) skips it.

        ``max_volume_credit`` is the file already backing the largest declared
        volume, if any: see ``_check_max_volume``, which credits it to the one
        pool that holds it.

        Callers that hold a message should go through ``check_message``, which
        derives every figure here from it; the scalars are the seam for the
        paths that build a request themselves (the migration import).

        ``exclude_vm_hash`` skips that VM's own registry record from the
        committed sums: the create paths record the VM before admission (the
        early owner record, or a leftover record on a recreate), and its own
        record must not count against its own request.
        """
        required_memory_mib = memory_mib
        required_vcpus = vcpus
        required_disk_mib = disk_mib

        committed_instance_memory_mib, committed_program_memory_mib, committed_vcpus = self._committed_resources(
            exclude_vm_hash
        )

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

        max_volume_error = self._check_max_volume(max_volume_mib, max_volume_credit)
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

    def _committed_resources(self, exclude_vm_hash: ItemHash | None) -> tuple[int, int, int]:
        """(committed_instance_memory_mib, committed_program_memory_mib,
        committed_vcpus) summed over the registry, skipping
        ``exclude_vm_hash``'s own record (see ``check_capacity``).

        A record is not proof that a VM runs. A create that fails against
        volumes that already existed retires RECREATE and deliberately keeps
        its record (``run._retire_after_create_failure``), so the sums here
        can include a VM that never started, until the next allocation cycle
        replaces or retires it. That is conservative (it under-admits, never
        over-admits) and it never blocks the retry of that VM's own create,
        which passes ``exclude_vm_hash``."""
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
            # V-PROGRAMs are full SNP VMs, admitted against the instance
            # bucket (run.py passes is_instance=True), so they must also be
            # counted there. Bucketing them as programs would both starve the
            # small program bucket and hide their memory from instance
            # admission (silent over-commit).
            if isinstance(record.message, (InstanceContent, VerifiableProgramContent)):
                committed_instance_memory_mib += memory
            else:
                committed_program_memory_mib += memory
            committed_vcpus += record_vcpus
        return committed_instance_memory_mib, committed_program_memory_mib, committed_vcpus

    @staticmethod
    def _check_max_volume(max_volume_mib: int, credit: HeldVolume | None = None) -> str | None:
        """None when ``max_volume_mib`` fits the roomiest eligible pool, else
        an error string describing the shortfall. No pool holds a volume
        split across disks, so this catches a request the aggregate free
        figure alone would wrongly admit.

        A pool's room is its free bytes plus the reclaimable bytes it holds,
        for the same reason the aggregate figure counts them: placement
        evicts that pool's retained directories before it refuses the volume.

        ``credit`` is the file that already backs this very volume, if there
        is one. Its bytes are added to the room of the one pool that holds it
        and to no other: that pool does not have to find the space again,
        while a pool that has never seen this volume still has to fit it whole.
        Crediting it globally (by shrinking ``max_volume_mib``) would instead
        excuse every pool, which is how a stale file could switch this check
        off entirely.
        """
        if max_volume_mib <= 0:
            return None
        credited_pool = credit.pool_path if credit is not None else None
        roomiest_bytes = max(
            (
                free
                + reclaimable_bytes(pool.path)
                + (credit.size_bytes if credit is not None and pool.path == credited_pool else 0)
                for pool, free in storage_pools.eligible_pool_free_bytes()
            ),
            default=0,
        )
        roomiest_mib = roomiest_bytes // (1024 * 1024)
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

        Reclaimable (retained) bytes count as free: the reconciler evicts them
        on demand when a placement needs the room.
        """
        return max(storage_pools.pools_disk_usage()[1], 0) + reclaimable_bytes()

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
