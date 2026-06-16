"""Translate an aleph_message ExecutableContent into a CreateVmSpec.

This is the entry point for the aleph-message side of the supervisor refactor
(Phase 0.C). It validates the message, downloads resources via the existing
AlephQemuResources machinery, and returns a message-agnostic CreateVmSpec that
the rest of the supervisor pipeline can work with.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from aleph_message.models import ExecutableContent, ItemHash, ProgramContent
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import AMDSEVPolicy, HypervisorType
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.program import AlephProgramResources
from aleph.vm.controllers.qemu.cloudinit import get_hostname_from_hash
from aleph.vm.controllers.qemu.instance import AlephQemuResources
from aleph.vm.storage import get_existing_file
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    GuestChannelSpec,
    NetworkConfig,
    PciAddress,
    TeeBackend,
    TeeConfig,
    VmId,
)
from aleph.vm.utils.runtime_channel import RUNTIME_CONTROL_PORT


async def build_create_vm_spec(
    vm_hash: ItemHash,
    message: ExecutableContent,
    *,
    gpus: Sequence[GpuSpec] | None = None,
) -> CreateVmSpec:
    """Translate *message* into a CreateVmSpec, downloading resources as needed.

    Validation is performed before any I/O. Raises InvalidBackendError for:
    - non-instance messages
    - non-QEMU hypervisor (instances are QEMU-only)

    Confidential (trusted_execution set) instances ARE supported: the firmware
    ref is resolved to a host path and ``spec.tee`` is populated so the engine
    takes the confidential launch path. The launched SEV policy is NO_DBG,
    matching the message path (which never reads message.policy); see the tee
    block below.

    The routing gate ``run._is_spec_eligible`` mirrors these checks to decide
    which messages reach this path; keep the two in sync.

    GPUs cross as a REQUEST: each ``message.requirements.gpu`` entry becomes a
    ``GpuSpec`` carrying ``device_id`` / ``model`` with an empty ``pci_host``.
    The engine resolves the concrete host card atomically inside
    ``pool.create_vm_from_spec`` (see GpuSpec). Callers may pass an explicit
    ``gpus`` list to override the derivation (the message-free migration path
    does not, so it derives from the message like the normal create).
    """
    # --- Validate before any I/O ---

    if not isinstance(message, InstanceContent):
        raise InvalidBackendError(f"Expected InstanceContent, got {type(message).__name__}")

    effective_hypervisor = message.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
    if effective_hypervisor != HypervisorType.qemu:
        raise InvalidBackendError(
            f"instances are QEMU-only, got hypervisor {effective_hypervisor!r}"
        )

    # --- GPU request ---
    # Each requested GPU becomes an unresolved GpuSpec (device_id/model set,
    # pci_host left empty). The engine binds device_id -> concrete host card
    # atomically in pool.create_vm_from_spec. The message GPU carries no model
    # field (it is a network-derived name), so model is left empty here.
    if gpus is None:
        requested_gpus = message.requirements.gpu if message.requirements and message.requirements.gpu else []
        gpus = [
            GpuSpec(
                pci_host=PciAddress(""),
                supports_x_vga=False,
                device_id=gpu.device_id,
                model="",
            )
            for gpu in requested_gpus
        ]

    # --- Materialise resources ---

    resources = AlephQemuResources(message, namespace=str(vm_hash))
    await resources.download_all()

    # --- Confidential (TEE) ---
    # A confidential instance carries trusted_execution. Resolve the firmware
    # ref to a host path here (agent territory, like every other resource) and
    # hand the engine a TeeConfig so it takes the confidential launch path.
    #
    # SAFETY-CRITICAL: the launched SEV policy is NO_DBG, reproducing the
    # message path exactly. The message path never reads
    # trusted_execution.policy: AlephQemuConfidentialInstance defaults
    # confidential_policy to AMDSEVPolicy.NO_DBG and VmExecution.create() does
    # not override it. We mirror that here (NOT message.policy) so the spec path
    # cannot launch a confidential VM under a weaker policy than today.
    tee: TeeConfig | None = None
    trusted_execution = getattr(message.environment, "trusted_execution", None)
    if trusted_execution is not None:
        firmware_path = await get_existing_file(trusted_execution.firmware)
        tee = TeeConfig(
            backend=TeeBackend.SEV,
            policy=hex(AMDSEVPolicy.NO_DBG),
            session_dir=DirectoryPath(settings.CONFIDENTIAL_SESSION_DIRECTORY / vm_hash),
            firmware_path=firmware_path,
        )

    # --- Build disk list ---

    disks: list[DiskSpec] = [
        DiskSpec(
            path=resources.rootfs_path,
            readonly=False,
            format=DiskFormat.QCOW2,
            role=DiskRole.ROOTFS,
        )
    ] + [
        DiskSpec(
            path=v.path_on_host,
            readonly=v.read_only,
            format=DiskFormat.RAW,
            role=DiskRole.EXTRA,
        )
        for v in resources.volumes
    ]

    return CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=message.resources.vcpus,
        memory_mib=message.resources.memory,
        tee=tee,
        network=NetworkConfig(
            internet_access=message.environment.internet,
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=list(gpus),
        numa_node=None,
        persistent=True,
        ssh_authorized_keys=list(message.authorized_keys or []),
        # Aleph's hostname convention (base32 of the item hash) is agent
        # vocabulary; the supervisor applies whatever name it is given.
        hostname=get_hostname_from_hash(vm_hash),
    )


async def build_program_create_vm_spec(
    vm_hash: ItemHash,
    message: ExecutableContent,
) -> tuple[CreateVmSpec, AlephProgramResources]:
    """Translate a program message into a CreateVmSpec, downloading resources.

    The agent half of the program create: code/runtime/data/volumes are
    downloaded here (Aleph storage is agent territory) and the spec carries
    resolved paths only. Returns the resources too — the agent needs them for
    the guest configuration push (code bytes, entrypoint, volume mounts),
    which never crosses the supervisor boundary.

    Persistence is threaded from the message: a persistent program boots under
    systemd (engine side); an on-demand one is a per-request ephemeral VM.
    """
    if not isinstance(message, ProgramContent):
        raise InvalidBackendError(f"Expected ProgramContent, got {type(message).__name__}")

    resources = AlephProgramResources(message, namespace=str(vm_hash))
    await resources.download_all()

    # The runtime image is the program's root filesystem: plain ROOTFS on the
    # wire. The code disk (squashfs encoding only) and the volumes are EXTRA
    # disks; their ORDER is the contract — the agent derives guest device
    # names (vdb, vdc, ...) from it for its configuration push.
    disks: list[DiskSpec] = [
        DiskSpec(
            path=resources.rootfs_path,
            readonly=True,
            format=DiskFormat.SQUASHFS,
            role=DiskRole.ROOTFS,
        )
    ]
    if resources.code_encoding == Encoding.squashfs:
        disks.append(
            DiskSpec(
                path=resources.code_path,
                readonly=True,
                format=DiskFormat.SQUASHFS,
                role=DiskRole.EXTRA,
            )
        )
    disks += [
        DiskSpec(
            path=volume.path_on_host,
            readonly=volume.read_only,
            format=DiskFormat.RAW,
            role=DiskRole.EXTRA,
        )
        for volume in resources.volumes
    ]

    spec = CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.FIRECRACKER,
        kernel_path=resources.kernel_image_path,
        initrd_path=Path(""),
        disks=disks,
        vcpus=message.resources.vcpus,
        memory_mib=message.resources.memory,
        tee=None,
        network=NetworkConfig(
            internet_access=bool(message.environment.internet),
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=[],
        numa_node=None,
        persistent=message.on.persistent,
        guest_channel=GuestChannelSpec(
            ready_port=RUNTIME_CONTROL_PORT,
            # The agent owns the boot-time policy for its runtime images.
            ready_timeout_secs=int(settings.INIT_TIMEOUT),
        ),
    )
    return spec, resources
