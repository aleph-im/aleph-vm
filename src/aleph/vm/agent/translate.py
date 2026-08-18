"""Translate an aleph_message ExecutableContent into a CreateVmSpec.

This is the entry point for the aleph-message side of the supervisor refactor
(Phase 0.C). It validates the message, downloads resources via the existing
AlephQemuResources machinery, and returns a message-agnostic CreateVmSpec that
the rest of the supervisor pipeline can work with.
"""

from __future__ import annotations

from pathlib import Path

from aleph_message.models import ExecutableContent, ItemHash, ProgramContent
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import HypervisorType
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm.agent.guest_ipv6 import compute_requested_ipv6
from aleph.vm.agent.vm.downloader import ProgramDownloader, QemuDownloader
from aleph.vm.conf import settings
from aleph.vm.storage import get_existing_file
from aleph.vm.supervisor_interface.errors import InvalidBackendError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GuestChannelSpec,
    NetworkConfig,
    TeeBackend,
    TeeConfig,
    VmId,
)
from aleph.vm.utils import get_hostname_from_hash
from aleph.vm.utils.runtime_channel import RUNTIME_CONTROL_PORT
from aleph.vm.vm_type import VmType


async def build_create_vm_spec(
    vm_hash: ItemHash,
    message: ExecutableContent,
) -> CreateVmSpec:
    """Translate *message* into a CreateVmSpec, downloading resources as needed.

    Validation is performed before any I/O. Raises InvalidBackendError for:
    - non-instance messages
    - non-QEMU hypervisor (instances are QEMU-only)

    Confidential (trusted_execution set) instances ARE supported: the firmware
    ref is resolved to a host path and ``spec.tee`` is populated so the engine
    takes the confidential launch path. The launched SEV policy is the one the
    message requested (trusted_execution.policy, schema-defaulted to NO_DBG);
    see the tee block below.

    The routing gate ``run._is_spec_eligible`` mirrors these checks to decide
    which messages reach this path; keep the two in sync.

    GPUs are left off the returned spec: the message's requested device_ids
    stop at the agent. The create path resolves them to concrete host cards
    through the agent's CapacityManager after this download completes and
    rewrites ``spec.gpus`` with the resolved cards.
    """
    # --- Validate before any I/O ---

    if not isinstance(message, InstanceContent):
        raise InvalidBackendError(f"Expected InstanceContent, got {type(message).__name__}")

    effective_hypervisor = message.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
    if effective_hypervisor != HypervisorType.qemu:
        raise InvalidBackendError(f"instances are QEMU-only, got hypervisor {effective_hypervisor!r}")

    # --- Materialise resources ---

    resources = QemuDownloader(message, namespace=str(vm_hash))
    await resources.download_all()

    # --- Confidential (TEE) ---
    # A confidential instance carries trusted_execution. Resolve the firmware
    # ref to a host path here (agent territory, like every other resource) and
    # hand the engine a TeeConfig so it takes the confidential launch path.
    #
    # The launched SEV policy is the one the message requested
    # (trusted_execution.policy). The aleph-message schema defaults it to
    # AMDSEVPolicy.NO_DBG, so it is always present; the supervisor applies it
    # verbatim and holds no opinion of its own.
    tee: TeeConfig | None = None
    trusted_execution = getattr(message.environment, "trusted_execution", None)
    if trusted_execution is not None:
        if getattr(trusted_execution, "is_snp", False):
            # SNP instances are built by build_snp_instance_spec
            # (snp_instance_launch.py), which supplies the measured runtime
            # bundle (OVMF/kernel/initrd/cmdline). This path has none of
            # that: a routing mistake that reached here would silently build
            # a SEV spec with no firmware. Fail loudly instead.
            raise InvalidBackendError("SNP instances are built by build_snp_instance_spec, not this path")
        firmware_path = await get_existing_file(trusted_execution.firmware)
        tee = TeeConfig(
            backend=TeeBackend.SEV,
            policy=hex(trusted_execution.policy),
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

    # The agent computes the static IPv6 (the address does not depend on the
    # vm_index) so the supervisor is told the address rather than deriving the
    # Aleph scheme; empty under the dynamic policy, where the supervisor assigns.
    requested_ipv6, ipv6_prefix_len = compute_requested_ipv6(vm_hash, VmType.from_message_content(message))

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
            requested_ipv6=requested_ipv6,
            ipv6_prefix_len=ipv6_prefix_len,
        ),
        gpus=[],
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
) -> tuple[CreateVmSpec, ProgramDownloader]:
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

    resources = ProgramDownloader(message, namespace=str(vm_hash))
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

    # A program's static IPv6 also depends only on the type and item hash, so
    # the agent computes it upfront (empty under the dynamic policy). The
    # daemon and the scheduler fold every Firecracker program (persistent or
    # not) into the microvm hextet: their VmType has no persistent_program
    # variant, and VmType::ipv6_value() maps them to 0x1. Passing the
    # message-derived type here would emit hextet 0x2 for persistent programs
    # and disagree with the address the rest of the network expects, so pin
    # this to microvm.
    requested_ipv6, ipv6_prefix_len = compute_requested_ipv6(vm_hash, VmType.microvm)

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
            requested_ipv6=requested_ipv6,
            ipv6_prefix_len=ipv6_prefix_len,
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
