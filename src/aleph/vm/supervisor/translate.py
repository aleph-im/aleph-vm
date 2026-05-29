"""Translate an aleph_message ExecutableContent into a CreateVmSpec.

This is the entry point for the aleph-message side of the supervisor refactor
(Phase 0.C). It validates the message, downloads resources via the existing
AlephQemuResources machinery, and returns a message-agnostic CreateVmSpec that
the rest of the supervisor pipeline can work with.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from aleph_message.models import ExecutableContent, ItemHash
from aleph_message.models.execution.environment import HypervisorType
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm.conf import settings
from aleph.vm.controllers.qemu.instance import AlephQemuResources
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    VmId,
)


async def build_create_vm_spec(
    vm_hash: ItemHash,
    message: ExecutableContent,
    *,
    gpus: Sequence[GpuSpec] = (),
) -> CreateVmSpec:
    """Translate *message* into a CreateVmSpec, downloading resources as needed.

    Validation is performed before any I/O. Raises InvalidBackendError for:
    - non-instance messages
    - non-QEMU hypervisor
    - confidential (trusted_execution set) instances
    """
    # --- Validate before any I/O ---

    if not isinstance(message, InstanceContent):
        raise InvalidBackendError(f"Expected InstanceContent, got {type(message).__name__}")

    effective_hypervisor = message.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
    if effective_hypervisor != HypervisorType.qemu:
        raise InvalidBackendError(f"Expected qemu hypervisor, got {effective_hypervisor!r}")

    if getattr(message.environment, "trusted_execution", None) is not None:
        raise InvalidBackendError("Confidential instances (trusted_execution set) are not supported by this path")

    # --- Materialise resources ---

    resources = AlephQemuResources(message, namespace=str(vm_hash))
    await resources.download_all()

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
        tee=None,
        network=NetworkConfig(
            internet_access=message.environment.internet,
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=list(gpus),
        numa_node=None,
        persistent=True,
        ssh_authorized_keys=list(message.authorized_keys or []),
    )
