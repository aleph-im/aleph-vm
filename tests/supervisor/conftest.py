"""Shared fixtures and a reusable CreateVmSpec factory for supervisor tests.

The message-free VmExecution is built from a CreateVmSpec via
VmExecution.from_spec(...). This factory mirrors the per-file _spec helpers
(see test_supervisor_spec_admission.py / test_supervisor_spec_pool_create.py)
so migrated tests share one construction path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    TeeConfig,
    VmId,
)

_DEFAULT_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


def make_spec(
    *,
    vm_hash: str = _DEFAULT_HASH,
    backend: Backend = Backend.QEMU,
    tee: TeeConfig | None = None,
    gpus: list[GpuSpec] | None = None,
    persistent: bool = True,
    memory_mib: int = 256,
    vcpus: int = 1,
    internet: bool = True,
    with_rootfs: bool = True,
    rootfs_path: Path = Path("/data/rootfs.qcow2"),
) -> CreateVmSpec:
    """Build a CreateVmSpec for tests, parameterized over the fields the
    migrated VmExecution tests exercise."""
    disks: list[DiskSpec] = []
    if with_rootfs:
        disks.append(
            DiskSpec(
                path=rootfs_path,
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        )
    return CreateVmSpec(
        vm_id=VmId(vm_hash),
        backend=backend,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=tee,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=gpus or [],
        numa_node=None,
        persistent=persistent,
    )


@pytest.fixture
def spec_factory():
    """Fixture handle for make_spec, for tests that prefer dependency injection."""
    return make_spec
