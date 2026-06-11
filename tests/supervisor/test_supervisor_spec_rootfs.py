"""Tests for CreateVmSpec.rootfs / require_rootfs accessors."""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
)


def _spec(*roles: DiskRole) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id="vm",
        backend=Backend.QEMU,
        kernel_path=Path("/k"),
        initrd_path=Path("/i"),
        disks=[
            DiskSpec(path=Path(f"/{role.value}{i}"), readonly=False, format=DiskFormat.QCOW2, role=role)
            for i, role in enumerate(roles)
        ],
        vcpus=1,
        memory_mib=512,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def test_rootfs_returns_the_single_rootfs_disk():
    spec = _spec(DiskRole.ROOTFS, DiskRole.EXTRA)
    rootfs = spec.rootfs
    assert rootfs is not None
    assert rootfs.role is DiskRole.ROOTFS
    assert spec.require_rootfs() is rootfs


def test_rootfs_is_none_for_a_rootfs_less_spec():
    # Programs carry code + runtime, no rootfs disk.
    spec = _spec(DiskRole.EXTRA, DiskRole.EXTRA)
    assert spec.rootfs is None


def test_require_rootfs_raises_when_absent():
    spec = _spec(DiskRole.EXTRA, DiskRole.EXTRA)
    with pytest.raises(InvalidBackendError, match="no ROOTFS"):
        spec.require_rootfs()


def test_more_than_one_rootfs_is_rejected_as_malformed():
    spec = _spec(DiskRole.ROOTFS, DiskRole.ROOTFS)
    with pytest.raises(InvalidBackendError, match="2 ROOTFS"):
        _ = spec.rootfs
    with pytest.raises(InvalidBackendError, match="2 ROOTFS"):
        spec.require_rootfs()
