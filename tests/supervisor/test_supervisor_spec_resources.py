"""Tests for AlephQemuResources.from_spec — the message-free resources holder."""

from __future__ import annotations

from pathlib import Path

from aleph.vm.controllers.qemu.instance import AlephQemuResources
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    VmId,
)


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId("deadbeef" * 8),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS),
            DiskSpec(
                path=Path("/data/extra.img"),
                readonly=True,
                format=DiskFormat.RAW,
                role=DiskRole.EXTRA,
                mount="/mnt/data",
            ),
        ],
        vcpus=4,
        memory_mib=2048,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True)],
        numa_node=None,
        persistent=True,
    )


def test_from_spec_populates_paths_without_download():
    resources = AlephQemuResources.from_spec(_spec(), namespace="ns")

    assert resources.message_content is None
    assert resources.namespace == "ns"
    assert resources.rootfs_path == Path("/data/rootfs.qcow2")
    assert len(resources.volumes) == 1
    assert resources.volumes[0].path_on_host == Path("/data/extra.img")
    assert resources.volumes[0].mount == "/mnt/data"
    assert resources.volumes[0].read_only is True
    assert len(resources.gpus) == 1
    assert resources.gpus[0].pci_host == "0000:01:00.0"
    assert resources.gpus[0].supports_x_vga is True


def test_from_spec_disk_usage_delta_is_zero():
    # The supervisor does not do admission; the spec holder reports no reservation.
    resources = AlephQemuResources.from_spec(_spec(), namespace="ns")
    assert resources.get_disk_usage_delta() == 0
