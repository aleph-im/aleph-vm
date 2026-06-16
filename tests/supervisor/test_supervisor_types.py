"""VmInfo contract carries precise TEE mode + attached GPUs; no agent-only fields."""

from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

from aleph.vm.supervisor.types import (
    Backend,
    ConfidentialMode,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    ErrorCode,
    GpuDevice,
    GpuSpec,
    HealthInfo,
    HealthStatus,
    HostInfo,
    IpAssignment,
    LogChunk,
    LogSource,
    NetworkConfig,
    PciAddress,
    Protocol,
    TeeBackend,
    TeeConfig,
    VmId,
    VmInfo,
    VmStatus,
)


def test_enums_have_expected_members():
    assert {b.name for b in Backend} == {"FIRECRACKER", "QEMU"}
    assert {s.name for s in VmStatus} == {
        "DEFINED",
        "BOOTING",
        "RUNNING",
        "STOPPING",
        "STOPPED",
        "FAILED",
    }
    assert {f.name for f in DiskFormat} == {"RAW", "QCOW2", "SQUASHFS"}
    assert {r.name for r in DiskRole} == {"ROOTFS", "EXTRA"}
    assert {p.name for p in Protocol} == {"TCP", "UDP"}
    assert {s.name for s in LogSource} == {"SERIAL", "STDOUT", "STDERR", "SYSTEMD"}
    assert "INTERNAL" in {c.name for c in ErrorCode}
    assert "VM_NOT_FOUND" in {c.name for c in ErrorCode}


def test_vm_info_is_frozen_dataclass():
    info = VmInfo(
        vm_id=VmId("abc"),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(address="10.0.0.2"),
        ipv6=IpAssignment(),
        uptime_secs=42,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    assert info.vm_id == "abc"
    with pytest.raises(FrozenInstanceError):
        info.vm_id = "other"  # type: ignore[misc]


def test_create_vm_spec_constructs_with_nested_dtos():
    spec = CreateVmSpec(
        vm_id=VmId("abc"),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/var/lib/x.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=2,
        memory_mib=2048,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )
    assert spec.disks[0].role is DiskRole.ROOTFS
    assert spec.network.internet_access is True


def test_supporting_dtos_construct():
    assert (
        TeeConfig(backend=TeeBackend.SEV_SNP, policy="", session_dir=DirectoryPath(Path("/x"))).backend
        is TeeBackend.SEV_SNP
    )
    assert GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True).supports_x_vga is True
    assert LogChunk(timestamp_ns=1, line="hello", source=LogSource.SERIAL).line == "hello"
    assert HealthInfo(status=HealthStatus.OK, vm_count=3).vm_count == 3
    assert HostInfo(cpu_count=8, memory_mib=16000).cpu_count == 8


def _minimal_vm_info(**overrides) -> VmInfo:
    base = dict(
        vm_id=VmId("vm-a"),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    base.update(overrides)
    return VmInfo(**base)


def test_vm_info_defaults_are_non_confidential_and_gpuless():
    info = _minimal_vm_info()
    assert info.confidential_mode is ConfidentialMode.NONE
    assert info.gpus == []


def test_vm_info_carries_precise_mode_and_devices():
    gpu = GpuDevice(pci_host="0000:01:00.0", device_id="10de:2504", model="RTX 3090", supports_x_vga=True)
    info = _minimal_vm_info(confidential_mode=ConfidentialMode.SEV_ES, gpus=[gpu])
    assert info.confidential_mode is ConfidentialMode.SEV_ES
    assert info.gpus[0].device_id == "10de:2504"


def test_vm_info_has_no_persistent_field():
    """persistent is an agent fact (registry), never on the supervisor contract."""
    assert "persistent" not in {f.name for f in fields(VmInfo)}


def test_confidential_mode_members():
    assert [m.name for m in ConfidentialMode] == ["NONE", "SEV", "SEV_ES", "SEV_SNP"]
