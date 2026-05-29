"""Tests for aleph.vm.supervisor.qemu_build.build_qemu_configuration."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from aleph.vm.controllers.configuration import HypervisorType, QemuVMConfiguration
from aleph.vm.controllers.qemu.cloudinit import get_hostname_from_hash
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.qemu_build import build_qemu_configuration
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

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_tap() -> object:
    """Return a SimpleNamespace that satisfies the TapInterface duck-type.

    Real ipaddress objects are used so that str() and .ip/.with_prefixlen
    produce the expected strings without extra plumbing.
    Typed as ``object`` here; tests cast it where TapInterface is needed.
    """
    return SimpleNamespace(
        device_name="tap0",
        guest_ip=ipaddress.IPv4Interface("10.0.0.2/30"),
        host_ip=ipaddress.IPv4Interface("10.0.0.1/30"),
        guest_ipv6=ipaddress.IPv6Interface("fc00::2/64"),
        host_ipv6=ipaddress.IPv6Interface("fc00::1/64"),
    )


def _make_spec(
    *,
    memory_mib: int = 2048,
    include_extra_disk: bool = True,
    include_gpu: bool = False,
    include_rootfs: bool = True,
) -> CreateVmSpec:
    disks: list[DiskSpec] = []
    if include_rootfs:
        disks.append(
            DiskSpec(
                path=Path("/data/rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        )
    if include_extra_disk:
        disks.append(
            DiskSpec(
                path=Path("/data/extra.img"),
                readonly=True,
                format=DiskFormat.RAW,
                role=DiskRole.EXTRA,
                mount="/mnt/data",
            )
        )

    gpus: list[GpuSpec] = []
    if include_gpu:
        gpus.append(GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True))

    return CreateVmSpec(
        vm_id=VmId("deadbeef" * 8),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=4,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=gpus,
        numa_node=None,
        persistent=True,
        ssh_authorized_keys=["ssh-rsa AAAA testkey"],
    )


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_qemu_configuration_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_qemu_configuration produces a correct Configuration."""
    from aleph.vm.network.interfaces import TapInterface

    captured: dict[str, object] = {}

    async def fake_cloud_init(  # type: ignore[no-untyped-def]
        disk_image_path,
        hostname,
        vm_id,
        ip,
        ipv6,
        ipv6_gateway,
        nameservers,
        route,
        ssh_authorized_keys,
        **kwargs,
    ) -> None:
        captured["hostname"] = hostname
        captured["ip"] = ip
        captured["ipv6"] = ipv6
        captured["ipv6_gateway"] = ipv6_gateway
        captured["route"] = route
        captured["keys"] = ssh_authorized_keys

    monkeypatch.setattr(
        "aleph.vm.supervisor.qemu_build.create_cloud_init_drive_image",
        fake_cloud_init,
    )

    spec = _make_spec(include_extra_disk=True)
    fake_tap = _make_fake_tap()
    tap = cast(TapInterface, fake_tap)

    config = await build_qemu_configuration(spec, vm_id=7, tap_interface=tap)

    # Top-level config
    assert config.hypervisor is HypervisorType.qemu
    assert config.vm_id == 7
    assert config.vm_hash == spec.vm_id

    # vm_configuration is a QemuVMConfiguration
    assert isinstance(config.vm_configuration, QemuVMConfiguration)
    vm_cfg = config.vm_configuration

    # image_path comes from ROOTFS disk
    assert vm_cfg.image_path == str(Path("/data/rootfs.qcow2"))

    # host_volumes: only EXTRA disks
    assert len(vm_cfg.host_volumes) == 1
    assert vm_cfg.host_volumes[0].path_on_host == Path("/data/extra.img")
    assert vm_cfg.host_volumes[0].read_only is True
    assert vm_cfg.host_volumes[0].mount == "/mnt/data"

    # vcpu_count
    assert vm_cfg.vcpu_count == 4

    # interface_name
    assert vm_cfg.interface_name == "tap0"

    # gpus empty for this spec
    assert vm_cfg.gpus == []

    # cloud-init path ends with expected name
    assert vm_cfg.cloud_init_drive_path is not None
    assert vm_cfg.cloud_init_drive_path.endswith(f"cloud-init-{spec.vm_id}.img")

    # cloud-init was called with the correct arguments derived from tap + spec
    assert captured, "create_cloud_init_drive_image was not called"
    assert captured["hostname"] == get_hostname_from_hash(spec.vm_id)  # type: ignore[arg-type]
    assert captured["ip"] == "10.0.0.2/30"
    assert captured["route"] == "10.0.0.1"
    assert captured["ipv6"] == "fc00::2/64"
    assert captured["ipv6_gateway"] == "fc00::1"
    assert captured["keys"] == spec.ssh_authorized_keys


@pytest.mark.asyncio
async def test_memory_mib_passed_correctly(monkeypatch: pytest.MonkeyPatch) -> None:
    """2048 MiB is passed to QEMU as 2048, not the prior under-allocated 1953."""

    async def fake_cloud_init(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        pass

    monkeypatch.setattr(
        "aleph.vm.supervisor.qemu_build.create_cloud_init_drive_image",
        fake_cloud_init,
    )

    spec = _make_spec(memory_mib=2048)
    from aleph.vm.network.interfaces import TapInterface

    tap = cast(TapInterface, _make_fake_tap())
    config = await build_qemu_configuration(spec, vm_id=1, tap_interface=tap)

    assert isinstance(config.vm_configuration, QemuVMConfiguration)
    assert config.vm_configuration.mem_size_mb == 2048


@pytest.mark.asyncio
async def test_gpu_spec_passed_through(monkeypatch: pytest.MonkeyPatch) -> None:
    """GpuSpec items are translated to QemuGPU on vm_configuration.gpus."""

    async def fake_cloud_init(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        pass

    monkeypatch.setattr(
        "aleph.vm.supervisor.qemu_build.create_cloud_init_drive_image",
        fake_cloud_init,
    )

    spec = _make_spec(include_gpu=True)
    from aleph.vm.network.interfaces import TapInterface

    tap = cast(TapInterface, _make_fake_tap())
    config = await build_qemu_configuration(spec, vm_id=2, tap_interface=tap)

    assert isinstance(config.vm_configuration, QemuVMConfiguration)
    assert len(config.vm_configuration.gpus) == 1
    assert config.vm_configuration.gpus[0].pci_host == "0000:01:00.0"
    assert config.vm_configuration.gpus[0].supports_x_vga is True


@pytest.mark.asyncio
async def test_no_tap_interface(monkeypatch: pytest.MonkeyPatch) -> None:
    """tap_interface=None yields interface_name=None in the vm_configuration."""

    async def fake_cloud_init(*args, **kwargs) -> None:  # type: ignore[no-untyped-def]
        pass

    monkeypatch.setattr(
        "aleph.vm.supervisor.qemu_build.create_cloud_init_drive_image",
        fake_cloud_init,
    )

    spec = _make_spec()
    config = await build_qemu_configuration(spec, vm_id=3, tap_interface=None)

    assert isinstance(config.vm_configuration, QemuVMConfiguration)
    assert config.vm_configuration.interface_name is None


# ---------------------------------------------------------------------------
# Error path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_rootfs_disk_raises() -> None:
    """A spec with no ROOTFS disk raises InvalidBackendError."""
    spec = _make_spec(include_rootfs=False, include_extra_disk=True)

    with pytest.raises(InvalidBackendError, match="ROOTFS"):
        await build_qemu_configuration(spec, vm_id=9, tap_interface=None)
