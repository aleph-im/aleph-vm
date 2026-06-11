"""Spec-driven Firecracker program controller: resources + boot config."""

from pathlib import Path

import pytest

from aleph.vm.controllers.firecracker.spec_program import (
    SpecFirecrackerProgram,
    SpecProgramResources,
)
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

VM_HASH = "feed" * 16


def make_spec(tmp_path: Path, *, code: bool = True, extra: int = 1, internet: bool = False) -> CreateVmSpec:
    kernel = tmp_path / "vmlinux.bin"
    runtime = tmp_path / "runtime.squashfs"
    kernel.write_bytes(b"kernel")
    runtime.write_bytes(b"runtime")
    disks = [DiskSpec(path=runtime, readonly=True, format=DiskFormat.SQUASHFS, role=DiskRole.RUNTIME)]
    if code:
        code_path = tmp_path / "code.squashfs"
        code_path.write_bytes(b"code")
        disks.append(DiskSpec(path=code_path, readonly=True, format=DiskFormat.SQUASHFS, role=DiskRole.CODE))
    for index in range(extra):
        volume = tmp_path / f"volume{index}.ext4"
        volume.write_bytes(b"volume")
        disks.append(
            DiskSpec(path=volume, readonly=False, format=DiskFormat.RAW, role=DiskRole.EXTRA, mount=f"/data{index}")
        )
    return CreateVmSpec(
        vm_id=VmId(VM_HASH),
        backend=Backend.FIRECRACKER,
        kernel_path=kernel,
        initrd_path=Path(""),
        disks=disks,
        vcpus=1,
        memory_mib=256,
        tee=None,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=False,
        program_mode=True,
    )


def test_resources_from_spec(tmp_path):
    spec = make_spec(tmp_path, code=True, extra=2)
    resources = SpecProgramResources.from_spec(spec)
    assert resources.kernel_image_path == spec.kernel_path
    assert resources.rootfs_path.name == "runtime.squashfs"
    assert resources.code_disk is not None and resources.code_disk.path.name == "code.squashfs"
    assert [disk.path.name for disk in resources.extra_disks] == ["volume0.ext4", "volume1.ext4"]


def test_resources_from_spec_without_code(tmp_path):
    spec = make_spec(tmp_path, code=False, extra=0)
    resources = SpecProgramResources.from_spec(spec)
    assert resources.code_disk is None
    assert resources.extra_disks == []


def test_resources_require_kernel(tmp_path):
    spec = make_spec(tmp_path)
    broken = CreateVmSpec(**{**spec.__dict__, "kernel_path": Path("")})
    with pytest.raises(InvalidBackendError):
        SpecProgramResources.from_spec(broken)


def test_resources_require_exactly_one_runtime(tmp_path):
    spec = make_spec(tmp_path)
    no_runtime = CreateVmSpec(
        **{**spec.__dict__, "disks": [disk for disk in spec.disks if disk.role is not DiskRole.RUNTIME]}
    )
    with pytest.raises(InvalidBackendError):
        SpecProgramResources.from_spec(no_runtime)


@pytest.mark.asyncio
async def test_setup_builds_firecracker_config(tmp_path, mocker):
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "USE_JAILER", False)
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch("aleph.vm.controllers.firecracker.spec_program.setfacl")

    spec = make_spec(tmp_path, code=True, extra=2)
    vm = SpecFirecrackerProgram(
        vm_id=3,
        vm_hash=spec.vm_id,
        spec=spec,
        resources=SpecProgramResources.from_spec(spec),
        tap_interface=None,
        prepare_jailer=False,
    )
    await vm.setup()
    config = vm._firecracker_config
    assert config is not None
    # Drive order is the agent-facing contract: rootfs, code (vdb), volumes (vdc...).
    assert [drive.drive_id for drive in config.drives] == ["rootfs", "vdb", "vdc", "vdd"]
    assert config.drives[0].is_root_device
    assert config.drives[0].path_on_host.name == "runtime.squashfs"
    assert config.drives[1].path_on_host.name == "code.squashfs"
    assert not config.drives[2].is_read_only  # writable volume
    assert config.vsock is not None
    assert config.machine_config.vcpu_count == 1
    assert config.machine_config.mem_size_mib == 256
    assert not config.network_interfaces


@pytest.mark.asyncio
async def test_guest_api_is_agent_owned(tmp_path, mocker):
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "USE_JAILER", False)
    spec = make_spec(tmp_path)
    vm = SpecFirecrackerProgram(
        vm_id=3,
        vm_hash=spec.vm_id,
        spec=spec,
        resources=SpecProgramResources.from_spec(spec),
        tap_interface=None,
        prepare_jailer=False,
    )
    # No-ops: the agent binds <vsock>_53 itself across the boundary.
    await vm.start_guest_api()
    await vm.stop_guest_api()
    assert vm.guest_api_process is None
