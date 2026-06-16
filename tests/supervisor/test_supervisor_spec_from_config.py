"""spec_from_controller_configuration — reverse of build_qemu_configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.conf import settings as real_settings
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.sizes import MiB
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.qemu_build import spec_from_controller_configuration
from aleph.vm.supervisor.types import Backend, DiskRole

_HASH = "deadbeef" * 8


def _config(*, interface_name: str | None = "tap7") -> Configuration:
    vm_cfg = QemuVMConfiguration(
        qemu_bin_path="/usr/bin/qemu-system-x86_64",
        image_path="/data/rootfs.qcow2",
        monitor_socket_path=Path("/run/m.socket"),
        qmp_socket_path=Path("/run/q.socket"),
        vcpu_count=4,
        mem_size_mb=MiB(2048),
        interface_name=interface_name,
        host_volumes=[QemuVMHostVolume(mount="/mnt/data", path_on_host=Path("/data/extra.img"), read_only=True)],
        gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
    )
    return Configuration(
        vm_id=7,
        vm_hash=_HASH,
        settings=real_settings,
        vm_configuration=vm_cfg,
        hypervisor=HypervisorType.qemu,
    )


def test_spec_from_config_roundtrips_core_fields():
    spec = spec_from_controller_configuration(_config())

    assert spec.vm_id == _HASH
    assert spec.backend is Backend.QEMU
    assert spec.vcpus == 4
    assert spec.memory_mib == 2048
    assert spec.network.internet_access is True  # interface_name present

    rootfs = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
    extra = [d for d in spec.disks if d.role is DiskRole.EXTRA]
    assert rootfs[0].path == Path("/data/rootfs.qcow2")
    assert extra[0].path == Path("/data/extra.img")
    assert extra[0].readonly is True
    assert len(spec.gpus) == 1
    assert spec.gpus[0].pci_host == "0000:01:00.0"


def test_spec_from_config_no_interface_means_no_internet():
    spec = spec_from_controller_configuration(_config(interface_name=None))
    assert spec.network.internet_access is False


def test_spec_from_config_rejects_non_qemu():
    from aleph.vm.controllers.configuration import VMConfiguration

    cfg = Configuration(
        vm_id=1,
        vm_hash=_HASH,
        settings=real_settings,
        vm_configuration=VMConfiguration(
            use_jailer=True,
            firecracker_bin_path=Path("/x"),
            jailer_bin_path=Path("/y"),
            config_file_path=Path("/z"),
            init_timeout=5.0,
        ),
        hypervisor=HypervisorType.firecracker,
    )
    with pytest.raises(InvalidBackendError):
        spec_from_controller_configuration(cfg)
