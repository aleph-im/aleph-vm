"""spec_from_controller_configuration — reverse of build_qemu_configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from aleph.vm.conf import settings as real_settings
from aleph.vm.sizes import MiB
from aleph.vm.supervisor.qemu_build import spec_from_controller_configuration
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.supervisor_interface.errors import InvalidBackendError
from aleph.vm.supervisor_interface.types import Backend, DiskRole, TeeBackend

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


def _confidential_config() -> Configuration:
    vm_cfg = QemuConfidentialVMConfiguration(
        qemu_bin_path="/usr/bin/qemu-system-x86_64",
        image_path="/data/rootfs.qcow2",
        monitor_socket_path=Path("/run/m.socket"),
        qmp_socket_path=Path("/run/q.socket"),
        vcpu_count=4,
        mem_size_mb=MiB(2048),
        interface_name="tap7",
        host_volumes=[QemuVMHostVolume(mount="/mnt/data", path_on_host=Path("/data/extra.img"), read_only=True)],
        gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
        ovmf_path=Path("/opt/ovmf/OVMF.fd"),
        sev_session_file=Path(f"/var/lib/aleph/sessions/{_HASH}/vm_session.b64"),
        sev_dh_cert_file=Path(f"/var/lib/aleph/sessions/{_HASH}/vm_godh.b64"),
        sev_policy=1,
    )
    return Configuration(
        vm_id=7,
        vm_hash=_HASH,
        settings=real_settings,
        vm_configuration=vm_cfg,
        hypervisor=HypervisorType.qemu,
    )


def test_spec_from_config_reconstructs_confidential_tee():
    """A confidential (SEV) controller config must reattach, not raise: the
    TeeConfig is rebuilt so the execution stays confidential and create() can
    take the AlephQemuConfidentialInstance path."""
    spec = spec_from_controller_configuration(_confidential_config())

    assert spec.tee is not None
    assert spec.tee.backend is TeeBackend.SEV
    # firmware_path is the only field AlephQemuConfidentialResources.from_spec
    # requires; it must be the on-disk OVMF blob.
    assert spec.tee.firmware_path == Path("/opt/ovmf/OVMF.fd")
    # Policy round-trips through int(.., 0) exactly (create() converts it back).
    assert int(spec.tee.policy, 0) == 1
    # Session dir is where the owner's already-uploaded certs live.
    assert spec.tee.session_dir == Path(f"/var/lib/aleph/sessions/{_HASH}")
    # Core fields still reconstruct, same as the plain path.
    assert spec.backend is Backend.QEMU
    assert spec.vcpus == 4
    assert spec.memory_mib == 2048
    rootfs = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
    assert rootfs[0].path == Path("/data/rootfs.qcow2")


def test_spec_from_config_rejects_non_qemu():
    from aleph.vm.supervisor_interface.configuration import VMConfiguration

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
