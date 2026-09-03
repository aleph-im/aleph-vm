"""Tests for aleph.vm.agent.translate.build_create_vm_spec."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from aleph_message.models import ItemHash, Payment, PaymentType
from aleph_message.models.execution.environment import (
    HypervisorType,
    InstanceEnvironment,
    MachineResources,
    TrustedExecutionEnvironment,
)
from aleph_message.models.execution.instance import InstanceContent, RootfsVolume
from aleph_message.models.execution.volume import ParentVolume, VolumePersistence
from aleph_message.utils import Mebibytes

from aleph.vm.agent.translate import build_create_vm_spec
from aleph.vm.agent.vm.downloader import QemuDownloader
from aleph.vm.host_volumes import HostVolume
from aleph.vm.supervisor_interface.errors import InvalidBackendError
from aleph.vm.supervisor_interface.types import Backend, DiskRole
from aleph.vm.utils import get_hostname_from_hash

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAKE_HASH = ItemHash("cafecafe" * 8)
_VM_HASH = ItemHash("deadbeef" * 8)


def _make_qemu_instance_message(
    *,
    internet: bool = True,
    vcpus: int = 2,
    memory: int = 2048,
    authorized_keys: list[str] | None = None,
    hypervisor: HypervisorType | None = HypervisorType.qemu,
    trusted_execution: TrustedExecutionEnvironment | None = None,
    payment: Payment | None = None,
) -> InstanceContent:
    return InstanceContent(
        address="0x1234567890abcdef1234567890abcdef12345678",
        time=1.0,
        allow_amend=False,
        authorized_keys=authorized_keys,
        payment=payment,
        environment=InstanceEnvironment(
            internet=internet,
            aleph_api=False,
            hypervisor=hypervisor,
            trusted_execution=trusted_execution,
        ),
        resources=MachineResources(vcpus=vcpus, memory=Mebibytes(memory), seconds=300),
        volumes=[],
        rootfs=RootfsVolume(
            parent=ParentVolume(ref=_FAKE_HASH, use_latest=False),
            persistence=VolumePersistence.host,
            size_mib=10000,
        ),
    )


# ---------------------------------------------------------------------------
# Happy-path test
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_build_create_vm_spec_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """build_create_vm_spec returns a correctly-populated CreateVmSpec."""
    rootfs = Path("/data/rootfs.qcow2")
    vol = HostVolume(
        mount="/mnt/x",
        path_on_host=Path("/data/vol.img"),
        read_only=True,
        size_mib=100,
    )

    async def fake_download_all(self: Any) -> None:
        self.rootfs_path = rootfs
        self.volumes = [vol]

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)

    message = _make_qemu_instance_message(
        internet=True,
        vcpus=4,
        memory=4096,
        authorized_keys=["ssh-rsa AAAA key1", "ssh-ed25519 BBBB key2"],
    )

    spec = await build_create_vm_spec(_VM_HASH, message)

    # backend and identity
    assert spec.backend is Backend.QEMU
    assert spec.persistent is True
    assert spec.vm_id == str(_VM_HASH)

    # resources
    assert spec.vcpus == 4
    assert spec.memory_mib == 4096

    # network
    assert spec.network.internet_access is True

    # ssh keys
    assert spec.ssh_authorized_keys == ["ssh-rsa AAAA key1", "ssh-ed25519 BBBB key2"]

    # the Aleph hostname convention is applied agent-side
    assert spec.hostname == get_hostname_from_hash(_VM_HASH)

    # disks
    assert len(spec.disks) == 2

    rootfs_disks = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
    assert len(rootfs_disks) == 1
    assert rootfs_disks[0].path == rootfs
    assert rootfs_disks[0].readonly is False

    extra_disks = [d for d in spec.disks if d.role is DiskRole.EXTRA]
    assert len(extra_disks) == 1
    assert extra_disks[0].path == Path("/data/vol.img")
    assert extra_disks[0].readonly is True

    # gpus default to empty
    assert spec.gpus == []

    # tee is None
    assert spec.tee is None


@pytest.mark.asyncio
async def test_build_create_vm_spec_ignores_gpu_requirements(monkeypatch: pytest.MonkeyPatch) -> None:
    """The message's requested device_ids stop at the agent: the built spec
    carries no GPUs. The create path resolves the requests to concrete host
    cards through the CapacityManager and rewrites spec.gpus afterwards."""
    from aleph_message.models.execution.environment import (
        GpuProperties,
        HostRequirements,
    )

    async def fake_download_all(self: Any) -> None:
        self.rootfs_path = Path("/data/rootfs.qcow2")
        self.volumes = []

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)

    message = _make_qemu_instance_message()
    message = message.model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="GH100",
                        device_class="0300",
                        device_id="10de:2504",
                    )
                ]
            )
        }
    )

    spec = await build_create_vm_spec(_VM_HASH, message)

    assert spec.gpus == []


@pytest.mark.asyncio
async def test_authorized_keys_none_becomes_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    """authorized_keys=None in the message yields an empty list in the spec."""

    async def fake_download_all(self: Any) -> None:
        self.rootfs_path = Path("/data/rootfs.qcow2")
        self.volumes = []

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)

    message = _make_qemu_instance_message(authorized_keys=None)
    spec = await build_create_vm_spec(_VM_HASH, message)

    assert spec.ssh_authorized_keys == []


# ---------------------------------------------------------------------------
# Rejection tests -- validation must happen BEFORE download
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_non_instance_message_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-InstanceContent message raises InvalidBackendError without downloading."""
    download_called = False

    async def should_not_be_called(self: Any) -> None:
        nonlocal download_called
        download_called = True

    # Use a SimpleNamespace stand-in -- constructing ProgramContent requires
    # many mandatory fields that are irrelevant to this validation path.
    fake_message = SimpleNamespace(
        environment=SimpleNamespace(hypervisor=HypervisorType.qemu, trusted_execution=None),
        resources=SimpleNamespace(vcpus=1, memory=512),
        authorized_keys=None,
    )

    monkeypatch.setattr(QemuDownloader, "download_all", should_not_be_called)

    with pytest.raises(InvalidBackendError, match="InstanceContent"):
        await build_create_vm_spec(_VM_HASH, fake_message)  # type: ignore[arg-type]

    assert not download_called, "download_all must not run when validation fails"


@pytest.mark.asyncio
async def test_firecracker_hypervisor_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """An InstanceContent with a firecracker hypervisor raises InvalidBackendError."""
    download_called = False

    async def should_not_be_called(self: Any) -> None:
        nonlocal download_called
        download_called = True

    monkeypatch.setattr(QemuDownloader, "download_all", should_not_be_called)

    message = _make_qemu_instance_message(hypervisor=HypervisorType.firecracker)

    with pytest.raises(InvalidBackendError, match="hypervisor"):
        await build_create_vm_spec(_VM_HASH, message)

    assert not download_called


@pytest.mark.asyncio
async def test_confidential_instance_populates_tee(monkeypatch: pytest.MonkeyPatch) -> None:
    """A confidential InstanceContent yields a CreateVmSpec carrying spec.tee:
    backend SEV, the requested policy (trusted_execution.policy, applied
    verbatim), the per-VM session dir, and the resolved firmware host path."""
    from aleph_message.models.execution.environment import AMDSEVPolicy

    from aleph.vm.conf import settings
    from aleph.vm.supervisor_interface.types import TeeBackend

    firmware_path = Path("/data/firmware.fd")

    async def fake_download_all(self: Any) -> None:
        self.rootfs_path = Path("/data/rootfs.qcow2")
        self.volumes = []

    async def fake_get_existing_file(ref: Any) -> Path:
        return firmware_path

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)
    monkeypatch.setattr("aleph.vm.agent.translate.get_existing_file", fake_get_existing_file)

    # The message requests a non-default policy: the spec must carry that
    # requested policy verbatim (the supervisor holds no opinion; the schema
    # defaults the policy at the message layer).
    requested_policy = int(AMDSEVPolicy.SEV_ES)
    message = _make_qemu_instance_message(
        trusted_execution=TrustedExecutionEnvironment(firmware=_FAKE_HASH, policy=requested_policy)
    )

    spec = await build_create_vm_spec(_VM_HASH, message)

    assert spec.tee is not None
    assert spec.tee.backend is TeeBackend.SEV
    assert int(spec.tee.policy, 0) == requested_policy
    assert requested_policy != int(AMDSEVPolicy.NO_DBG)
    assert spec.tee.session_dir == settings.CONFIDENTIAL_SESSION_DIRECTORY / _VM_HASH
    assert spec.tee.firmware_path == firmware_path


@pytest.mark.asyncio
async def test_snp_instance_rejected_before_any_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """An SEV-SNP instance reaching this path is a routing mistake (run.py
    sends it to build_snp_instance_spec): rejected loudly, before any I/O."""
    from aleph_message.models.execution.environment import (
        LaunchMeasurement,
        SevSnpRegisters,
        TeePlatform,
    )

    async def fail_download_all(self: Any) -> None:
        raise AssertionError("download must not run for a rejected message")

    monkeypatch.setattr(QemuDownloader, "download_all", fail_download_all)

    message = _make_qemu_instance_message(
        trusted_execution=TrustedExecutionEnvironment(
            mode="sev_snp",
            runtime=_FAKE_HASH,
            measurements=[
                LaunchMeasurement(
                    platform=TeePlatform.sev_snp,
                    registers=SevSnpRegisters(launch="aa" * 48),
                    vcpu_type="EPYC-v4",
                )
            ],
            policy=0x30000,
        ),
        payment=Payment(type=PaymentType.credit),
    )

    with pytest.raises(InvalidBackendError, match="build_snp_instance_spec"):
        await build_create_vm_spec(_VM_HASH, message)


@pytest.mark.asyncio
async def test_tdx_instance_rejected_before_any_download(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TDX instance has no launch path on this CRN: rejected with the mode
    named, before any I/O (its message carries no firmware to resolve)."""
    from aleph_message.models.execution.environment import (
        LaunchMeasurement,
        TdxRegisters,
        TeePlatform,
    )

    async def fail_download_all(self: Any) -> None:
        raise AssertionError("download must not run for a rejected message")

    monkeypatch.setattr(QemuDownloader, "download_all", fail_download_all)

    message = _make_qemu_instance_message(
        trusted_execution=TrustedExecutionEnvironment(
            mode="tdx",
            runtime=_FAKE_HASH,
            measurements=[
                LaunchMeasurement(
                    platform=TeePlatform.tdx,
                    registers=TdxRegisters(
                        mrtd="11" * 48,
                        rtmr1="22" * 48,
                        rtmr2="33" * 48,
                        mrconfigid="44" * 48,
                    ),
                )
            ],
        ),
        payment=Payment(type=PaymentType.credit),
    )

    with pytest.raises(InvalidBackendError, match="tdx instances are not supported"):
        await build_create_vm_spec(_VM_HASH, message)


# ---------------------------------------------------------------------------
# Hypervisor-default branch tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_hypervisor_none_defaults_to_qemu(monkeypatch: pytest.MonkeyPatch) -> None:
    """hypervisor=None with INSTANCE_DEFAULT_HYPERVISOR=qemu succeeds."""
    rootfs = Path("/data/rootfs.qcow2")

    async def fake_download_all(self: Any) -> None:
        self.rootfs_path = rootfs
        self.volumes = []

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)
    monkeypatch.setattr("aleph.vm.conf.settings.INSTANCE_DEFAULT_HYPERVISOR", HypervisorType.qemu)

    message = _make_qemu_instance_message(hypervisor=None)
    spec = await build_create_vm_spec(_VM_HASH, message)

    assert spec.backend is Backend.QEMU


@pytest.mark.asyncio
async def test_hypervisor_none_defaults_to_firecracker_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """hypervisor=None with INSTANCE_DEFAULT_HYPERVISOR=firecracker raises InvalidBackendError.

    Validation must fire before any download.
    """
    download_called = False

    async def should_not_be_called(self: Any) -> None:
        nonlocal download_called
        download_called = True

    monkeypatch.setattr(QemuDownloader, "download_all", should_not_be_called)
    monkeypatch.setattr("aleph.vm.conf.settings.INSTANCE_DEFAULT_HYPERVISOR", HypervisorType.firecracker)

    message = _make_qemu_instance_message(hypervisor=None)

    with pytest.raises(InvalidBackendError, match="hypervisor"):
        await build_create_vm_spec(_VM_HASH, message)

    assert not download_called, "download_all must not run when validation fails"
