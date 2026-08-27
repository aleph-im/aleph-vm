"""Conformance for the Rust daemon's lifecycle surface (increment 3),
restricted to what runs without root: CreateVm rejection paths, the
NOT_FOUND vocabulary of every mutation, DeleteVm's on-disk and sqlite
effects (read back by the SQLAlchemy models and by a restarted daemon),
and the unprivileged-nftables failure shape of AddPortForward.

The oracle: the wire contract's error vocabulary
(aleph.vm.supervisor_interface.errors) for the rejection paths, and the exact
controller-configuration JSON / frozen SQLAlchemy `PortMapping` schema
(tests/conformance/oracle.py) for the persistence assertions. The full boot paths (systemd units, taps,
kernel nftables) are covered by the implementation-agnostic
tests/integration suite run as root.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from conftest import cargo_missing
from oracle import Base, PortMapping
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError,
    InternalSupervisorError,
    InvalidBackendError,
    NotImplementedSupervisorError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    GuestChannelSpec,
    HostPort,
    NetworkConfig,
    PciAddress,
    PortForwardSpec,
    Protocol,
    TeeBackend,
    TeeConfig,
    VmId,
    VmStatus,
)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(cargo_missing(), reason="cargo is not on PATH"),
]


def _fixture_hash(name: str) -> str:
    return hashlib.sha256(f"conformance-lifecycle-{name}".encode()).hexdigest()


STOPPED_HASH = _fixture_hash("stopped")
KEPT_HASH = _fixture_hash("kept")
UNKNOWN_HASH = "1" * 64


def _write_configuration(root: Path, vm_hash: str, vm_index: int) -> Configuration:
    configuration = Configuration(
        vm_id=vm_index,
        vm_hash=vm_hash,
        settings=ControllerSettings(),
        vm_configuration=QemuVMConfiguration(
            qemu_bin_path="/usr/bin/qemu-system-x86_64",
            cloud_init_drive_path=str(root / f"cloud-init-{vm_hash}.img"),
            image_path=str(root / "volumes/persistent" / vm_hash / "rootfs.qcow2"),
            monitor_socket_path=root / f"{vm_hash}-monitor.socket",
            qmp_socket_path=root / f"{vm_hash}-qmp.socket",
            qga_socket_path=root / f"{vm_hash}-qga.socket",
            vcpu_count=1,
            mem_size_mb=512,
            interface_name=f"vmtap{vm_index}",
            host_volumes=[
                QemuVMHostVolume(
                    mount="",
                    path_on_host=root / "volumes" / f"{vm_hash}-data.img",
                    read_only=False,
                )
            ],
            gpus=[],
        ),
        hypervisor=HypervisorType.qemu,
    )
    (root / f"{vm_hash}-controller.json").write_text(
        configuration.model_dump_json(by_alias=True, exclude_none=True, indent=4)
    )
    return configuration


def _seed_root(root: Path) -> None:
    """Two stopped adopted VMs with active port mappings, a cloud-init seed
    and a writable data volume each."""
    (root / "volumes").mkdir(parents=True, exist_ok=True)
    engine = create_engine(f"sqlite:///{root / 'supervisor.sqlite3'}")
    Base.metadata.create_all(engine)
    now = datetime.now(tz=timezone.utc)
    with Session(engine) as session:
        for vm_hash, vm_index, host_port in ((STOPPED_HASH, 3, 24500), (KEPT_HASH, 4, 24501)):
            _write_configuration(root, vm_hash, vm_index)
            (root / f"cloud-init-{vm_hash}.img").write_bytes(b"seed")
            (root / "volumes" / f"{vm_hash}-data.img").write_bytes(b"data")
            session.add(
                PortMapping(vm_hash=vm_hash, vm_port=22, host_port=host_port, tcp=True, udp=False, created_at=now)
            )
        session.commit()


def _rows(root: Path, vm_hash: str) -> list[PortMapping]:
    """Every row of a VM (active and soft-deleted), read through the actual
    SQLAlchemy model so datetime decoding is exercised too."""
    engine = create_engine(f"sqlite:///{root / 'supervisor.sqlite3'}")
    with Session(engine) as session:
        rows = session.execute(select(PortMapping).where(PortMapping.vm_hash == vm_hash)).scalars().all()
        session.expunge_all()
    return list(rows)


def _spec(vm_id: str, **overrides) -> CreateVmSpec:
    base: dict = {
        "vm_id": VmId(vm_id),
        "backend": Backend.QEMU,
        "kernel_path": Path(""),
        "initrd_path": Path(""),
        "disks": [
            DiskSpec(path=Path("/tmp/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)
        ],
        "vcpus": 1,
        "memory_mib": 256,
        "tee": None,
        "network": NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        "gpus": [],
        "numa_node": None,
        "persistent": True,
    }
    base.update(overrides)
    return CreateVmSpec(**base)


@pytest.fixture
def lifecycle_daemon(start_daemon, execution_root: Path):
    _seed_root(execution_root)
    # Hermetic on runners without a default route; the adopted VMs are all
    # stopped, so nothing here needs host networking.
    with start_daemon(execution_root, {"ALEPH_VM_ALLOW_VM_NETWORKING": "false"}) as (process, socket_path):
        yield execution_root, socket_path


@pytest.mark.asyncio
async def test_create_vm_rejections_carry_the_python_error_vocabulary(lifecycle_daemon):
    _, socket_path = lifecycle_daemon
    client = GrpcSupervisor(socket_path)
    try:
        # Ephemeral Firecracker programs (increment 4): a channel-less spec
        # is the Python InvalidBackendError, before any side effect;
        # persistent programs remain UNIMPLEMENTED (controller port).
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_spec(UNKNOWN_HASH, backend=Backend.FIRECRACKER, persistent=False))
        assert str(excinfo.value) == "Firecracker spec VMs require a guest_channel"
        with pytest.raises(NotImplementedSupervisorError):
            await client.create_vm(
                _spec(
                    UNKNOWN_HASH,
                    backend=Backend.FIRECRACKER,
                    persistent=True,
                    guest_channel=GuestChannelSpec(ready_port=52, ready_timeout_secs=1),
                )
            )

        # Confidential creation (increment 6) rides the QEMU create path, but
        # a confidential spec without a resolved firmware_path is refused
        # (InvalidBackendError) before any side effect: a confidential VM must
        # never boot under a weaker configuration.
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(
                _spec(
                    UNKNOWN_HASH,
                    tee=TeeConfig(
                        backend=TeeBackend.SEV,
                        policy="0x1",
                        session_dir=DirectoryPath("/tmp"),
                        firmware_path=None,
                    ),
                )
            )
        assert str(excinfo.value) == "Confidential spec has no resolved firmware_path; refusing to build configuration"

        # The physical-memory backstop, with the Python message shape.
        with pytest.raises(InsufficientResourcesError) as excinfo:
            await client.create_vm(_spec(UNKNOWN_HASH, memory_mib=2**60))
        assert str(excinfo.value).startswith("Insufficient memory to create VM: required")
        assert "host_reserved 2048 MiB" in str(excinfo.value)

        # GPU validation: the inventory is empty (no GPU support), so any
        # pci_host is unknown; message identical to _validate_spec_gpus.
        with pytest.raises(InsufficientResourcesError) as excinfo:
            await client.create_vm(
                _spec(UNKNOWN_HASH, gpus=[GpuSpec(pci_host=PciAddress("0000:99:00.0"), supports_x_vga=True)])
            )
        assert str(excinfo.value) == "No GPU at pci_host '0000:99:00.0' in the host inventory"

        # A non-persistent QEMU spec dies INTERNAL (Python: the
        # NotImplementedError from AlephQemuInstance.start()).
        with pytest.raises(InternalSupervisorError):
            await client.create_vm(_spec(UNKNOWN_HASH, persistent=False))

        # Rootfs-disk validation: InvalidBackendError (INVALID_ARGUMENT +
        # the INVALID_BACKEND ErrorDetail trailer, which is what the client
        # keys the exception type on) with types.py's exact messages, before
        # any side effect.
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_spec(UNKNOWN_HASH, disks=[]))
        assert str(excinfo.value) == "CreateVmSpec has no ROOTFS disk"

        rootfs = DiskSpec(path=Path("/tmp/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_spec(UNKNOWN_HASH, disks=[rootfs, rootfs]))
        assert str(excinfo.value) == "CreateVmSpec has 2 ROOTFS disks, expected at most one"
        # No side effect: the rejected VM does not exist.
        with pytest.raises(VmNotFoundError):
            await client.get_vm(VmId(UNKNOWN_HASH))
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_mutations_on_unknown_vms_raise_vm_not_found(lifecycle_daemon):
    _, socket_path = lifecycle_daemon
    client = GrpcSupervisor(socket_path)
    vm_id = VmId(UNKNOWN_HASH)
    try:
        calls = [
            client.stop_vm(vm_id),
            client.start_vm(vm_id),
            client.reboot_vm(vm_id),
            client.delete_vm(vm_id),
            client.add_port_forward(
                PortForwardSpec(vm_id=vm_id, host_port=HostPort(0), vm_port=22, protocol=Protocol.TCP)
            ),
            client.remove_port_forward(vm_id, HostPort(24000), Protocol.TCP),
        ]
        for call in calls:
            with pytest.raises(VmNotFoundError) as excinfo:
                await call
            # Python's _abort(VmNotFoundError(vm_id)): the message is the id.
            assert str(excinfo.value) == UNKNOWN_HASH
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stop_vm_is_idempotent_on_an_adopted_stopped_vm(lifecycle_daemon):
    # VmExecution.stop() early-returns once stopped_at is set; an adopted
    # stopped VM answers STOPPED without touching systemd.
    _, socket_path = lifecycle_daemon
    client = GrpcSupervisor(socket_path)
    try:
        info = await client.stop_vm(VmId(STOPPED_HASH))
        assert info.status is VmStatus.STOPPED
        assert info.stopped_at_ns > 0
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_add_port_forward_without_nftables_base_chains_fails_like_python(lifecycle_daemon):
    # Unprivileged, the ruleset fetch yields nothing (the Python nftables
    # binding degrades the same way), so the DNAT rule build raises
    # NoBaseChainFound and the RPC aborts INTERNAL with its exact message.
    _, socket_path = lifecycle_daemon
    client = GrpcSupervisor(socket_path)
    try:
        with pytest.raises(InternalSupervisorError) as excinfo:
            await client.add_port_forward(
                PortForwardSpec(vm_id=VmId(STOPPED_HASH), host_port=HostPort(0), vm_port=22, protocol=Protocol.TCP)
            )
        assert str(excinfo.value) == "Could not find any base chain for hook 'prerouting'"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_delete_vm_sweeps_the_definition_and_soft_deletes_the_mappings(start_daemon, execution_root: Path):
    _seed_root(execution_root)
    extra_env = {"ALEPH_VM_ALLOW_VM_NETWORKING": "false"}

    with start_daemon(execution_root, extra_env) as (process, socket_path):
        client = GrpcSupervisor(socket_path)
        try:
            assert (await client.health()).vm_count == 2

            # Full delete: definition, seed and mappings go; storage is
            # never the daemon's to delete, so the data volume stays.
            await client.delete_vm(VmId(STOPPED_HASH))
            with pytest.raises(VmNotFoundError):
                await client.get_vm(VmId(STOPPED_HASH))
            assert not (execution_root / f"{STOPPED_HASH}-controller.json").exists()
            assert not (execution_root / f"cloud-init-{STOPPED_HASH}.img").exists()
            assert (execution_root / "volumes" / f"{STOPPED_HASH}-data.img").exists()

            # A second VM deleted the same way: both retire their port rows
            # (keep_port_mappings has its own test below) and both keep
            # their disks.
            await client.delete_vm(VmId(KEPT_HASH))
            assert (execution_root / "volumes" / f"{KEPT_HASH}-data.img").exists()
        finally:
            await client.close()

    # The store is read back through the actual SQLAlchemy models: both
    # deleted VMs' rows are soft-deleted with the SQLAlchemy datetime
    # rendering.
    (deleted_row,) = _rows(execution_root, STOPPED_HASH)
    assert deleted_row.deleted_at is not None
    (kept_row,) = _rows(execution_root, KEPT_HASH)
    assert kept_row.deleted_at is not None

    # A restarted daemon adopts neither VM: their definitions are gone.
    with start_daemon(execution_root, extra_env) as (process, socket_path):
        client = GrpcSupervisor(socket_path)
        try:
            assert (await client.health()).vm_count == 0
            assert await client.list_port_forwards() == []
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_delete_with_keep_port_mappings_preserves_the_rows(start_daemon, execution_root: Path):
    _seed_root(execution_root)
    with start_daemon(execution_root, {"ALEPH_VM_ALLOW_VM_NETWORKING": "false"}) as (process, socket_path):
        client = GrpcSupervisor(socket_path)
        try:
            # A delete+recreate cycle: the recreated VM must reload the same
            # host ports.
            await client.delete_vm(VmId(KEPT_HASH), keep_port_mappings=True)
        finally:
            await client.close()
    (row,) = _rows(execution_root, KEPT_HASH)
    assert row.deleted_at is None, "keep_port_mappings must preserve the persisted rows"
    assert row.host_port == 24501
