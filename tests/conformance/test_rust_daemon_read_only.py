"""Conformance for the Rust daemon's read-only world (increment 2).

Builds a fixture EXECUTION_ROOT with the actual Python models (pydantic
``Configuration`` serialized exactly like ``save_controller_configuration``,
the SQLAlchemy ``PortMapping`` schema for supervisor.sqlite3), boots the
compiled daemon on it and asserts the read-only RPCs through the production
Python client.

The oracle is model-predicted: the restarted Python daemon
(``load_persistent_executions``) only ever adopts VMs whose controller units
are ACTIVE, and no ``aleph-vm-controller@*.service`` unit exists for these
fixture hashes, so every VM must be reported STOPPED with no tap addresses
and no port forwards (a live in-process Python daemon comparison would need
root and real units; see docs/plans/rust-port-divergences.md entries 11-14
for where the stopped-VM reporting deliberately goes beyond Python, which
destroys such state at startup instead of reporting it). The VmSpec oracle
IS Python code: ``spec_from_controller_configuration``, the exact
reconstruction the restarted Python daemon serves from GetVmSpec.
"""

from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from aleph.vm.supervisor.networking_db import Base, PortMapping
from aleph.vm.supervisor.qemu_build import spec_from_controller_configuration
from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmStatus,
)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is not on PATH"),
]


def _fixture_hash(name: str) -> str:
    return hashlib.sha256(f"conformance-{name}".encode()).hexdigest()


QEMU_HASH = _fixture_hash("qemu")
GPU_HASH = _fixture_hash("gpu")
CONFIDENTIAL_HASH = _fixture_hash("confidential")
UNKNOWN_HASH = "0" * 64


def _qemu_vm_configuration(root: Path, vm_hash: str, **overrides) -> dict:
    base = {
        "qemu_bin_path": "/usr/bin/qemu-system-x86_64",
        "cloud_init_drive_path": str(root / f"cloud-init-{vm_hash}.img"),
        "image_path": str(root / "volumes/persistent" / vm_hash / "rootfs.qcow2"),
        "monitor_socket_path": root / f"{vm_hash}-monitor.socket",
        "qmp_socket_path": root / f"{vm_hash}-qmp.socket",
        "qga_socket_path": root / f"{vm_hash}-qga.socket",
        "vcpu_count": 4,
        "mem_size_mb": 4096,
        "interface_name": "vmtap3",
        "host_volumes": [],
        "gpus": [],
    }
    base.update(overrides)
    return base


def _build_configurations(root: Path) -> dict[str, Configuration]:
    settings_slice = ControllerSettings()
    session_dir = root / "confidential_sessions" / CONFIDENTIAL_HASH
    configurations = {
        QEMU_HASH: Configuration(
            vm_id=3,
            vm_hash=QEMU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **_qemu_vm_configuration(
                    root,
                    QEMU_HASH,
                    host_volumes=[
                        QemuVMHostVolume(
                            mount="",
                            path_on_host=root / "volumes/persistent" / QEMU_HASH / "data.qcow2",
                            read_only=False,
                        )
                    ],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
        GPU_HASH: Configuration(
            vm_id=4,
            vm_hash=GPU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **_qemu_vm_configuration(
                    root,
                    GPU_HASH,
                    interface_name="vmtap4",
                    gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
        CONFIDENTIAL_HASH: Configuration(
            vm_id=5,
            vm_hash=CONFIDENTIAL_HASH,
            settings=settings_slice,
            vm_configuration=QemuConfidentialVMConfiguration(
                **_qemu_vm_configuration(root, CONFIDENTIAL_HASH, interface_name="vmtap5"),
                ovmf_path=Path("/opt/aleph-vm/firmware/OVMF_CSV.fd"),
                sev_session_file=session_dir / "vm_session.b64",
                sev_dh_cert_file=session_dir / "vm_godh.b64",
                # NO_DBG only: no SEV-ES bit, so the reported mode is SEV
                # (the committed cargo fixture covers the SEV-ES branch).
                sev_policy=0x1,
            ),
            hypervisor=HypervisorType.qemu,
        ),
    }
    for vm_hash, configuration in configurations.items():
        # Exactly what save_controller_configuration writes.
        (root / f"{vm_hash}-controller.json").write_text(
            configuration.model_dump_json(by_alias=True, exclude_none=True, indent=4)
        )
    return configurations


def _build_database(root: Path) -> None:
    engine = create_engine(f"sqlite:///{root / 'supervisor.sqlite3'}")
    Base.metadata.create_all(engine)
    now = datetime.now(tz=timezone.utc)
    with Session(engine) as session:
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=22, host_port=24000, tcp=True, udp=False, created_at=now))
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=8080, host_port=24001, tcp=True, udp=True, created_at=now))
        session.commit()


@pytest.fixture
def adopted_daemon(start_daemon, tmp_path: Path):
    """The daemon booted on an EXECUTION_ROOT holding three model-written
    controller configs and a model-written port-mapping store."""
    configurations = _build_configurations(tmp_path)
    _build_database(tmp_path)
    with start_daemon(tmp_path) as (process, socket_path):
        yield configurations, socket_path


@pytest.mark.asyncio
async def test_the_adopted_world_reports_every_fixture_vm_stopped(adopted_daemon):
    configurations, socket_path = adopted_daemon
    client = GrpcSupervisor(socket_path)
    try:
        health = await client.health()
        assert health.vm_count == len(configurations)

        vms = await client.list_vms()
        assert [vm.vm_id for vm in vms] == sorted(configurations), "sorted-config adoption order"

        for vm in vms:
            # No aleph-vm-controller@{hash}.service exists for the fixture
            # hashes: every VM is adopted stopped.
            assert vm.status is VmStatus.STOPPED
            assert vm.backend is Backend.QEMU
            assert vm.uptime_secs == 0
            assert vm.numa_node is None
            assert vm.status_message == ""
            # A stopped VM has no tap: empty assignments, per the proto.
            assert vm.ipv4 == IpAssignment()
            assert vm.ipv6 == IpAssignment()
            assert vm.defined_at_ns > 0
            assert vm.stopped_at_ns > 0
            assert vm.preparing_at_ns == 0
            assert vm.prepared_at_ns == 0
            assert vm.starting_at_ns == 0
            assert vm.started_at_ns == 0
            assert vm.stopping_at_ns == 0
            # Python parity: adopted executions never rebuild their GPU list.
            assert vm.gpus == []
            assert vm.guest_channel_path == ""
            assert vm.guest_ready_payload == b""
            assert vm.awaiting_confidential_init is False

        by_id = {vm.vm_id: vm for vm in vms}
        assert by_id[QEMU_HASH].confidential_mode is ConfidentialMode.NONE
        assert by_id[GPU_HASH].confidential_mode is ConfidentialMode.NONE
        # sev_policy 0x1 carries no SEV-ES bit: precise mode is SEV.
        assert by_id[CONFIDENTIAL_HASH].confidential_mode is ConfidentialMode.SEV

        # GetVm agrees with the list entries field for field.
        for vm_hash, listed in by_id.items():
            assert await client.get_vm(VmId(vm_hash)) == listed
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_get_vm_spec_matches_the_python_reconstruction(adopted_daemon):
    configurations, socket_path = adopted_daemon
    client = GrpcSupervisor(socket_path)
    try:
        for vm_hash, configuration in configurations.items():
            # The exact spec the restarted Python daemon would serve:
            # execution.vm_spec = spec_from_controller_configuration(config).
            expected = spec_from_controller_configuration(configuration)
            assert await client.get_vm_spec(VmId(vm_hash)) == expected
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_unknown_vms_raise_vm_not_found(adopted_daemon):
    _, socket_path = adopted_daemon
    client = GrpcSupervisor(socket_path)
    try:
        for call in (client.get_vm, client.get_vm_spec, client.list_port_forwards):
            with pytest.raises(VmNotFoundError) as excinfo:
                await call(VmId(UNKNOWN_HASH))
            # Python's _abort(VmNotFoundError(vm_id)): the message is the id.
            assert str(excinfo.value) == UNKNOWN_HASH
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_stopped_vms_expose_no_port_forwards(adopted_daemon):
    # Python parity: mapped_ports is only rebuilt for VMs adopted running
    # (and a VM stopped through StopVm holds none either); the persisted
    # rows stay in the database for the next start.
    _, socket_path = adopted_daemon
    client = GrpcSupervisor(socket_path)
    try:
        assert await client.list_port_forwards() == []
        assert await client.list_port_forwards(VmId(QEMU_HASH)) == []
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("journalctl") is None, reason="journalctl is not on PATH")
async def test_get_logs_is_empty_for_units_that_never_logged(adopted_daemon):
    # Python parity: _history_chunks performs no existence check and an
    # identifier that never logged yields an empty history, for known and
    # unknown VMs alike.
    _, socket_path = adopted_daemon
    client = GrpcSupervisor(socket_path)
    try:
        assert await client.get_logs(VmId(QEMU_HASH)) == []
        assert await client.get_logs(VmId(UNKNOWN_HASH)) == []
    finally:
        await client.close()
