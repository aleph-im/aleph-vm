"""Tests for the directory-based migration ops (export_vm / import_vm /
get_migration_status) and the manifest module behind them."""

import asyncio
import dataclasses
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.supervisor import migrate
from aleph.vm.supervisor.errors import (
    InternalSupervisorError,
    InvalidBackendError,
    MigrationInProgressError,
    MigrationNotFoundError,
    NotImplementedSupervisorError,
    VmAlreadyExistsError,
    VmNotFoundError,
)
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    MigrationId,
    MigrationPhase,
    NetworkConfig,
    VmId,
)

VM_ID = VmId("deadbeef" * 8)


def make_spec(disks: list[DiskSpec]) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VM_ID,
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
        ssh_authorized_keys=["ssh-ed25519 AAAA test"],
        hostname="migrated-vm",
    )


def make_disk_files(tmp_path: Path) -> list[DiskSpec]:
    rootfs = tmp_path / "rootfs.raw"
    rootfs.write_bytes(b"rootfs-bytes" * 100)
    data = tmp_path / "data.raw"
    data.write_bytes(b"data-bytes" * 100)
    return [
        DiskSpec(path=rootfs, readonly=False, format=DiskFormat.RAW, role=DiskRole.ROOTFS),
        DiskSpec(path=data, readonly=False, format=DiskFormat.RAW, role=DiskRole.EXTRA),
    ]


def make_execution(*, spec, persistent=True, hypervisor=HypervisorType.qemu):
    return SimpleNamespace(
        vm_hash=str(VM_ID),
        persistent=persistent,
        systemd_manager=object(),
        is_program=False,
        is_instance=True,
        hypervisor=hypervisor,
        vm_spec=spec,
    )


class FakePool:
    def __init__(self, executions=None):
        self.executions = executions or {}


def make_supervisor(execution=None) -> InProcessSupervisor:
    executions = {str(VM_ID): execution} if execution is not None else {}
    sup = InProcessSupervisor(pool=FakePool(executions))
    sup.stop_vm = AsyncMock()
    sup.start_vm = AsyncMock()
    sup.create_vm = AsyncMock(return_value="vm-info-sentinel")
    return sup


async def wait_for_export(sup: InProcessSupervisor, vm_id: VmId) -> None:
    task = sup._migration_tasks.get(vm_id)
    if task is not None:
        await task


# ── Manifest module ──────────────────────────────────────────────────────────


def test_manifest_roundtrips_the_spec(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    disks = [migrate.ManifestDisk(name="disk0.raw", sha256="ab" * 32, size_bytes=10)]
    spec = dataclasses.replace(spec, disks=spec.disks[:1])

    migrate.write_manifest(tmp_path, spec, disks)
    loaded_spec, loaded_disks = migrate.read_manifest(tmp_path, VM_ID)

    assert loaded_disks == disks
    # Disk paths are source-host specific and rewritten at import; the
    # rest of the spec must roundtrip exactly.
    assert loaded_spec == spec


def test_read_manifest_missing_raises_migration_not_found(tmp_path):
    with pytest.raises(MigrationNotFoundError):
        migrate.read_manifest(tmp_path, VM_ID)


def test_read_manifest_rejects_other_vm(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    migrate.write_manifest(tmp_path, spec, [migrate.ManifestDisk("d", "0" * 64, 1)] * 2)
    with pytest.raises(InternalSupervisorError, match="not"):
        migrate.read_manifest(tmp_path, VmId("beef" * 16))


def test_read_manifest_rejects_unknown_format(tmp_path):
    (tmp_path / migrate.MANIFEST_NAME).write_text(json.dumps({"format": 99, "vm_id": str(VM_ID)}))
    with pytest.raises(InternalSupervisorError, match="format"):
        migrate.read_manifest(tmp_path, VM_ID)


def test_read_manifest_rejects_disk_count_mismatch(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    migrate.write_manifest(tmp_path, spec, [migrate.ManifestDisk("disk0.raw", "0" * 64, 1)])
    with pytest.raises(InternalSupervisorError, match="disk"):
        migrate.read_manifest(tmp_path, VM_ID)


# ── export_vm ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_unknown_vm(tmp_path):
    sup = make_supervisor()
    with pytest.raises(VmNotFoundError):
        await sup.export_vm(VM_ID, DirectoryPath(tmp_path))


@pytest.mark.asyncio
async def test_export_rejects_firecracker(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    sup = make_supervisor(make_execution(spec=spec, hypervisor=HypervisorType.firecracker))
    with pytest.raises(InvalidBackendError):
        await sup.export_vm(VM_ID, DirectoryPath(tmp_path))


@pytest.mark.asyncio
async def test_export_rejects_message_built_vms(tmp_path):
    sup = make_supervisor(make_execution(spec=None))
    with pytest.raises(NotImplementedSupervisorError):
        await sup.export_vm(VM_ID, DirectoryPath(tmp_path))


@pytest.mark.asyncio
async def test_export_writes_disks_and_manifest_and_stops_the_vm(tmp_path):
    """RAW disks are copied verbatim, the manifest matches them, progress
    reaches bytes_total and the phase ends COMPLETE with the VM stopped."""
    disks = make_disk_files(tmp_path)
    spec = make_spec(disks)
    sup = make_supervisor(make_execution(spec=spec))
    destination = tmp_path / "export"

    job = await sup.export_vm(VM_ID, DirectoryPath(destination))
    assert job.phase is MigrationPhase.PREPARING
    assert job.bytes_total == sum(d.path.stat().st_size for d in disks)

    await wait_for_export(sup, VM_ID)
    status = await sup.get_migration_status(VM_ID, job.migration_id)

    assert status.phase is MigrationPhase.COMPLETE
    assert status.bytes_transferred == job.bytes_total
    sup.stop_vm.assert_awaited_once_with(VM_ID)
    sup.start_vm.assert_not_awaited()

    exported_spec, manifest_disks = migrate.read_manifest(destination, VM_ID)
    assert exported_spec == spec
    for manifest_disk, disk in zip(manifest_disks, disks, strict=True):
        exported = destination / manifest_disk.name
        assert exported.read_bytes() == disk.path.read_bytes()
        assert manifest_disk.size_bytes == exported.stat().st_size


@pytest.mark.asyncio
async def test_export_failure_marks_failed_and_restarts_the_vm(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    sup = make_supervisor(make_execution(spec=spec))
    sup.stop_vm = AsyncMock(side_effect=RuntimeError("unit refused to stop"))

    job = await sup.export_vm(VM_ID, DirectoryPath(tmp_path / "export"))
    await wait_for_export(sup, VM_ID)
    status = await sup.get_migration_status(VM_ID, job.migration_id)

    assert status.phase is MigrationPhase.FAILED
    assert "unit refused to stop" in status.error_message
    sup.start_vm.assert_awaited_once_with(VM_ID)


@pytest.mark.asyncio
async def test_second_export_while_running_is_rejected(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    sup = make_supervisor(make_execution(spec=spec))
    release = asyncio.Event()

    async def slow_stop(_vm_id):
        await release.wait()

    sup.stop_vm = AsyncMock(side_effect=slow_stop)

    await sup.export_vm(VM_ID, DirectoryPath(tmp_path / "export"))
    try:
        with pytest.raises(MigrationInProgressError):
            await sup.export_vm(VM_ID, DirectoryPath(tmp_path / "export2"))
    finally:
        release.set()
        await wait_for_export(sup, VM_ID)


# ── import_vm ────────────────────────────────────────────────────────────────


async def _make_export(sup, tmp_path) -> Path:
    destination = tmp_path / "export"
    job = await sup.export_vm(VM_ID, DirectoryPath(destination))
    await wait_for_export(sup, VM_ID)
    status = await sup.get_migration_status(VM_ID, job.migration_id)
    assert status.phase is MigrationPhase.COMPLETE
    return destination


@pytest.mark.asyncio
async def test_import_recreates_the_vm_with_rewritten_disk_paths(tmp_path, mocker):
    disks = make_disk_files(tmp_path)
    spec = make_spec(disks)
    exporter = make_supervisor(make_execution(spec=spec))
    export_dir = await _make_export(exporter, tmp_path)

    volumes_root = tmp_path / "volumes"
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", volumes_root)

    importer = make_supervisor()
    result = await importer.import_vm(VM_ID, DirectoryPath(export_dir))

    assert result == "vm-info-sentinel"
    importer.create_vm.assert_awaited_once()
    imported_spec = importer.create_vm.await_args.args[0]
    assert imported_spec.vm_id == VM_ID
    assert imported_spec.hostname == spec.hostname
    for new_disk, old_disk in zip(imported_spec.disks, disks, strict=True):
        assert new_disk.path.parent == volumes_root / str(VM_ID)
        assert new_disk.path.read_bytes() == old_disk.path.read_bytes()
        assert new_disk.role == old_disk.role


@pytest.mark.asyncio
async def test_import_rejects_existing_vm_before_copying(tmp_path, mocker):
    disks = make_disk_files(tmp_path)
    exporter = make_supervisor(make_execution(spec=make_spec(disks)))
    export_dir = await _make_export(exporter, tmp_path)

    volumes_root = tmp_path / "volumes"
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", volumes_root)

    occupied = make_supervisor(make_execution(spec=make_spec(disks)))
    with pytest.raises(VmAlreadyExistsError):
        await occupied.import_vm(VM_ID, DirectoryPath(export_dir))
    assert not (volumes_root / str(VM_ID)).exists()


@pytest.mark.asyncio
async def test_import_rejects_corrupt_disk(tmp_path, mocker):
    disks = make_disk_files(tmp_path)
    exporter = make_supervisor(make_execution(spec=make_spec(disks)))
    export_dir = await _make_export(exporter, tmp_path)
    (export_dir / "disk0.raw").write_bytes(b"tampered")

    volumes_root = tmp_path / "volumes"
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", volumes_root)

    importer = make_supervisor()
    with pytest.raises(InternalSupervisorError, match="checksum"):
        await importer.import_vm(VM_ID, DirectoryPath(export_dir))
    importer.create_vm.assert_not_awaited()
    # The half-copied destination directory is cleaned up.
    assert not (volumes_root / str(VM_ID)).exists()


@pytest.mark.asyncio
async def test_import_from_empty_dir_raises_migration_not_found(tmp_path):
    importer = make_supervisor()
    with pytest.raises(MigrationNotFoundError):
        await importer.import_vm(VM_ID, DirectoryPath(tmp_path))


# ── get_migration_status ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_migration_status_unknown_id():
    sup = make_supervisor()
    with pytest.raises(MigrationNotFoundError):
        await sup.get_migration_status(VM_ID, MigrationId("nope"))


@pytest.mark.asyncio
async def test_get_migration_status_rejects_foreign_vm(tmp_path):
    spec = make_spec(make_disk_files(tmp_path))
    sup = make_supervisor(make_execution(spec=spec))
    job = await sup.export_vm(VM_ID, DirectoryPath(tmp_path / "export"))
    await wait_for_export(sup, VM_ID)

    with pytest.raises(MigrationNotFoundError):
        await sup.get_migration_status(VmId("beef" * 16), job.migration_id)
