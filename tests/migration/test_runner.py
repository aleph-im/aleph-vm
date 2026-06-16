"""Tests for the export and import background runners."""

import asyncio
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, MessageType
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.migration.jobs import ExportJob, _reset_migration_semaphore_for_tests
from aleph.vm.migration.runner import run_export
from aleph.vm.models import MigrationState
from aleph.vm.supervisor.errors import VmNotFoundError


@pytest.fixture(autouse=True)
def _reset_semaphore():
    _reset_migration_semaphore_for_tests()
    yield
    _reset_migration_semaphore_for_tests()


def _export_supervisor(volumes_dir: Path, *, missing: bool = False):
    """A fake supervisor for the export runner: stop_vm_for_export returns the
    given volumes dir, restart_after_failed_export records the call."""
    sup = MagicMock()
    if missing:
        sup.stop_vm_for_export = AsyncMock(side_effect=VmNotFoundError("nope"))
    else:
        sup.stop_vm_for_export = AsyncMock(return_value=volumes_dir)
    sup.restart_after_failed_export = AsyncMock()
    return sup


def _import_supervisor(*, has_vm: bool = False, create_side_effect=None):
    """A fake supervisor for the import runner."""
    sup = MagicMock()
    sup.create_migrated_vm = AsyncMock(side_effect=create_side_effect, return_value=MagicMock())
    if has_vm:
        sup.get_vm = AsyncMock(return_value=MagicMock())
    else:
        sup.get_vm = AsyncMock(side_effect=VmNotFoundError("absent"))
    return sup


@pytest.mark.asyncio
async def testrun_export_success(tmp_path, monkeypatch):
    """Happy path: graceful shutdown succeeds, two qcow2 disks compress, state ends in EXPORTED."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    volumes_dir = tmp_path / str(vm_hash)
    volumes_dir.mkdir(parents=True)
    (volumes_dir / "rootfs.qcow2").write_bytes(b"x" * 1024)
    (volumes_dir / "data.qcow2").write_bytes(b"y" * 2048)

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    async def fake_compress(src: Path, dst: Path):
        dst.write_bytes(b"compressed")

    monkeypatch.setattr("aleph.vm.migration.runner.compress_disk", fake_compress)

    supervisor = _export_supervisor(volumes_dir)
    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    await run_export(job, supervisor)

    supervisor.stop_vm_for_export.assert_awaited_once_with(vm_hash)
    assert job.state == MigrationState.EXPORTED
    assert job.finished_at is not None
    assert job.error is None
    assert job.token is not None and len(job.token) > 16
    assert job.disk_files is not None and len(job.disk_files) == 2
    assert {df.name for df in job.disk_files} == {"rootfs.qcow2", "data.qcow2"}
    assert all(Path(p).exists() for p in job.export_paths)
    # Each disk file carries a SHA-256 of the compressed export.
    expected = hashlib.sha256(b"compressed").hexdigest()
    assert all(df.sha256 == expected for df in job.disk_files)


@pytest.mark.asyncio
async def testrun_export_compression_failure(tmp_path, monkeypatch):
    """If compress_disk raises on any file, state goes to EXPORT_FAILED and partial exports are deleted."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    volumes_dir = tmp_path / str(vm_hash)
    volumes_dir.mkdir(parents=True)
    (volumes_dir / "rootfs.qcow2").write_bytes(b"x")
    (volumes_dir / "data.qcow2").write_bytes(b"y")

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    calls = {"n": 0}

    async def flaky_compress(src: Path, dst: Path):
        calls["n"] += 1
        if calls["n"] == 1:
            dst.write_bytes(b"first")
        else:
            raise RuntimeError("boom")

    monkeypatch.setattr("aleph.vm.migration.runner.compress_disk", flaky_compress)

    supervisor = _export_supervisor(volumes_dir)
    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    await run_export(job, supervisor)

    assert job.state == MigrationState.EXPORT_FAILED
    assert "boom" in job.error
    # No partial export files should remain.
    assert list(volumes_dir.glob("*.export.qcow2")) == []
    # VM restart attempted through the supervisor.
    supervisor.restart_after_failed_export.assert_awaited_once_with(vm_hash)


from aleph.vm.migration.jobs import ImportJob


@pytest.mark.asyncio
async def testrun_import_success(tmp_path, monkeypatch):
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    # Simulate a parent image already cached.
    parent_path = tmp_path / "parent.qcow2"
    parent_path.write_bytes(b"parent")

    fake_message = MagicMock()
    fake_message.type = MessageType.instance
    fake_message.content.environment.hypervisor = HypervisorType.qemu
    fake_message.content.environment.trusted_execution = None
    fake_message.content.rootfs.parent.ref = "parentref"

    async def fake_load_message(_hash):
        return (fake_message, fake_message)

    async def fake_get_rootfs_base_path(_ref):
        return parent_path

    async def fake_detect_format(_path):
        return "qcow2"

    async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"downloaded")
        if on_chunk is not None:
            on_chunk(10)
        return 10

    async def fake_rebase(overlay, parent, fmt):
        return None

    supervisor = _import_supervisor()

    monkeypatch.setattr("aleph.vm.migration.runner.load_updated_message", fake_load_message)
    monkeypatch.setattr("aleph.vm.migration.runner.get_rootfs_base_path", fake_get_rootfs_base_path)
    monkeypatch.setattr("aleph.vm.migration.runner.detect_parent_format", fake_detect_format)
    monkeypatch.setattr("aleph.vm.migration.runner.download_disk_from_source", fake_download)
    monkeypatch.setattr("aleph.vm.migration.runner.rebase_overlay", fake_rebase)

    from aleph.vm.migration.jobs import DiskFileInfo
    from aleph.vm.migration.runner import run_import

    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src.example",
        source_port=443,
    )
    disk_files = [
        DiskFileInfo(
            name="rootfs.qcow2",
            size_bytes=10,
            sha256="0" * 64,
            download_path=f"/control/machine/{vm_hash}/migration/disk/rootfs.qcow2",
        )
    ]

    await run_import(job, supervisor, disk_files=disk_files, export_token="t0k3n")

    assert job.state == MigrationState.IMPORTED
    assert job.error is None
    assert job.bytes_downloaded == 10
    assert job.transfer_time_ms is not None
    supervisor.create_migrated_vm.assert_awaited_once()


@pytest.mark.asyncio
async def testrun_import_aborts_when_message_not_instance(tmp_path, monkeypatch):
    """If the fetched message isn't an instance, state ends in IMPORT_FAILED."""
    from aleph.vm.migration.jobs import DiskFileInfo, ImportJob
    from aleph.vm.migration.runner import run_import

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    fake_message = MagicMock()
    fake_message.type = MessageType.program  # NOT instance
    fake_message.content.environment.hypervisor = HypervisorType.qemu
    fake_message.content.environment.trusted_execution = None

    monkeypatch.setattr(
        "aleph.vm.migration.runner.load_updated_message",
        AsyncMock(return_value=(fake_message, fake_message)),
    )

    supervisor = _import_supervisor()
    job = ImportJob(
        vm_hash=ItemHash(settings.FAKE_INSTANCE_ID),
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src",
        source_port=443,
    )
    await run_import(
        job,
        supervisor,
        disk_files=[DiskFileInfo(name="rootfs.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
        export_token="t",
    )

    assert job.state == MigrationState.IMPORT_FAILED
    assert "not an instance" in job.error.lower()


@pytest.mark.asyncio
async def testrun_import_cleans_dest_dir_on_download_failure(tmp_path, monkeypatch):
    """If download_disk_from_source raises, dest_dir is rmtree'd."""
    from aleph.vm.migration.jobs import DiskFileInfo, ImportJob
    from aleph.vm.migration.runner import run_import

    parent_path = tmp_path / "parent.qcow2"
    parent_path.write_bytes(b"parent")
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    fake_message = MagicMock()
    fake_message.type = MessageType.instance
    fake_message.content.environment.hypervisor = HypervisorType.qemu
    fake_message.content.environment.trusted_execution = None
    fake_message.content.rootfs.parent.ref = "p"

    async def boom_download(*args, **kwargs):
        raise RuntimeError("network exploded")

    monkeypatch.setattr(
        "aleph.vm.migration.runner.load_updated_message",
        AsyncMock(return_value=(fake_message, fake_message)),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.get_rootfs_base_path",
        AsyncMock(return_value=parent_path),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.detect_parent_format",
        AsyncMock(return_value="qcow2"),
    )
    monkeypatch.setattr("aleph.vm.migration.runner.download_disk_from_source", boom_download)

    supervisor = _import_supervisor(has_vm=False)
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src",
        source_port=443,
    )
    await run_import(
        job,
        supervisor,
        disk_files=[DiskFileInfo(name="rootfs.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
        export_token="t",
    )

    assert job.state == MigrationState.IMPORT_FAILED
    assert "network exploded" in job.error
    # dest_dir should have been rmtree'd
    assert not (tmp_path / str(vm_hash)).exists()


@pytest.mark.asyncio
async def testrun_import_cleans_dest_dir_on_create_a_vm_failure(tmp_path, monkeypatch):
    """If pool.create_a_vm raises, dest_dir is rmtree'd."""
    from aleph.vm.migration.jobs import DiskFileInfo, ImportJob
    from aleph.vm.migration.runner import run_import

    parent_path = tmp_path / "parent.qcow2"
    parent_path.write_bytes(b"parent")
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    fake_message = MagicMock()
    fake_message.type = MessageType.instance
    fake_message.content.environment.hypervisor = HypervisorType.qemu
    fake_message.content.environment.trusted_execution = None
    fake_message.content.rootfs.parent.ref = "p"

    async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"x")
        return 1

    monkeypatch.setattr(
        "aleph.vm.migration.runner.load_updated_message",
        AsyncMock(return_value=(fake_message, fake_message)),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.get_rootfs_base_path",
        AsyncMock(return_value=parent_path),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.detect_parent_format",
        AsyncMock(return_value="qcow2"),
    )
    monkeypatch.setattr("aleph.vm.migration.runner.download_disk_from_source", fake_download)
    monkeypatch.setattr("aleph.vm.migration.runner.rebase_overlay", AsyncMock())

    supervisor = _import_supervisor(has_vm=False, create_side_effect=RuntimeError("pool kaboom"))

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src",
        source_port=443,
    )
    await run_import(
        job,
        supervisor,
        disk_files=[DiskFileInfo(name="rootfs.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
        export_token="t",
    )

    assert job.state == MigrationState.IMPORT_FAILED
    assert "pool kaboom" in job.error
    assert not (tmp_path / str(vm_hash)).exists()


@pytest.mark.asyncio
async def testrun_import_keeps_dest_dir_when_supervisor_already_has_vm(tmp_path, monkeypatch):
    """Defence-in-depth: if the supervisor already reports a VM for this hash,
    do NOT rmtree the dest dir on failure."""
    from aleph.vm.migration.jobs import DiskFileInfo, ImportJob
    from aleph.vm.migration.runner import run_import

    parent_path = tmp_path / "parent.qcow2"
    parent_path.write_bytes(b"parent")
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    fake_message = MagicMock()
    fake_message.type = MessageType.instance
    fake_message.content.environment.hypervisor = HypervisorType.qemu
    fake_message.content.environment.trusted_execution = None
    fake_message.content.rootfs.parent.ref = "p"

    async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        dest_path.write_bytes(b"x")
        return 1

    monkeypatch.setattr(
        "aleph.vm.migration.runner.load_updated_message",
        AsyncMock(return_value=(fake_message, fake_message)),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.get_rootfs_base_path",
        AsyncMock(return_value=parent_path),
    )
    monkeypatch.setattr(
        "aleph.vm.migration.runner.detect_parent_format",
        AsyncMock(return_value="qcow2"),
    )
    monkeypatch.setattr("aleph.vm.migration.runner.download_disk_from_source", fake_download)
    monkeypatch.setattr(
        "aleph.vm.migration.runner.rebase_overlay",
        AsyncMock(side_effect=RuntimeError("rebase failed")),
    )

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    supervisor = _import_supervisor(has_vm=True)  # supervisor ALREADY reports it

    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="src",
        source_port=443,
    )
    await run_import(
        job,
        supervisor,
        disk_files=[DiskFileInfo(name="rootfs.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
        export_token="t",
    )

    assert job.state == MigrationState.IMPORT_FAILED
    # Dest dir survives because the supervisor already reports a VM for this hash
    assert (tmp_path / str(vm_hash)).exists()


@pytest.mark.asyncio
async def test_semaphore_serialises_two_exports(tmp_path, monkeypatch):
    """With MAX_CONCURRENT_MIGRATIONS=1, two concurrent run_export calls must run sequentially."""
    from aleph.vm.migration.jobs import ExportJob, _reset_migration_semaphore_for_tests
    from aleph.vm.migration.runner import run_export

    monkeypatch.setattr(settings, "MAX_CONCURRENT_MIGRATIONS", 1)
    _reset_migration_semaphore_for_tests()

    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    # Use two distinct vm_hashes by simulating different content
    hash_a = ItemHash(settings.FAKE_INSTANCE_ID)
    # Construct a different valid hash by toggling a hex char
    hex_b = settings.FAKE_INSTANCE_ID
    hash_b = ItemHash(hex_b[:-1] + ("0" if hex_b[-1] != "0" else "1"))

    for h in (hash_a, hash_b):
        d = tmp_path / str(h)
        d.mkdir()
        (d / "rootfs.qcow2").write_bytes(b"x")

    in_flight = 0
    max_in_flight = 0

    async def slow_compress(src, dst):
        nonlocal in_flight, max_in_flight
        in_flight += 1
        max_in_flight = max(max_in_flight, in_flight)
        await asyncio.sleep(0.05)  # let the other coro try to enter
        dst.write_bytes(b"c")
        in_flight -= 1

    monkeypatch.setattr("aleph.vm.migration.runner.compress_disk", slow_compress)

    sup_a = _export_supervisor(tmp_path / str(hash_a))
    sup_b = _export_supervisor(tmp_path / str(hash_b))

    job_a = ExportJob(vm_hash=hash_a, state=MigrationState.EXPORTING, started_at=datetime.now(timezone.utc))
    job_b = ExportJob(vm_hash=hash_b, state=MigrationState.EXPORTING, started_at=datetime.now(timezone.utc))

    await asyncio.gather(run_export(job_a, sup_a), run_export(job_b, sup_b))

    assert max_in_flight == 1, f"Expected serial execution, but {max_in_flight} ran in parallel"
    assert job_a.state == MigrationState.EXPORTED
    assert job_b.state == MigrationState.EXPORTED


@pytest.mark.asyncio
async def test_download_disk_verifies_sha256(tmp_path):
    """download_disk_from_source raises and unlinks the partial file when sha256 mismatches."""
    from aleph.vm.migration.helpers import download_disk_from_source

    payload = b"hello world"
    correct = hashlib.sha256(payload).hexdigest()

    class FakeResponse:
        status = 200

        def __init__(self, body):
            self._body = body

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        @property
        def content(self):
            class _Content:
                @staticmethod
                async def iter_chunked(_size):
                    for chunk in (b"hello ", b"world"):
                        yield chunk

            return _Content()

        async def text(self):
            return ""

    class FakeSession:
        def get(self, _url, params=None):
            return FakeResponse(payload)

    dest = tmp_path / "rootfs.qcow2"

    # Happy path: matching hash, file lands at dest_path.
    n = await download_disk_from_source(FakeSession(), "http://x", dest, "tok", expected_sha256=correct)
    assert n == len(payload)
    assert dest.read_bytes() == payload

    # Bad hash: file is unlinked, RuntimeError raised, dest is gone.
    dest.unlink()
    with pytest.raises(RuntimeError, match="sha256 mismatch"):
        await download_disk_from_source(FakeSession(), "http://x", dest, "tok", expected_sha256="f" * 64)
    assert not dest.exists()
    assert not dest.with_suffix(dest.suffix + ".part").exists()


@pytest.mark.asyncio
async def test_export_ttl_removes_files_and_forgets_job(tmp_path, monkeypatch):
    """After TTL expires, export files are deleted and the job is removed from the registry."""
    from aleph.vm.migration.jobs import ExportJob, export_jobs
    from aleph.vm.migration.runner import schedule_export_ttl

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    export_paths = [tmp_path / "fake.export.qcow2"]
    export_paths[0].write_bytes(b"orphan")

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTED,
        started_at=datetime.now(timezone.utc),
        export_paths=export_paths,
    )
    export_jobs[vm_hash] = job

    schedule_export_ttl(job, timeout=0)  # fire immediately
    await asyncio.sleep(0.05)  # let the task run

    assert vm_hash not in export_jobs
    assert not export_paths[0].exists()

    export_jobs.clear()
