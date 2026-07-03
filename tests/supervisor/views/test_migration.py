"""Tests for cold (stop/start) migration endpoints."""

import asyncio
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.conf import settings
from aleph.vm.models import MigrationState
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)


def _vm_info(
    vm_id,
    status: VmStatus = VmStatus.RUNNING,
    backend: Backend = Backend.QEMU,
    confidential_mode: ConfidentialMode = ConfidentialMode.NONE,
) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(vm_id)),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=backend,
        numa_node=None,
        status_message="",
        confidential_mode=confidential_mode,
    )


def _migration_supervisor(get_vm=None, **overrides):
    """A MagicMock supervisor wired with the migration-relevant methods.

    get_vm defaults to raising VmNotFoundError (no VM present); pass an
    AsyncMock to model a present VM. Override any method via keyword.
    """
    sup = MagicMock()
    sup.get_vm = get_vm if get_vm is not None else AsyncMock(side_effect=VmNotFoundError("absent"))
    # The export stop rides the standard stop_vm RPC; the runner derives the
    # volumes dir from settings.PERSISTENT_VOLUMES_DIR itself.
    sup.stop_vm = AsyncMock()
    sup.start_vm = AsyncMock()
    sup.create_vm = AsyncMock(return_value=MagicMock())
    sup.delete_vm = AsyncMock()
    for name, value in overrides.items():
        setattr(sup, name, value)
    return sup


@pytest.fixture(autouse=True)
def _clear_migration_registries():
    from aleph.vm.agent.migration.jobs import export_jobs, import_jobs

    export_jobs.clear()
    import_jobs.clear()
    yield
    export_jobs.clear()
    import_jobs.clear()


@pytest.fixture
def mock_vm_hash():
    """Return a valid VM hash for testing."""
    return ItemHash(settings.FAKE_INSTANCE_ID)


@pytest.fixture
def mock_scheduler_auth(mocker):
    """Mock the scheduler authentication to always pass.

    The migration handlers wrap themselves with @requires_allocation_auth, which
    looks up authenticate_api_request in its own module
    (aleph.vm.agent.views.allocation_auth) — patch there.
    """
    mocker.patch(
        "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
        new_callable=AsyncMock,
        return_value=True,
    )


async def wait_for_export_state(client: TestClient, vm_hash, target_state: str, timeout: float = 5.0):
    """Poll /export/status until job.state == target_state or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        r = await client.get(f"/control/machine/{vm_hash}/migration/export/status")
        if r.status == HTTPStatus.OK:
            data = await r.json()
            if data["state"] == target_state:
                return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"export job did not reach {target_state} within {timeout}s")


async def wait_for_import_state(client: TestClient, vm_hash, target_state: str, timeout: float = 5.0):
    """Poll /control/migrate/{vm_hash}/status until job.state == target_state or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        r = await client.get(f"/control/migrate/{vm_hash}/status")
        if r.status == HTTPStatus.OK:
            data = await r.json()
            if data["state"] == target_state:
                return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"import job did not reach {target_state} within {timeout}s")


class TestMigrationExportEndpoint:
    """Tests for POST /control/machine/{ref}/migration/export."""

    @pytest.mark.asyncio
    async def test_export_unauthorized(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that unauthorized requests are rejected."""
        mocker.patch(
            "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
            new_callable=AsyncMock,
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_export_vm_not_found(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails if VM not found."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_export_vm_not_running(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails if VM is not running."""
        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash, status=VmStatus.STOPPED))
        )
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "not running" in data["error"]

    @pytest.mark.asyncio
    async def test_export_not_qemu(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails for non-QEMU VMs."""
        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash, backend=Backend.FIRECRACKER))
        )
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "QEMU" in data["error"]

    @pytest.mark.asyncio
    async def test_export_confidential_rejected(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export rejects confidential VMs."""
        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash, confidential_mode=ConfidentialMode.SEV))
        )
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "confidential" in data["error"]

    @pytest.mark.asyncio
    async def test_export_already_completed_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        """Test that POST /export returns 409 when a terminal-state job already exists."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
        )

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash)))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.CONFLICT

    @pytest.mark.asyncio
    async def test_export_returns_202_and_completes(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """Test successful export: POST returns 202, polling reaches EXPORTED."""

        async def fake_compress(src, dst):
            dst.write_bytes(b"compressed")

        mocker.patch("aleph.vm.agent.migration.runner.compress_disk", fake_compress)

        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash)),
        )
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r.status == HTTPStatus.ACCEPTED
        body = await r.json()
        assert body["state"] == "exporting"
        assert "status" not in body
        assert body["status_url"].endswith("/migration/export/status")

        data = await wait_for_export_state(client, mock_vm_hash, "exported")
        assert data["disk_files"] is not None
        assert data["export_token"]


class TestMigrationDiskDownloadEndpoint:
    """Tests for GET /control/machine/{ref}/migration/disk/{filename}."""

    @pytest.mark.asyncio
    async def test_download_no_export_state(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that download fails when no export job exists."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=invalid")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_download_invalid_token(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download fails with invalid token."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            token="correct-token",
            volumes_dir=tmp_path,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=wrong-token")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_download_file_not_found(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download returns 404 for missing file."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            token="test-token",
            volumes_dir=tmp_path,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.get(
            f"/control/machine/{mock_vm_hash}/migration/disk/nonexistent.qcow2?token=test-token"
        )
        assert response.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_download_success(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test successful file download."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        # The handler reads from `{volumes_dir}/{filename}.export.qcow2`
        export_file = tmp_path / "rootfs.qcow2.export.qcow2"
        export_file.write_bytes(b"compressed qcow2 data")

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            token="test-token",
            volumes_dir=tmp_path,
            export_paths=[export_file],
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=test-token")
        assert response.status == HTTPStatus.OK
        body = await response.read()
        assert body == b"compressed qcow2 data"


class TestMigrationImportEndpoint:
    """Tests for POST /control/migrate."""

    @pytest.mark.asyncio
    async def test_import_unauthorized(self, aiohttp_client, mocker):
        """Test that unauthorized requests are rejected."""
        mocker.patch(
            "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
            new_callable=AsyncMock,
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={
                "vm_hash": "a" * 64,
                "source_host": "source.example.com",
                "export_token": "token",
                "disk_files": [],
            },
        )
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_import_invalid_request(self, aiohttp_client, mocker, mock_scheduler_auth):
        """Test that invalid request body is rejected."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post("/control/migrate", json={"vm_hash": "a" * 64})
        assert response.status == HTTPStatus.BAD_REQUEST

    @pytest.mark.asyncio
    async def test_import_vm_already_running(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that import fails if VM already running on host."""
        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash)))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={
                "vm_hash": str(mock_vm_hash),
                "source_host": "source.example.com",
                "export_token": "token",
                "disk_files": [
                    {
                        "name": "rootfs.qcow2",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                        "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                    }
                ],
            },
        )
        assert response.status == HTTPStatus.CONFLICT

    @pytest.mark.asyncio
    async def test_import_not_instance(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Wrong message type is now reported via the import status endpoint (async)."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.program

        mocker.patch(
            "aleph.vm.agent.migration.runner.load_updated_message",
            AsyncMock(return_value=(mock_message, mock_message)),
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={
                "vm_hash": str(mock_vm_hash),
                "source_host": "source.example.com",
                "export_token": "token",
                "disk_files": [
                    {
                        "name": "rootfs.qcow2",
                        "size_bytes": 1,
                        "sha256": "0" * 64,
                        "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                    }
                ],
            },
        )
        assert response.status == HTTPStatus.ACCEPTED

        data = await wait_for_import_state(client, mock_vm_hash, "import_failed")
        assert "not an instance" in data["error"]

    @pytest.mark.asyncio
    async def test_import_returns_202_and_completes(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        from aleph_message.models import MessageType
        from aleph_message.models.execution.environment import HypervisorType

        # Patch every external call inside _run_import.
        fake_message = mocker.Mock()
        fake_message.type = MessageType.instance
        fake_message.content.environment.hypervisor = HypervisorType.qemu
        fake_message.content.environment.trusted_execution = None
        fake_message.content.rootfs.parent.ref = "parent"

        mocker.patch(
            "aleph.vm.agent.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.agent.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.agent.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.agent.migration.runner.rebase_overlay", AsyncMock())
        mocker.patch(
            "aleph.vm.agent.migration.runner.build_create_vm_spec",
            AsyncMock(return_value=mocker.Mock(vm_id=VmId(str(mock_vm_hash)))),
        )
        # Post-create tail (wait-until-running + port forwards) is covered in the
        # runner unit tests; stub it so the endpoint test's fake supervisor need
        # not report RUNNING for the migrated VM.
        mocker.patch("aleph.vm.agent.migration.runner.finish_instance_create", AsyncMock())

        async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            if on_chunk:
                on_chunk(1)
            return 1

        mocker.patch("aleph.vm.agent.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        supervisor = _migration_supervisor()
        app["supervisor"] = supervisor
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src.example",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [
                {
                    "name": "rootfs.qcow2",
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                    "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                }
            ],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.ACCEPTED

        data = await wait_for_import_state(client, mock_vm_hash, "imported")
        assert data["transfer_time_ms"] is not None
        # Import creates the VM through the standard create_vm RPC.
        supervisor.create_vm.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_second_post_returns_existing_import_job(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """Two POSTs while a job is IMPORTING return 202 referencing the same job."""
        from aleph_message.models import MessageType
        from aleph_message.models.execution.environment import HypervisorType

        # Make the import hang in the disk-download step.
        slow = asyncio.Event()

        async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
            await slow.wait()
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            return 1

        fake_message = mocker.Mock()
        fake_message.type = MessageType.instance
        fake_message.content.environment.hypervisor = HypervisorType.qemu
        fake_message.content.environment.trusted_execution = None
        fake_message.content.rootfs.parent.ref = "parent"

        mocker.patch(
            "aleph.vm.agent.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.agent.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.agent.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.agent.migration.runner.rebase_overlay", AsyncMock())
        mocker.patch("aleph.vm.agent.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor()
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src.example",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [
                {
                    "name": "rootfs.qcow2",
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                    "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                }
            ],
        }
        r1 = await client.post("/control/migrate", json=body)
        assert r1.status == HTTPStatus.ACCEPTED
        r2 = await client.post("/control/migrate", json=body)
        assert r2.status == HTTPStatus.ACCEPTED

        d1, d2 = await r1.json(), await r2.json()
        assert d1["started_at"] == d2["started_at"]

        slow.set()
        await asyncio.sleep(0.1)

    @pytest.mark.asyncio
    async def test_post_against_imported_returns_409(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ImportJob, import_jobs

        import_jobs[mock_vm_hash] = ImportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.IMPORTED,
            started_at=datetime.now(timezone.utc),
            source_host="src",
            source_port=443,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [{"name": "rootfs.qcow2", "size_bytes": 1, "sha256": "0" * 64, "download_path": "/x"}],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.CONFLICT


class TestMigrationStatusEndpoints:
    @pytest.mark.asyncio
    async def test_export_status_404_for_unknown_vm_hash(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)
        r = await client.get(f"/control/machine/{mock_vm_hash}/migration/export/status")
        assert r.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_import_status_404_for_unknown_vm_hash(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)
        r = await client.get(f"/control/migrate/{mock_vm_hash}/status")
        assert r.status == HTTPStatus.NOT_FOUND


class TestMigrationCleanupEndpoint:
    """Tests for POST /control/machine/{ref}/migration/cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_unauthorized(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that unauthorized requests are rejected."""
        mocker.patch(
            "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
            new_callable=AsyncMock,
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_cleanup_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test successful cleanup when an EXPORTED job is present."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
        )

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        supervisor = _migration_supervisor()
        app["supervisor"] = supervisor
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "completed"
        # Cleanup drops the migrated-away source through the standard delete_vm
        # RPC (wipe=False: the destination owns the disks now).
        supervisor.delete_vm.assert_awaited_once_with(VmId(str(mock_vm_hash)), wipe=False)


class TestMigrationState:
    """Tests for updated MigrationState enum."""

    def test_migration_state_values(self):
        """Test that all migration states have correct values."""
        assert MigrationState.NONE.value == "none"
        assert MigrationState.EXPORTING.value == "exporting"
        assert MigrationState.EXPORTED.value == "exported"
        assert MigrationState.EXPORT_FAILED.value == "export_failed"
        assert MigrationState.IMPORTING.value == "importing"
        assert MigrationState.IMPORTED.value == "imported"
        assert MigrationState.IMPORT_FAILED.value == "import_failed"

    def test_migration_state_is_string_enum(self):
        """Test that MigrationState is a string enum."""
        assert isinstance(MigrationState.NONE, str)

    def test_old_states_removed(self):
        """Test that old live migration states are removed."""
        assert not hasattr(MigrationState, "PREPARING")
        assert not hasattr(MigrationState, "WAITING")
        assert not hasattr(MigrationState, "MIGRATING")
        assert not hasattr(MigrationState, "COMPLETED")
        assert not hasattr(MigrationState, "FAILED")


class TestMigrationExportIdempotency:
    @pytest.mark.asyncio
    async def test_second_post_returns_existing_job(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """Two POSTs while a job is EXPORTING return 202 referencing the same job."""
        # Make compress_disk hang so the job stays in EXPORTING.
        slow = asyncio.Event()

        async def fake_compress(src, dst):
            await slow.wait()
            dst.write_bytes(b"x")

        mocker.patch("aleph.vm.agent.migration.runner.compress_disk", fake_compress)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

        # Pre-create the volumes dir so the runner finds disk files to compress.
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True, exist_ok=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash)),
        )
        client: TestClient = await aiohttp_client(app)

        r1 = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r1.status == HTTPStatus.ACCEPTED

        r2 = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r2.status == HTTPStatus.ACCEPTED

        d1, d2 = await r1.json(), await r2.json()
        assert d1["started_at"] == d2["started_at"]  # same job

        # Let the job finish so the test cleans up.
        slow.set()
        # Give the runner a tick to complete.
        await asyncio.sleep(0.1)


class TestMigrationFailedReset:
    @pytest.mark.asyncio
    async def test_export_post_after_failed_resets_and_restarts(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """POST against an EXPORT_FAILED slot clears partial files and starts a fresh job."""
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs

        partial = tmp_path / "rootfs.qcow2.export.qcow2"
        partial.write_bytes(b"partial")

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORT_FAILED,
            started_at=datetime.now(timezone.utc),
            error="boom",
            export_paths=[partial],
        )

        async def fake_compress(src, dst):
            dst.write_bytes(b"compressed")

        mocker.patch("aleph.vm.agent.migration.runner.compress_disk", fake_compress)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor(
            get_vm=AsyncMock(return_value=_vm_info(mock_vm_hash)),
        )
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert r.status == HTTPStatus.ACCEPTED
        body = await r.json()
        # Descriptor reports the freshly-created job (state == EXPORTING) without the prior error.
        assert body["state"] == "exporting"
        assert "error" not in body
        # Partial file from the previous failed attempt has been deleted.
        assert not partial.exists()

        await wait_for_export_state(client, mock_vm_hash, "exported")

    @pytest.mark.asyncio
    async def test_import_post_after_failed_resets_and_restarts(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """POST against an IMPORT_FAILED slot rmtrees dest_dir and starts a fresh job."""
        from datetime import datetime, timezone

        from aleph_message.models import MessageType
        from aleph_message.models.execution.environment import HypervisorType

        from aleph.vm.agent.migration.jobs import ImportJob, import_jobs

        prior_dest = tmp_path / "prior_dest"
        prior_dest.mkdir()
        (prior_dest / "junk").write_bytes(b"junk")

        import_jobs[mock_vm_hash] = ImportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.IMPORT_FAILED,
            started_at=datetime.now(timezone.utc),
            source_host="src",
            source_port=443,
            error="prior failure",
            dest_dir=prior_dest,
        )

        fake_message = mocker.Mock()
        fake_message.type = MessageType.instance
        fake_message.content.environment.hypervisor = HypervisorType.qemu
        fake_message.content.environment.trusted_execution = None
        fake_message.content.rootfs.parent.ref = "parent"

        mocker.patch(
            "aleph.vm.agent.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.agent.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.agent.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.agent.migration.runner.rebase_overlay", AsyncMock())
        mocker.patch(
            "aleph.vm.agent.migration.runner.build_create_vm_spec",
            AsyncMock(return_value=mocker.Mock(vm_id=VmId(str(mock_vm_hash)))),
        )
        mocker.patch("aleph.vm.agent.migration.runner.finish_instance_create", AsyncMock())

        async def fake_download(session, url, dest_path, token, *, expected_sha256, on_chunk=None):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            if on_chunk:
                on_chunk(1)
            return 1

        mocker.patch("aleph.vm.agent.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        app = setup_webapp(supervisor=LocalSupervisor(mocker.Mock(executions={})))
        app["supervisor"] = _migration_supervisor()
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src.example",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [
                {
                    "name": "rootfs.qcow2",
                    "size_bytes": 1,
                    "sha256": "0" * 64,
                    "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                }
            ],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.ACCEPTED
        descriptor = await r.json()
        # Descriptor reports the freshly-created job (state == IMPORTING) without the prior error.
        assert descriptor["state"] == "importing"
        assert "status" not in descriptor
        assert "error" not in descriptor
        # Previous dest dir was rmtree'd by the reset.
        assert not prior_dest.exists()

        await wait_for_import_state(client, mock_vm_hash, "imported")


class TestMigrationCleanupGuard:
    @pytest.mark.asyncio
    async def test_cleanup_without_exported_job_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "No completed export" in body["error"]


class TestImportRequestSourceHostValidation:
    """Validator on ColdMigrationImportRequest.source_host blocks obvious SSRF targets."""

    @pytest.mark.parametrize(
        "bad_host",
        [
            "127.0.0.1",  # IPv4 loopback
            "127.42.42.42",  # anywhere in 127.0.0.0/8
            "::1",  # IPv6 loopback
            "169.254.169.254",  # cloud metadata service
            "fe80::1",  # IPv6 link-local
            "224.0.0.1",  # multicast
            "0.0.0.0",  # unspecified
            "localhost",
            "LocalHost",
            "",
        ],
    )
    def test_rejects_unsafe_hosts(self, bad_host):
        from pydantic import ValidationError

        from aleph.vm.agent.migration.jobs import DiskFileInfo
        from aleph.vm.agent.views.migration import ColdMigrationImportRequest

        with pytest.raises(ValidationError):
            ColdMigrationImportRequest(
                vm_hash="0" * 64,
                source_host=bad_host,
                source_port=443,
                export_token="t",
                disk_files=[DiskFileInfo(name="a.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
            )

    @pytest.mark.parametrize(
        "good_host",
        [
            "8.8.8.8",  # routable IPv4
            "2001:db8::1",  # documentation IPv6 (treated as routable for our purposes)
            "src.example.com",  # hostname — we don't resolve, allow-list belongs higher up
            "crn-42",
        ],
    )
    def test_accepts_routable_or_hostname(self, good_host):
        from aleph.vm.agent.migration.jobs import DiskFileInfo
        from aleph.vm.agent.views.migration import ColdMigrationImportRequest

        ColdMigrationImportRequest(
            vm_hash="0" * 64,
            source_host=good_host,
            source_port=443,
            export_token="t",
            disk_files=[DiskFileInfo(name="a.qcow2", size_bytes=1, sha256="0" * 64, download_path="/x")],
        )


class TestMigrationCleanupActiveDownload:
    @pytest.mark.asyncio
    async def test_cleanup_during_download_returns_409(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        from datetime import datetime, timezone

        from aleph.vm.agent.migration.jobs import ExportJob, export_jobs
        from aleph.vm.models import MigrationState

        job = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            active_downloads=1,
        )
        export_jobs[mock_vm_hash] = job

        pool = mocker.Mock(executions={})
        app = setup_webapp(supervisor=LocalSupervisor(pool))
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "download" in body["error"].lower()


class TestMigrationEndpointsDoNotTouchThePool:
    """Guard: the three migration endpoints reach VMs only through the
    supervisor. No raw pool access (require_vm_pool, vm_pool, pool.create_a_vm,
    pool.executions) survives anywhere in their source."""

    def test_endpoints_have_no_pool_references(self):
        import inspect

        from aleph.vm.agent.views import migration as migration_views

        forbidden = ("require_vm_pool", "vm_pool", "pool.create_a_vm", "pool.executions")
        for endpoint in (
            migration_views.migration_export,
            migration_views.migration_import,
            migration_views.migration_cleanup,
        ):
            source = inspect.getsource(endpoint)
            for token in forbidden:
                assert token not in source, f"{endpoint.__name__} still references {token!r}"
