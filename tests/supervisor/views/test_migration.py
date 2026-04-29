"""Tests for cold (stop/start) migration endpoints."""

import asyncio
from http import HTTPStatus
from unittest.mock import AsyncMock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.models import MigrationState
from aleph.vm.orchestrator.supervisor import setup_webapp


@pytest.fixture(autouse=True)
def _clear_migration_registries():
    from aleph.vm.migration.jobs import export_jobs, import_jobs
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
    """Mock the scheduler authentication to always pass."""
    mocker.patch(
        "aleph.vm.orchestrator.views.migration.authenticate_api_request",
        return_value=True,
    )


def _make_running_qemu_execution(mocker, vm_hash):
    """Helper to create a mock running QEMU execution."""
    execution = mocker.Mock()
    execution.vm_hash = vm_hash
    execution.is_running = True
    execution.is_stopping = False
    execution.hypervisor = HypervisorType.qemu
    execution.is_confidential = False
    execution.systemd_manager = mocker.Mock()
    execution.controller_service = f"aleph-vm-controller@{vm_hash}.service"
    execution.vm = mocker.Mock()
    execution.vm.qmp_socket_path = mocker.Mock()
    execution.vm.qmp_socket_path.exists.return_value = True
    return execution


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
            "aleph.vm.orchestrator.views.migration.authenticate_api_request",
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_export_vm_not_found(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails if VM not found."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_export_vm_not_running(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails if VM is not running."""
        execution = mocker.Mock(is_running=False, is_stopping=False)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "not running" in data["error"]

    @pytest.mark.asyncio
    async def test_export_not_qemu(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails for non-QEMU VMs."""
        execution = mocker.Mock(
            is_running=True,
            is_stopping=False,
            hypervisor=HypervisorType.firecracker,
        )
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "QEMU" in data["error"]

    @pytest.mark.asyncio
    async def test_export_confidential_rejected(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export rejects confidential VMs."""
        execution = mocker.Mock(
            is_running=True,
            is_stopping=False,
            hypervisor=HypervisorType.qemu,
            is_confidential=True,
        )
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
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

        from aleph.vm.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
        )

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.CONFLICT

    @pytest.mark.asyncio
    async def test_export_returns_202_and_completes(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """Test successful export: POST returns 202, polling reaches EXPORTED."""
        mocker.patch("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())

        async def fake_compress(src, dst):
            dst.write_bytes(b"compressed")

        mocker.patch("aleph.vm.migration.runner.compress_disk", fake_compress)

        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
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
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=invalid")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_download_invalid_token(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download fails with invalid token."""
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            token="correct-token",
            volumes_dir=tmp_path,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=wrong-token")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_download_file_not_found(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download returns 404 for missing file."""
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            token="test-token",
            volumes_dir=tmp_path,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(
            f"/control/machine/{mock_vm_hash}/migration/disk/nonexistent.qcow2?token=test-token"
        )
        assert response.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_download_success(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test successful file download."""
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, export_jobs

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
        app = setup_webapp(pool=pool)
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
            "aleph.vm.orchestrator.views.migration.authenticate_api_request",
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
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
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post("/control/migrate", json={"vm_hash": "a" * 64})
        assert response.status == HTTPStatus.BAD_REQUEST

    @pytest.mark.asyncio
    async def test_import_vm_already_running(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that import fails if VM already running on host."""
        pool = mocker.Mock(executions={mock_vm_hash: mocker.Mock(is_running=True)})
        app = setup_webapp(pool=pool)
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
            "aleph.vm.migration.runner.load_updated_message",
            AsyncMock(return_value=(mock_message, mock_message)),
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
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
            "aleph.vm.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.migration.runner.rebase_overlay", AsyncMock())

        async def fake_download(session, url, dest_path, token, on_chunk=None):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            if on_chunk:
                on_chunk(1)
            return 1

        mocker.patch("aleph.vm.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        pool = mocker.Mock(executions={})
        pool.create_a_vm = AsyncMock()
        app = setup_webapp(pool=pool)
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
                    "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                }
            ],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.ACCEPTED

        data = await wait_for_import_state(client, mock_vm_hash, "imported")
        assert data["transfer_time_ms"] is not None

    @pytest.mark.asyncio
    async def test_second_post_returns_existing_import_job(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path
    ):
        """Two POSTs while a job is IMPORTING return 202 referencing the same job."""
        from aleph_message.models import MessageType
        from aleph_message.models.execution.environment import HypervisorType

        # Make the import hang in the disk-download step.
        slow = asyncio.Event()

        async def fake_download(session, url, dest_path, token, on_chunk=None):
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
            "aleph.vm.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.migration.runner.rebase_overlay", AsyncMock())
        mocker.patch("aleph.vm.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        pool = mocker.Mock(executions={})
        pool.create_a_vm = AsyncMock()
        app = setup_webapp(pool=pool)
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
    async def test_post_against_imported_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ImportJob, import_jobs

        import_jobs[mock_vm_hash] = ImportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.IMPORTED,
            started_at=datetime.now(timezone.utc),
            source_host="src",
            source_port=443,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        body = {
            "vm_hash": str(mock_vm_hash),
            "source_host": "src",
            "source_port": 443,
            "export_token": "tok",
            "disk_files": [{"name": "rootfs.qcow2", "size_bytes": 1, "download_path": "/x"}],
        }
        r = await client.post("/control/migrate", json=body)
        assert r.status == HTTPStatus.CONFLICT


class TestMigrationStatusEndpoints:
    @pytest.mark.asyncio
    async def test_export_status_404_for_unknown_vm_hash(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)
        r = await client.get(f"/control/machine/{mock_vm_hash}/migration/export/status")
        assert r.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_import_status_404_for_unknown_vm_hash(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)
        r = await client.get(f"/control/migrate/{mock_vm_hash}/status")
        assert r.status == HTTPStatus.NOT_FOUND


class TestMigrationCleanupEndpoint:
    """Tests for POST /control/machine/{ref}/migration/cleanup."""

    @pytest.mark.asyncio
    async def test_cleanup_unauthorized(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that unauthorized requests are rejected."""
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.authenticate_api_request",
            return_value=False,
        )
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_cleanup_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test successful cleanup when an EXPORTED job is present."""
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, export_jobs

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
        )

        pool = mocker.AsyncMock()
        pool.executions = {}
        # forget_vm is sync in production (not awaited); use a regular Mock
        # so we don't emit a RuntimeWarning about an unawaited coroutine.
        pool.forget_vm = mocker.Mock()
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "completed"
        pool.stop_vm.assert_called_once_with(mock_vm_hash)
        pool.forget_vm.assert_called_once_with(mock_vm_hash)


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

        mocker.patch("aleph.vm.migration.runner.compress_disk", fake_compress)
        mocker.patch("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

        # Pre-create the volumes dir so the runner finds disk files to compress.
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True, exist_ok=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
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

        from aleph.vm.migration.jobs import ExportJob, export_jobs

        partial = tmp_path / "rootfs.qcow2.export.qcow2"
        partial.write_bytes(b"partial")

        export_jobs[mock_vm_hash] = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORT_FAILED,
            started_at=datetime.now(timezone.utc),
            error="boom",
            export_paths=[partial],
        )

        mocker.patch("aleph.vm.migration.runner.graceful_shutdown", AsyncMock())

        async def fake_compress(src, dst):
            dst.write_bytes(b"compressed")

        mocker.patch("aleph.vm.migration.runner.compress_disk", fake_compress)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        volumes = tmp_path / str(mock_vm_hash)
        volumes.mkdir(parents=True)
        (volumes / "rootfs.qcow2").write_bytes(b"x")

        execution = _make_running_qemu_execution(mocker, mock_vm_hash)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
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

        from aleph.vm.migration.jobs import ImportJob, import_jobs

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
            "aleph.vm.migration.runner.load_updated_message",
            AsyncMock(return_value=(fake_message, fake_message)),
        )
        mocker.patch(
            "aleph.vm.migration.runner.get_rootfs_base_path",
            AsyncMock(return_value=tmp_path / "parent.qcow2"),
        )
        mocker.patch("aleph.vm.migration.runner.detect_parent_format", AsyncMock(return_value="qcow2"))
        mocker.patch("aleph.vm.migration.runner.rebase_overlay", AsyncMock())

        async def fake_download(session, url, dest_path, token, on_chunk=None):
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(b"x")
            if on_chunk:
                on_chunk(1)
            return 1

        mocker.patch("aleph.vm.migration.runner.download_disk_from_source", fake_download)
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        (tmp_path / "parent.qcow2").write_bytes(b"x")

        pool = mocker.Mock(executions={})
        pool.create_a_vm = AsyncMock()
        app = setup_webapp(pool=pool)
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
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "No completed export" in body["error"]


class TestMigrationCleanupActiveDownload:
    @pytest.mark.asyncio
    async def test_cleanup_during_download_returns_409(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        from datetime import datetime, timezone

        from aleph.vm.migration.jobs import ExportJob, export_jobs
        from aleph.vm.models import MigrationState

        job = ExportJob(
            vm_hash=mock_vm_hash,
            state=MigrationState.EXPORTED,
            started_at=datetime.now(timezone.utc),
            active_downloads=1,
        )
        export_jobs[mock_vm_hash] = job

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        r = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")
        assert r.status == HTTPStatus.CONFLICT
        body = await r.json()
        assert "download" in body["error"].lower()
