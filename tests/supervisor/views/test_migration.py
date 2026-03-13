"""Tests for cold (stop/start) migration endpoints."""

import asyncio
from http import HTTPStatus
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.models import MigrationState
from aleph.vm.orchestrator.supervisor import setup_webapp


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


def _make_running_qemu_execution(mocker, vm_hash, migration_state=MigrationState.NONE):
    """Helper to create a mock running QEMU execution."""
    execution = mocker.Mock()
    execution.vm_hash = vm_hash
    execution.is_running = True
    execution.is_stopping = False
    execution.hypervisor = HypervisorType.qemu
    execution.is_confidential = False
    execution.migration_state = migration_state
    execution.export_token = None
    execution.systemd_manager = mocker.Mock()
    execution.controller_service = f"aleph-vm-controller@{vm_hash}.service"
    execution.vm = mocker.Mock()
    execution.vm.qmp_socket_path = mocker.Mock()
    execution.vm.qmp_socket_path.exists.return_value = True
    return execution


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
    async def test_export_already_in_progress(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that export fails if migration already in progress."""
        execution = _make_running_qemu_execution(mocker, mock_vm_hash, MigrationState.EXPORTING)
        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")
        assert response.status == HTTPStatus.CONFLICT

    @pytest.mark.asyncio
    async def test_export_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path):
        """Test successful export."""
        execution = _make_running_qemu_execution(mocker, mock_vm_hash)

        pool = mocker.Mock(executions={mock_vm_hash: execution})
        app = setup_webapp(pool=pool)

        # Create a fake disk file
        volumes_dir = tmp_path / str(mock_vm_hash)
        volumes_dir.mkdir()
        rootfs = volumes_dir / "rootfs.qcow2"
        rootfs.write_bytes(b"fake qcow2 data")

        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._graceful_shutdown",
            new_callable=AsyncMock,
        )

        # Mock _compress_disk to just copy the file
        async def fake_compress(src, dst):
            dst.write_bytes(src.read_bytes())

        mocker.patch(
            "aleph.vm.orchestrator.views.migration._compress_disk",
            side_effect=fake_compress,
        )
        mocker.patch("aleph.vm.orchestrator.views.migration.create_task_log_exceptions", return_value=mocker.Mock())

        client: TestClient = await aiohttp_client(app)
        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/export")

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "ready"
        assert len(data["disk_files"]) == 1
        assert data["disk_files"][0]["name"] == "rootfs.qcow2"
        assert data["export_token"]
        assert execution.migration_state == MigrationState.EXPORTED


class TestMigrationDiskDownloadEndpoint:
    """Tests for GET /control/machine/{ref}/migration/disk/{filename}."""

    @pytest.mark.asyncio
    async def test_download_no_export_state(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that download fails when no export state exists."""
        # Clear any existing export state
        from aleph.vm.orchestrator.views.migration import _export_state

        _export_state.pop(mock_vm_hash, None)

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=invalid")
        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_download_invalid_token(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download fails with invalid token."""
        from aleph.vm.orchestrator.views.migration import _export_state

        _export_state[mock_vm_hash] = {
            "token": "correct-token",
            "disk_files": [],
            "export_paths": [],
            "volumes_dir": str(tmp_path),
        }

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=wrong-token")
        assert response.status == HTTPStatus.UNAUTHORIZED

        # Cleanup
        _export_state.pop(mock_vm_hash, None)

    @pytest.mark.asyncio
    async def test_download_file_not_found(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test that download returns 404 for missing file."""
        from aleph.vm.orchestrator.views.migration import _export_state

        _export_state[mock_vm_hash] = {
            "token": "test-token",
            "disk_files": [],
            "export_paths": [],
            "volumes_dir": str(tmp_path),
        }

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(
            f"/control/machine/{mock_vm_hash}/migration/disk/nonexistent.qcow2?token=test-token"
        )
        assert response.status == HTTPStatus.NOT_FOUND

        # Cleanup
        _export_state.pop(mock_vm_hash, None)

    @pytest.mark.asyncio
    async def test_download_success(self, aiohttp_client, mocker, mock_vm_hash, tmp_path):
        """Test successful file download."""
        from aleph.vm.orchestrator.views.migration import _export_state

        export_file = tmp_path / "rootfs.qcow2.export.qcow2"
        export_file.write_bytes(b"compressed qcow2 data")

        _export_state[mock_vm_hash] = {
            "token": "test-token",
            "disk_files": [],
            "export_paths": [str(export_file)],
            "volumes_dir": str(tmp_path),
        }

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.get(f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2?token=test-token")
        assert response.status == HTTPStatus.OK
        body = await response.read()
        assert body == b"compressed qcow2 data"

        # Cleanup
        _export_state.pop(mock_vm_hash, None)


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
                "disk_files": [],
            },
        )
        assert response.status == HTTPStatus.CONFLICT

    @pytest.mark.asyncio
    async def test_import_not_instance(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that import fails for non-instance messages."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.program

        mocker.patch(
            "aleph.vm.orchestrator.views.migration.load_updated_message",
            return_value=(mock_message, mock_message),
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
                "disk_files": [],
            },
        )
        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "not an instance" in data["error"]

    @pytest.mark.asyncio
    async def test_import_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash, tmp_path):
        """Test successful import."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.instance
        mock_message.content = mocker.Mock()
        mock_message.content.environment = mocker.Mock()
        mock_message.content.environment.hypervisor = HypervisorType.qemu
        mock_message.content.environment.trusted_execution = None
        mock_message.content.rootfs = mocker.Mock()
        mock_message.content.rootfs.parent = mocker.Mock()
        mock_message.content.rootfs.parent.ref = ItemHash("b" * 64)

        mocker.patch(
            "aleph.vm.orchestrator.views.migration.load_updated_message",
            return_value=(mock_message, mock_message),
        )

        parent_path = tmp_path / "parent.qcow2"
        parent_path.write_bytes(b"parent image")
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.get_rootfs_base_path",
            return_value=parent_path,
        )
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._detect_parent_format",
            return_value="qcow2",
        )
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._download_disk_from_source",
            return_value=1024,
        )
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._rebase_overlay",
            new_callable=AsyncMock,
        )
        mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

        # Create the destination directory so overlay_path.exists() returns True
        dest_dir = tmp_path / str(mock_vm_hash)
        dest_dir.mkdir()
        (dest_dir / "rootfs.qcow2").write_bytes(b"overlay")

        mock_execution = mocker.Mock()
        pool = mocker.AsyncMock()
        pool.executions = {}
        pool.create_a_vm = AsyncMock(return_value=mock_execution)

        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={
                "vm_hash": str(mock_vm_hash),
                "source_host": "source.example.com",
                "source_port": 443,
                "export_token": "test-token",
                "disk_files": [
                    {
                        "name": "rootfs.qcow2",
                        "size_bytes": 1024,
                        "download_path": f"/control/machine/{mock_vm_hash}/migration/disk/rootfs.qcow2",
                    }
                ],
            },
        )

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "completed"
        assert "transfer_time_ms" in data
        assert data["total_bytes_transferred"] == 1024

        pool.create_a_vm.assert_called_once()


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
        """Test successful cleanup."""
        pool = mocker.AsyncMock()
        pool.executions = {}
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "completed"
        pool.stop_vm.assert_called_once_with(mock_vm_hash)
        pool.forget_vm.assert_called_once_with(mock_vm_hash)


class TestMigrationHelpers:
    """Tests for migration helper functions."""

    @pytest.mark.asyncio
    async def test_graceful_shutdown_success(self, mocker):
        """Test graceful shutdown via QMP system_powerdown."""
        from aleph.vm.orchestrator.views.migration import _graceful_shutdown

        mock_client = mocker.Mock()
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.QemuVmClient",
            return_value=mock_client,
        )

        execution = mocker.Mock()
        execution.vm_hash = "test"
        execution.vm = mocker.Mock()
        execution.systemd_manager = mocker.Mock()
        execution.systemd_manager.is_service_active.return_value = False
        execution.controller_service = "test-service"

        await _graceful_shutdown(execution, timeout=2)

        mock_client.system_powerdown.assert_called_once()
        mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_graceful_shutdown_timeout_forces_stop(self, mocker):
        """Test that shutdown falls back to force stop on timeout."""
        from aleph.vm.orchestrator.views.migration import _graceful_shutdown

        mock_client = mocker.Mock()
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.QemuVmClient",
            return_value=mock_client,
        )

        execution = mocker.Mock()
        execution.vm_hash = "test"
        execution.vm = mocker.Mock()
        execution.systemd_manager = mocker.Mock()
        # Service stays active (never shuts down)
        execution.systemd_manager.is_service_active.return_value = True
        execution.controller_service = "test-service"

        await _graceful_shutdown(execution, timeout=1)

        execution.systemd_manager.stop_and_disable.assert_called_once_with("test-service")

    @pytest.mark.asyncio
    async def test_compress_disk(self, mocker, tmp_path):
        """Test disk compression with qemu-img convert."""
        from aleph.vm.orchestrator.views.migration import _compress_disk

        source = tmp_path / "source.qcow2"
        dest = tmp_path / "dest.qcow2"
        source.write_bytes(b"fake qcow2")

        mock_proc = mocker.Mock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
        mocker.patch("shutil.which", return_value="/usr/bin/qemu-img")

        await _compress_disk(source, dest)

    @pytest.mark.asyncio
    async def test_compress_disk_failure(self, mocker, tmp_path):
        """Test that compress_disk raises on failure."""
        from aleph.vm.orchestrator.views.migration import _compress_disk

        source = tmp_path / "source.qcow2"
        dest = tmp_path / "dest.qcow2"
        source.write_bytes(b"fake qcow2")

        mock_proc = mocker.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"error: bad image"))

        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
        mocker.patch("shutil.which", return_value="/usr/bin/qemu-img")

        with pytest.raises(RuntimeError, match="qemu-img convert failed"):
            await _compress_disk(source, dest)

    @pytest.mark.asyncio
    async def test_rebase_overlay(self, mocker, tmp_path):
        """Test overlay rebase with qemu-img rebase."""
        from aleph.vm.orchestrator.views.migration import _rebase_overlay

        overlay = tmp_path / "overlay.qcow2"
        parent = tmp_path / "parent.qcow2"
        overlay.write_bytes(b"overlay")
        parent.write_bytes(b"parent")

        mock_proc = mocker.Mock()
        mock_proc.returncode = 0
        mock_proc.communicate = AsyncMock(return_value=(b"", b""))

        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
        mocker.patch("shutil.which", return_value="/usr/bin/qemu-img")

        await _rebase_overlay(overlay, parent, "qcow2")

    @pytest.mark.asyncio
    async def test_rebase_overlay_failure(self, mocker, tmp_path):
        """Test that rebase raises on failure."""
        from aleph.vm.orchestrator.views.migration import _rebase_overlay

        mock_proc = mocker.Mock()
        mock_proc.returncode = 1
        mock_proc.communicate = AsyncMock(return_value=(b"", b"rebase error"))

        mocker.patch("asyncio.create_subprocess_exec", return_value=mock_proc)
        mocker.patch("shutil.which", return_value="/usr/bin/qemu-img")

        with pytest.raises(RuntimeError, match="qemu-img rebase failed"):
            await _rebase_overlay(tmp_path / "a.qcow2", tmp_path / "b.qcow2", "qcow2")

    @pytest.mark.asyncio
    async def test_download_disk_from_source(self, mocker, tmp_path):
        """Test streaming download with atomic rename."""
        from aleph.vm.orchestrator.views.migration import _download_disk_from_source

        dest_path = tmp_path / "rootfs.qcow2"
        test_data = b"downloaded disk data"

        # Create a mock response with async iterator
        mock_content = mocker.Mock()

        async def mock_iter_chunked(size):
            yield test_data

        mock_content.iter_chunked = mock_iter_chunked

        mock_response = mocker.AsyncMock()
        mock_response.status = 200
        mock_response.content = mock_content
        mock_response.__aenter__ = mocker.AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = mocker.AsyncMock(return_value=False)

        mock_session = mocker.Mock()
        mock_session.get = mocker.Mock(return_value=mock_response)

        result = await _download_disk_from_source(
            mock_session, "https://source:443/disk/rootfs.qcow2", dest_path, "token"
        )

        assert result == len(test_data)
        assert dest_path.exists()
        assert dest_path.read_bytes() == test_data

    @pytest.mark.asyncio
    async def test_download_disk_from_source_http_error(self, mocker, tmp_path):
        """Test that download raises on HTTP error."""
        from aleph.vm.orchestrator.views.migration import _download_disk_from_source

        dest_path = tmp_path / "rootfs.qcow2"

        mock_response = mocker.AsyncMock()
        mock_response.status = 404
        mock_response.text = mocker.AsyncMock(return_value="Not found")
        mock_response.__aenter__ = mocker.AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = mocker.AsyncMock(return_value=False)

        mock_session = mocker.Mock()
        mock_session.get = mocker.Mock(return_value=mock_response)

        with pytest.raises(RuntimeError, match="HTTP 404"):
            await _download_disk_from_source(mock_session, "https://source:443/disk/rootfs.qcow2", dest_path, "token")


class TestMigrationState:
    """Tests for updated MigrationState enum."""

    def test_migration_state_values(self):
        """Test that all migration states have correct values."""
        assert MigrationState.NONE.value == "none"
        assert MigrationState.EXPORTING.value == "exporting"
        assert MigrationState.EXPORTED.value == "exported"
        assert MigrationState.IMPORTING.value == "importing"
        assert MigrationState.COMPLETED.value == "completed"
        assert MigrationState.FAILED.value == "failed"

    def test_migration_state_is_string_enum(self):
        """Test that MigrationState is a string enum."""
        assert isinstance(MigrationState.NONE, str)

    def test_old_states_removed(self):
        """Test that old live migration states are removed."""
        assert not hasattr(MigrationState, "PREPARING")
        assert not hasattr(MigrationState, "WAITING")
        assert not hasattr(MigrationState, "MIGRATING")
