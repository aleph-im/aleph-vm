"""Tests for the migration views and endpoints."""

import asyncio
from http import HTTPStatus
from unittest import mock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.models import MigrationState
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.storage import get_message


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


class TestAllocateMigrationEndpoint:
    """Tests for POST /control/migrate endpoint."""

    @pytest.mark.asyncio
    async def test_allocate_migration_unauthorized(self, aiohttp_client, mocker):
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
            json={"vm_hash": "a" * 64, "migration_port": 4444},
        )

        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_allocate_migration_invalid_request(self, aiohttp_client, mocker, mock_scheduler_auth):
        """Test that invalid request body is rejected."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        # Missing migration_port
        response = await client.post(
            "/control/migrate",
            json={"vm_hash": "a" * 64},
        )

        assert response.status == HTTPStatus.BAD_REQUEST

    @pytest.mark.asyncio
    async def test_allocate_migration_vm_already_exists(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        """Test that allocate fails if VM already exists on host."""
        pool = mocker.Mock(
            executions={
                mock_vm_hash: mocker.Mock(is_running=True),
            }
        )
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={"vm_hash": str(mock_vm_hash), "migration_port": 4444},
        )

        assert response.status == HTTPStatus.CONFLICT
        data = await response.json()
        assert data["status"] == "error"
        assert "already running" in data["error"]

    @pytest.mark.asyncio
    async def test_allocate_migration_not_instance(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that allocate fails for non-instance messages."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.program  # Not an instance

        mocker.patch(
            "aleph.vm.orchestrator.views.migration.load_updated_message",
            return_value=(mock_message, mock_message),
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={"vm_hash": str(mock_vm_hash), "migration_port": 4444},
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "not an instance" in data["error"]

    @pytest.mark.asyncio
    async def test_allocate_migration_not_qemu(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that allocate fails for non-QEMU instances."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.instance
        mock_message.content = mocker.Mock()
        mock_message.content.environment = mocker.Mock()
        mock_message.content.environment.hypervisor = HypervisorType.firecracker

        mocker.patch(
            "aleph.vm.orchestrator.views.migration.load_updated_message",
            return_value=(mock_message, mock_message),
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={"vm_hash": str(mock_vm_hash), "migration_port": 4444},
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "QEMU" in data["error"]

    @pytest.mark.asyncio
    async def test_allocate_migration_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test successful migration allocation."""
        from aleph_message.models import MessageType

        mock_message = mocker.Mock()
        mock_message.type = MessageType.instance
        mock_message.content = mocker.Mock()
        mock_message.content.environment = mocker.Mock()
        mock_message.content.environment.hypervisor = HypervisorType.qemu

        mocker.patch(
            "aleph.vm.orchestrator.views.migration.load_updated_message",
            return_value=(mock_message, mock_message),
        )

        mock_execution = mocker.Mock()
        mock_execution.vm_hash = mock_vm_hash

        pool = mocker.AsyncMock()
        pool.executions = {}
        pool.network = mocker.Mock(host_ipv4="192.168.1.100")
        pool.create_a_vm = mocker.AsyncMock(return_value=mock_execution)

        # Mock the finalization task
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._start_migration_finalization_task",
        )

        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            "/control/migrate",
            json={"vm_hash": str(mock_vm_hash), "migration_port": 4444},
        )

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "ready"
        assert data["migration_port"] == 4444
        assert data["migration_host"] == "192.168.1.100"

        # Verify create_a_vm was called with correct parameters
        pool.create_a_vm.assert_called_once()
        call_kwargs = pool.create_a_vm.call_args[1]
        assert call_kwargs["incoming_migration_port"] == 4444
        assert call_kwargs["persistent"] is True


class TestMigrationStartEndpoint:
    """Tests for POST /control/machine/{ref}/migration/start endpoint."""

    @pytest.mark.asyncio
    async def test_migration_start_unauthorized(self, aiohttp_client, mocker, mock_vm_hash):
        """Test that unauthorized requests are rejected."""
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.authenticate_api_request",
            return_value=False,
        )

        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.UNAUTHORIZED

    @pytest.mark.asyncio
    async def test_migration_start_vm_not_found(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that migration fails if VM not found."""
        pool = mocker.Mock(executions={})
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.NOT_FOUND

    @pytest.mark.asyncio
    async def test_migration_start_vm_not_running(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that migration fails if VM is not running."""
        pool = mocker.Mock(
            executions={
                mock_vm_hash: mocker.Mock(
                    vm_hash=mock_vm_hash,
                    is_running=False,
                    is_stopping=False,
                ),
            }
        )
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "not running" in data["error"]

    @pytest.mark.asyncio
    async def test_migration_start_not_qemu(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test that migration fails for non-QEMU VMs."""
        pool = mocker.Mock(
            executions={
                mock_vm_hash: mocker.Mock(
                    vm_hash=mock_vm_hash,
                    is_running=True,
                    is_stopping=False,
                    hypervisor=HypervisorType.firecracker,
                ),
            }
        )
        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.BAD_REQUEST
        data = await response.json()
        assert "QEMU" in data["error"]

    @pytest.mark.asyncio
    async def test_migration_start_success(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test successful migration start."""
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = True

        mock_execution = mocker.Mock(
            vm_hash=mock_vm_hash,
            is_running=True,
            is_stopping=False,
            hypervisor=HypervisorType.qemu,
            vm=mock_vm,
            migration_state=MigrationState.NONE,
        )

        pool = mocker.AsyncMock()
        pool.executions = {mock_vm_hash: mock_execution}

        # Mock QemuVmClient
        mock_client = mocker.Mock()
        mock_client.migrate = mocker.Mock()
        mock_client.query_migrate = mocker.Mock(
            return_value={
                "status": "completed",
                "downtime": 50,
                "ram": {"transferred": 1000000},
            }
        )
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.QemuVmClient",
            return_value=mock_client,
        )

        # Mock the wait function to return immediately
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._wait_for_migration_completion",
            return_value={
                "status": "completed",
                "downtime": 50,
                "ram": {"transferred": 1000000},
            },
        )

        # Mock cleanup
        mocker.patch(
            "aleph.vm.orchestrator.views.migration._cleanup_source_vm",
        )

        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.OK
        data = await response.json()
        assert data["status"] == "completed"
        assert "total_time_ms" in data
        assert data["downtime_ms"] == 50
        assert data["transferred_bytes"] == 1000000

        # Verify migrate was called
        mock_client.migrate.assert_called_once_with(
            "tcp:192.168.1.100:4444",
            bandwidth_limit_mbps=None,
        )

    @pytest.mark.asyncio
    async def test_migration_start_with_bandwidth_limit(
        self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash
    ):
        """Test migration with bandwidth limit."""
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = True

        mock_execution = mocker.Mock(
            vm_hash=mock_vm_hash,
            is_running=True,
            is_stopping=False,
            hypervisor=HypervisorType.qemu,
            vm=mock_vm,
            migration_state=MigrationState.NONE,
        )

        pool = mocker.AsyncMock()
        pool.executions = {mock_vm_hash: mock_execution}

        mock_client = mocker.Mock()
        mock_client.migrate = mocker.Mock()
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.QemuVmClient",
            return_value=mock_client,
        )

        mocker.patch(
            "aleph.vm.orchestrator.views.migration._wait_for_migration_completion",
            return_value={"status": "completed", "ram": {"transferred": 1000000}},
        )
        mocker.patch("aleph.vm.orchestrator.views.migration._cleanup_source_vm")

        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={
                "destination_host": "192.168.1.100",
                "destination_port": 4444,
                "bandwidth_limit_mbps": 100,
            },
        )

        assert response.status == HTTPStatus.OK

        # Verify migrate was called with bandwidth limit
        mock_client.migrate.assert_called_once_with(
            "tcp:192.168.1.100:4444",
            bandwidth_limit_mbps=100,
        )

    @pytest.mark.asyncio
    async def test_migration_start_failure(self, aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
        """Test migration failure handling."""
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = True

        mock_execution = mocker.Mock(
            vm_hash=mock_vm_hash,
            is_running=True,
            is_stopping=False,
            hypervisor=HypervisorType.qemu,
            vm=mock_vm,
            migration_state=MigrationState.NONE,
        )

        pool = mocker.AsyncMock()
        pool.executions = {mock_vm_hash: mock_execution}

        mock_client = mocker.Mock()
        mocker.patch(
            "aleph.vm.orchestrator.views.migration.QemuVmClient",
            return_value=mock_client,
        )

        mocker.patch(
            "aleph.vm.orchestrator.views.migration._wait_for_migration_completion",
            return_value={"status": "failed", "error-desc": "Connection refused"},
        )

        app = setup_webapp(pool=pool)
        client: TestClient = await aiohttp_client(app)

        response = await client.post(
            f"/control/machine/{mock_vm_hash}/migration/start",
            json={"destination_host": "192.168.1.100", "destination_port": 4444},
        )

        assert response.status == HTTPStatus.INTERNAL_SERVER_ERROR
        data = await response.json()
        assert data["status"] == "error"
        assert "Connection refused" in data["error"]
        assert mock_execution.migration_state == MigrationState.FAILED


class TestMigrationHelperFunctions:
    """Tests for migration helper functions."""

    @pytest.mark.asyncio
    async def test_wait_for_migration_completion_success(self, mocker):
        """Test waiting for migration to complete successfully."""
        from aleph.vm.orchestrator.views.migration import _wait_for_migration_completion

        mock_client = mocker.Mock()
        mock_client.query_migrate = mocker.Mock(
            side_effect=[
                {"status": "active", "ram": {"transferred": 500000, "total": 1000000}},
                {"status": "active", "ram": {"transferred": 800000, "total": 1000000}},
                {"status": "completed", "downtime": 50, "ram": {"transferred": 1000000, "total": 1000000}},
            ]
        )

        result = await _wait_for_migration_completion(
            mock_client,
            ItemHash("a" * 64),
            poll_interval=0.01,
        )

        assert result["status"] == "completed"
        assert mock_client.query_migrate.call_count == 3

    @pytest.mark.asyncio
    async def test_wait_for_migration_completion_failure(self, mocker):
        """Test waiting for migration that fails."""
        from aleph.vm.orchestrator.views.migration import _wait_for_migration_completion

        mock_client = mocker.Mock()
        mock_client.query_migrate = mocker.Mock(return_value={"status": "failed", "error-desc": "Connection lost"})

        result = await _wait_for_migration_completion(
            mock_client,
            ItemHash("a" * 64),
            poll_interval=0.01,
        )

        assert result["status"] == "failed"

    @pytest.mark.asyncio
    async def test_wait_for_migration_completion_timeout(self, mocker):
        """Test migration timeout handling."""
        from aleph.vm.orchestrator.views.migration import _wait_for_migration_completion

        mock_client = mocker.Mock()
        mock_client.query_migrate = mocker.Mock(
            return_value={"status": "active", "ram": {"transferred": 500000, "total": 1000000}}
        )
        mock_client.migrate_cancel = mocker.Mock()

        result = await _wait_for_migration_completion(
            mock_client,
            ItemHash("a" * 64),
            poll_interval=0.01,
            timeout=0.05,
        )

        assert result["status"] == "failed"
        assert "timed out" in result["error-desc"]
        mock_client.migrate_cancel.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleanup_source_vm(self, mocker):
        """Test source VM cleanup after migration."""
        from aleph.vm.orchestrator.views.migration import _cleanup_source_vm

        mock_execution = mocker.Mock()
        mock_execution.vm_hash = ItemHash("a" * 64)

        pool = mocker.AsyncMock()

        await _cleanup_source_vm(pool, mock_execution)

        pool.stop_vm.assert_called_once_with(mock_execution.vm_hash)
        pool.forget_vm.assert_called_once_with(mock_execution.vm_hash)

    @pytest.mark.asyncio
    async def test_cleanup_source_vm_handles_errors(self, mocker):
        """Test that cleanup errors don't raise exceptions."""
        from aleph.vm.orchestrator.views.migration import _cleanup_source_vm

        mock_execution = mocker.Mock()
        mock_execution.vm_hash = ItemHash("a" * 64)

        pool = mocker.AsyncMock()
        pool.stop_vm = mocker.AsyncMock(side_effect=Exception("Stop failed"))

        # Should not raise
        await _cleanup_source_vm(pool, mock_execution)


class TestMigrationState:
    """Tests for MigrationState enum."""

    def test_migration_state_values(self):
        """Test that all migration states have correct values."""
        assert MigrationState.NONE.value == "none"
        assert MigrationState.PREPARING.value == "preparing"
        assert MigrationState.WAITING.value == "waiting"
        assert MigrationState.MIGRATING.value == "migrating"
        assert MigrationState.COMPLETED.value == "completed"
        assert MigrationState.FAILED.value == "failed"

    def test_migration_state_is_string_enum(self):
        """Test that MigrationState is a string enum."""
        assert isinstance(MigrationState.NONE, str)
        assert MigrationState.RUNNING if hasattr(MigrationState, "RUNNING") else True
