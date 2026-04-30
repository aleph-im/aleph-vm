"""Tests for the QEMU VM client and status models."""

import pytest

from aleph.vm.controllers.qemu.client import VmRunStatus, VmStatus


class TestVmRunStatus:
    """Tests for the VmRunStatus enum."""

    def test_all_status_values_exist(self):
        """Test that all expected QEMU status values are defined."""
        expected_statuses = [
            "debug",
            "finish-migrate",
            "inmigrate",
            "internal-error",
            "io-error",
            "paused",
            "postmigrate",
            "prelaunch",
            "restore-vm",
            "running",
            "save-vm",
            "shutdown",
            "suspended",
            "watchdog",
            "guest-panicked",
            "colo",
        ]
        for status in expected_statuses:
            assert status in [s.value for s in VmRunStatus]

    def test_status_string_values(self):
        """Test that status values match QEMU's expected strings."""
        assert VmRunStatus.RUNNING.value == "running"
        assert VmRunStatus.INMIGRATE.value == "inmigrate"
        assert VmRunStatus.PAUSED.value == "paused"
        assert VmRunStatus.PRELAUNCH.value == "prelaunch"


class TestVmStatus:
    """Tests for the VmStatus model."""

    def test_create_running_status(self):
        """Test creating a running VM status."""
        status = VmStatus(status=VmRunStatus.RUNNING, running=True, singlestep=False)
        assert status.status == VmRunStatus.RUNNING
        assert status.running is True
        assert status.singlestep is False

    def test_create_from_dict(self):
        """Test creating VmStatus from a dict (like QMP response)."""
        qmp_response = {"status": "running", "running": True, "singlestep": False}
        status = VmStatus.model_validate(qmp_response)
        assert status.status == VmRunStatus.RUNNING
        assert status.running is True

    def test_create_inmigrate_status(self):
        """Test creating an inmigrate VM status."""
        qmp_response = {"status": "inmigrate", "running": False, "singlestep": False}
        status = VmStatus.model_validate(qmp_response)
        assert status.status == VmRunStatus.INMIGRATE
        assert status.running is False

    def test_is_running_property(self):
        """Test the is_running property."""
        # VM is running
        running_status = VmStatus(status=VmRunStatus.RUNNING, running=True)
        assert running_status.is_running is True

        # VM has running status but running=False (shouldn't happen, but test anyway)
        weird_status = VmStatus(status=VmRunStatus.RUNNING, running=False)
        assert weird_status.is_running is False

        # VM is paused
        paused_status = VmStatus(status=VmRunStatus.PAUSED, running=False)
        assert paused_status.is_running is False

    def test_is_migrating_property(self):
        """Test the is_migrating property."""
        # Incoming migration
        inmigrate_status = VmStatus(status=VmRunStatus.INMIGRATE, running=False)
        assert inmigrate_status.is_migrating is True

        # Post migration
        postmigrate_status = VmStatus(status=VmRunStatus.POSTMIGRATE, running=False)
        assert postmigrate_status.is_migrating is True

        # Finish migration
        finish_status = VmStatus(status=VmRunStatus.FINISH_MIGRATE, running=False)
        assert finish_status.is_migrating is True

        # Running (not migrating)
        running_status = VmStatus(status=VmRunStatus.RUNNING, running=True)
        assert running_status.is_migrating is False

    def test_is_error_property(self):
        """Test the is_error property."""
        # Internal error
        error_status = VmStatus(status=VmRunStatus.INTERNAL_ERROR, running=False)
        assert error_status.is_error is True

        # IO error
        io_error_status = VmStatus(status=VmRunStatus.IO_ERROR, running=False)
        assert io_error_status.is_error is True

        # Guest panicked
        panic_status = VmStatus(status=VmRunStatus.GUEST_PANICKED, running=False)
        assert panic_status.is_error is True

        # Shutdown
        shutdown_status = VmStatus(status=VmRunStatus.SHUTDOWN, running=False)
        assert shutdown_status.is_error is True

        # Running (not an error)
        running_status = VmStatus(status=VmRunStatus.RUNNING, running=True)
        assert running_status.is_error is False

    def test_singlestep_default(self):
        """Test that singlestep defaults to False."""
        qmp_response = {"status": "running", "running": True}
        status = VmStatus.model_validate(qmp_response)
        assert status.singlestep is False

    def test_model_dump(self):
        """Test that model_dump works for JSON serialization."""
        status = VmStatus(status=VmRunStatus.RUNNING, running=True, singlestep=False)
        dumped = status.model_dump()
        assert dumped["status"] == VmRunStatus.RUNNING
        assert dumped["running"] is True
        assert dumped["singlestep"] is False


def _make_mock_vm(mocker):
    """Create a mock VM with QMP socket path."""
    mock_vm = mocker.Mock()
    mock_vm.qmp_socket_path = mocker.Mock()
    mock_vm.qmp_socket_path.exists.return_value = True
    return mock_vm


class TestQemuVmClientMocked:
    """Tests for QemuVmClient methods using mocks."""

    def test_query_status_returns_dict(self, mocker):
        """Test that query_status returns the QMP response dict."""
        mock_qmp = mocker.Mock()
        mock_qmp.command.return_value = {"status": "running", "running": True, "singlestep": False}
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            return_value=mock_qmp,
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        status = client.query_status()

        assert isinstance(status, dict)
        assert status["status"] == "running"
        assert status["running"] is True

    def test_system_powerdown(self, mocker):
        """Test that system_powerdown sends the correct QMP command."""
        mock_qmp = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            return_value=mock_qmp,
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.system_powerdown()

        mock_qmp.command.assert_called_with("system_powerdown")

    def test_close_closes_qmp(self, mocker):
        """Test that close() closes the QMP connection."""
        mock_qmp = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            return_value=mock_qmp,
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.close()

        mock_qmp.close.assert_called_once()

    def test_client_raises_on_missing_socket(self, mocker):
        """Test that client raises exception when QMP socket doesn't exist."""
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = False

        from aleph.vm.controllers.qemu.client import QemuVmClient

        with pytest.raises(Exception, match="VM is not running"):
            QemuVmClient(mock_vm)
