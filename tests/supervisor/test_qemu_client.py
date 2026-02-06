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
    """Create a mock VM with both QMP and QGA socket paths."""
    mock_vm = mocker.Mock()
    mock_vm.qmp_socket_path = mocker.Mock()
    mock_vm.qmp_socket_path.exists.return_value = True
    mock_vm.qga_socket_path = mocker.Mock()
    mock_vm.qga_socket_path.exists.return_value = True
    return mock_vm


class TestQemuVmClientMocked:
    """Tests for QemuVmClient methods using mocks."""

    def test_migrate_builds_correct_uri(self, mocker):
        """Test that migrate method builds the correct destination URI."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.migrate("tcp:192.168.1.100:4444")

        # Verify migrate was called on QMP client with correct parameters
        mock_qmp.command.assert_any_call("migrate-set-capabilities", capabilities=mocker.ANY)
        mock_qmp.command.assert_any_call("migrate", uri="tcp:192.168.1.100:4444", blk=True, inc=True)

    def test_migrate_with_bandwidth_limit(self, mocker):
        """Test that migrate sets bandwidth limit when specified."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.migrate("tcp:192.168.1.100:4444", bandwidth_limit_mbps=100)

        # Verify bandwidth limit was set on QMP client (100 MB/s = 100 * 1024 * 1024 bytes/s)
        mock_qmp.command.assert_any_call("migrate_set_speed", value=100 * 1024 * 1024)

    def test_query_migrate_returns_dict(self, mocker):
        """Test that query_migrate returns the migration status dict."""
        mock_qmp = mocker.Mock()
        mock_qmp.command.return_value = {
            "status": "active",
            "ram": {"transferred": 1000000, "total": 5000000},
        }
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.query_migrate()

        assert result["status"] == "active"
        assert result["ram"]["transferred"] == 1000000

    def test_query_status_returns_vm_status(self, mocker):
        """Test that query_status returns a VmStatus object."""
        mock_qmp = mocker.Mock()
        mock_qmp.command.return_value = {"status": "running", "running": True, "singlestep": False}
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        status = client.query_status()

        assert isinstance(status, VmStatus)
        assert status.status == VmRunStatus.RUNNING
        assert status.is_running is True

    def test_migrate_cancel(self, mocker):
        """Test that migrate_cancel calls the correct QMP command."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.migrate_cancel()

        mock_qmp.command.assert_called_with("migrate_cancel")

    def test_guest_exec(self, mocker):
        """Test that guest_exec calls the correct QGA command."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_qga.command.return_value = {"pid": 12345}
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.guest_exec("/bin/bash", ["-c", "echo test"])

        assert result["pid"] == 12345
        # Verify the command was sent through QGA, not QMP
        mock_qga.command.assert_called_with(
            "guest-exec", path="/bin/bash", arg=["-c", "echo test"], **{"capture-output": True}
        )
        mock_qmp.command.assert_not_called()

    def test_guest_exec_status(self, mocker):
        """Test that guest_exec_status returns command status via QGA."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_qga.command.return_value = {"exited": True, "exitcode": 0}
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.guest_exec_status(12345)

        assert result["exited"] is True
        assert result["exitcode"] == 0
        # Verify the command was sent through QGA, not QMP
        mock_qga.command.assert_called_with("guest-exec-status", pid=12345)
        mock_qmp.command.assert_not_called()

    def test_reconfigure_guest_network(self, mocker):
        """Test that reconfigure_guest_network creates correct netplan config via QGA."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_qga.command.return_value = {"pid": 12345}
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.reconfigure_guest_network(
            new_ip="10.0.0.5/24",
            gateway="10.0.0.1",
            nameservers=["8.8.8.8", "8.8.4.4"],
        )

        assert result["pid"] == 12345
        # Verify guest-exec was called on QGA with bash
        call_args = mock_qga.command.call_args
        assert call_args[0][0] == "guest-exec"
        assert call_args[1]["path"] == "/bin/bash"
        mock_qmp.command.assert_not_called()

    def test_wait_for_guest_agent_success(self, mocker):
        """Test wait_for_guest_agent returns True when agent responds via QGA."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_qga.command.return_value = {}  # guest-ping returns empty dict
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )
        mocker.patch("aleph.vm.controllers.qemu.client.time.sleep")
        mocker.patch("aleph.vm.controllers.qemu.client.time.monotonic", side_effect=[0, 1])

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.wait_for_guest_agent(timeout_seconds=10)

        assert result is True
        mock_qga.command.assert_called_with("guest-ping")

    def test_wait_for_guest_agent_timeout(self, mocker):
        """Test wait_for_guest_agent returns False on timeout."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_qga.command.side_effect = Exception("Guest agent not available")
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )
        mocker.patch("aleph.vm.controllers.qemu.client.time.sleep")
        # Simulate time passing
        mocker.patch("aleph.vm.controllers.qemu.client.time.monotonic", side_effect=[0, 5, 11])

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        result = client.wait_for_guest_agent(timeout_seconds=10)

        assert result is False

    def test_client_raises_on_missing_socket(self, mocker):
        """Test that client raises exception when QMP socket doesn't exist."""
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = False

        from aleph.vm.controllers.qemu.client import QemuVmClient

        with pytest.raises(Exception, match="VM is not running"):
            QemuVmClient(mock_vm)

    def test_guest_exec_raises_when_qga_unavailable(self, mocker):
        """Test that guest_exec raises when QGA socket is not available."""
        mock_qmp = mocker.Mock()
        mock_vm = mocker.Mock()
        mock_vm.qmp_socket_path = mocker.Mock()
        mock_vm.qmp_socket_path.exists.return_value = True
        mock_vm.qga_socket_path = mocker.Mock()
        mock_vm.qga_socket_path.exists.return_value = False

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            return_value=mock_qmp,
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        with pytest.raises(Exception, match="QEMU Guest Agent socket is not available"):
            client.guest_exec("/bin/bash", ["-c", "echo test"])

    def test_close_closes_both_clients(self, mocker):
        """Test that close() closes both QMP and QGA connections."""
        mock_qmp = mocker.Mock()
        mock_qga = mocker.Mock()
        mock_vm = _make_mock_vm(mocker)

        mocker.patch(
            "aleph.vm.controllers.qemu.client.qmp.QEMUMonitorProtocol",
            side_effect=[mock_qmp, mock_qga],
        )

        from aleph.vm.controllers.qemu.client import QemuVmClient

        client = QemuVmClient(mock_vm)
        client.close()

        mock_qmp.close.assert_called_once()
        mock_qga.close.assert_called_once()
