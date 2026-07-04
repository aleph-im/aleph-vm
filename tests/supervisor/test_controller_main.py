"""The controller process entry point (supervisor/controllers/__main__.py):
config-file loading, the NETWORK_INTERFACE guard, and --print-settings."""

import json
from unittest.mock import AsyncMock

import pytest

import aleph.vm.supervisor.controllers.__main__ as controller_main


def _write_config(tmp_path, settings_dict: dict):
    config = {
        "vm_id": 3,
        "vm_hash": "cafe" * 16,
        "settings": settings_dict,
        "vm_configuration": {
            "use_jailer": False,
            "firecracker_bin_path": "/opt/firecracker",
            "jailer_bin_path": "/opt/jailer",
            "config_file_path": "/tmp/config.json",
            "init_timeout": 30.0,
        },
        "hypervisor": "firecracker",
    }
    path = tmp_path / "controller.json"
    path.write_text(json.dumps(config))
    return path


def test_main_exits_when_config_has_no_network_interface(tmp_path, mocker):
    """A config with no NETWORK_INTERFACE (never written by a healthy
    supervisor, conceivable in a hand-edited or truncated file) must exit
    with a clear error instead of crashing inside Network()."""
    config_path = _write_config(tmp_path, {})
    mocker.patch("sys.argv", ["controller", "-c", str(config_path)])

    with pytest.raises(SystemExit) as excinfo:
        controller_main.main()

    assert excinfo.value.code == 1


def test_main_print_settings_shows_the_controller_slice(tmp_path, mocker, capsys):
    config_path = _write_config(tmp_path, {"NETWORK_INTERFACE": "eth0"})
    mocker.patch("sys.argv", ["controller", "-c", str(config_path), "--print-settings"])
    mocker.patch.object(controller_main, "Network")
    mocker.patch.object(controller_main, "run_persistent_vm", new=AsyncMock())

    controller_main.main()

    printed = capsys.readouterr().out
    assert '"NETWORK_INTERFACE": "eth0"' in printed
    # Only the controller slice, not a full node-settings dump.
    assert "CONNECTIVITY" not in printed
    assert "SUPERVISOR_GRPC_SOCKET" not in printed


def test_main_exits_when_config_file_is_missing(tmp_path, mocker):
    mocker.patch("sys.argv", ["controller", "-c", str(tmp_path / "nope.json")])

    with pytest.raises(SystemExit) as excinfo:
        controller_main.main()

    assert excinfo.value.code == 1
