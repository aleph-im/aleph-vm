"""save_controller_configuration must be atomic.

The controller configs are what a (re)starting supervisor daemon adopts
running VMs from; a plain in-place truncate-and-write leaves a window where
a reader (notably the Rust daemon scanning EXECUTION_ROOT during a handoff)
sees a truncated file and drops the VM. The write must therefore go through
a same-directory temporary file and os.replace, so the destination path
only ever holds either the previous complete config or the new one.
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    VMConfiguration,
    get_controller_configuration_path,
    save_controller_configuration,
)

VM_HASH = "cafe" * 16


def _configuration() -> Configuration:
    return Configuration(
        vm_id=3,
        vm_hash=VM_HASH,
        settings=ControllerSettings(),
        vm_configuration=VMConfiguration(
            use_jailer=False,
            firecracker_bin_path="/opt/firecracker/firecracker",
            jailer_bin_path="/opt/firecracker/jailer",
            config_file_path="/tmp/config.json",
            init_timeout=30.0,
        ),
        hypervisor=HypervisorType.firecracker,
    )


@pytest.fixture
def execution_root(monkeypatch, tmp_path: Path) -> Path:
    monkeypatch.setattr(settings, "EXECUTION_ROOT", tmp_path)
    return tmp_path


def test_save_writes_the_config_and_leaves_no_temporary_file(execution_root: Path):
    path = save_controller_configuration(VM_HASH, _configuration())

    assert path == get_controller_configuration_path(VM_HASH)
    assert json.loads(path.read_text())["vm_hash"] == VM_HASH
    assert path.stat().st_mode & 0o777 == 0o644
    assert [entry for entry in execution_root.iterdir()] == [path]


def test_save_replaces_atomically_never_exposing_a_partial_file(execution_root: Path, monkeypatch):
    # An older config is already on disk: the handoff window under test.
    target = get_controller_configuration_path(VM_HASH)
    target.write_text("OLD COMPLETE CONFIG")

    observed: dict[str, Any] = {}
    real_replace = os.replace

    def observing_replace(src, dst):
        # At replace time the destination still holds the previous complete
        # content and the source already holds the FULL new payload: at no
        # instant can a reader observe a truncated configuration.
        observed["destination_before"] = Path(dst).read_text()
        observed["source_payload"] = json.loads(Path(src).read_text())
        return real_replace(src, dst)

    monkeypatch.setattr(os, "replace", observing_replace)
    save_controller_configuration(VM_HASH, _configuration())

    assert observed["destination_before"] == "OLD COMPLETE CONFIG"
    assert observed["source_payload"]["vm_hash"] == VM_HASH
    assert json.loads(target.read_text())["vm_hash"] == VM_HASH


def test_a_failed_replace_keeps_the_old_config_and_cleans_the_temp_file(execution_root: Path, monkeypatch):
    target = get_controller_configuration_path(VM_HASH)
    target.write_text("OLD COMPLETE CONFIG")

    def failing_replace(src, dst):
        msg = "disk on fire"
        raise OSError(msg)

    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(OSError, match="disk on fire"):
        save_controller_configuration(VM_HASH, _configuration())

    assert target.read_text() == "OLD COMPLETE CONFIG"
    assert [entry for entry in execution_root.iterdir()] == [target]
