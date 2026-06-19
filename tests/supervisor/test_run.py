from datetime import datetime, timezone
from pathlib import Path

from aleph_message.models import ItemHash
from conftest import make_spec

from aleph.vm.models import VmExecution
from aleph.vm.supervisor_interface.types import DirectoryPath, TeeBackend, TeeConfig

VM_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


def _tee() -> TeeConfig:
    return TeeConfig(
        backend=TeeBackend.SEV,
        policy="0x1",
        session_dir=DirectoryPath(Path("/tmp/session")),
        firmware_path=Path("/data/firmware.fd"),
    )


def make_execution(*, mocker, confidential: bool = False, controller_active: bool = False) -> VmExecution:
    """Build a persistent spec-built execution whose systemd controller state is mocked."""
    spec = make_spec(vm_hash=str(VM_HASH), persistent=True, tee=_tee() if confidential else None)
    systemd_manager = mocker.Mock(is_service_active=mocker.Mock(return_value=controller_active))
    return VmExecution.from_spec(spec, snapshot_manager=None, systemd_manager=systemd_manager)


def mark_started(execution: VmExecution) -> None:
    """Put the execution in the state left by VmExecution.start()."""
    execution.times.starting_at = datetime.now(tz=timezone.utc)
    execution.times.started_at = datetime.now(tz=timezone.utc)
    execution.ready_event.set()


def test_confidential_instance_awaits_init_after_start(mocker):
    """A confidential VM created but not yet initialized by its owner must be
    reported as awaiting its confidential initialization, not as some unknown state."""
    execution = make_execution(mocker=mocker, confidential=True)
    mark_started(execution)

    assert execution.is_running is False
    assert execution.is_awaiting_confidential_init is True


def test_confidential_instance_not_awaiting_init_once_controller_runs(mocker):
    """Once the owner initialized the VM (controller service active), it is running."""
    execution = make_execution(mocker=mocker, confidential=True, controller_active=True)
    mark_started(execution)

    assert execution.is_running is True
    assert execution.is_awaiting_confidential_init is False


def test_confidential_instance_not_awaiting_init_when_stopping(mocker):
    execution = make_execution(mocker=mocker, confidential=True)
    mark_started(execution)
    execution.times.stopping_at = datetime.now(tz=timezone.utc)

    assert execution.is_awaiting_confidential_init is False


def test_non_confidential_instance_never_awaits_init(mocker):
    execution = make_execution(mocker=mocker, confidential=False)
    mark_started(execution)

    assert execution.is_awaiting_confidential_init is False
