from datetime import datetime, timezone

import pytest
from aleph_message.models import InstanceContent, ItemHash

from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.run import start_persistent_vm

VM_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")
FIRMWARE_HASH = "facefacefacefacefacefacefacefacefacefacefacefacefacefacefaceface"


@pytest.fixture()
def instance_content() -> dict:
    return {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
        "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
        "payment": {"type": "hold", "chain": "ETH"},
        "requirements": None,
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 1000,
        },
    }


@pytest.fixture()
def confidential_instance_content(instance_content) -> dict:
    instance_content["environment"]["hypervisor"] = "qemu"
    instance_content["environment"]["trusted_execution"] = {"policy": 1, "firmware": FIRMWARE_HASH}
    return instance_content


def make_execution(
    content: dict,
    mocker,
    *,
    controller_active: bool = False,
    active_state: str | None = None,
) -> VmExecution:
    """Build a persistent execution whose systemd controller state is mocked.

    ``active_state`` sets ``get_service_active_state``'s return value
    (used by the new "check systemd state before stopping" logic in
    ``start_persistent_vm``).
    """
    message = InstanceContent.model_validate(content)
    systemd_manager = mocker.Mock(
        is_service_active=mocker.Mock(return_value=controller_active),
        get_service_active_state=mocker.Mock(return_value=active_state or "unknown"),
    )
    return VmExecution(
        vm_hash=VM_HASH,
        message=message,
        original=message,
        snapshot_manager=None,
        systemd_manager=systemd_manager,
        persistent=True,
    )


def mark_started(execution: VmExecution) -> None:
    """Put the execution in the state left by VmExecution.start()."""
    execution.times.starting_at = datetime.now(tz=timezone.utc)
    execution.times.started_at = datetime.now(tz=timezone.utc)
    execution.ready_event.set()


def test_confidential_instance_awaits_init_after_start(confidential_instance_content, mocker):
    """A confidential VM created but not yet initialized by its owner must be
    reported as awaiting its confidential initialization, not as some unknown state."""
    execution = make_execution(confidential_instance_content, mocker)
    mark_started(execution)

    assert execution.is_running is False
    assert execution.is_awaiting_confidential_init is True


def test_confidential_instance_not_awaiting_init_once_controller_runs(confidential_instance_content, mocker):
    """Once the owner initialized the VM (controller service active), it is running."""
    execution = make_execution(confidential_instance_content, mocker, controller_active=True)
    mark_started(execution)

    assert execution.is_running is True
    assert execution.is_awaiting_confidential_init is False


def test_confidential_instance_not_awaiting_init_when_stopping(confidential_instance_content, mocker):
    execution = make_execution(confidential_instance_content, mocker)
    mark_started(execution)
    execution.times.stopping_at = datetime.now(tz=timezone.utc)

    assert execution.is_awaiting_confidential_init is False


def test_non_confidential_instance_never_awaits_init(instance_content, mocker):
    execution = make_execution(instance_content, mocker)
    mark_started(execution)

    assert execution.is_awaiting_confidential_init is False
