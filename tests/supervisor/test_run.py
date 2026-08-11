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


@pytest.mark.asyncio
async def test_start_persistent_vm_keeps_confidential_instance_awaiting_init(confidential_instance_content, mocker):
    """An allocation for a confidential VM waiting for its owner's session must not
    stop and recreate it (it would loop forever: the VM can only start once the
    owner uploads the session certificates via /confidential/initialize)."""
    execution = make_execution(confidential_instance_content, mocker)
    mark_started(execution)
    execution.vm = mocker.Mock()

    stop_mock = mocker.patch.object(execution, "stop", new=mocker.AsyncMock())
    create_mock = mocker.patch("aleph.vm.orchestrator.run.create_vm_execution", new=mocker.AsyncMock())

    pool = mocker.Mock(executions={VM_HASH: execution})

    result = await start_persistent_vm(VM_HASH, pubsub=None, pool=pool)

    assert result is execution
    stop_mock.assert_not_called()
    create_mock.assert_not_called()
    pool.forget_vm.assert_not_called()


# --- start_persistent_vm's transient-state guard -----------------------------
#
# Regression tests for the "unknown execution state, stopping the vm" branch.
# Right after a start, systemd may still be `activating` for a few hundred
# milliseconds: is_running is False (state != "active"), is_starting is False
# (started_at was already set optimistically), is_stopping is False. A second
# allocation POST landing in that window used to fall through and stop the VM,
# whose graceful shutdown then SIGKILLed because the firecracker API socket
# wasn't accepting connections yet — corrupting the BTRFS rootfs. The guard
# checks systemd's real state and only stops on definitively-terminal states.


@pytest.mark.parametrize("transient_state", ["active", "activating", "unknown"])
@pytest.mark.asyncio
async def test_start_persistent_vm_does_not_stop_on_transient_systemd_state(instance_content, mocker, transient_state):
    execution = make_execution(instance_content, mocker, active_state=transient_state)
    mark_started(execution)
    execution.vm = mocker.Mock()

    stop_mock = mocker.patch.object(execution, "stop", new=mocker.AsyncMock())
    create_mock = mocker.patch("aleph.vm.orchestrator.run.create_vm_execution", new=mocker.AsyncMock())

    pool = mocker.Mock(executions={VM_HASH: execution})

    result = await start_persistent_vm(VM_HASH, pubsub=None, pool=pool)

    # Together these assertions prove the transient branch returned
    # early without touching state: the same execution came back, no
    # stop was issued (neither on the wrapper nor on execution.vm),
    # no recreation happened, and the pool was not asked to forget it.
    assert result is execution
    stop_mock.assert_not_called()
    execution.vm.stop.assert_not_called()
    create_mock.assert_not_called()
    pool.forget_vm.assert_not_called()


@pytest.mark.parametrize("terminal_state", ["failed", "inactive", "deactivating"])
@pytest.mark.asyncio
async def test_start_persistent_vm_stops_and_recreates_on_terminal_systemd_state(
    instance_content, mocker, terminal_state
):
    execution = make_execution(instance_content, mocker, active_state=terminal_state)
    mark_started(execution)
    execution.vm = mocker.Mock()

    stop_mock = mocker.patch.object(execution, "stop", new=mocker.AsyncMock())
    new_execution = mocker.Mock()
    new_execution.becomes_ready = mocker.AsyncMock()
    new_execution.cancel_expiration = mocker.Mock()
    create_mock = mocker.patch(
        "aleph.vm.orchestrator.run.create_vm_execution",
        new=mocker.AsyncMock(return_value=new_execution),
    )

    pool = mocker.Mock(executions={VM_HASH: execution})

    result = await start_persistent_vm(VM_HASH, pubsub=None, pool=pool)

    stop_mock.assert_awaited_once()
    create_mock.assert_awaited_once()
    assert result is new_execution


# --- Batched running_states lookup -----------------------------------------
#
# On CRNs with many persistent VMs, iterating executions and calling
# execution.is_running per VM issues O(N) synchronous D-Bus round-trips on
# the event loop. update_allocations now snapshots the state once via
# get_services_active_states off-thread and passes the map to
# start_persistent_vm (and to get_persistent_executions). These tests pin
# the "map wins over D-Bus" invariant so a future refactor can't silently
# reintroduce the per-VM lookup.


@pytest.mark.asyncio
async def test_start_persistent_vm_uses_running_states_map_for_fast_path(instance_content, mocker):
    """When running_states says the VM is running, do not touch systemd."""
    execution = make_execution(instance_content, mocker, controller_active=False)
    mark_started(execution)
    execution.vm = mocker.Mock()

    stop_mock = mocker.patch.object(execution, "stop", new=mocker.AsyncMock())
    create_mock = mocker.patch("aleph.vm.orchestrator.run.create_vm_execution", new=mocker.AsyncMock())

    pool = mocker.Mock(executions={VM_HASH: execution})
    running_states = {execution.controller_service: True}

    result = await start_persistent_vm(VM_HASH, pubsub=None, pool=pool, running_states=running_states)

    assert result is execution
    stop_mock.assert_not_called()
    create_mock.assert_not_called()
    # Per-VM D-Bus should have been bypassed entirely.
    execution.systemd_manager.is_service_active.assert_not_called()
    execution.systemd_manager.get_service_active_state.assert_not_called()


@pytest.mark.asyncio
async def test_start_persistent_vm_running_states_missing_service_falls_through(instance_content, mocker):
    """Missing entry in running_states means 'not running per the batch snapshot'.

    Since this is our controlled fast-path decision, the code should treat
    it as False (not-running) and follow the same else-branch logic as
    when execution.is_running would have returned False - i.e. check the
    real systemd state before deciding to stop or leave alone.
    """
    execution = make_execution(instance_content, mocker, active_state="active")
    mark_started(execution)
    execution.vm = mocker.Mock()

    stop_mock = mocker.patch.object(execution, "stop", new=mocker.AsyncMock())
    create_mock = mocker.patch("aleph.vm.orchestrator.run.create_vm_execution", new=mocker.AsyncMock())

    pool = mocker.Mock(executions={VM_HASH: execution})
    running_states: dict[str, bool] = {}  # deliberately empty: no snapshot for this service

    result = await start_persistent_vm(VM_HASH, pubsub=None, pool=pool, running_states=running_states)

    # Falls through to the transient-state guard which sees 'active' and
    # returns the execution unchanged. Confirms the map path composes
    # correctly with the systemd-state check in the else branch.
    assert result is execution
    stop_mock.assert_not_called()
    create_mock.assert_not_called()


def test_get_persistent_executions_uses_running_states_map(instance_content, mocker):
    """pool.get_persistent_executions with a map must NOT call is_running per-VM."""
    from aleph.vm.pool import VmPool

    execution_up = make_execution(instance_content, mocker)
    execution_up.vm_hash = ItemHash("a" * 64)

    execution_down = make_execution(instance_content, mocker)
    execution_down.vm_hash = ItemHash("b" * 64)

    pool = VmPool.__new__(VmPool)
    pool.executions = {execution_up.vm_hash: execution_up, execution_down.vm_hash: execution_down}

    running_states = {
        execution_up.controller_service: True,
        execution_down.controller_service: False,
    }

    result = list(pool.get_persistent_executions(running_states=running_states))

    assert result == [execution_up]
    execution_up.systemd_manager.is_service_active.assert_not_called()
    execution_down.systemd_manager.is_service_active.assert_not_called()
