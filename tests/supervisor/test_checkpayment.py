import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import Chain, InstanceContent, ItemHash, PaymentType
from aleph_message.status import MessageStatus

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.tasks import _group_executions_by_payment, check_payment
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.pool import VmPool
from aleph.vm.supervisor.types import VmId


@pytest.fixture()
def fake_instance_content():
    fake = {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
        "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
        "payment": {"type": "superfluid", "chain": "BASE"},
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

    return fake


def _make_supervisor() -> MagicMock:
    """Return a fake Supervisor with delete_vm as an AsyncMock."""
    return MagicMock(delete_vm=AsyncMock())


def _make_registry() -> AgentVmRegistry:
    """Return a real AgentVmRegistry (check_payment groups via the registry)."""
    return AgentVmRegistry()


@pytest.mark.asyncio
async def test_enough_flow(mocker, fake_instance_content):
    """Execution with community flow

    Cost 500
    Community 100
    CRN 400
    Both Flow are 500.
    Should not stop

    """
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.is_after_community_wallet_start", return_value=True)

    loop = asyncio.get_event_loop()
    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(executions):
        return 500 * len(executions)

    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", compute_required_flow)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    mocker.patch.object(VmExecution, "is_running", new=True)
    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))

    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    assert execution.times.started_at is None

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)
    assert pool.executions == {hash: execution}
    execution.stop.assert_not_called()
    supervisor.delete_vm.assert_not_called()


@pytest.mark.asyncio
async def test_enough_flow_not_community(mocker, fake_instance_content):
    """Execution without community flow

    Cost 500
    Community 0
    CRN 500
    Both Flow are 500.
    Should not stop

    """
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.is_after_community_wallet_start", return_value=False)

    loop = asyncio.get_event_loop()
    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=500, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(executions):
        return 500 * len(executions)

    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", compute_required_flow)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    mocker.patch.object(VmExecution, "is_running", new=True)
    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))

    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    assert execution.times.started_at is None

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)
    assert pool.executions == {hash: execution}
    execution.stop.assert_not_called()
    supervisor.delete_vm.assert_not_called()


@pytest.mark.asyncio
async def test_not_enough_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)

    loop = asyncio.get_event_loop()
    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=2, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.model_validate(fake_instance_content)

    mocker.patch.object(VmExecution, "is_running", new=True)
    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)

    # Insufficient-funds stop: supervisor.delete_vm is called, registry.forget is NOT called
    # (VM may be re-paid and restarted).
    supervisor.delete_vm.assert_awaited_once_with(VmId(str(hash)))
    assert ItemHash(hash) in registry


@pytest.mark.asyncio
async def test_not_enough_community_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    loop = asyncio.get_event_loop()
    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    async def get_stream(sender, receiver, chain):
        if receiver == mock_community_wallet_address:
            return 0
        elif receiver == settings.PAYMENT_RECEIVER_ADDRESS:
            return 10

    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", new=get_stream)
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.model_validate(fake_instance_content)

    mocker.patch.object(VmExecution, "is_running", new=True)
    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)

    # Insufficient-funds stop: supervisor.delete_vm is called, registry.forget is NOT called.
    supervisor.delete_vm.assert_awaited_once_with(VmId(str(hash)))
    assert ItemHash(hash) in registry


@pytest.mark.asyncio
async def test_message_removing_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.REMOVING)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.model_validate(fake_instance_content)

    mocker.patch.object(VmExecution, "is_running", new=True)
    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadece"
    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)

    supervisor.delete_vm.assert_not_called()
    assert ItemHash(hash) in registry


@pytest.mark.asyncio
async def test_removed_message_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    pool = VmPool()
    supervisor = _make_supervisor()
    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.REMOVED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    mock_delete_port_mappings = mocker.patch(
        "aleph.vm.orchestrator.tasks.delete_port_mappings", new_callable=mocker.AsyncMock
    )
    message = InstanceContent.model_validate(fake_instance_content)

    mocker.patch.object(VmExecution, "is_running", new=True)
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadece"
    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )

    pool.executions = {hash: execution}
    registry.record(ItemHash(hash), message=message, original=message, persistent=execution.persistent)

    executions_by_sender = _group_executions_by_payment(pool, registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    # Consecutive-confirmation counter requires 3 checks before stopping
    await check_payment(pool=pool, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_called()

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_called()

    await check_payment(pool=pool, supervisor=supervisor, registry=registry)
    # Terminal-status dealloc: supervisor.delete_vm + delete_port_mappings (residual) + registry.forget
    supervisor.delete_vm.assert_awaited_once_with(VmId(str(hash)))
    mock_delete_port_mappings.assert_awaited_once_with(hash)
    assert ItemHash(hash) not in registry
    # pool.stop_vm and pool.forget_vm must NOT be called
