import asyncio

import pytest
from aleph_message.models import Chain, InstanceContent, PaymentType
from aleph_message.status import MessageStatus

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.tasks import check_payment
from aleph.vm.pool import VmPool


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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)
    assert pool.executions == {hash: execution}
    execution.stop.assert_not_called()


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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)
    assert pool.executions == {hash: execution}
    execution.stop.assert_not_called()


@pytest.mark.asyncio
async def test_not_enough_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)

    loop = asyncio.get_event_loop()
    pool = VmPool()
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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)

    execution.stop.assert_called_with()


@pytest.mark.asyncio
async def test_not_enough_community_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    loop = asyncio.get_event_loop()
    pool = VmPool()
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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)

    execution.stop.assert_called_with()


@pytest.mark.asyncio
async def test_message_removing_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    pool = VmPool()
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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)

    execution.stop.assert_not_called()


@pytest.mark.asyncio
async def test_removed_message_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    pool = VmPool()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.REMOVED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    mocker.patch("aleph.vm.orchestrator.tasks.delete_port_mappings", new_callable=mocker.AsyncMock)
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

    executions_by_sender = pool.get_executions_by_address(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    # Consecutive-confirmation counter requires 3 checks before stopping
    mock_stop_vm = mocker.patch.object(pool, "stop_vm", new=mocker.AsyncMock())
    mock_forget_vm = mocker.patch.object(pool, "forget_vm")

    await check_payment(pool=pool)
    mock_stop_vm.assert_not_called()

    await check_payment(pool=pool)
    mock_stop_vm.assert_not_called()

    await check_payment(pool=pool)
    mock_stop_vm.assert_called_once_with(hash)
    mock_forget_vm.assert_called_once_with(hash)


@pytest.mark.asyncio
async def test_persistent_vm_uses_batched_running_states(mocker, fake_instance_content):
    """check_payment batches systemd state lookups for persistent VMs.

    Verifies that the asyncio.to_thread + get_services_active_states
    path is taken (single batched D-Bus call) instead of the per-VM
    is_running property, and that the returned dict drives the filter
    in get_executions_by_address.
    """
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch(
        "aleph.vm.orchestrator.tasks.get_community_wallet_address",
        return_value=mock_community_wallet_address,
    )
    mocker.patch("aleph.vm.orchestrator.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(executions):
        return 500 * len(executions)

    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", compute_required_flow)

    message = InstanceContent.model_validate(fake_instance_content)
    hash_active = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadec0"
    hash_inactive = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadec1"

    mocker.patch.object(VmExecution, "stop", new=mocker.AsyncMock(return_value=False))

    systemd_manager = mocker.Mock()
    systemd_manager.get_services_active_states = mocker.Mock(
        return_value={
            f"aleph-vm-controller@{hash_active}.service": True,
            f"aleph-vm-controller@{hash_inactive}.service": False,
        }
    )

    pool = VmPool()
    pool.systemd_manager = systemd_manager

    active_execution = VmExecution(
        vm_hash=hash_active,
        message=message,
        original=message,
        persistent=True,
        snapshot_manager=None,
        systemd_manager=systemd_manager,
    )
    inactive_execution = VmExecution(
        vm_hash=hash_inactive,
        message=message,
        original=message,
        persistent=True,
        snapshot_manager=None,
        systemd_manager=systemd_manager,
    )
    pool.executions = {hash_active: active_execution, hash_inactive: inactive_execution}

    await check_payment(pool=pool)

    systemd_manager.get_services_active_states.assert_called_once()
    queried_services = set(systemd_manager.get_services_active_states.call_args.args[0])
    assert queried_services == {
        f"aleph-vm-controller@{hash_active}.service",
        f"aleph-vm-controller@{hash_inactive}.service",
    }

    by_sender = pool.get_executions_by_address(
        payment_type=PaymentType.superfluid,
        running_states={
            f"aleph-vm-controller@{hash_active}.service": True,
            f"aleph-vm-controller@{hash_inactive}.service": False,
        },
    )
    listed = [e for chains in by_sender.values() for executions in chains.values() for e in executions]
    assert active_execution in listed
    assert inactive_execution not in listed
