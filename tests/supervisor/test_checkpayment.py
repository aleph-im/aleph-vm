from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import Chain, InstanceContent, ItemHash, PaymentType
from aleph_message.status import MessageStatus

from aleph.vm.agent.tasks import _group_executions_by_payment, check_payment
from aleph.vm.agent.vm.retire import RetireReason
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)


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


def _make_supervisor(infos: list[VmInfo] | None = None) -> MagicMock:
    """Return a fake Supervisor with delete_vm as an AsyncMock and list_vms returning infos."""
    supervisor = MagicMock(delete_vm=AsyncMock())
    supervisor.list_vms = AsyncMock(return_value=infos or [])
    return supervisor


def _make_registry() -> AgentVmRegistry:
    """Return a real AgentVmRegistry (check_payment groups via the registry)."""
    return AgentVmRegistry()


def _make_info(vm_hash: str, *, started_at_ns: int = 0, confidential: bool = False) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_hash),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        started_at_ns=started_at_ns,
        confidential_mode=ConfidentialMode.SEV if confidential else ConfidentialMode.NONE,
    )


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
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)

    registry = _make_registry()
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(vm_hashes):
        return 500 * len(list(vm_hashes))

    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", compute_required_flow)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    await check_payment(supervisor=supervisor, registry=registry)
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
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=False)

    registry = _make_registry()
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=500, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(vm_hashes):
        return 500 * len(list(vm_hashes))

    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", compute_required_flow)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    await check_payment(supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_called()


@pytest.mark.asyncio
async def test_not_enough_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)

    registry = _make_registry()
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=2, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    await check_payment(supervisor=supervisor, registry=registry)

    # Insufficient-funds stop: retire_vm is called with GONE, not supervisor.delete_vm
    # directly.
    retire.assert_awaited_once_with(ItemHash(hash), RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_not_enough_community_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    async def get_stream(sender, receiver, chain):
        if receiver == mock_community_wallet_address:
            return 0
        elif receiver == settings.PAYMENT_RECEIVER_ADDRESS:
            return 10

    mocker.patch("aleph.vm.agent.tasks.get_stream", new=get_stream)
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    await check_payment(supervisor=supervisor, registry=registry)

    # Insufficient-funds stop: retire_vm is called with GONE, not supervisor.delete_vm
    # directly.
    retire.assert_awaited_once_with(ItemHash(hash), RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_message_removing_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.REMOVING)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadece"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    await check_payment(supervisor=supervisor, registry=registry)

    supervisor.delete_vm.assert_not_called()
    assert ItemHash(hash) in registry


@pytest.mark.asyncio
async def test_removed_message_status(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")

    registry = _make_registry()
    mock_community_wallet_address = "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90"

    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=400, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value=mock_community_wallet_address)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.REMOVED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadece"
    info = _make_info(hash)
    supervisor = _make_supervisor([info])
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)

    executions_by_sender = _group_executions_by_payment([info], registry, PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert list(executions_by_sender["0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9"][Chain.BASE]) == [info]

    # Consecutive-confirmation counter requires 3 checks before stopping
    await check_payment(supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_called()

    await check_payment(supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_called()

    await check_payment(supervisor=supervisor, registry=registry)
    # Terminal-status dealloc retires the VM as GONE: retire_vm owns the
    # supervisor quiesce, the registry forget and the persisted record cleanup.
    retire.assert_awaited_once_with(ItemHash(hash), RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_terminal_status_retires_as_gone(mocker, fake_instance_content):
    from aleph.vm.agent import tasks

    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.FORGOTTEN)
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    # The payment loops still run over the same snapshot: keep them satisfied
    # so only the terminal-status branch retires anything.
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=10_000, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=0)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    tasks._terminal_strike_count.clear()

    # settings.FAKE_INSTANCE_ID is explicitly skipped by the terminal-status
    # loop (it has no real on-chain message to check), so use a distinct hash
    # here, same as test_removed_message_status does.
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadecf"
    vm_hash = ItemHash(hash)
    registry = _make_registry()
    message = InstanceContent.model_validate(fake_instance_content)
    registry.record(vm_hash, message=message, original=message, persistent=True)
    info = _make_info(hash)
    supervisor = _make_supervisor([info])

    for _ in range(tasks.STOP_AFTER_CONFIRMATIONS):
        await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_awaited_once_with(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_insufficient_stream_retires_as_gone(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=2, autospec=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    registry = _make_registry()
    message = InstanceContent.model_validate(fake_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    vm_hash = ItemHash(hash)
    registry.record(vm_hash, message=message, original=message, persistent=False)
    info = _make_info(hash)
    supervisor = _make_supervisor([info])

    await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_awaited_once_with(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
