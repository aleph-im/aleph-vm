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
async def test_check_payment_tolerates_a_non_hash_vm_id(mocker):
    """One supervisor id that is not an item hash must not take the whole
    payment sweep down: it is dropped at the snapshot (the reconciler's
    supervisor_hashes rule) and the other VMs are still checked."""
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x23C7")
    status = mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)

    checked = "cafe" * 16  # not FAKE_INSTANCE_ID, which the sweep skips
    supervisor = _make_supervisor([_make_info("not-an-item-hash"), _make_info(checked)])

    await check_payment(supervisor=supervisor, registry=_make_registry())

    status.assert_awaited_once_with(ItemHash(checked))
    retire.assert_not_awaited()


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

    await _sweep_until_confirmed(supervisor, registry, retire)

    # Insufficient-funds stop: retire_vm is called with GONE, not supervisor.delete_vm
    # directly.
    retire.assert_awaited_once_with(ItemHash(hash), RetireReason.GONE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


async def _sweep_until_confirmed(supervisor, registry, retire) -> None:
    """Run the sweep the number of times a shortfall must be seen before it
    retires anything, checking that the earlier sweeps retired nothing."""
    from aleph.vm.agent import tasks

    tasks._shortfall_strike_count.clear()
    for _ in range(tasks.STOP_AFTER_CONFIRMATIONS - 1):
        await check_payment(supervisor=supervisor, registry=registry)
        retire.assert_not_awaited()
    await check_payment(supervisor=supervisor, registry=registry)


@pytest.mark.asyncio
async def test_a_shortfall_that_clears_resets_its_confirmations(mocker, fake_instance_content):
    """Two sweeps short, one covered, two short again: nothing is retired.
    One bad API answer, or a top-up that lands between two sweeps, must not
    add up to a stop."""
    from aleph.vm.agent import tasks

    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", return_value=5)
    stream = mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=2, autospec=True)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    tasks._shortfall_strike_count.clear()

    registry = _make_registry()
    message = InstanceContent.model_validate(fake_instance_content)
    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    registry.record(ItemHash(hash), message=message, original=message, persistent=False)
    supervisor = _make_supervisor([_make_info(hash)])

    for flow in (2, 2, 10_000, 2, 2):
        stream.return_value = flow
        await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_not_awaited()
    assert tasks._shortfall_strike_count == {hash: 2}


@pytest.mark.asyncio
async def test_the_youngest_vm_is_the_one_found_short_on_every_sweep(mocker, fake_instance_content):
    """With two VMs and room for one, the same VM must be short on each sweep
    for its confirmations to add up, whatever order the supervisor lists them
    in: the most recently started one goes."""
    from aleph.vm.agent import tasks

    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch("aleph.vm.agent.tasks.get_community_wallet_address", return_value="0x" + "1" * 40)
    mocker.patch("aleph.vm.agent.tasks.is_after_community_wallet_start", return_value=True)
    mocker.patch("aleph.vm.agent.tasks.get_message_status", return_value=MessageStatus.PROCESSED)

    async def compute_required_flow(vm_hashes):
        return 5 * len(list(vm_hashes))

    mocker.patch("aleph.vm.agent.tasks.compute_required_flow", compute_required_flow)
    mocker.patch("aleph.vm.agent.tasks.get_stream", return_value=6, autospec=True)
    retire = mocker.patch("aleph.vm.agent.tasks.retire_vm", new_callable=AsyncMock)
    tasks._shortfall_strike_count.clear()

    registry = _make_registry()
    message = InstanceContent.model_validate(fake_instance_content)
    old, young = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca", "cafe" * 16
    for vm_hash in (old, young):
        registry.record(ItemHash(vm_hash), message=message, original=message, persistent=False)
    old_info, young_info = _make_info(old, started_at_ns=1), _make_info(young, started_at_ns=2)

    for listing in ([old_info, young_info], [young_info, old_info], [old_info, young_info]):
        supervisor = _make_supervisor(listing)
        await check_payment(supervisor=supervisor, registry=registry)

    retire.assert_awaited_once()
    assert retire.await_args.args[0] == ItemHash(young)


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

    await _sweep_until_confirmed(supervisor, registry, retire)

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

    await _sweep_until_confirmed(supervisor, registry, retire)

    retire.assert_awaited_once_with(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
