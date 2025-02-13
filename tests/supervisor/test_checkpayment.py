import asyncio
import pytest

from aleph.vm.conf import Settings, settings
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.tasks import check_payment
from aleph.vm.pool import VmPool
from aleph_message.models import InstanceContent, Chain
from aleph_message.models import PaymentType
from aleph_message.status import MessageStatus


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
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch.object(settings, "COMMUNITY_WALLET_ADDRESS", "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90")

    loop = asyncio.get_event_loop()
    pool = VmPool(loop=loop)
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=5, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.parse_obj(fake_instance_content)

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

    pool.executions = {hash: execution}

    executions_by_sender = pool.get_executions_by_sender(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)
    assert pool.executions == {hash: execution}
    execution.stop.assert_not_called()


@pytest.mark.asyncio
async def test_not_enough_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch.object(settings, "COMMUNITY_WALLET_ADDRESS", "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90")

    loop = asyncio.get_event_loop()
    pool = VmPool(loop=loop)
    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", return_value=2, autospec=True)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.parse_obj(fake_instance_content)

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

    executions_by_sender = pool.get_executions_by_sender(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)

    execution.stop.assert_called_with()


@pytest.mark.asyncio
async def test_not_enough_community_flow(mocker, fake_instance_content):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "PAYMENT_RECEIVER_ADDRESS", "0xD39C335404a78E0BDCf6D50F29B86EFd57924288")
    mocker.patch.object(settings, "COMMUNITY_WALLET_ADDRESS", "0x23C7A99d7AbebeD245d044685F1893aeA4b5Da90")

    loop = asyncio.get_event_loop()
    pool = VmPool(loop=loop)

    async def get_stream(sender, receiver, chain):
        if receiver == settings.COMMUNITY_WALLET_ADDRESS:
            return 0
        elif receiver == settings.PAYMENT_RECEIVER_ADDRESS:
            return 10

    mocker.patch("aleph.vm.orchestrator.tasks.get_stream", new=get_stream)
    mocker.patch("aleph.vm.orchestrator.tasks.get_message_status", return_value=MessageStatus.PROCESSED)
    mocker.patch("aleph.vm.orchestrator.tasks.compute_required_flow", return_value=5)
    message = InstanceContent.parse_obj(fake_instance_content)

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

    executions_by_sender = pool.get_executions_by_sender(payment_type=PaymentType.superfluid)
    assert len(executions_by_sender) == 1
    assert executions_by_sender == {"0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9": {Chain.BASE: [execution]}}

    await check_payment(pool=pool)

    execution.stop.assert_called_with()
