"""Operator endpoints that retire through ``retire_vm``.

Split out of the old ``tests/supervisor/views/test_operator.py``, which was
removed with the Python supervisor daemon: these cases only ever needed a
``Supervisor``, so they drive ``setup_webapp`` with a mock of that interface.

Covers the erase/stop/reboot/reinstall paths converted to ``retire_vm`` and
the erase of data the supervisor has forgotten (a retained ``.reclaimable``
directory), whose owner is proven from the marker or the agent DB.
"""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import TrustedExecutionEnvironment

from aleph.vm.agent import metrics
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.agent.views.operator import _security_aggregate_cache
from aleph.vm.agent.vm.reclaimable import ReclaimableMarker
from aleph.vm.agent.vm.retire import RetireReason
from aleph.vm.conf import settings
from aleph.vm.storage import get_message
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)

_FAKE_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


def _vm_info(
    status: VmStatus = VmStatus.RUNNING,
    vm_id: str = _FAKE_HASH,
    confidential_mode: ConfidentialMode = ConfidentialMode.NONE,
    awaiting_confidential_init: bool = False,
) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_id),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=confidential_mode,
        awaiting_confidential_init=awaiting_confidential_init,
    )


def _fake_supervisor(status: VmStatus = VmStatus.RUNNING) -> MagicMock:
    return MagicMock(
        get_vm=AsyncMock(return_value=_vm_info(status)),
        delete_vm=AsyncMock(),
        stop_vm=AsyncMock(return_value=_vm_info(VmStatus.STOPPED)),
        start_vm=AsyncMock(return_value=_vm_info(VmStatus.RUNNING)),
        reboot_vm=AsyncMock(),
        freeze_guest=AsyncMock(return_value=True),
        thaw_guest=AsyncMock(),
    )


@pytest.fixture(autouse=True)
def _clear_caches():
    """Clear all API response caches between tests."""
    _security_aggregate_cache.clear()
    yield
    _security_aggregate_cache.clear()


@pytest.mark.asyncio
async def test_operator_erase_with_delegation(aiohttp_client, mocker):
    """Test that a delegated address can successfully erase a VM via the supervisor."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    delegated_address = "0x9999999999999999999999999999999999999999"
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=delegated_address,
    )

    # Mock the API response for security aggregate with valid delegation
    mock_response = mocker.AsyncMock()
    mock_response.json = mocker.AsyncMock(
        return_value={
            "data": {
                "security": {
                    "authorizations": [
                        {
                            "address": delegated_address,
                            "types": ["INSTANCE"],
                        }
                    ]
                }
            }
        }
    )
    mock_response.raise_for_status = mocker.Mock()

    mock_session = mocker.AsyncMock()
    mock_session.get = mocker.AsyncMock(return_value=mock_response)
    mocker.patch("aleph.vm.agent.views.operator.get_session", return_value=mock_session)

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)
    client: TestClient = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{vm_hash}/erase",
    )

    assert response.status == 200
    retire.assert_awaited_once_with(vm_hash, RetireReason.ERASE, supervisor=fake_sup, registry=app["vm_registry"])
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_erase_when_the_supervisor_forgot_the_vm(aiohttp_client, mocker):
    """The supervisor forgets a VM on restart or after a delete while its
    disks stay. The registry still knows who owns them, so the owner's erase
    must go through instead of 404ing on the supervisor's ignorance."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=True,
    )
    fake_sup = _fake_supervisor()
    fake_sup.get_vm = AsyncMock(side_effect=VmNotFoundError(str(vm_hash)))
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/erase")

    assert response.status == 200
    retire.assert_awaited_once_with(vm_hash, RetireReason.ERASE, supervisor=fake_sup, registry=app["vm_registry"])


def _retained(owner: str | None):
    """A .reclaimable marker as retire_vm(GONE) leaves it under keep."""
    return ReclaimableMarker(
        reclaimable_since=datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc),
        reason="gone",
        size_bytes=4096,
        owner=owner,
    )


async def _erase_a_retained_vm(aiohttp_client, mocker, *, sender: str, marker):
    """Erase a VM the node only knows through its marker: no registry record,
    no DB rows (the state a GONE under keep actually leaves)."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    mocker.patch("aleph.vm.agent.views.authentication.authenticate_jwk", return_value=sender)
    mocker.patch("aleph.vm.agent.views.operator.retained_marker", return_value=marker)
    mocker.patch.object(metrics, "get_last_record_for_vm", AsyncMock(return_value=None))

    app = setup_webapp(supervisor=_fake_supervisor())
    fake_sup = _fake_supervisor()
    fake_sup.get_vm = AsyncMock(side_effect=VmNotFoundError(str(vm_hash)))
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/erase")
    return response, retire, app, fake_sup, vm_hash


@pytest.mark.asyncio
async def test_operator_erase_wipes_retained_data_for_its_owner(aiohttp_client, mocker):
    """Under VOLUME_RETENTION=keep a GONE drops the registry record and the DB
    rows and keeps the disks behind a .reclaimable marker. The marker's owner
    is the only thing left to authorize against, and the owner must be able to
    have their retained data wiped."""
    owner = "0x1234567890123456789012345678901234567890"

    response, retire, app, fake_sup, vm_hash = await _erase_a_retained_vm(
        aiohttp_client, mocker, sender=owner, marker=_retained(owner)
    )

    assert response.status == 200
    retire.assert_awaited_once_with(vm_hash, RetireReason.ERASE, supervisor=fake_sup, registry=app["vm_registry"])


@pytest.mark.asyncio
async def test_operator_erase_of_retained_data_by_a_stranger_is_403(aiohttp_client, mocker):
    """Retention is not a hole: only the marker's owner may wipe it."""
    response, retire, _app, _sup, _hash = await _erase_a_retained_vm(
        aiohttp_client,
        mocker,
        sender="0x9999999999999999999999999999999999999999",
        marker=_retained("0x1234567890123456789012345678901234567890"),
    )

    assert response.status == 403
    retire.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_erase_of_a_marker_without_an_owner_is_403(aiohttp_client, mocker):
    """A marker written before the owner field, or an orphan directory for a
    VM whose message this node never held: nothing can prove ownership, so
    nothing is wiped on request."""
    response, retire, _app, _sup, _hash = await _erase_a_retained_vm(
        aiohttp_client,
        mocker,
        sender="0x1234567890123456789012345678901234567890",
        marker=_retained(None),
    )

    assert response.status == 403
    retire.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_erase_of_a_hash_nothing_knows_is_404(aiohttp_client, mocker):
    """No record and no retained directory: there is nothing to erase."""
    settings.ENABLE_QEMU_SUPPORT = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mocker.patch("aleph.vm.agent.views.operator.retained_marker", return_value=None)
    mocker.patch.object(metrics, "get_last_record_for_vm", AsyncMock(return_value=None))

    app = setup_webapp(supervisor=_fake_supervisor())
    app["supervisor"] = _fake_supervisor()
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/erase")

    assert response.status == 404
    retire.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_stop_non_persistent_retires_as_recreate(aiohttp_client, mocker):
    """Stop a non-persistent (ephemeral) VM: no stop state, so the stop cycle
    is retire_vm(RECREATE), not stop_vm nor a plain delete_vm."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=False,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/stop")

    assert response.status == 200
    assert await response.text() == f"Stopped VM with ref {vm_hash}"
    retire.assert_awaited_once_with(vm_hash, RetireReason.RECREATE, supervisor=fake_sup)
    fake_sup.stop_vm.assert_not_awaited()
    fake_sup.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_operator_reboot_non_persistent(aiohttp_client, mocker):
    """Reboot a non-persistent VM: retire_vm(RECREATE) then
    create_vm_execution_or_raise_http_error called."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    mock_create_vm = mocker.patch(
        "aleph.vm.agent.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=False,
    )
    fake_sup = _fake_supervisor(VmStatus.RUNNING)
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reboot")

    assert response.status == 200
    assert await response.text() == f"Rebooted VM with ref {vm_hash}"
    retire.assert_awaited_once_with(vm_hash, RetireReason.RECREATE, supervisor=fake_sup)
    fake_sup.delete_vm.assert_not_awaited()
    fake_sup.reboot_vm.assert_not_awaited()
    mock_create_vm.assert_awaited_once_with(
        vm_hash=vm_hash,
        supervisor=fake_sup,
        registry=app["vm_registry"],
        capacity=app["capacity"],
    )


@pytest.mark.asyncio
async def test_operator_reinstall_persistent_confidential_rebuilds_from_scratch(aiohttp_client, mocker):
    """A persistent confidential instance is not reinstalled in place: its
    rootfs is measured and staged, so it goes delete -> purge -> create,
    keeping its host ports and its persistent flag."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)
    content = instance_message.content.model_copy(deep=True)
    content.environment.trusted_execution = TrustedExecutionEnvironment()

    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )
    mock_create_vm = mocker.patch(
        "aleph.vm.agent.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(vm_hash, message=content, original=content, persistent=True)
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)
    mock_purge = mocker.patch("aleph.vm.agent.views.operator.purge_vm_volumes")
    mock_staging = mocker.patch("aleph.vm.agent.views.operator.purge_vm_staging")
    mock_recreate = mocker.patch("aleph.vm.agent.views.operator.recreate_vm_volumes", new=AsyncMock())

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reinstall")

    assert response.status == 200
    fake_sup.stop_vm.assert_not_awaited()
    mock_recreate.assert_not_awaited()
    retire.assert_awaited_once_with(vm_hash, RetireReason.RECREATE, supervisor=fake_sup)
    fake_sup.delete_vm.assert_not_awaited()
    mock_purge.assert_called_once_with(vm_hash, include_data_volumes=True)
    mock_staging.assert_called_once_with(vm_hash)
    mock_create_vm.assert_awaited_once_with(
        vm_hash=vm_hash,
        supervisor=fake_sup,
        registry=app["vm_registry"],
        capacity=app["capacity"],
        persistent=True,
    )


@pytest.mark.asyncio
async def test_operator_reinstall_non_persistent_recreates(aiohttp_client, mocker):
    """Non-persistent record: the VM is deleted, its storage purged, and it is
    rebuilt through the create path."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    mocker.patch(
        "aleph.vm.agent.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    )

    mock_create_vm = mocker.patch(
        "aleph.vm.agent.views.operator.create_vm_execution_or_raise_http_error",
        new=AsyncMock(),
    )

    app = setup_webapp(supervisor=_fake_supervisor())
    app["vm_registry"].record(
        vm_hash,
        message=instance_message.content,
        original=instance_message.content,
        persistent=False,  # non-persistent
    )
    fake_sup = _fake_supervisor()
    app["supervisor"] = fake_sup
    retire = mocker.patch("aleph.vm.agent.views.operator.retire_vm", new_callable=AsyncMock)
    mock_purge = mocker.patch("aleph.vm.agent.views.operator.purge_vm_volumes")
    mock_staging = mocker.patch("aleph.vm.agent.views.operator.purge_vm_staging")

    client: TestClient = await aiohttp_client(app)
    response = await client.post(f"/control/machine/{vm_hash}/reinstall")

    assert response.status == 200
    # A delete+recreate cycle: RECREATE keeps the host ports for the
    # recreated VM to reload.
    retire.assert_awaited_once_with(vm_hash, RetireReason.RECREATE, supervisor=fake_sup)
    fake_sup.delete_vm.assert_not_awaited()
    mock_purge.assert_called_once_with(vm_hash, include_data_volumes=True)
    mock_staging.assert_called_once_with(vm_hash)
    mock_create_vm.assert_awaited_once_with(
        vm_hash=vm_hash,
        supervisor=fake_sup,
        registry=app["vm_registry"],
        capacity=app["capacity"],
        persistent=False,
    )
