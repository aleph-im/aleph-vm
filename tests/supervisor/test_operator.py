import io
import tempfile
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import aiohttp
import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.storage import get_message


@pytest.mark.asyncio
async def test_operator_confidential_initialize_not_authorized(aiohttp_client):
    """Test that the confidential initialize endpoint rejects if the sender is not the good one. Auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    class FakeExecution:
        message = None
        is_running: bool = True
        is_confidential: bool = False

    class FakeVmPool:
        executions: dict[ItemHash, FakeExecution] = {}

        def __init__(self):
            self.executions[settings.FAKE_INSTANCE_ID] = FakeExecution()

    with mock.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value="",
    ):
        with mock.patch(
            "aleph.vm.orchestrator.views.operator.is_sender_authorized",
            return_value=False,
        ) as is_sender_authorized_mock:
            app = setup_webapp()
            app["vm_pool"] = FakeVmPool()
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{settings.FAKE_INSTANCE_ID}/confidential/initialize",
            )
            assert response.status == 403
            assert await response.text() == "Unauthorized sender"
            is_sender_authorized_mock.assert_called_once()


@pytest.mark.asyncio
async def test_operator_confidential_initialize_already_running(aiohttp_client):
    """Test that the confidential initialize endpoint rejects if the VM is already running. Auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    class FakeExecution:
        message = instance_message.content
        is_running: bool = True
        is_confidential: bool = False

    class FakeVmPool:
        executions: dict[ItemHash, FakeExecution] = {}

        def __init__(self):
            self.executions[vm_hash] = FakeExecution()

    with mock.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=instance_message.sender,
    ):
        app = setup_webapp()
        app["vm_pool"] = FakeVmPool()
        client = await aiohttp_client(app)
        response = await client.post(
            f"/control/machine/{vm_hash}/confidential/initialize",
            json={"persistent_vms": []},
        )
        assert response.status == 403
        assert await response.text() == f"VM with ref {vm_hash} already running"


@pytest.mark.asyncio
async def test_operator_confidential_initialize(aiohttp_client):
    """Test that the certificates system endpoint responds. No auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    instance_message = await get_message(ref=vm_hash)

    class FakeExecution:
        message = instance_message.content
        is_running: bool = False
        is_confidential: bool = True
        controller_service: str = ""

    class MockSystemDManager:
        enable_and_start = MagicMock(return_value=True)

    class FakeVmPool:
        executions: dict[ItemHash, FakeExecution] = {}

        def __init__(self):
            self.executions[vm_hash] = FakeExecution()
            self.systemd_manager = MockSystemDManager()

    with tempfile.NamedTemporaryFile() as temp_file:
        form_data = aiohttp.FormData()
        form_data.add_field("session", open(temp_file.name, "rb"), filename="session.b64")
        form_data.add_field("godh", open(temp_file.name, "rb"), filename="godh.b64")

        with mock.patch(
            "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
            return_value=instance_message.sender,
        ):
            app = setup_webapp()
            app["vm_pool"] = FakeVmPool()
            client = await aiohttp_client(app)
            response = await client.post(
                f"/control/machine/{vm_hash}/confidential/initialize",
                data=form_data,
            )
            assert response.status == 200
            assert await response.text() == f"Started VM with ref {vm_hash}"
            app["vm_pool"].systemd_manager.enable_and_start.assert_called_once()
