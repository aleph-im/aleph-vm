"""The owner-signed single-VM notification starts the VM without a payment check."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, MessageType

from aleph.vm.agent.supervisor import setup_webapp

VM_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


@pytest.mark.asyncio
async def test_notify_allocation_does_not_check_payment(aiohttp_client, mocker):
    """No balance, price or stream lookup stands between the message and the
    create call: payment is the scheduler's and the CCN's to enforce, and a VM
    started past either is swept by the next allocation that omits it."""
    message = MagicMock()
    message.type = MessageType.instance
    message.content.requirements = None
    message.content.payment.type = "superfluid"
    mocker.patch("aleph.vm.agent.views.try_get_message", return_value=message)
    mocker.patch("aleph.vm.agent.views.update_aggregate_settings", new_callable=AsyncMock)
    mocker.patch("aleph.vm.agent.views.sync_domain_mappings", new_callable=AsyncMock)
    start = mocker.patch("aleph.vm.agent.views.start_persistent_vm", new_callable=AsyncMock)

    app = setup_webapp(supervisor=MagicMock())
    app["pubsub"] = None
    client = await aiohttp_client(app)
    response = await client.post("/control/allocation/notify", json={"instance": str(VM_HASH)})

    assert response.status == 200, await response.text()
    assert (await response.json())["successful"] is True
    assert start.await_args.args[0] == VM_HASH
