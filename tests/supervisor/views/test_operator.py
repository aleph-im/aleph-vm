import pytest

from aleph.vm.orchestrator.supervisor import setup_webapp


@pytest.mark.asyncio
async def test_reboot_ok(aiohttp_client, mocker):
    mock_address = "mock_address"
    mock_hash = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=mock_address,
    )

    class FakeVmPool:
        executions = {
            mock_hash: mocker.Mock(
                vm_hash=mock_hash,
                message=mocker.Mock(address=mock_address),
                is_confidential=False,
                is_running=True,
            ),
        }
        systemd_manager = mocker.Mock(restart=mocker.Mock())

    app = setup_webapp()
    pool = FakeVmPool()
    app["vm_pool"] = pool
    app["pubsub"] = FakeVmPool()
    client = await aiohttp_client(app)
    response = await client.post(
        f"/control/machine/{mock_hash}/reboot",
    )
    assert response.status == 200
    assert (
        await response.text() == "Rebooted VM with ref fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"
    )
    assert pool.systemd_manager.restart.call_count == 1
