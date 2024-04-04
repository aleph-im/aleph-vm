import asyncio
import logging

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker import AlephFirecrackerProgram
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.storage import get_message


@pytest.mark.asyncio
async def test_create_execution():
    """
    Create a new VM execution and check that it starts properly.
    """

    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash("3fc0aa9569da840c43e7bd2033c3c580abb46b007527d6d20f2d4e98e867f7af")
    message = await get_message(ref=vm_hash)

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message.content,
        original=message.content,
        snapshot_manager=None,
        systemd_manager=None,
        persistent=False,
    )

    # Downloading the resources required may take some time, limit it to 10 seconds
    await asyncio.wait_for(execution.prepare(), timeout=30)

    vm = execution.create(vm_id=3, tap_interface=None)
    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephFirecrackerProgram)
    assert vm.vm_id == 3

    await execution.start()
    await execution.stop()
