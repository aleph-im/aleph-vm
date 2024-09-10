import asyncio
import logging

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import Settings, settings
from aleph.vm.controllers.firecracker import AlephFirecrackerProgram
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.storage import get_message


@pytest.mark.asyncio
async def test_create_execution(mocker):
    """
    Create a new VM execution and check that it starts properly.
    """
    mock_settings = Settings()
    mocker.patch("aleph.vm.conf.settings", new=mock_settings)
    mocker.patch("aleph.vm.storage.settings", new=mock_settings)
    mocker.patch("aleph.vm.controllers.firecracker.executable.settings", new=mock_settings)
    mocker.patch("aleph.vm.controllers.firecracker.program.settings", new=mock_settings)

    if not mock_settings.FAKE_DATA_RUNTIME.exists():
        pytest.xfail("Test Runtime not setup. run `cd runtimes/aleph-debian-12-python && sudo ./create_disk_image.sh`")

    mock_settings.FAKE_DATA_PROGRAM = mock_settings.BENCHMARK_FAKE_DATA_PROGRAM
    mock_settings.ALLOW_VM_NETWORKING = False
    mock_settings.USE_JAILER = False

    logging.basicConfig(level=logging.DEBUG)
    mock_settings.PRINT_SYSTEM_LOGS = True

    # Ensure that the settings are correct and required files present.
    mock_settings.setup()
    mock_settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
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


# This test depends on having a vm-connector running on port 4021
@pytest.mark.asyncio
async def test_create_execution_online(vm_hash: ItemHash = None):
    """
    Create a new VM execution without building it locally and check that it starts properly.
    """

    vm_hash = vm_hash or settings.CHECK_FASTAPI_VM_ID

    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    message, original_message = await load_updated_message(vm_hash)

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message.content,
        original=original_message.content,
        snapshot_manager=None,
        systemd_manager=None,
        persistent=False,
    )

    # Downloading the resources required may take some time, limit it to 120 seconds
    # since it is a bit slow in GitHub Actions
    await asyncio.wait_for(execution.prepare(), timeout=120)

    vm = execution.create(vm_id=3, tap_interface=None)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephFirecrackerProgram)
    vm.enable_console = True
    vm.fvm.enable_log = True
    assert vm.vm_id == 3

    await execution.start()
    await execution.stop()


# This test depends on having a vm-connector running on port 4021
@pytest.mark.asyncio
async def test_create_execution_legacy():
    """
    Create a new VM execution based on the legacy FastAPI check and ensure that it starts properly.
    """
    await test_create_execution_online(vm_hash=settings.LEGACY_CHECK_FASTAPI_VM_ID)
