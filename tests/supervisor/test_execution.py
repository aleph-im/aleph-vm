import asyncio
import logging
from typing import Any

import pytest
from aleph_message import parse_message
from aleph_message.models import ItemHash

from aleph.vm.conf import Settings, settings
from aleph.vm.controllers.firecracker import AlephFirecrackerProgram
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.storage import get_message
from aleph.vm.utils import fix_message_validation


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
    await asyncio.wait_for(execution.prepare(), timeout=300)

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
    await asyncio.wait_for(execution.prepare(), timeout=300)

    vm = execution.create(vm_id=3, tap_interface=None)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephFirecrackerProgram)
    vm.enable_console = True
    vm.fvm.enable_log = True
    assert vm.vm_id == 3

    await execution.start()
    await execution.stop()


@pytest.fixture()
def fake_message():
    fake = {
        "sender": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "chain": "ETH",
        "signature": "0x12592841210ef84888315d12b9c39225b8ba6b958b067790540a7971a95e8d4e6ce81deeb8e1f05f6141d8d62218641be1aa9b335463cdc5a43354205d4c9e351c",
        "type": "PROGRAM",
        "item_type": "inline",
        "item_hash": "63faf8b5db1cf8d965e6a464a0cb8062af8e7df131729e48738342d956f29ace",
        "time": "2024-04-23T12:10:41.801703+00:00",
        "channel": None,
        "content": {
            "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
            "time": 1713874241.800818,
            "allow_amend": False,
            "metadata": None,
            "authorized_keys": None,
            "variables": None,
            "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
            "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
            "payment": None,
            "requirements": None,
            "volumes": [
                {
                    "comment": "Persistence",
                    "mount": "/var/lib/example",
                    "parent": None,
                    "persistence": "host",
                    "name": "increment-storage",
                    "size_mib": 1,
                },
            ],
            "replaces": None,
            "type": "vm-function",
            "code": {
                "encoding": "zip",
                "entrypoint": "main:app",
                "ref": "79f19811f8e843f37ff7535f634b89504da3d8f03e1f0af109d1791cf6add7af",
                "interface": None,
                "args": None,
                "use_latest": True,
            },
            "runtime": {
                "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
                "use_latest": True,
                "comment": "",
            },
            "data": None,
            "export": None,
            "on": {"http": True, "message": None, "persistent": False},
        },
        "confirmed": True,
        "confirmations": [
            {
                "chain": "ETH",
                "height": 19718321,
                "hash": "0x4b8f9f232602ef8ca9bf0ba4fd907f1feef2bfc865a32b2c51fa40b72fa5ba49",
            }
        ],
    }

    return fake


def drop_none_recursively(data: dict) -> dict:
    """
    Recursively removes keys with None values from a dictionary.

    """
    if not isinstance(data, dict):
        return data  # Base case: if not a dictionary, return as-is.

    cleaned_dict: dict[Any, Any] = {}

    for key, value in data.items():
        if value is None:
            continue  # Skip keys with None values.
        elif isinstance(value, dict):
            # Recur for nested dictionaries.
            nested_cleaned = drop_none_recursively(value)
            if nested_cleaned:  # Include only if not empty.
                cleaned_dict[key] = nested_cleaned
        elif isinstance(value, list):
            # Recur for dictionaries within lists.
            cleaned_list = [drop_none_recursively(item) if isinstance(item, dict) else item for item in value]
            cleaned_dict[key] = [item for item in cleaned_list if item]
        else:
            cleaned_dict[key] = value  # Keep other values.

    return cleaned_dict


@pytest.mark.asyncio
async def test_create_execution_from_fake_message(fake_message):
    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    fake_message = drop_none_recursively(fake_message)
    fix_message_validation(fake_message)

    parsed_fake_message = parse_message(message_dict=fake_message)

    message, original_message = parsed_fake_message, parsed_fake_message

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
    await asyncio.wait_for(execution.prepare(), timeout=300)

    vm = execution.create(vm_id=3, tap_interface=None)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephFirecrackerProgram)
    vm.enable_console = True
    vm.fvm.enable_log = True
    assert vm.vm_id == 3

    await execution.start()
    await execution.stop()


@pytest.mark.asyncio
async def test_create_execution_volume_with_no_name(fake_message):
    """Regression test for ALEPH-307: VM init fail if volume name is empty string"""

    vm_hash = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)
    volume_with_no_name = {
        "comment": "Persistence with no name",
        "mount": "/var/lib/example",
        "parent": None,
        "persistence": "host",
        "name": "",
        "size_mib": 1,
    }
    volume_with_no_mount = {
        "comment": "Persistence with no mount name",
        "mount": "",
        "parent": None,
        "persistence": "host",
        "name": "",
        "size_mib": 1,
    }
    fake_message["content"]["volumes"] = [volume_with_no_name, volume_with_no_mount]
    fake_message = drop_none_recursively(fake_message)
    fix_message_validation(fake_message)

    parsed_fake_message = parse_message(message_dict=fake_message)

    message, original_message = parsed_fake_message, parsed_fake_message

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
    await asyncio.wait_for(execution.prepare(), timeout=300)

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
