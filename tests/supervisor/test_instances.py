import asyncio
import logging
from pathlib import Path
from typing import Optional
from asyncio.subprocess import Process
import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker import AlephFirecrackerInstance
from aleph.vm.controllers.__main__ import configuration_from_file, execute_persistent_vm
from aleph.vm.hypervisors.firecracker.microvm import MicroVM
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.storage import get_message
from aleph.vm.systemd import SystemDManager
from aleph.vm.vm_type import VmType
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from unittest.mock import AsyncMock

@pytest.mark.asyncio
class MockSystemDManager(SystemDManager):
    execution: Optional[MicroVM] = None
    process: Optional[Process] = None

    async def enable_and_start(self, vm_hash: str):
        config_path = Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-controller.json")
        config = configuration_from_file(config_path)
        self.execution, self.process = await execute_persistent_vm(config)
        return self.execution, self.process

    def is_service_enabled(self, service: str):
        return self.process is not None

    def is_service_active(self, service: str):
        return self.process is not None

    async def stop_and_disable(self, vm_hash: str):
        if self.process:
            self.process.kill()
        self.process = None
        self.execution = None
        return self.execution, self.process


@pytest.mark.asyncio
async def test_create_instance():
    """
    Create an instance and check that it start / init / stop properly.
    """

    settings.USE_FAKE_INSTANCE_BASE = True
    settings.FAKE_DATA_PROGRAM = settings.BENCHMARK_FAKE_DATA_PROGRAM
    settings.ALLOW_VM_NETWORKING = True
    settings.USE_JAILER = False

    logging.basicConfig(level=logging.DEBUG)
    settings.PRINT_SYSTEM_LOGS = True

    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    message = await get_message(ref=vm_hash)

    mock_systemd_manager = MockSystemDManager()

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message.content,
        original=message.content,
        snapshot_manager=None,
        systemd_manager=None,
        persistent=True,
    )

    # Downloading the resources required may take some time, limit it to 10 seconds
    await asyncio.wait_for(execution.prepare(), timeout=30)

    # Creating a Network to initialize the tap_interface that is needed for the creation of an instance
    network = Network(
        vm_ipv4_address_pool_range=settings.IPV4_ADDRESS_POOL,
        vm_network_size=settings.IPV4_NETWORK_PREFIX_LENGTH,
        external_interface=settings.NETWORK_INTERFACE,
        ipv6_allocator=make_ipv6_allocator(
            allocation_policy=settings.IPV6_ALLOCATION_POLICY,
            address_pool=settings.IPV6_ADDRESS_POOL,
            subnet_prefix=settings.IPV6_SUBNET_PREFIX,
        ),
        use_ndp_proxy=False,
        ipv6_forwarding_enabled=False,
    )
    network.setup()

    tap_interface = await network.prepare_tap(3, vm_hash, VmType.instance)
    await network.create_tap(3, tap_interface)

    vm = execution.create(vm_id=3, tap_interface=tap_interface)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephFirecrackerInstance)
    assert vm.vm_id == 3
    assert vm.persistent
    assert vm.enable_networking

    await execution.start()
    firecracker_execution, process = await mock_systemd_manager.enable_and_start(execution.vm_hash)
    assert isinstance(firecracker_execution, MicroVM)
    assert firecracker_execution.proc is not None
    firecracker_execution, process = await mock_systemd_manager.stop_and_disable(execution.vm_hash)
    await execution.stop()
    assert firecracker_execution is None
