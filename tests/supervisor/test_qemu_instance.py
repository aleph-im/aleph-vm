import asyncio
import logging
from asyncio.subprocess import Process
from pathlib import Path

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.controllers.__main__ import configuration_from_file, execute_persistent_vm
from aleph.vm.controllers.qemu import AlephQemuInstance
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM
from aleph.vm.models import VmExecution
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.orchestrator import metrics
from aleph.vm.storage import get_message
from aleph.vm.systemd import SystemDManager
from aleph.vm.vm_type import VmType


@pytest.mark.asyncio
class MockSystemDManager(SystemDManager):
    execution: QemuVM | None = None
    process: Process | None = None

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
async def test_create_qemu_instance():
    """
    Create an instance and check that it start / init / stop properly.
    """

    settings.USE_FAKE_INSTANCE_BASE = True
    settings.FAKE_INSTANCE_MESSAGE = settings.FAKE_INSTANCE_QEMU_MESSAGE
    settings.FAKE_INSTANCE_BASE = settings.FAKE_QEMU_INSTANCE_BASE
    settings.ENABLE_CONFIDENTIAL_COMPUTING = False
    settings.ALLOW_VM_NETWORKING = False
    settings.USE_JAILER = False
    if not settings.FAKE_INSTANCE_BASE.exists():
        pytest.xfail("Test Runtime not setup. run `cd runtimes/instance-rootfs && sudo ./create-debian-12-disk.sh`")

    logging.basicConfig(level=logging.DEBUG)

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

    await asyncio.wait_for(execution.prepare(), timeout=60)
    vm_id = 3

    vm = execution.create(vm_id=vm_id, tap_interface=None)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephQemuInstance)
    assert vm.vm_id == vm_id

    await execution.start()
    qemu_execution, process = await mock_systemd_manager.enable_and_start(execution.vm_hash)
    assert isinstance(qemu_execution, QemuVM)
    assert qemu_execution.qemu_process is not None
    qemu_execution, process = await mock_systemd_manager.stop_and_disable(execution.vm_hash)
    await execution.stop()
    assert qemu_execution is None


@pytest.mark.asyncio
async def test_create_qemu_instance_online():
    """
    Create an instance and check that it start / init / stop properly.
    """

    settings.USE_FAKE_INSTANCE_BASE = True
    settings.FAKE_INSTANCE_MESSAGE = settings.FAKE_INSTANCE_QEMU_MESSAGE
    settings.FAKE_INSTANCE_BASE = settings.FAKE_QEMU_INSTANCE_BASE
    settings.ENABLE_CONFIDENTIAL_COMPUTING = False
    settings.ALLOW_VM_NETWORKING = True
    settings.USE_JAILER = False

    logging.basicConfig(level=logging.DEBUG)

    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()
    if not settings.FAKE_INSTANCE_BASE.exists():
        pytest.xfail("Test Runtime not setup. run `cd runtimes/instance-rootfs && sudo ./create-debian-12-disk.sh`")

    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    message = await get_message(ref=vm_hash)

    mock_systemd_manager = MockSystemDManager()

    network = (
        Network(
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
        if settings.ALLOW_VM_NETWORKING
        else None
    )

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message.content,
        original=message.content,
        snapshot_manager=None,
        systemd_manager=None,
        persistent=True,
    )

    await asyncio.wait_for(execution.prepare(), timeout=60)
    vm_id = 3

    vm_type = VmType.from_message_content(message.content)
    tap_interface = await network.prepare_tap(vm_id, vm_hash, vm_type)
    await network.create_tap(vm_id, tap_interface)

    vm = execution.create(vm_id=vm_id, tap_interface=tap_interface)

    # Test that the VM is created correctly. It is not started yet.
    assert isinstance(vm, AlephQemuInstance)
    assert vm.vm_id == vm_id

    await execution.start()
    qemu_execution, process = await mock_systemd_manager.enable_and_start(execution.vm_hash)
    assert isinstance(qemu_execution, QemuVM)
    assert qemu_execution.qemu_process is not None
    await execution.wait_for_persistent_boot()
    qemu_execution, process = await mock_systemd_manager.stop_and_disable(execution.vm_hash)
    await execution.stop()
    assert qemu_execution is None
