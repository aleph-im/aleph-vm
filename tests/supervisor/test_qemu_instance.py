import asyncio
import logging
import tempfile
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

    async def enable_and_start(self, service: str) -> tuple[QemuVM | None, Process | None]:
        # aleph-vm-controller@decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca.service-controller.json
        vm_hash = service.split("@", maxsplit=1)[1].split(".", maxsplit=1)[0]

        config_path = Path(f"{settings.EXECUTION_ROOT}/{vm_hash}-controller.json")
        config = configuration_from_file(config_path)
        self.execution, self.process = await execute_persistent_vm(config)
        return self.execution, self.process

    def is_service_enabled(self, service: str):
        return self.process is not None

    def is_service_active(self, service: str):
        return self.process is not None and not self.process.returncode

    async def stop_and_disable(self, vm_hash: str):
        if self.process:
            self.process.kill()
        self.process = None
        self.execution = None
        return self.execution, self.process


@pytest.mark.asyncio
async def test_create_qemu_instance(mocker):
    """
    Create an instance and check that it start / init / stop properly.
    No network.
    We don't actually check that the system ping since there is no network
    """
    original_linux_path = settings.LINUX_PATH
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", False)
    mocker.patch.object(settings, "USE_FAKE_INSTANCE_BASE", True)
    mocker.patch.object(settings, "FAKE_INSTANCE_MESSAGE", settings.FAKE_INSTANCE_QEMU_MESSAGE)
    mocker.patch.object(settings, "FAKE_INSTANCE_BASE", settings.FAKE_QEMU_INSTANCE_BASE)
    mocker.patch.object(settings, "ENABLE_CONFIDENTIAL_COMPUTING", False)
    mocker.patch.object(settings, "USE_JAILER", False)
    tmp_dir = tempfile.TemporaryDirectory(prefix="alephtest_")
    tmp_path = Path(tmp_dir.name)
    cache_root = tmp_path / "cache"
    exec_root = tmp_path / "exec"
    mocker.patch.object(settings, "CACHE_ROOT", cache_root)
    mocker.patch.object(settings, "EXECUTION_ROOT", exec_root)
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", exec_root / "volumes" / "persistent")
    mocker.patch.object(settings, "JAILER_BASE_DIRECTORY", exec_root / "jailer")
    mocker.patch.object(settings, "EXECUTION_LOG_DIRECTORY", exec_root / "executions")

    # Patch journal.stream so the output of qemu process is shown in the test output
    mocker.patch("aleph.vm.hypervisors.qemu.qemuvm.journal.stream", return_value=None)

    if not settings.FAKE_INSTANCE_BASE.exists():
        pytest.xfail(
            "Test Runtime not setup. run `cd runtimes/instance-rootfs && sudo ./create-debian-12-qemu-disk.sh`"
        )

    logging.basicConfig(level=logging.DEBUG)
    logger = logging.getLogger(__name__)
    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()
    logger.info(settings.EXECUTION_ROOT)
    logger.info(settings.PERSISTENT_VOLUMES_DIR)

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

    await asyncio.wait_for(execution.start(), timeout=120)
    qemu_execution, process = await mock_systemd_manager.enable_and_start(execution.controller_service)
    assert isinstance(qemu_execution, QemuVM)
    assert qemu_execution.qemu_process is not None
    await asyncio.sleep(30)
    await mock_systemd_manager.stop_and_disable(execution.vm_hash)
    await qemu_execution.qemu_process.wait()
    assert qemu_execution.qemu_process.returncode is not None
    await asyncio.wait_for(execution.stop(), timeout=60)
    settings.LINUX_PATH = original_linux_path


@pytest.mark.asyncio
async def test_create_qemu_instance_online(mocker):
    """
    Create an instance and check that it start / init / stop properly.
    With network, wait for ping
    """
    original_linux_path = settings.LINUX_PATH
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", True)
    mocker.patch.object(settings, "USE_FAKE_INSTANCE_BASE", True)
    mocker.patch.object(settings, "FAKE_INSTANCE_MESSAGE", settings.FAKE_INSTANCE_QEMU_MESSAGE)
    mocker.patch.object(settings, "FAKE_INSTANCE_BASE", settings.FAKE_QEMU_INSTANCE_BASE)
    mocker.patch.object(settings, "ENABLE_CONFIDENTIAL_COMPUTING", False)
    mocker.patch.object(settings, "USE_JAILER", False)

    tmp_dir = tempfile.TemporaryDirectory(prefix="alephtest_")
    tmp_path = Path(tmp_dir.name)
    cache_root = tmp_path / "cache"
    exec_root = tmp_path / "exec"
    mocker.patch.object(settings, "CACHE_ROOT", cache_root)
    mocker.patch.object(settings, "EXECUTION_ROOT", exec_root)
    mocker.patch.object(settings, "PERSISTENT_VOLUMES_DIR", exec_root / "volumes" / "persistent")
    mocker.patch.object(settings, "JAILER_BASE_DIRECTORY", exec_root / "jailer")
    mocker.patch.object(settings, "EXECUTION_LOG_DIRECTORY", exec_root / "executions")

    # Patch journal.stream so the output of qemu process is shown in the test output
    mocker.patch("aleph.vm.hypervisors.qemu.qemuvm.journal.stream", return_value=None)

    if not settings.FAKE_INSTANCE_BASE.exists():
        pytest.xfail(
            f"Test instance disk {settings.FAKE_QEMU_INSTANCE_BASE} not setup. run `cd runtimes/instance-rootfs && sudo ./create-debian-12-qemu-disk.sh` "
        )
    logger = logging.getLogger(__name__)
    # Ensure that the settings are correct and required files present.
    settings.setup()
    settings.check()
    logger.info(settings.EXECUTION_ROOT)
    logger.info(settings.PERSISTENT_VOLUMES_DIR)
    # The database is required for the metrics and is currently not optional.
    engine = metrics.setup_engine()
    await metrics.create_tables(engine)

    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    message = await get_message(ref=vm_hash)

    mock_systemd_manager = MockSystemDManager()

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

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message.content,
        original=message.content,
        snapshot_manager=None,
        systemd_manager=mock_systemd_manager,
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

    await asyncio.wait_for(execution.start(), timeout=120)
    qemu_execution = mock_systemd_manager.execution
    assert isinstance(qemu_execution, QemuVM)
    assert qemu_execution.qemu_process is not None
    await execution.init_task
    assert execution.init_task.result() is True, "VM failed to start"
    qemu_execution, process = await mock_systemd_manager.stop_and_disable(execution.vm_hash)
    await asyncio.wait_for(execution.stop(), timeout=60)
    assert qemu_execution is None

    settings.LINUX_PATH = original_linux_path
