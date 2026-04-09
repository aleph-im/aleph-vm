from unittest import mock

import pytest
from aleph_message.models import InstanceContent

from aleph.vm.resources import InsufficientResourcesError, get_gpu_devices


@pytest.fixture()
def mock_instance_content():
    fake = {
        "address": "0x9319Ad3B7A8E0eE24f2E639c40D8eD124C5520Ba",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
        "resources": {"vcpus": 4, "memory": 2048, "seconds": 30, "published_ports": None},
        "payment": {"type": "credit", "chain": "BASE"},
        "requirements": None,
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 10240,
        },
    }

    return fake


def mock_is_kernel_enabled_gpu(pci_host: str) -> bool:
    value = True if pci_host == "01:00.0" else False
    return value


def test_get_gpu_devices():
    class DevicesReturn:
        stdout: str = (
            '00:1f.0 "ISA bridge [0601]" "Intel Corporation [8086]" "Device [7a06]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.4 "SMBus [0c05]" "Intel Corporation [8086]" "Raptor Lake-S PCH SMBus Controller [7a23]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.5 "Serial bus controller [0c80]" "Intel Corporation [8086]" "Raptor Lake SPI (flash) Controller [7a24]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n01:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [27b0]" -ra1 -p00 "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [16fa]"'
            '\n01:00.1 "Audio device [0403]" "NVIDIA Corporation [10de]" "Device [22bc]" -ra1 -p00 "NVIDIA Corporation [10de]" "Device [16fa]"'
            '\n02:00.0 "Non-Volatile memory controller [0108]" "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [a80a]" -p02 "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [aa0a]"'
        )

    with mock.patch(
        "subprocess.run",
        return_value=DevicesReturn(),
    ):
        with mock.patch(
            "aleph.vm.resources.is_kernel_enabled_gpu",
            wraps=mock_is_kernel_enabled_gpu,
        ):
            expected_gpu_devices = get_gpu_devices()

            assert expected_gpu_devices[0].vendor == "NVIDIA"
            assert expected_gpu_devices[0].device_name == "AD104GL [RTX 4000 SFF Ada Generation]"
            assert expected_gpu_devices[0].device_class == "0300"
            assert expected_gpu_devices[0].pci_host == "01:00.0"
            assert expected_gpu_devices[0].device_id == "10de:27b0"


def _make_pool(
    mocker,
    *,
    physical_memory_mib: int,
    physical_cores: int,
    available_disk_mib: int,
    host_reserved_mib: int = 0,
    program_reserved_mib: int = 0,
):
    """Build a VmPool stub with just enough state for check_admission.

    Tests pass explicit reservation values so the bucket math is clear
    in each scenario, rather than depending on the production defaults.
    """
    from aleph.vm.conf import settings
    from aleph.vm.pool import VmPool  # local import keeps module-level import light

    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    mocker.patch.object(
        pool,
        "calculate_available_disk",
        return_value=available_disk_mib * 1024 * 1024,
    )
    mocker.patch(
        "aleph.vm.pool.psutil.virtual_memory",
        return_value=mocker.MagicMock(total=physical_memory_mib * 1024 * 1024),
    )
    mocker.patch("aleph.vm.pool.psutil.cpu_count", return_value=physical_cores)
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", host_reserved_mib)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", program_reserved_mib)
    return pool


def _make_program_execution(hash_: str, memory_mib: int, vcpus: int):
    """Build a mock execution object for a running program."""
    execution = mock.MagicMock()
    execution.is_instance = False
    execution.vm_hash = hash_
    execution.message.resources.memory = memory_mib
    execution.message.resources.vcpus = vcpus
    return execution


def _make_instance_execution(hash_: str, memory_mib: int, vcpus: int):
    """Build a mock execution object for a running instance."""
    execution = mock.MagicMock()
    execution.is_instance = True
    execution.vm_hash = hash_
    execution.message.resources.memory = memory_mib
    execution.message.resources.vcpus = vcpus
    return execution


def test_check_admission_passes_with_ample_capacity(mocker, mock_instance_content):
    # 16 GiB physical, 4 GiB host reserved, 4 GiB program reserved
    # → instance cap = 8 GiB. Instance requests 2 GiB. Plenty of room.
    pool = _make_pool(
        mocker,
        physical_memory_mib=16384,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=4096,
        program_reserved_mib=4096,
    )
    content = InstanceContent.model_validate(mock_instance_content)
    pool.check_admission(content)


def test_check_admission_refuses_insufficient_instance_memory(mocker, mock_instance_content):
    # 4 GiB physical, 1 GiB host reserved, 1 GiB program reserved
    # → instance cap = 2 GiB. Instance requests 2048 MiB, an existing
    # instance already consumes 1 GiB, leaving 1 GiB. Refused.
    pool = _make_pool(
        mocker,
        physical_memory_mib=4096,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=1024,
        program_reserved_mib=1024,
    )
    pool.executions["existing"] = _make_instance_execution(hash_="existing", memory_mib=1024, vcpus=1)
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="instance bucket"):
        pool.check_admission(content)


def test_check_admission_refuses_insufficient_vcpus(mocker, mock_instance_content):
    # Instance requests 4 vCPUs; host has 1 core x 4.0 overcommit = 4 cap,
    # and an already-committed instance takes 1 vCPU, leaving 3.
    pool = _make_pool(
        mocker,
        physical_memory_mib=16384,
        physical_cores=1,
        available_disk_mib=20480,
        host_reserved_mib=0,
        program_reserved_mib=0,
    )
    pool.executions["existing"] = _make_instance_execution(hash_="existing", memory_mib=128, vcpus=1)
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="vCPUs"):
        pool.check_admission(content)


def test_check_admission_refuses_insufficient_disk(mocker, mock_instance_content):
    # Instance requests 10240 MiB of rootfs; only 5120 MiB available.
    pool = _make_pool(
        mocker,
        physical_memory_mib=16384,
        physical_cores=8,
        available_disk_mib=5120,
        host_reserved_mib=0,
        program_reserved_mib=0,
    )
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="Disk"):
        pool.check_admission(content)


def test_check_admission_skips_renotify_of_running_instance(mocker, mock_instance_content):
    # Even if capacity is exhausted, a re-notify for an already-running VM
    # must pass — the instance is already accounted for.
    pool = _make_pool(
        mocker,
        physical_memory_mib=512,
        physical_cores=1,
        available_disk_mib=100,
    )
    pool.executions["abc"] = mock.MagicMock()
    content = InstanceContent.model_validate(mock_instance_content)
    pool.check_admission(content, current_vm_hash="abc")


def test_check_admission_excludes_current_hash_from_committed(mocker, mock_instance_content):
    # An instance being re-evaluated (e.g. restart) must not count against
    # itself when it is not yet in the pool but its hash is supplied.
    pool = _make_pool(
        mocker,
        physical_memory_mib=16384,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=0,
        program_reserved_mib=0,
    )
    content = InstanceContent.model_validate(mock_instance_content)
    pool.check_admission(content, current_vm_hash="not-in-pool")


def test_check_admission_instance_cannot_eat_program_reservation(mocker, mock_instance_content):
    # 6 GiB physical, 0 host reserved, 4 GiB program reserved.
    # Instance cap = 6 - 0 - 4 = 2 GiB. A 2048 MiB instance request with
    # no committed state must still be refused because 2 GiB is the
    # absolute ceiling for instances and the fixture requests exactly
    # that. We commit 1 MiB first to push the request just over.
    pool = _make_pool(
        mocker,
        physical_memory_mib=6144,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=0,
        program_reserved_mib=4096,
    )
    pool.executions["tiny"] = _make_instance_execution(hash_="tiny", memory_mib=1, vcpus=0)
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="instance bucket"):
        pool.check_admission(content)


def test_check_admission_program_gets_reserved_space_when_instances_full(mocker):
    # Physical 8 GiB, 0 host reserved, 2 GiB program reserved.
    # Instance cap = 6 GiB. Fill instance bucket entirely.
    # A program requesting 512 MiB must still be admitted because the
    # program bucket has its own budget untouched by instances.
    pool = _make_pool(
        mocker,
        physical_memory_mib=8192,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=0,
        program_reserved_mib=2048,
    )
    pool.executions["huge-instance"] = _make_instance_execution(hash_="huge-instance", memory_mib=6144, vcpus=2)
    program_content = _fake_program_content(memory_mib=512, vcpus=1)
    pool.check_admission(program_content)


def test_check_admission_refuses_program_exceeding_program_bucket(mocker):
    # Physical 8 GiB, 0 host reserved, 1 GiB program reserved.
    # A program asking for 2 GiB cannot fit in the 1 GiB bucket even
    # though the instance bucket has tons of room.
    pool = _make_pool(
        mocker,
        physical_memory_mib=8192,
        physical_cores=8,
        available_disk_mib=20480,
        host_reserved_mib=0,
        program_reserved_mib=1024,
    )
    program_content = _fake_program_content(memory_mib=2048, vcpus=1)
    with pytest.raises(InsufficientResourcesError, match="program bucket"):
        pool.check_admission(program_content)


class _FakeProgramContent:
    """Minimal non-InstanceContent stub that satisfies check_admission.

    check_admission only reads ``message.resources`` and
    ``message.volumes`` and tests ``isinstance(message, InstanceContent)``.
    A plain class avoids constructing a full ProgramContent, which would
    require a realistic code reference and runtime hash.
    """

    def __init__(self, *, memory_mib: int, vcpus: int):
        resources = mock.MagicMock()
        resources.memory = memory_mib
        resources.vcpus = vcpus
        self.resources = resources
        self.volumes = None


def _fake_program_content(*, memory_mib: int, vcpus: int) -> _FakeProgramContent:
    return _FakeProgramContent(memory_mib=memory_mib, vcpus=vcpus)
