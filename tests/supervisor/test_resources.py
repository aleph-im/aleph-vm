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


def _make_pool(mocker, *, physical_memory_mib: int, physical_cores: int, available_disk_mib: int):
    """Build a VmPool stub with just enough state for check_admission."""
    from aleph.vm.pool import VmPool  # local import to keep module-level import light

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
    return pool


def test_check_admission_passes_with_ample_capacity(mocker, mock_instance_content):
    pool = _make_pool(
        mocker,
        physical_memory_mib=8192,
        physical_cores=8,
        available_disk_mib=20480,
    )
    content = InstanceContent.model_validate(mock_instance_content)
    pool.check_admission(content)


def test_check_admission_refuses_insufficient_memory(mocker, mock_instance_content):
    # Instance requests 2048 MiB; host has 1024 MiB x 1.1 overcommit = 1126 MiB cap.
    pool = _make_pool(
        mocker,
        physical_memory_mib=1024,
        physical_cores=8,
        available_disk_mib=20480,
    )
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="Memory"):
        pool.check_admission(content)


def test_check_admission_refuses_insufficient_vcpus(mocker, mock_instance_content):
    # Instance requests 4 vCPUs; host has 1 core x 4.0 overcommit = 4 cap,
    # and an already-committed instance takes 1 vCPU, leaving 3.
    pool = _make_pool(
        mocker,
        physical_memory_mib=8192,
        physical_cores=1,
        available_disk_mib=20480,
    )
    existing = mock.MagicMock()
    existing.is_instance = True
    existing.vm_hash = "existing"
    existing.message.resources.memory = 128
    existing.message.resources.vcpus = 1
    pool.executions["existing"] = existing
    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="vCPUs"):
        pool.check_admission(content)


def test_check_admission_refuses_insufficient_disk(mocker, mock_instance_content):
    # Instance requests 10240 MiB of rootfs; only 5120 MiB available.
    pool = _make_pool(
        mocker,
        physical_memory_mib=8192,
        physical_cores=8,
        available_disk_mib=5120,
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


def test_check_admission_counts_running_programs(mocker, mock_instance_content):
    # A running program's memory and vCPUs must count toward the committed
    # totals: admission decisions cannot ignore non-instance executions.
    pool = _make_pool(
        mocker,
        physical_memory_mib=4096,
        physical_cores=4,
        available_disk_mib=20480,
    )
    # Cap: 4096 * 1.1 = 4505 MiB memory, 4 * 4.0 = 16 vCPUs.
    # One running program already consumes 3500 MiB. A new instance asking
    # for 2048 MiB would exceed the memory cap (3500 + 2048 = 5548 > 4505).
    program = mock.MagicMock()
    program.is_instance = False
    program.vm_hash = "program-hash"
    program.message.resources.memory = 3500
    program.message.resources.vcpus = 1
    pool.executions["program-hash"] = program

    content = InstanceContent.model_validate(mock_instance_content)
    with pytest.raises(InsufficientResourcesError, match="Memory"):
        pool.check_admission(content)


def test_check_admission_excludes_current_hash_from_committed(mocker, mock_instance_content):
    # An instance being re-evaluated (e.g. restart) must not count against
    # itself when it is not yet in the pool but its hash is supplied.
    pool = _make_pool(
        mocker,
        physical_memory_mib=4096,
        physical_cores=8,
        available_disk_mib=20480,
    )
    # Cap: 4096 * 1.1 = 4505 MiB. Instance requests 2048. OK.
    content = InstanceContent.model_validate(mock_instance_content)
    pool.check_admission(content, current_vm_hash="not-in-pool")
