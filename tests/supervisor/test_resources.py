from unittest import mock

import pytest
from aleph_message.models import InstanceContent, InstanceMessage

from aleph.vm.resources import (
    InsufficientResourcesError,
    check_sufficient_resources,
    get_gpu_devices,
)


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


def test_check_sufficient_resources(mocker, mock_instance_content):
    required = {"vcpus": 4, "memory_mb": 2048, "disk_mb": 10240}

    mocker.patch("aleph.vm.orchestrator.resources.psutil.cpu_count", return_value=required["vcpus"])
    mocker.patch(
        "aleph.vm.orchestrator.resources.psutil.virtual_memory",
        return_value=mocker.MagicMock(available=(required["memory_mb"] * 1000 * 1024)),
    )

    content = InstanceContent.model_validate(mock_instance_content)

    check_sufficient_resources((required["disk_mb"] * 1000 * 1024), content)


def test_check_sufficient_resources_not_enough(mocker, mock_instance_content):
    required = {"vcpus": 4, "memory_mb": 2048, "disk_mb": 10240}
    available = {"vcpus": 2, "memory_mb": 1024, "disk_mb": 5120}
    error = InsufficientResourcesError(
        "Insufficient resources to create VM. vCPUs: required 4, available 2; "
        "Memory: required 2048 MB, available 1024.00 MB; "
        "Disk: required 10240 MB, available 5120.00 MB",
        required=required,
        available=available,
    )

    mocker.patch("aleph.vm.orchestrator.resources.psutil.cpu_count", return_value=available["vcpus"])
    mocker.patch(
        "aleph.vm.orchestrator.resources.psutil.virtual_memory",
        return_value=mocker.MagicMock(available=(available["memory_mb"] * 1000 * 1024)),
    )

    content = InstanceContent.model_validate(mock_instance_content)

    with pytest.raises(InsufficientResourcesError, match=str(error)):
        check_sufficient_resources((available["disk_mb"] * 1000 * 1024), content)
