from unittest import mock

from aleph.vm.resources import get_gpu_devices


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

            print(expected_gpu_devices)

            assert expected_gpu_devices[0].vendor == "NVIDIA"
            assert expected_gpu_devices[0].device_name == "AD104GL [RTX 4000 SFF Ada Generation]"
            assert expected_gpu_devices[0].device_class == "0300"
            assert expected_gpu_devices[0].pci_host == "01:00.0"
            assert expected_gpu_devices[0].device_id == "10de:27b0"
