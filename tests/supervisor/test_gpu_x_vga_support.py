from unittest import mock

import pytest

from aleph.vm.controllers.configuration import QemuGPU
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM
from aleph.vm.resources import GpuDevice, GpuDeviceClass, HostGPU


class TestGpuXVgaSupport:
    """Tests for GPU x-vga support detection and usage"""

    def test_qemuvm_get_gpu_args_with_x_vga_support(self):
        """Test that _get_gpu_args includes x-vga=on when the GPU supports it"""
        # Create a QemuVM instance with a GPU that supports x-vga
        qemu_vm = QemuVM("test_hash", mock.MagicMock())
        qemu_vm.gpus = [QemuGPU(pci_host="01:00.0", supports_x_vga=True)]

        # Get GPU args
        gpu_args = qemu_vm._get_gpu_args()

        # Check that x-vga=on is included in the device args
        device_arg = next(arg for arg in gpu_args if arg.startswith("vfio-pci"))
        assert "x-vga=on" in device_arg

    def test_qemuvm_get_gpu_args_without_x_vga_support(self):
        """Test that _get_gpu_args excludes x-vga=on when the GPU doesn't support it"""
        # Create a QemuVM instance with a GPU that doesn't support x-vga
        qemu_vm = QemuVM("test_hash", mock.MagicMock())
        qemu_vm.gpus = [QemuGPU(pci_host="01:00.0", supports_x_vga=False)]

        # Get GPU args
        gpu_args = qemu_vm._get_gpu_args()

        # Check that x-vga=on is NOT included in the device args
        device_arg = next(arg for arg in gpu_args if arg.startswith("vfio-pci"))
        assert "x-vga=on" not in device_arg

    def test_qemuvm_get_gpu_args_with_multiple_gpus(self):
        """Test that _get_gpu_args correctly handles multiple GPUs with different x-vga support"""
        # Create a QemuVM instance with multiple GPUs with different x-vga support
        qemu_vm = QemuVM("test_hash", mock.MagicMock())
        qemu_vm.gpus = [
            QemuGPU(pci_host="01:00.0", supports_x_vga=True),
            QemuGPU(pci_host="02:00.0", supports_x_vga=False),
        ]

        # Get GPU args
        gpu_args = qemu_vm._get_gpu_args()

        # Extract the device arguments
        device_args = [arg for arg in gpu_args if arg.startswith("vfio-pci")]

        # Check that we have two GPU device entries
        assert len(device_args) == 2

        # Check that x-vga=on is included only for the GPU that supports it
        assert any(arg for arg in device_args if "01:00.0" in arg and "x-vga=on" in arg)
        assert any(arg for arg in device_args if "02:00.0" in arg and "x-vga=on" not in arg)


class TestGpuDeviceXVgaSupport:
    """Tests for x-vga support detection based on GPU device class"""

    def test_vga_compatible_controller_supports_x_vga(self):
        """Test that VGA compatible controllers (0300) support x-vga"""
        # Create a GPU device with VGA compatible controller class
        gpu = GpuDevice(
            pci_host="01:00.0",
            vendor="NVIDIA",
            device_name="RTX 3080",
            device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
            device_id="10de:2206",
            supports_x_vga=True,  # This should be overridden by the property
        )

        # Check that x-vga is supported
        assert gpu.has_x_vga_support is True

    def test_3d_controller_does_not_support_x_vga(self):
        """Test that 3D controllers (0302) do not support x-vga"""
        # Create a GPU device with 3D controller class
        gpu = GpuDevice(
            pci_host="01:00.0",
            vendor="NVIDIA",
            device_name="Tesla T4",
            device_class=GpuDeviceClass._3D_CONTROLLER,
            device_id="10de:1eb8",
            supports_x_vga=True,  # This should be overridden by the property
        )

        # Check that x-vga is not supported
        assert gpu.has_x_vga_support is False

    def test_parse_gpu_device_info_sets_x_vga_support(self):
        """Test that parse_gpu_device_info sets supports_x_vga based on device class"""
        import aleph.vm.resources

        # Create a mock for parse_gpu_device_info
        with mock.patch("aleph.vm.resources.parse_gpu_device_info") as mock_parse:
            # Configure the mock to return a GPU with VGA compatible controller class
            vga_gpu = GpuDevice(
                pci_host="01:00.0",
                vendor="NVIDIA",
                device_name="RTX 3080",
                device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
                device_id="10de:2206",
                supports_x_vga=True,
            )
            mock_parse.return_value = vga_gpu

            # Call the parse function (it will return our mock)
            mock_line = '01:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "GA102 [GeForce RTX 3080] [2206]" -ra1'
            result = aleph.vm.resources.parse_gpu_device_info(mock_line)

            # Check that supports_x_vga is set to True for VGA compatible controller
            assert result.supports_x_vga is True

            # Configure the mock to return a GPU with 3D controller class
            _3d_gpu = GpuDevice(
                pci_host="02:00.0",
                vendor="NVIDIA",
                device_name="Tesla T4",
                device_class=GpuDeviceClass._3D_CONTROLLER,
                device_id="10de:1eb8",
                supports_x_vga=False,
            )
            mock_parse.return_value = _3d_gpu

            # Call the parse function (it will return our mock)
            mock_line = '02:00.0 "3D controller [0302]" "NVIDIA Corporation [10de]" "Tesla T4 [1eb8]" -ra1'
            result = aleph.vm.resources.parse_gpu_device_info(mock_line)

            # Check that supports_x_vga is set to False for 3D controller
            assert result.supports_x_vga is False


@pytest.mark.asyncio
class TestQemuGpuConfiguration:
    """Tests for configuration of QemuGPU with x-vga support detection"""

    def test_gpu_configuration_sets_supports_x_vga(self):
        """Test that GPU configuration correctly sets the supports_x_vga flag from the GPU's device class"""
        # Create test GPU devices with different device classes
        vga_gpu = HostGPU(pci_host="01:00.0")
        vga_gpu.supports_x_vga = True

        _3d_gpu = HostGPU(pci_host="02:00.0")
        _3d_gpu.supports_x_vga = False

        # Create QemuGPU instances from the test devices
        qemu_gpus = [
            QemuGPU(pci_host=vga_gpu.pci_host, supports_x_vga=vga_gpu.supports_x_vga),
            QemuGPU(pci_host=_3d_gpu.pci_host, supports_x_vga=_3d_gpu.supports_x_vga),
        ]

        # Check that x-vga support is correctly set for each GPU
        assert len(qemu_gpus) == 2
        assert qemu_gpus[0].pci_host == "01:00.0"
        assert qemu_gpus[0].supports_x_vga is True
        assert qemu_gpus[1].pci_host == "02:00.0"
        assert qemu_gpus[1].supports_x_vga is False
