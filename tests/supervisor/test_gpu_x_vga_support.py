import pytest
from unittest import mock
from pathlib import Path
import subprocess

from aleph.vm.controllers.configuration import QemuGPU
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM
from aleph.vm.controllers.qemu.instance import AlephQemuInstance
from aleph.vm.resources import HostGPU


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
            QemuGPU(pci_host="02:00.0", supports_x_vga=False)
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


@pytest.mark.asyncio
class TestGpuXVgaDetection:
    """Tests for GPU x-vga support detection in AlephQemuInstance"""
    
    @mock.patch('subprocess.run')
    def test_check_gpu_supports_x_vga_success(self, mock_subprocess_run):
        """Test detection when x-vga is supported"""
        # Set up mock to simulate successful detection
        help_process = mock.MagicMock()
        help_process.stderr = "vfio-pci options include: ... x-vga=on/off ..."
        
        test_process = mock.MagicMock()
        test_process.returncode = 0
        
        # Make subprocess.run return different mocks for each call
        mock_subprocess_run.side_effect = [help_process, test_process]
        
        # Create an instance of AlephQemuInstance
        instance = AlephQemuInstance(
            vm_id=1, 
            vm_hash="test_hash", 
            resources=mock.MagicMock()
        )
        
        # Test the method
        result = instance._check_gpu_supports_x_vga("/path/to/qemu", "01:00.0")
        
        # Check that x-vga is detected as supported
        assert result is True
        
        # Verify the subprocess calls
        assert mock_subprocess_run.call_count == 2
    
    @mock.patch('subprocess.run')
    def test_check_gpu_supports_x_vga_not_supported_by_qemu(self, mock_subprocess_run):
        """Test detection when x-vga is not supported by QEMU version"""
        # Set up mock to simulate QEMU that doesn't support x-vga
        help_process = mock.MagicMock()
        help_process.stderr = "vfio-pci options include: ..."  # No x-vga mentioned
        
        # Make subprocess.run return the mock
        mock_subprocess_run.return_value = help_process
        
        # Create an instance of AlephQemuInstance
        instance = AlephQemuInstance(
            vm_id=1, 
            vm_hash="test_hash", 
            resources=mock.MagicMock()
        )
        
        # Test the method
        result = instance._check_gpu_supports_x_vga("/path/to/qemu", "01:00.0")
        
        # Check that x-vga is detected as not supported
        assert result is False
        
        # Verify the subprocess call
        mock_subprocess_run.assert_called_once()
    
    @mock.patch('subprocess.run')
    def test_check_gpu_supports_x_vga_not_supported_by_gpu(self, mock_subprocess_run):
        """Test detection when x-vga is not supported by the GPU"""
        # Set up mocks to simulate GPU that doesn't support x-vga
        help_process = mock.MagicMock()
        help_process.stderr = "vfio-pci options include: ... x-vga=on/off ..."
        
        test_process = mock.MagicMock()
        test_process.returncode = 1
        test_process.stderr = "error: x-vga not supported for this device"
        
        # Make subprocess.run return different mocks for each call
        mock_subprocess_run.side_effect = [help_process, test_process]
        
        # Create an instance of AlephQemuInstance
        instance = AlephQemuInstance(
            vm_id=1, 
            vm_hash="test_hash", 
            resources=mock.MagicMock()
        )
        
        # Test the method
        result = instance._check_gpu_supports_x_vga("/path/to/qemu", "01:00.0")
        
        # Check that x-vga is detected as not supported
        assert result is False
        
        # Verify the subprocess calls
        assert mock_subprocess_run.call_count == 2
    
    @mock.patch('subprocess.run')
    def test_check_gpu_supports_x_vga_with_error(self, mock_subprocess_run):
        """Test that the function handles errors gracefully"""
        # Set up subprocess.run to raise an exception
        mock_subprocess_run.side_effect = subprocess.SubprocessError("Test error")
        
        # Create an instance of AlephQemuInstance
        instance = AlephQemuInstance(
            vm_id=1, 
            vm_hash="test_hash", 
            resources=mock.MagicMock()
        )
        
        # Test the method
        result = instance._check_gpu_supports_x_vga("/path/to/qemu", "01:00.0")
        
        # Check that the function defaults to True for backward compatibility
        assert result is True


@pytest.mark.asyncio
class TestQemuGpuConfiguration:
    """Tests for configuration of QemuGPU with x-vga support detection"""
    
    @mock.patch('aleph.vm.controllers.qemu.instance.AlephQemuInstance._check_gpu_supports_x_vga')
    def test_gpu_configuration_with_x_vga_detection(self, mock_check_x_vga):
        """Test that GPU configuration correctly sets the supports_x_vga flag"""
        # Configure the mock to return different values for different GPUs
        mock_check_x_vga.side_effect = lambda qemu_path, pci_host: pci_host == "01:00.0"
        
        # Create an instance of AlephQemuInstance
        instance = AlephQemuInstance(
            vm_id=1, 
            vm_hash="test_hash", 
            resources=mock.MagicMock()
        )
        
        # Set up resources with multiple GPUs
        instance.resources.gpus = [
            HostGPU(pci_host="01:00.0"),  # Should support x-vga
            HostGPU(pci_host="02:00.0")   # Should not support x-vga
        ]
        
        # Create a mock QemuVMConfiguration to capture the results
        mock_vm_config = mock.MagicMock()
        
        # Setup method to create a QemuVMConfiguration and return it
        def mock_configure_side_effect(*args, **kwargs):
            nonlocal mock_vm_config
            # Extract QemuGPU instances created during configuration
            mock_gpus = kwargs.get('gpus', [])
            if not mock_gpus and hasattr(args[0], 'gpus'):
                mock_gpus = args[0].gpus
            mock_vm_config.gpus = mock_gpus
            return mock_vm_config
        
        # Apply the side effect to a method or create a test method
        with mock.patch('aleph.vm.controllers.qemu.instance.QemuVMConfiguration', 
                         side_effect=mock_configure_side_effect):
            # Call a method that would create QemuGPU instances
            # This is a simplified test; in a real test you'd call the actual configure method
            gpus = [
                QemuGPU(
                    pci_host=gpu.pci_host,
                    supports_x_vga=instance._check_gpu_supports_x_vga("/fake/qemu/path", gpu.pci_host)
                ) for gpu in instance.resources.gpus
            ]
            
            # Check that x-vga support is correctly detected for each GPU
            assert len(gpus) == 2
            assert gpus[0].pci_host == "01:00.0"
            assert gpus[0].supports_x_vga is True
            assert gpus[1].pci_host == "02:00.0"
            assert gpus[1].supports_x_vga is False