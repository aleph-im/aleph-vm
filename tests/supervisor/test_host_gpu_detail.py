"""HostGPU retains device_id + model so the supervisor can report full GpuDevices."""

import pytest
from pydantic import ValidationError

from aleph.vm.resources import HostGPU


def test_hostgpu_fields_default_for_spec_path():
    """The spec path (controllers/qemu/instance.py) builds HostGPU with only
    pci_host + supports_x_vga; the new fields must default, not break it."""
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True)
    assert gpu.device_id == ""
    assert gpu.model is None


def test_hostgpu_round_trips_detail():
    """device_id + model survive serialization (persist -> reload of a VM)."""
    gpu = HostGPU(pci_host="0000:01:00.0", supports_x_vga=True, device_id="10de:2504", model="RTX 3090")
    reloaded = HostGPU.model_validate(gpu.model_dump())
    assert reloaded.device_id == "10de:2504"
    assert reloaded.model == "RTX 3090"


def test_inventory_gpu_accepts_and_defaults_cc_mode():
    from aleph.vm.resources import GpuDevice

    raw = {
        "vendor": "NVIDIA",
        "device_name": "GB202",
        "device_class": "0300",
        "pci_host": "06:00.0",
        "device_id": "10de:2b85",
    }
    assert GpuDevice.model_validate(raw).cc_mode is None
    assert GpuDevice.model_validate(raw | {"cc_mode": "on"}).cc_mode == "on"
    with pytest.raises(ValidationError):
        GpuDevice.model_validate(raw | {"cc_mode": "maybe"})
