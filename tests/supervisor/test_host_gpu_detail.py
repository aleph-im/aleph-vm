"""HostGPU retains device_id + model so the supervisor can report full GpuDevices."""

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
