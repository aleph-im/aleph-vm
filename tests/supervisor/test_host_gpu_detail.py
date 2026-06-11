"""HostGPU retains device_id + model so the supervisor can report full GpuDevices."""

from aleph.vm.resources import GpuDevice, GpuDeviceClass, HostGPU


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


def test_prepare_gpus_retains_detail():
    """prepare_gpus must copy device_id + model off the matched GpuDevice."""
    from aleph_message.models import ItemHash
    from aleph_message.models.execution.environment import (
        GpuProperties,
        HostRequirements,
        HypervisorType,
        InstanceEnvironment,
        MachineResources,
        NodeRequirements,
    )
    from aleph_message.models.execution.instance import InstanceContent, RootfsVolume
    from aleph_message.models.execution.volume import ParentVolume, VolumePersistence
    from aleph_message.utils import Mebibytes

    from aleph.vm.models import VmExecution

    _FAKE_HASH = ItemHash("cafecafe" * 8)
    _NODE_HASH = ItemHash("beefdead" * 8)

    # Build a real InstanceContent with a GPU requirement.
    # GpuProperties has vendor, device_name, device_class, device_id — no model field.
    # GPU support requires: QEMU hypervisor + a pinned node_hash in requirements.
    content = InstanceContent(
        address="0x1234567890abcdef1234567890abcdef12345678",
        time=1.0,
        allow_amend=False,
        environment=InstanceEnvironment(internet=False, aleph_api=False, hypervisor=HypervisorType.qemu),
        resources=MachineResources(vcpus=1, memory=Mebibytes(512), seconds=30),
        volumes=[],
        rootfs=RootfsVolume(
            parent=ParentVolume(ref=_FAKE_HASH, use_latest=False),
            persistence=VolumePersistence.host,
            size_mib=10000,
        ),
        requirements=HostRequirements(
            node=NodeRequirements(node_hash=_NODE_HASH),
            gpu=[
                GpuProperties(
                    vendor="NVIDIA",
                    device_name="GA102",
                    device_class="0300",
                    device_id="10de:2504",
                )
            ],
        ),
    )

    vm_hash = ItemHash("deadbeef" * 8)
    execution = VmExecution(
        vm_hash=vm_hash,
        message=content,
        original=content,
        snapshot_manager=None,
        systemd_manager=None,
        persistent=False,
    )

    available = [
        GpuDevice(
            vendor="NVIDIA",
            model="RTX 3090",
            device_name="GA102",
            device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
            pci_host="0000:01:00.0",
            device_id="10de:2504",
            compatible=True,
        )
    ]

    execution.prepare_gpus(available)

    assert len(execution.gpus) == 1
    assert execution.gpus[0].device_id == "10de:2504"
    assert execution.gpus[0].model == "RTX 3090"
