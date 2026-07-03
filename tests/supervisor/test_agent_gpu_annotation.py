"""The agent, not the supervisor, annotates the GPU inventory with network
knowledge: `model` (the card's name on the Aleph network) and `compatible`
(whether the settings aggregate whitelists the device_id). The supervisor
reports raw hardware over GetHostInfo."""

from types import SimpleNamespace

import pytest

from aleph.vm.agent.resources import _gpus_from_host_info


def _raw_gpu(device_id: str, pci_host: str) -> dict:
    """A GPU dict as the supervisor reports it: no network annotation."""
    return {
        "vendor": "NVIDIA",
        "model": None,
        "device_name": f"Device {device_id}",
        "device_class": "0300",
        "pci_host": pci_host,
        "device_id": device_id,
        "compatible": False,
    }


@pytest.mark.asyncio
async def test_agent_annotates_gpus_from_aggregate(mocker):
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch(
        "aleph.vm.agent.resources.get_compatible_gpus",
        return_value=[
            {"device_id": "10de:27b0", "model": "RTX 4000 ADA", "vendor": "NVIDIA", "name": "AD104GL"},
        ],
    )
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:27b0", "01:00.0"), _raw_gpu("10de:ffff", "02:00.0")],
        available_gpus=[_raw_gpu("10de:27b0", "01:00.0")],
    )

    gpu = await _gpus_from_host_info(host_info)

    whitelisted, unlisted = gpu.devices
    assert whitelisted.model == "RTX 4000 ADA"
    assert whitelisted.compatible is True
    # A card the network does not support stays in the inventory, unannotated.
    assert unlisted.model is None
    assert unlisted.compatible is False
    assert gpu.available_devices[0].model == "RTX 4000 ADA"
    assert gpu.available_devices[0].compatible is True


@pytest.mark.asyncio
async def test_agent_annotation_survives_missing_aggregate(mocker):
    """Aggregate unreachable: the cache stays empty and every card reports
    incompatible, but the endpoint keeps working."""
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch("aleph.vm.agent.resources.get_compatible_gpus", return_value=[])
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:27b0", "01:00.0")],
        available_gpus=[],
    )

    gpu = await _gpus_from_host_info(host_info)

    assert gpu.devices[0].model is None
    assert gpu.devices[0].compatible is False
    assert gpu.available_devices == []
