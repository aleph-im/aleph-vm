"""The agent, not the supervisor, annotates the GPU inventory with network
knowledge: `model` (the card's name on the Aleph network), `compatible`
(whether the settings aggregate whitelists the device_id) and `modes` (how
this host can hand the card over). The supervisor reports raw hardware over
GetHostInfo."""

from types import SimpleNamespace

import pytest

from aleph.vm.agent import aggregate
from aleph.vm.agent.aggregate import CompatibleGPU
from aleph.vm.agent.resources import GpuProperties, _gpus_from_host_info


def _raw_gpu(device_id: str, pci_host: str) -> dict:
    """A GPU dict as the supervisor reports it: raw hardware, no `model` or
    `compatible` key at all (GpuDevice does not carry them)."""
    return {
        "vendor": "NVIDIA",
        "device_name": f"Device {device_id}",
        "device_class": "0300",
        "pci_host": pci_host,
        "device_id": device_id,
    }


@pytest.mark.asyncio
async def test_agent_annotates_gpus_from_aggregate(mocker):
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch(
        "aleph.vm.agent.resources.get_compatible_gpus",
        return_value=[
            CompatibleGPU(device_id="10de:27b0", model="RTX 4000 ADA", vendor="NVIDIA", name="AD104GL"),
        ],
    )
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:27b0", "01:00.0"), _raw_gpu("10de:ffff", "02:00.0")],
        available_gpus=[_raw_gpu("10de:27b0", "01:00.0")],
    )

    gpu = await _gpus_from_host_info(host_info, confidential=False)

    whitelisted, unlisted = gpu.devices
    assert whitelisted.model == "RTX 4000 ADA"
    assert whitelisted.compatible is True
    # A card the network does not support stays in the inventory, its model
    # falling back to the hardware name, and stays marked incompatible.
    assert unlisted.model == "Device 10de:ffff"
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

    gpu = await _gpus_from_host_info(host_info, confidential=False)

    assert gpu.devices[0].model == "Device 10de:27b0"
    assert gpu.devices[0].compatible is False
    assert gpu.available_devices == []


def test_get_compatible_gpus_skips_malformed_entries(mocker):
    """The whitelist is remote data: one bad aggregate entry must not take
    down every consumer (e.g. the public usage endpoint)."""
    valid = {"device_id": "10de:27b0", "model": "RTX 4000 ADA", "vendor": "NVIDIA", "name": "AD104GL"}
    mocker.patch.object(
        aggregate._settings_cache,
        "get",
        return_value={"compatible_gpus": [valid, {"device_id": "10de:2204"}, "not-a-dict"]},
    )

    gpus = aggregate.get_compatible_gpus()

    assert [gpu.device_id for gpu in gpus] == ["10de:27b0"]


def test_get_compatible_gpus_tolerates_missing_key(mocker):
    """Older aggregates omit compatible_gpus entirely."""
    mocker.patch.object(
        aggregate._settings_cache,
        "get",
        return_value={"community_wallet_address": "0x0"},
    )

    assert aggregate.get_compatible_gpus() == []


@pytest.mark.asyncio
async def test_unwhitelisted_gpu_falls_back_to_device_name(mocker):
    """Every released scheduler decodes `model` as a required string: a card
    absent from the whitelist must still carry one, or the whole usage
    response fails to decode and the node is marked unhealthy."""
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch("aleph.vm.agent.resources.get_compatible_gpus", return_value=[])
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:233b", "01:00.0")],
        available_gpus=[_raw_gpu("10de:233b", "01:00.0")],
    )

    gpu = await _gpus_from_host_info(host_info, confidential=False)

    device = gpu.devices[0]
    assert device.model == "Device 10de:233b"
    assert device.compatible is False


@pytest.mark.asyncio
async def test_whitelisted_gpu_keeps_network_model(mocker):
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch(
        "aleph.vm.agent.resources.get_compatible_gpus",
        return_value=[
            CompatibleGPU(device_id="10de:27b0", model="RTX 4000 ADA", vendor="NVIDIA", name="AD104GL"),
        ],
    )
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:27b0", "01:00.0")],
        available_gpus=[_raw_gpu("10de:27b0", "01:00.0")],
    )

    gpu = await _gpus_from_host_info(host_info, confidential=False)

    device = gpu.devices[0]
    assert device.model == "RTX 4000 ADA"
    assert device.compatible is True


@pytest.mark.asyncio
async def test_unwhitelisted_gpu_model_survives_the_endpoint_serialisation(mocker):
    """Regression for the scheduler decode failure: `model_dump_json(exclude_none=True)`,
    the exact call /about/usage/system makes, must still carry a `model` key
    for a device the network has no name for. Pydantic drops a field whose
    value is None under exclude_none, which is how this bug reached prod."""
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch("aleph.vm.agent.resources.get_compatible_gpus", return_value=[])
    host_info = SimpleNamespace(
        gpu_inventory=[_raw_gpu("10de:233b", "01:00.0")],
        available_gpus=[_raw_gpu("10de:233b", "01:00.0")],
    )

    gpu: GpuProperties = await _gpus_from_host_info(host_info, confidential=False)
    payload = gpu.model_dump_json(exclude_none=True)

    assert '"model":"Device 10de:233b"' in payload
    assert '"compatible":false' in payload
    # The placement signal a scheduler reads; older ones ignore the key.
    assert '"modes":["plain"]' in payload


@pytest.mark.asyncio
async def test_a_cc_card_of_unknown_family_offers_no_mode(mocker):
    """Every card is listed once; `modes` is what placement reads. The
    supervisor cannot move a card whose family it does not know, so a CC
    card without one serves neither kind of guest; an off card is plain."""
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch(
        "aleph.vm.agent.resources.get_compatible_gpus",
        return_value=[CompatibleGPU(device_id="10de:233b", model="H200", vendor="NVIDIA", name="GH100")],
    )
    plain = _raw_gpu("10de:27b0", "01:00.0")
    cc = _raw_gpu("10de:233b", "02:00.0") | {"cc_mode": "on"}
    devtools = _raw_gpu("10de:233b", "03:00.0") | {"cc_mode": "devtools"}
    off = _raw_gpu("10de:233b", "04:00.0") | {"cc_mode": "off"}
    host_info = SimpleNamespace(gpu_inventory=[plain, cc, devtools, off], available_gpus=[plain, devtools, off])

    gpu = await _gpus_from_host_info(host_info, confidential=True)

    assert [(d.pci_host, d.modes) for d in gpu.devices] == [
        ("01:00.0", ["plain"]),
        ("02:00.0", []),
        ("03:00.0", []),
        ("04:00.0", ["plain"]),
    ]
    assert [(d.pci_host, d.modes) for d in gpu.available_devices] == [
        ("01:00.0", ["plain"]),
        ("03:00.0", []),
        ("04:00.0", ["plain"]),
    ]
    assert (gpu.devices[1].model, gpu.devices[1].cc_mode) == ("H200", "on")


@pytest.mark.asyncio
async def test_a_card_of_a_known_family_offers_both_modes(mocker):
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch("aleph.vm.agent.resources.get_compatible_gpus", return_value=[])
    plain = _raw_gpu("10de:27b0", "01:00.0")
    cc = _raw_gpu("10de:233b", "02:00.0") | {"cc_mode": "on", "arch": "hopper"}
    devtools = _raw_gpu("10de:233b", "03:00.0") | {"cc_mode": "devtools", "arch": "hopper"}
    off = _raw_gpu("10de:233b", "04:00.0") | {"cc_mode": "off", "arch": "hopper"}
    unprobed = _raw_gpu("10de:233b", "05:00.0") | {"arch": "hopper"}
    host_info = SimpleNamespace(
        gpu_inventory=[plain, cc, devtools, off, unprobed],
        available_gpus=[plain, cc, devtools, off, unprobed],
        gpu_cc_switches={"02:00.0": 1},
    )

    gpu = await _gpus_from_host_info(host_info, confidential=True)

    # The daemon moves any decoded card at create; an unprobed one is plain
    # only, since no read-back could confirm a switch.
    assert [(d.pci_host, d.modes) for d in gpu.available_devices] == [
        ("01:00.0", ["plain"]),
        ("02:00.0", ["plain", "cc"]),
        ("03:00.0", ["plain", "cc"]),
        ("04:00.0", ["plain", "cc"]),
        ("05:00.0", ["plain"]),
    ]
    assert gpu.cc_switches == {"02:00.0": 1}


@pytest.mark.asyncio
async def test_a_host_that_cannot_launch_snp_offers_no_cc_mode(mocker):
    """Same gate as tee.nvidia_cc: a CC card on a host with no confidential
    guest to put it in is plain capacity at best."""
    mocker.patch("aleph.vm.agent.resources.update_aggregate_settings")
    mocker.patch("aleph.vm.agent.resources.get_compatible_gpus", return_value=[])
    cc = _raw_gpu("10de:233b", "02:00.0") | {"cc_mode": "on", "arch": "hopper"}
    host_info = SimpleNamespace(gpu_inventory=[cc], available_gpus=[cc])

    gpu = await _gpus_from_host_info(host_info, confidential=False)

    assert [(d.pci_host, d.modes) for d in gpu.available_devices] == [("02:00.0", ["plain"])]
