"""tee.nvidia_cc is advertised only for cards probed in CC mode 'on', and
only when the host can launch SEV-SNP: a confidential GPU on a host that
cannot run a confidential guest is not a capability."""

import pytest

from aleph.vm.agent.resources import NvidiaCcProperties, nvidia_cc_properties


def _gpu(device_id: str, pci_host: str, cc_mode: str | None) -> dict:
    raw = {
        "vendor": "NVIDIA",
        "device_name": "GB202",
        "device_class": "0300",
        "pci_host": pci_host,
        "device_id": device_id,
    }
    if cc_mode is not None:
        raw["cc_mode"] = cc_mode
    return raw


def test_only_on_mode_cards_are_listed():
    props = nvidia_cc_properties(
        [
            _gpu("10de:2b85", "06:00.0", "on"),
            _gpu("10de:2b85", "07:00.0", "devtools"),
            _gpu("10de:2b85", "08:00.0", None),
        ],
        {"10de:2b85": "RTX PRO 6000"},
    )
    assert props == NvidiaCcProperties(devices=[{"device_id": "10de:2b85", "model": "RTX PRO 6000"}])


def test_no_on_mode_card_means_no_block():
    assert nvidia_cc_properties([_gpu("10de:2b85", "06:00.0", "off")], {}) is None
    assert nvidia_cc_properties([], {}) is None


@pytest.mark.asyncio
async def test_capability_gates_nvidia_cc_on_snp(mocker):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from aleph.vm.agent import resources

    mocker.patch.object(
        resources,
        "_get_static_machine_capability",
        AsyncMock(return_value=SimpleNamespace(model_copy=lambda update: SimpleNamespace(**update))),
    )
    mocker.patch.object(resources, "check_amd_sev_snp_supported", return_value=False)
    mocker.patch.object(resources, "update_aggregate_settings", AsyncMock())
    mocker.patch.object(resources, "get_compatible_gpus", return_value=[])
    supervisor = SimpleNamespace(
        get_host_info=AsyncMock(return_value=SimpleNamespace(available_gpus=[_gpu("10de:2b85", "06:00.0", "on")]))
    )

    # No SNP launch capability: the GPU block is withheld even though a card is on.
    mocker.patch.object(
        resources,
        "get_snp_launch_capability",
        AsyncMock(return_value=SimpleNamespace(supported_vcpu_types=[], unavailable_reason="no qemu")),
    )
    capability = await resources.get_machine_capability(supervisor)
    assert capability.tee is None

    # With SNP, the block appears next to sev_snp.
    mocker.patch.object(
        resources,
        "get_snp_launch_capability",
        AsyncMock(return_value=SimpleNamespace(supported_vcpu_types=["EPYC-v4"], unavailable_reason=None)),
    )
    capability = await resources.get_machine_capability(supervisor)
    assert capability.tee.sev_snp.supported_vcpu_types == ["EPYC-v4"]
    assert capability.tee.nvidia_cc.devices[0].device_id == "10de:2b85"
