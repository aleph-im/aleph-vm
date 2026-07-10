"""SNP guest vCPU model probing and TEE capability advertising.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised in /about/usage/system properties.tee, so the advertised
list must reflect what this exact QEMU + kernel + silicon can launch.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.agent.resources import get_machine_properties
from aleph.vm.agent.vcpu_probe import (
    filter_snp_vcpu_types,
    get_supported_snp_vcpu_types,
)


def test_filter_snp_vcpu_types():
    definitions = [
        {"name": "EPYC-v4", "unavailable-features": []},
        {"name": "EPYC-Genoa", "unavailable-features": ["some-feature"]},
        {"name": "EPYC", "unavailable-features": []},
        {"name": "Skylake-Server", "unavailable-features": []},
    ]
    assert filter_snp_vcpu_types(definitions) == ["EPYC", "EPYC-v4"]


@pytest.mark.asyncio
async def test_get_supported_snp_vcpu_types_no_snp(mocker):
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=False)
    probe = mocker.patch("aleph.vm.agent.vcpu_probe.query_cpu_definitions", new_callable=AsyncMock)
    assert await get_supported_snp_vcpu_types.__wrapped__() == []
    probe.assert_not_awaited()


@pytest.mark.asyncio
async def test_get_supported_snp_vcpu_types_probe_failure(mocker):
    # We never advertise what we cannot prove: a failed probe advertises nothing
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=True)
    mocker.patch(
        "aleph.vm.agent.vcpu_probe.query_cpu_definitions",
        new_callable=AsyncMock,
        side_effect=OSError("qemu-system-x86_64 not found"),
    )
    assert await get_supported_snp_vcpu_types.__wrapped__() == []


@pytest.mark.asyncio
async def test_get_supported_snp_vcpu_types_success(mocker):
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=True)
    mocker.patch(
        "aleph.vm.agent.vcpu_probe.query_cpu_definitions",
        new_callable=AsyncMock,
        return_value=[
            {"name": "EPYC-Milan", "unavailable-features": []},
            {"name": "EPYC-Genoa", "unavailable-features": ["flag"]},
        ],
    )
    assert await get_supported_snp_vcpu_types.__wrapped__() == ["EPYC-Milan"]


def _mock_cpu_info() -> dict:
    return {"architecture": "x86_64", "vendor": "AuthenticAMD", "model": "EPYC", "frequency": 2000, "count": 8}


@pytest.mark.asyncio
async def test_machine_properties_tee_block(mocker):
    mocker.patch("aleph.vm.agent.resources.get_hardware_info", new_callable=AsyncMock, return_value={})
    mocker.patch("aleph.vm.agent.resources.get_cpu_info", return_value=_mock_cpu_info())
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_supported", return_value=True)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_es_supported", return_value=True)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_snp_supported", return_value=True)
    mocker.patch(
        "aleph.vm.agent.resources.get_supported_snp_vcpu_types",
        new_callable=AsyncMock,
        return_value=["EPYC", "EPYC-v4"],
    )

    properties = await get_machine_properties.__wrapped__()
    assert properties.tee is not None
    assert properties.tee.sev_snp is not None
    assert properties.tee.sev_snp.supported_vcpu_types == ["EPYC", "EPYC-v4"]
    dumped = properties.model_dump(exclude_none=True)
    assert dumped["tee"] == {"sev_snp": {"supported_vcpu_types": ["EPYC", "EPYC-v4"]}}


@pytest.mark.asyncio
async def test_machine_properties_no_tee_block_without_models(mocker):
    mocker.patch("aleph.vm.agent.resources.get_hardware_info", new_callable=AsyncMock, return_value={})
    mocker.patch("aleph.vm.agent.resources.get_cpu_info", return_value=_mock_cpu_info())
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_supported", return_value=False)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_es_supported", return_value=False)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_snp_supported", return_value=False)
    mocker.patch(
        "aleph.vm.agent.resources.get_supported_snp_vcpu_types",
        new_callable=AsyncMock,
        return_value=[],
    )

    properties = await get_machine_properties.__wrapped__()
    assert properties.tee is None
    # exclude_none keeps the usage-endpoint JSON free of a null tee key
    assert "tee" not in properties.model_dump(exclude_none=True)


def test_check_amd_sev_snp_requires_dev_sev(mocker):
    # SNP launches go through /dev/sev like SEV/SEV-ES; a host without the
    # device node cannot launch, whatever the kernel module parameter says
    from aleph.vm import utils

    mocker.patch("aleph.vm.utils.check_system_module", return_value="Y")
    path_cls = mocker.patch("aleph.vm.utils.Path")
    path_cls.return_value.exists.return_value = False
    assert utils.check_amd_sev_snp_supported() is False
    path_cls.return_value.exists.return_value = True
    assert utils.check_amd_sev_snp_supported() is True
