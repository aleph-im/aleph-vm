"""tee.tdx is advertised when the kernel has TDX on and the Quote Generation
Service answers; it is its own axis, independent of the SNP vCPU probe, and
carries no GPU block."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aleph.vm.agent import resources
from aleph.vm.agent.resources import TdxProperties, TeeProperties


def _static(mocker, name):
    mocker.patch.object(
        resources,
        name,
        AsyncMock(return_value=SimpleNamespace(model_copy=lambda update: SimpleNamespace(**update))),
    )


def _no_snp(mocker):
    mocker.patch.object(resources, "check_amd_sev_snp_supported", return_value=False)
    mocker.patch.object(resources, "get_supported_snp_vcpu_types", AsyncMock(return_value=[]))
    mocker.patch.object(
        resources,
        "get_snp_launch_capability",
        AsyncMock(return_value=SimpleNamespace(supported_vcpu_types=[], unavailable_reason="no qemu")),
    )


@pytest.mark.asyncio
async def test_tdx_alone_makes_a_tee_block(mocker):
    _static(mocker, "_get_static_machine_properties")
    _static(mocker, "_get_static_machine_capability")
    _no_snp(mocker)
    mocker.patch.object(resources, "check_intel_tdx_module", return_value=True)
    mocker.patch.object(resources, "check_intel_tdx_supported", return_value=True)
    supervisor = SimpleNamespace(get_host_info=AsyncMock())

    properties = await resources.get_machine_properties(SimpleNamespace(available_gpus=[]))
    capability = await resources.get_machine_capability(supervisor)

    assert properties.tee == TeeProperties(tdx=TdxProperties(qgs=True))
    assert properties.tee.model_dump(exclude_none=True) == {"tdx": {"qgs": True}}
    assert capability.tee == properties.tee
    assert capability.tee_unavailable_reason is None
    # No SNP, so no confidential-GPU block and nothing to ask the supervisor.
    supervisor.get_host_info.assert_not_awaited()


@pytest.mark.asyncio
async def test_tdx_rides_next_to_sev_snp(mocker):
    _static(mocker, "_get_static_machine_capability")
    mocker.patch.object(resources, "check_amd_sev_snp_supported", return_value=True)
    mocker.patch.object(
        resources,
        "get_snp_launch_capability",
        AsyncMock(return_value=SimpleNamespace(supported_vcpu_types=["EPYC-v4"], unavailable_reason=None)),
    )
    mocker.patch.object(resources, "update_aggregate_settings", AsyncMock())
    mocker.patch.object(resources, "get_compatible_gpus", return_value=[])
    mocker.patch.object(resources, "check_intel_tdx_supported", return_value=True)
    supervisor = SimpleNamespace(get_host_info=AsyncMock(return_value=SimpleNamespace(available_gpus=[])))

    capability = await resources.get_machine_capability(supervisor)
    assert capability.tee.sev_snp.supported_vcpu_types == ["EPYC-v4"]
    assert capability.tee.tdx == TdxProperties(qgs=True)


@pytest.mark.asyncio
async def test_no_tee_block_without_tdx_or_snp(mocker):
    _static(mocker, "_get_static_machine_properties")
    _static(mocker, "_get_static_machine_capability")
    _no_snp(mocker)
    mocker.patch.object(resources, "check_intel_tdx_module", return_value=False)
    mocker.patch.object(resources, "check_intel_tdx_supported", return_value=False)

    assert (await resources.get_machine_properties(SimpleNamespace(available_gpus=[]))).tee is None
    capability = await resources.get_machine_capability(SimpleNamespace(get_host_info=AsyncMock()))
    assert capability.tee is None
    assert capability.tee_unavailable_reason is None


@pytest.mark.asyncio
async def test_tdx_without_qgs_is_withheld_and_explained(mocker, monkeypatch):
    """The kernel has TDX on but nothing answers on the QGS socket: no
    capability, and /about/capability says why."""
    _static(mocker, "_get_static_machine_capability")
    _no_snp(mocker)
    monkeypatch.setenv("ALEPH_VM_TDX_QGS_SOCKET", "/nonexistent/qgs.socket")
    mocker.patch.object(resources, "check_intel_tdx_module", return_value=True)
    mocker.patch.object(resources, "check_intel_tdx_supported", return_value=False)

    capability = await resources.get_machine_capability(SimpleNamespace(get_host_info=AsyncMock()))
    assert capability.tee is None
    assert "Quote Generation Service" in capability.tee_unavailable_reason
    assert "/nonexistent/qgs.socket" in capability.tee_unavailable_reason


@pytest.mark.asyncio
async def test_cpu_features_list_tdx(mocker):
    mocker.patch("aleph.vm.agent.resources.get_hardware_info", new_callable=AsyncMock, return_value={})
    mocker.patch(
        "aleph.vm.agent.resources.get_cpu_info",
        return_value={
            "architecture": "x86_64",
            "vendor": "GenuineIntel",
            "model": "Xeon",
            "frequency": 2000,
            "count": 8,
        },
    )
    mocker.patch(
        "aleph.vm.agent.resources.get_memory_info", return_value={"size": 1, "units": "GB", "type": None, "clock": None}
    )
    for name in ("check_amd_sev_supported", "check_amd_sev_es_supported", "check_amd_sev_snp_supported"):
        mocker.patch.object(resources, name, return_value=False)
    mocker.patch.object(resources, "check_intel_tdx_supported", return_value=True)

    properties = await resources._get_static_machine_properties.__wrapped__()
    capability = await resources._get_static_machine_capability.__wrapped__()
    assert properties.cpu.features == ["tdx"]
    assert capability.cpu.features == ["tdx"]
