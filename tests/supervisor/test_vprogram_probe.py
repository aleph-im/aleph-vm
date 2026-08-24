"""SNP guest vCPU model probing and TEE capability advertising.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised in /about/usage/system properties.tee, so the advertised
list must reflect what this exact QEMU + kernel + silicon can launch.
"""

import asyncio
from unittest.mock import AsyncMock

import pytest

from aleph.vm.agent import resources
from aleph.vm.agent.resources import get_machine_properties
from aleph.vm.agent.vcpu_probe import (
    PROBE_RETRY_SECONDS,
    filter_snp_vcpu_types,
    get_supported_snp_vcpu_types,
    reset_snp_vcpu_probe_cache,
)
from aleph.vm.utils import async_cache


@pytest.fixture(autouse=True)
def _fresh_probe_cache():
    """Every test starts from an unprobed host and leaves one behind."""
    reset_snp_vcpu_probe_cache()
    yield
    reset_snp_vcpu_probe_cache()


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
    assert await get_supported_snp_vcpu_types() == []
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
    assert await get_supported_snp_vcpu_types() == []


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
    assert await get_supported_snp_vcpu_types() == ["EPYC-Milan"]


def _mock_cpu_info() -> dict:
    return {"architecture": "x86_64", "vendor": "AuthenticAMD", "model": "EPYC", "frequency": 2000, "count": 8}


@pytest.fixture(autouse=True)
def _fresh_static_properties(monkeypatch):
    """The static half of the machine properties is process-cached; give each
    test its own cache so a mock from one cannot leak into the next."""
    monkeypatch.setattr(
        resources,
        "_get_static_machine_properties",
        async_cache(resources._get_static_machine_properties.__wrapped__),
    )


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

    properties = await get_machine_properties()
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

    properties = await get_machine_properties()
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


# ---------------------------------------------------------------------------
# What the probe remembers, and for how long.
#
# The list it returns feeds both what the node advertises and which models it
# will launch, so a failed attempt must not be mistaken for a fact about the
# host: it is retried, while a successful one is kept.
# ---------------------------------------------------------------------------


def _snp_host(mocker, probe):
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=True)
    return mocker.patch("aleph.vm.agent.vcpu_probe.query_cpu_definitions", new_callable=AsyncMock, **probe)


def _clock(mocker, start: float = 1000.0):
    """A controllable time.monotonic for the probe module."""
    now = {"t": start}
    mocker.patch("aleph.vm.agent.vcpu_probe.time.monotonic", side_effect=lambda: now["t"])
    return now


@pytest.mark.asyncio
async def test_a_successful_probe_is_not_repeated(mocker):
    probe = _snp_host(mocker, {"return_value": [{"name": "EPYC-v4", "unavailable-features": []}]})
    assert await get_supported_snp_vcpu_types() == ["EPYC-v4"]
    assert await get_supported_snp_vcpu_types() == ["EPYC-v4"]
    assert probe.await_count == 1


@pytest.mark.asyncio
async def test_a_failed_probe_is_not_repeated_within_the_retry_window(mocker):
    # A host with no working qemu must not be re-probed, and stalled for up to
    # the probe timeout, on every usage poll and every launch.
    clock = _clock(mocker)
    probe = _snp_host(mocker, {"side_effect": OSError("qemu-system-x86_64 not found")})
    assert await get_supported_snp_vcpu_types() == []
    clock["t"] += PROBE_RETRY_SECONDS / 2
    assert await get_supported_snp_vcpu_types() == []
    assert probe.await_count == 1


@pytest.mark.asyncio
async def test_a_failed_probe_is_retried_after_the_window_and_recovers(mocker):
    # The case that used to need an agent restart: a transient failure at boot.
    clock = _clock(mocker)
    probe = _snp_host(mocker, {"side_effect": TimeoutError("probe timed out")})
    assert await get_supported_snp_vcpu_types() == []

    probe.side_effect = None
    probe.return_value = [{"name": "EPYC-v4", "unavailable-features": []}]
    clock["t"] += PROBE_RETRY_SECONDS
    assert await get_supported_snp_vcpu_types() == ["EPYC-v4"]
    assert probe.await_count == 2
    # ...and once recovered it is a fact, kept for good.
    clock["t"] += PROBE_RETRY_SECONDS * 10
    assert await get_supported_snp_vcpu_types() == ["EPYC-v4"]
    assert probe.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_first_callers_probe_once(mocker):
    # The usage endpoint and a launch can race at startup; one qemu, not two.
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_probe():
        started.set()
        await release.wait()
        return [{"name": "EPYC-v4", "unavailable-features": []}]

    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=True)
    probe = mocker.patch("aleph.vm.agent.vcpu_probe.query_cpu_definitions", side_effect=slow_probe)

    first = asyncio.create_task(get_supported_snp_vcpu_types())
    await started.wait()
    second = asyncio.create_task(get_supported_snp_vcpu_types())
    await asyncio.sleep(0)
    release.set()
    assert await asyncio.gather(first, second) == [["EPYC-v4"], ["EPYC-v4"]]
    assert probe.call_count == 1


def _static_host(mocker):
    hardware = mocker.patch("aleph.vm.agent.resources.get_hardware_info", new_callable=AsyncMock, return_value={})
    mocker.patch("aleph.vm.agent.resources.get_cpu_info", return_value=_mock_cpu_info())
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_supported", return_value=True)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_es_supported", return_value=True)
    mocker.patch("aleph.vm.agent.resources.check_amd_sev_snp_supported", return_value=True)
    return hardware


@pytest.mark.asyncio
async def test_advertisement_recovers_after_a_failed_first_probe(mocker):
    # End to end through the usage endpoint's view: the tee block reappears
    # once the probe recovers, without the process-cached static properties
    # having pinned its absence.
    _static_host(mocker)
    clock = _clock(mocker)
    probe = _snp_host(mocker, {"side_effect": OSError("qemu-system-x86_64 not found")})

    assert (await get_machine_properties()).tee is None

    probe.side_effect = None
    probe.return_value = [{"name": "EPYC-v4", "unavailable-features": []}]
    clock["t"] += PROBE_RETRY_SECONDS
    properties = await get_machine_properties()
    assert properties.tee is not None
    assert properties.tee.sev_snp is not None
    assert properties.tee.sev_snp.supported_vcpu_types == ["EPYC-v4"]


@pytest.mark.asyncio
async def test_static_properties_stay_cached_across_calls(mocker):
    # Splitting the tee block out must not cost a hardware scan per poll.
    hardware = _static_host(mocker)
    _snp_host(mocker, {"return_value": [{"name": "EPYC-v4", "unavailable-features": []}]})
    await get_machine_properties()
    await get_machine_properties()
    assert hardware.await_count == 1
