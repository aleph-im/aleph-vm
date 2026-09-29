"""Settings.check_confidential_computing: the host prerequisites behind
ENABLE_CONFIDENTIAL_COMPUTING, and the Intel TDX waiver of the AMD tooling."""

import pytest

from aleph.vm.conf import settings


@pytest.fixture
def no_amd_tooling(mocker, tmp_path):
    mocker.patch.object(settings, "ENABLE_QEMU_SUPPORT", True)
    mocker.patch.object(settings, "SEV_CTL_PATH", tmp_path / "missing-sevctl")
    mocker.patch("aleph.vm.conf.check_amd_sev_supported", return_value=False)
    mocker.patch("aleph.vm.conf.check_amd_sev_es_supported", return_value=False)


def test_a_tdx_host_waives_the_amd_tooling(mocker, no_amd_tooling):
    """An Intel TDX host has no sevctl and no SEV modules; a usable TDX
    stands in for those gates, mirroring the daemon's startup check."""
    mocker.patch("aleph.vm.conf.check_intel_tdx_supported", return_value=True)
    settings.check_confidential_computing()


def test_a_host_without_tdx_still_needs_the_amd_tooling(mocker, no_amd_tooling):
    mocker.patch("aleph.vm.conf.check_intel_tdx_supported", return_value=False)
    with pytest.raises(AssertionError, match="File not found"):
        settings.check_confidential_computing()


def test_a_tdx_host_still_needs_qemu(mocker):
    mocker.patch("aleph.vm.conf.check_intel_tdx_supported", return_value=True)
    mocker.patch.object(settings, "ENABLE_QEMU_SUPPORT", False)
    with pytest.raises(AssertionError, match="Qemu Support is needed"):
        settings.check_confidential_computing()
