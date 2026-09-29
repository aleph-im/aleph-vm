import socket
from pathlib import Path
from unittest import mock

from aleph.vm import utils
from aleph.vm.utils import (
    check_amd_sev_es_supported,
    check_amd_sev_snp_supported,
    check_amd_sev_supported,
    check_intel_tdx_module,
    check_intel_tdx_supported,
    check_system_module,
    check_tdx_qgs_reachable,
    tdx_qgs_socket_path,
)


def test_check_system_module_enabled():
    with mock.patch(
        "pathlib.Path.exists",
        return_value=True,
    ):
        expected_value = "Y"
        with mock.patch(
            "aleph.vm.utils.Path.open",
            mock.mock_open(read_data=expected_value),
        ):
            output = check_system_module("kvm_amd/parameters/sev_enp")
            assert output == expected_value

            assert check_amd_sev_supported() is True
            assert check_amd_sev_es_supported() is True
            assert check_amd_sev_snp_supported() is True

        with mock.patch(
            "aleph.vm.utils.Path.open",
            mock.mock_open(read_data="N"),
        ):
            output = check_system_module("kvm_amd/parameters/sev_enp")
            assert output == "N"

            assert check_amd_sev_supported() is False
            assert check_amd_sev_es_supported() is False
            assert check_amd_sev_snp_supported() is False


def _module_param(value: str | None):
    def read(module_path: str) -> str | None:
        assert module_path == "kvm_intel/parameters/tdx"
        return value

    return read


def test_check_intel_tdx_requires_the_module_and_a_live_qgs(monkeypatch, tmp_path):
    qgs = tmp_path / "qgs.socket"
    monkeypatch.setenv("ALEPH_VM_TDX_QGS_SOCKET", str(qgs))
    assert tdx_qgs_socket_path() == qgs

    # Module on, nothing listening: not a capability.
    monkeypatch.setattr(utils, "check_system_module", _module_param("Y"))
    assert check_intel_tdx_module() is True
    assert check_tdx_qgs_reachable() is False
    assert check_intel_tdx_supported() is False

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(qgs))
        listener.listen(8)
        assert check_tdx_qgs_reachable() is True
        assert check_intel_tdx_supported() is True

        # QGS up but the kernel has TDX off or the module is absent.
        for value in ("N", None):
            monkeypatch.setattr(utils, "check_system_module", _module_param(value))
            assert check_intel_tdx_module() is False
            assert check_intel_tdx_supported() is False

    # Listener gone, socket inode left behind: refused.
    monkeypatch.setattr(utils, "check_system_module", _module_param("Y"))
    assert check_intel_tdx_supported() is False


def test_tdx_qgs_socket_path_defaults_to_the_dcap_location(monkeypatch):
    monkeypatch.delenv("ALEPH_VM_TDX_QGS_SOCKET", raising=False)
    assert tdx_qgs_socket_path() == Path("/var/run/tdx-qgs/qgs.socket")
    # An empty override is an unset override.
    monkeypatch.setenv("ALEPH_VM_TDX_QGS_SOCKET", "")
    assert tdx_qgs_socket_path() == Path("/var/run/tdx-qgs/qgs.socket")
