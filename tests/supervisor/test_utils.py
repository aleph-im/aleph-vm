from unittest import mock

from aleph.vm.utils import (
    check_amd_sev_es_supported,
    check_amd_sev_snp_supported,
    check_amd_sev_supported,
    check_system_module,
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
