from unittest import mock

from aleph.vm.utils import check_system_module


def test_check_system_module_enabled():
    with mock.patch(
        "aleph.vm.utils.subprocess.check_output",
        return_value="Y",
    ):
        expected_value = "Y"
        output = check_system_module("kvm_amd/parameters/sev_enp")
        assert output == expected_value
