from unittest import mock

from aleph.vm.utils import check_system_module


def test_check_system_module_enabled():

    with mock.patch(
            "pathlib.Path.exists",
            return_value=True,
    ):
        expected_value = "Y"
        with mock.patch(
            "pathlib.Path.open",
            mock.mock_open(read_data=expected_value),
        ):

            output = check_system_module("kvm_amd/parameters/sev_enp")
            assert output == expected_value
