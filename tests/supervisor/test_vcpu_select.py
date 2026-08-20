from dataclasses import dataclass

import pytest

from aleph.vm.agent.vcpu_select import (
    DEFAULT_MEASUREMENT_VCPU_TYPE,
    requested_vcpu_types,
    select_snp_vcpu_type,
)
from aleph.vm.supervisor_interface.errors import VmSetupError


@dataclass
class FakeMeasurement:
    vcpu_type: str | None


def test_requested_reads_measurement_models_in_order():
    measurements = [FakeMeasurement("EPYC-Genoa-v2"), FakeMeasurement("EPYC-v4")]
    assert requested_vcpu_types(measurements) == ["EPYC-Genoa-v2", "EPYC-v4"]


def test_requested_defaults_untagged_measurement_to_the_launch_model():
    assert requested_vcpu_types([FakeMeasurement(None)]) == [DEFAULT_MEASUREMENT_VCPU_TYPE]


def test_requested_dedupes_case_insensitively_keeping_first_spelling():
    measurements = [FakeMeasurement("EPYC-v4"), FakeMeasurement("epyc-v4")]
    assert requested_vcpu_types(measurements) == ["EPYC-v4"]


def test_requested_of_none_is_empty():
    assert requested_vcpu_types(None) == []


def test_select_returns_the_only_launchable_model():
    assert select_snp_vcpu_type(["EPYC-v4"], ["EPYC", "EPYC-v4"]) == "EPYC-v4"


def test_select_prefers_message_order():
    chosen = select_snp_vcpu_type(["EPYC-Genoa-v2", "EPYC-v4"], ["EPYC-v4", "EPYC-Genoa-v2"])
    assert chosen == "EPYC-Genoa-v2"


def test_select_matches_case_insensitively_and_returns_the_host_spelling():
    # QEMU's -cpu is case sensitive; the probe list is what QEMU reported.
    assert select_snp_vcpu_type(["epyc-v4"], ["EPYC-v4"]) == "EPYC-v4"


def test_select_raises_when_no_model_is_launchable():
    with pytest.raises(VmSetupError) as excinfo:
        select_snp_vcpu_type(["EPYC-Genoa-v2"], ["EPYC", "EPYC-v4"])
    message = str(excinfo.value)
    assert "EPYC-Genoa-v2" in message
    assert "EPYC-v4" in message


def test_select_raises_when_the_host_advertises_nothing():
    with pytest.raises(VmSetupError):
        select_snp_vcpu_type(["EPYC-v4"], [])


def test_select_raises_when_nothing_was_requested():
    with pytest.raises(VmSetupError):
        select_snp_vcpu_type([], ["EPYC-v4"])
