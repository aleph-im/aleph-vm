from dataclasses import FrozenInstanceError

import pytest

from aleph.vm.contract.types import HardwareResources


def test_defaults_match_machineresources():
    hw = HardwareResources()
    assert (hw.vcpus, hw.memory) == (1, 128)


def test_explicit_values():
    hw = HardwareResources(vcpus=4, memory=2048)
    assert (hw.vcpus, hw.memory) == (4, 2048)


def test_is_frozen():
    hw = HardwareResources()
    with pytest.raises(FrozenInstanceError):
        hw.vcpus = 2  # type: ignore[misc]


def test_has_no_seconds_field():
    # seconds is agent-side policy; the daemon must not carry it.
    assert "seconds" not in HardwareResources().__dataclass_fields__
