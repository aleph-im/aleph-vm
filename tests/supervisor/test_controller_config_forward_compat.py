"""Controller configs must survive settings schema drift in both directions.

Historically every <vm_hash>-controller.json embedded a FULL Settings dump
parsed with extra=forbid, so any settings rename broke parsing of configs
written by the previous version (1.13.0's CONNECTIVITY_DNS_HOSTNAME, renamed
in #974) and the supervisor daemon aborted startup: an in-place upgrade with
live VMs crash-looped the node.

The config now embeds only ControllerSettings, the slice the controller
process actually reads, and ignores unknown keys: old full dumps keep
parsing with no file migration, and future removals from the slice do too."""

import pytest
from pydantic import ValidationError

from aleph.vm.conf import Settings
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    VMConfiguration,
)


def _controller_config_dict(settings_value) -> dict:
    return {
        "vm_id": 3,
        "vm_hash": "cafe" * 16,
        "settings": settings_value,
        "vm_configuration": {
            "use_jailer": False,
            "firecracker_bin_path": "/opt/firecracker",
            "jailer_bin_path": "/opt/jailer",
            "config_file_path": "/tmp/config.json",
            "init_timeout": 30.0,
        },
        "hypervisor": HypervisorType.firecracker,
    }


def test_full_1_13_0_style_settings_dump_still_parses():
    """Old configs carry a full Settings dump including keys that no longer
    exist (CONNECTIVITY_DNS_HOSTNAME): the surplus is ignored, the slice the
    controller needs is extracted."""
    settings_dict = Settings().model_dump(exclude_none=True)
    settings_dict.pop("CONNECTIVITY_DNS_HOSTNAMES", None)
    settings_dict["CONNECTIVITY_DNS_HOSTNAME"] = "example.org"
    settings_dict["NETWORK_INTERFACE"] = "eth0"

    config = Configuration.model_validate(_controller_config_dict(settings_dict))

    assert config.settings.NETWORK_INTERFACE == "eth0"
    assert config.settings.IPV4_NETWORK_PREFIX_LENGTH == 24
    assert not hasattr(config.settings, "CONNECTIVITY_DNS_HOSTNAME")
    assert isinstance(config.vm_configuration, VMConfiguration)


def test_arbitrary_unknown_settings_key_is_ignored():
    """The guard is structural: any future rename/removal must not break
    reattach across an upgrade."""
    settings_dict = Settings().model_dump(exclude_none=True)
    settings_dict["SOME_SETTING_REMOVED_IN_THE_FUTURE"] = {"nested": True}

    config = Configuration.model_validate(_controller_config_dict(settings_dict))

    assert config.vm_id == 3


def test_missing_slice_keys_fall_back_to_defaults():
    """A key absent from an old dump (or dropped from a future slice) takes
    the conf.py default instead of failing."""
    config = Configuration.model_validate(_controller_config_dict({"NETWORK_INTERFACE": "eth0"}))

    assert config.settings.IPV4_ADDRESS_POOL == "172.16.0.0/12"
    assert config.settings.USE_NDP_PROXY is True


def test_known_key_with_wrong_type_still_rejected():
    """Leniency is only about unknown keys: a corrupt value for a setting the
    controller reads must fail loudly rather than misconfigure a VM."""
    with pytest.raises(ValidationError):
        Configuration.model_validate(_controller_config_dict({"IPV4_NETWORK_PREFIX_LENGTH": "not-a-number"}))


def test_writers_pass_the_live_settings_object():
    """Configuration builders pass the full Settings instance; pydantic
    extracts the controller slice (from_attributes), so the file on disk
    carries only what the controller reads."""
    source = Settings()
    source.NETWORK_INTERFACE = "enp3s0"

    config = Configuration.model_validate(_controller_config_dict(source))

    assert config.settings.NETWORK_INTERFACE == "enp3s0"
    dumped = config.model_dump()["settings"]
    assert set(dumped) == set(ControllerSettings.model_fields)
