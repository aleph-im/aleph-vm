"""Controller configs written by an older aleph-vm must still parse after a
settings rename or removal.

Every <vm_hash>-controller.json embeds a full Settings dump. Settings uses
extra=forbid, so without a lenient parse a key that a NEWER version renamed
(e.g. 1.13.0's CONNECTIVITY_DNS_HOSTNAME, now CONNECTIVITY_DNS_HOSTNAMES)
makes the embedded parse raise, load_persistent_executions propagates it, and
the supervisor daemon aborts startup BY DESIGN on unparseable controller
configs: an in-place package upgrade with live VMs crash-loops the node."""

import pytest
from pydantic import ValidationError

from aleph.vm.conf import Settings
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    HypervisorType,
    VMConfiguration,
)


def _controller_config_dict(settings_dict: dict) -> dict:
    return {
        "vm_id": 3,
        "vm_hash": "cafe" * 16,
        "settings": settings_dict,
        "vm_configuration": {
            "use_jailer": False,
            "firecracker_bin_path": "/opt/firecracker",
            "jailer_bin_path": "/opt/jailer",
            "config_file_path": "/tmp/config.json",
            "init_timeout": 30.0,
        },
        "hypervisor": HypervisorType.firecracker,
    }


def test_settings_dump_with_renamed_key_still_parses():
    """A 1.13.0-era dump carries CONNECTIVITY_DNS_HOSTNAME (renamed since):
    unknown keys must be dropped, not rejected."""
    settings_dict = Settings().model_dump(exclude_none=True)
    settings_dict.pop("CONNECTIVITY_DNS_HOSTNAMES", None)
    settings_dict["CONNECTIVITY_DNS_HOSTNAME"] = "example.org"

    config = Configuration.model_validate(_controller_config_dict(settings_dict))

    # The legacy key is dropped; the current setting falls back to its default.
    assert config.settings.CONNECTIVITY_DNS_HOSTNAMES == Settings().CONNECTIVITY_DNS_HOSTNAMES
    assert not hasattr(config.settings, "CONNECTIVITY_DNS_HOSTNAME")
    assert isinstance(config.vm_configuration, VMConfiguration)


def test_settings_dump_with_arbitrary_unknown_key_still_parses():
    """The guard is structural: any future rename/removal must not break
    reattach across an upgrade."""
    settings_dict = Settings().model_dump(exclude_none=True)
    settings_dict["SOME_SETTING_REMOVED_IN_THE_FUTURE"] = {"nested": True}

    config = Configuration.model_validate(_controller_config_dict(settings_dict))

    assert config.vm_id == 3


def test_known_key_with_wrong_type_still_rejected():
    """Leniency is only about unknown keys: a corrupt value for a live
    setting must still fail loudly rather than misconfigure a VM."""
    settings_dict = Settings().model_dump(exclude_none=True)
    settings_dict["CONNECTIVITY_DNS_HOSTNAMES"] = 42

    with pytest.raises(ValidationError):
        Configuration.model_validate(_controller_config_dict(settings_dict))
