"""Cloud-init seed parity: the Rust daemon emits the NoCloud user-data and
network-config as `#cloud-config` + JSON where Python emits YAML. JSON is a
YAML subset, so the parity target is the PARSED mapping: the committed Rust
fixtures (rust/crates/supervisor-daemon/tests/fixtures/cloudinit/, pinned by
cargo tests) must parse to exactly what the actual Python builders
(controllers/qemu/cloudinit.py) produce for the same inputs.

No daemon and no root needed; this is a pure function comparison.
"""

from __future__ import annotations

import json
import os
from ipaddress import IPv6Network
from pathlib import Path

import pytest
import yaml
from conftest import cargo_missing

from aleph.vm.network.interfaces import TapInterface
from aleph.vm.network.ipaddresses import IPv4NetworkWithInterfaces
from aleph.vm.supervisor.controllers.qemu.cloudinit import (
    create_metadata_file,
    create_network_file,
    encode_user_data,
)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(cargo_missing(), reason="cargo is not on PATH"),
]

FIXTURES = Path(__file__).resolve().parents[2] / "rust/crates/supervisor-daemon/tests/fixtures/cloudinit"


def _rust_fixture(name: str) -> dict:
    text = (FIXTURES / name).read_text()
    if text.startswith("#cloud-config\n"):
        text = text[len("#cloud-config\n") :]
    return json.loads(text)


def test_user_data_parses_to_the_python_cloud_config():
    # Same inputs as the pinning cargo test (cloudinit.rs).
    python = yaml.safe_load(encode_user_data("my-host", ["ssh-ed25519 AAAA test@host"], has_gpu=False).decode())
    assert _rust_fixture("user-data.json") == python

    python_gpu = yaml.safe_load(encode_user_data("my-host", [], has_gpu=True).decode())
    assert _rust_fixture("user-data-gpu.json") == python_gpu

    # The confidential create path (increment 6): the LUKS growpart bootcmds
    # and no guest agent (is_confidential=True, install_guest_agent=False).
    python_confidential = yaml.safe_load(
        encode_user_data(
            "my-host",
            ["ssh-ed25519 AAAA test@host"],
            has_gpu=False,
            is_confidential=True,
            install_guest_agent=False,
        ).decode()
    )
    assert _rust_fixture("user-data-confidential.json") == python_confidential


def test_network_config_parses_to_the_python_netplan_mapping():
    # The tap of the cargo fixture: vm_index 4 in the default pools.
    tap = TapInterface(
        "vmtap4",
        ip_network=IPv4NetworkWithInterfaces("172.16.4.0/24"),
        ipv6_network=IPv6Network("fc00:1:2:3:3:aaaa:bbbb:cc00/124"),
        ndp_proxy=None,
    )
    # The exact derivations of build_cloud_init_drive (qemu_build.py).
    python = yaml.safe_load(
        create_network_file(
            ip=tap.guest_ip.with_prefixlen,
            ipv6=tap.guest_ipv6.with_prefixlen,
            ipv6_gateway=str(tap.host_ipv6.ip),
            nameservers=["1.1.1.1", "8.8.8.8"],
            route=str(tap.host_ip).split("/", 1)[0],
        ).decode()
    )
    assert _rust_fixture("network-config.json") == python

    # Networking disabled: empty addresses, null nameservers.
    python = yaml.safe_load(create_network_file(ip="", ipv6="", ipv6_gateway="", nameservers=None, route="").decode())
    assert _rust_fixture("network-config-no-dns.json") == python


def test_metadata_is_byte_identical():
    rust = '{"instance-id": "iid-instance-4", "local-hostname": "my-host"}'
    assert create_metadata_file("my-host", 4).decode() == rust
