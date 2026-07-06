"""Generate the Rust daemon's test fixtures from the actual Python models.

Writes, under rust/crates/supervisor-daemon/tests/fixtures/:
- three controller configuration JSONs (plain QEMU, QEMU with GPU,
  confidential QEMU), serialized by the pydantic ``Configuration`` model
  exactly as ``save_controller_configuration`` writes them;
- ``supervisor.sqlite3``, a port-mapping store created and populated by the
  SQLAlchemy ``PortMapping`` model (same schema, same datetime encoding as
  a live node's database);
- ``nftables.json``, the firewall.py oracle: canned input rulesets and the
  exact nftables JSON command batches the Python firewall functions emit
  for them (captured by stubbing the fetch/execute edges), plus predicate
  expectations. The Rust pure rule layer replays these byte-for-byte;
- ``written-controller-config.json``, the exact bytes
  ``save_controller_configuration`` writes for a spec-created VM (the
  parity target of the Rust controller-config writer).

The fixtures are committed; regenerate them after a model change with:

    venv/bin/python scripts/generate_rust_fixtures.py

The VM hashes are sha256("rust-fixture-<name>") and must match the
constants in rust/crates/supervisor-daemon/src/test_fixtures.rs.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from ipaddress import IPv6Network
from pathlib import Path
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from aleph.vm.conf import settings
from aleph.vm.network import firewall
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.network.ipaddresses import IPv4NetworkWithInterfaces
from aleph.vm.supervisor.networking_db import Base, PortMapping
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "rust/crates/supervisor-daemon/tests/fixtures"

EXECUTION_ROOT = Path("/var/lib/aleph/vm")
VOLUMES_DIR = EXECUTION_ROOT / "volumes/persistent"


def fixture_hash(name: str) -> str:
    return hashlib.sha256(f"rust-fixture-{name}".encode()).hexdigest()


QEMU_HASH = fixture_hash("qemu")
GPU_HASH = fixture_hash("gpu")
CONFIDENTIAL_HASH = fixture_hash("confidential")
PORTS_ONLY_HASH = fixture_hash("ports-only")


def qemu_vm_configuration(vm_hash: str, **overrides) -> dict:
    base = {
        "qemu_bin_path": "/usr/bin/qemu-system-x86_64",
        "cloud_init_drive_path": str(EXECUTION_ROOT / f"cloud-init-{vm_hash}.img"),
        "image_path": str(VOLUMES_DIR / vm_hash / "rootfs.qcow2"),
        "monitor_socket_path": EXECUTION_ROOT / f"{vm_hash}-monitor.socket",
        "qmp_socket_path": EXECUTION_ROOT / f"{vm_hash}-qmp.socket",
        "qga_socket_path": EXECUTION_ROOT / f"{vm_hash}-qga.socket",
        "vcpu_count": 2,
        "mem_size_mb": 2048,
        "interface_name": "vmtap3",
        "host_volumes": [],
        "gpus": [],
    }
    base.update(overrides)
    return base


def write_configuration(vm_hash: str, configuration: Configuration) -> None:
    # Same serialization as save_controller_configuration.
    path = FIXTURES_DIR / f"{vm_hash}-controller.json"
    path.write_text(configuration.model_dump_json(by_alias=True, exclude_none=True, indent=4))
    print(f"wrote {path}")


def build_configurations() -> None:
    settings_slice = ControllerSettings()

    write_configuration(
        QEMU_HASH,
        Configuration(
            vm_id=3,
            vm_hash=QEMU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **qemu_vm_configuration(
                    QEMU_HASH,
                    host_volumes=[
                        QemuVMHostVolume(
                            mount="",
                            path_on_host=VOLUMES_DIR / QEMU_HASH / "data.qcow2",
                            read_only=False,
                        )
                    ],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )

    write_configuration(
        GPU_HASH,
        Configuration(
            vm_id=4,
            vm_hash=GPU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **qemu_vm_configuration(
                    GPU_HASH,
                    interface_name="vmtap4",
                    gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )

    session_dir = Path("/var/lib/aleph/vm/confidential_sessions") / CONFIDENTIAL_HASH
    write_configuration(
        CONFIDENTIAL_HASH,
        Configuration(
            vm_id=5,
            vm_hash=CONFIDENTIAL_HASH,
            settings=settings_slice,
            vm_configuration=QemuConfidentialVMConfiguration(
                **qemu_vm_configuration(CONFIDENTIAL_HASH, interface_name="vmtap5"),
                ovmf_path=Path("/opt/aleph-vm/firmware/OVMF_CSV.fd"),
                sev_session_file=session_dir / "vm_session.b64",
                sev_dh_cert_file=session_dir / "vm_godh.b64",
                # NO_DBG | SEV_ES: the SEV-ES bit (0x4) must be set so the
                # Rust confidential_mode mapping is exercised.
                sev_policy=0x5,
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )


def build_database() -> None:
    db_path = FIXTURES_DIR / "supervisor.sqlite3"
    db_path.unlink(missing_ok=True)
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    # A fixed instant keeps regeneration byte-stable: rerunning the script
    # must produce a zero diff on the committed sqlite file.
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session(engine) as session:
        # A soft-deleted mapping: must never surface.
        session.add(
            PortMapping(
                vm_hash=QEMU_HASH,
                vm_port=22,
                host_port=24022,
                tcp=True,
                udp=False,
                created_at=now,
                deleted_at=now,
            )
        )
        # The active mappings of the QEMU fixture VM.
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=22, host_port=24000, tcp=True, udp=False, created_at=now))
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=8080, host_port=24001, tcp=True, udp=True, created_at=now))
        # A mapping for a VM with no controller config: the world view must
        # never surface it.
        session.add(
            PortMapping(
                vm_hash=PORTS_ONLY_HASH,
                vm_port=443,
                host_port=24002,
                tcp=True,
                udp=False,
                created_at=now,
            )
        )
        session.commit()
    print(f"wrote {db_path}")


CREATED_HASH = fixture_hash("created")


def build_written_controller_config() -> None:
    """The exact bytes save_controller_configuration writes for a VM created
    through the spec path (build_qemu_configuration inputs, pydantic
    serialization). The Rust controller-config writer must reproduce them
    byte-for-byte so a rollback to the Python daemon reparses its files
    unchanged."""
    session_dir = EXECUTION_ROOT / "jailer"
    settings_slice = ControllerSettings(
        JAILER_BASE_DIR=session_dir,
        NETWORK_INTERFACE="eth0",
    )
    configuration = Configuration(
        vm_id=6,
        vm_hash=CREATED_HASH,
        settings=settings_slice,
        vm_configuration=QemuVMConfiguration(
            **qemu_vm_configuration(
                CREATED_HASH,
                interface_name="vmtap6",
                host_volumes=[
                    QemuVMHostVolume(
                        mount="",
                        path_on_host=VOLUMES_DIR / CREATED_HASH / "data.qcow2",
                        read_only=False,
                    )
                ],
                gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
            )
        ),
        hypervisor=HypervisorType.qemu,
    )
    path = FIXTURES_DIR / "written-controller-config.json"
    path.write_text(configuration.model_dump_json(by_alias=True, exclude_none=True, indent=4))
    print(f"wrote {path}")


# ── nftables oracle ────────────────────────────────────────────────────────
#
# Canned `nft -j list ruleset` snapshots (ip and ip6 merged, the shape
# get_existing_nftables_ruleset returns) and the command batches firewall.py
# emits for them. The fetch/execute edges are stubbed so the capture is pure:
# same input ruleset in, same command batches out, no root needed. The Rust
# nft module replays every scenario against the same inputs.

NFT_IFACE = "eth0"


def _base_chain(family, table, name, type_, hook, prio, handle):
    return {
        "chain": {
            "family": family,
            "table": table,
            "name": name,
            "handle": handle,
            "type": type_,
            "hook": hook,
            "prio": prio,
            "policy": "accept",
        }
    }


def _plain_chain(family, table, name, handle):
    return {"chain": {"family": family, "table": table, "name": name, "handle": handle}}


def _rule(family, table, chain, handle, expr):
    return {"rule": {"family": family, "table": table, "chain": chain, "handle": handle, "expr": expr}}


def _jump(target):
    return [{"jump": {"target": target}}]


def _ct_established_related():
    return [
        {
            "match": {
                "op": "in",
                "left": {"ct": {"key": "state"}},
                "right": ["established", "related"],
            }
        },
        {"accept": None},
    ]


def _iif_oif(iif, oif, verdict):
    return [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": iif}},
        {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": oif}},
        verdict,
    ]


def _dnat_rule_expr(host_port, addr, vm_port, protocol):
    return [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": NFT_IFACE}},
        {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": host_port}},
        {"dnat": {"addr": addr, "port": vm_port}},
    ]


def _forward_accept_expr(vm_port, protocol):
    return [
        {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": NFT_IFACE}},
        {"match": {"op": "==", "left": {"payload": {"protocol": protocol, "field": "dport"}}, "right": vm_port}},
        {"accept": None},
    ]


def bare_host_ruleset() -> list[dict]:
    """A host with the distro base chains but no aleph state yet. The raw
    PREROUTING chain (prio -300) exercises the nat-vs-raw prerouting
    selection."""
    return [
        {"table": {"family": "ip", "name": "raw", "handle": 1}},
        _base_chain("ip", "raw", "PREROUTING", "filter", "prerouting", -300, 1),
        {"table": {"family": "ip", "name": "nat", "handle": 2}},
        _base_chain("ip", "nat", "PREROUTING", "nat", "prerouting", -100, 1),
        _base_chain("ip", "nat", "POSTROUTING", "nat", "postrouting", 100, 2),
        {"table": {"family": "ip", "name": "filter", "handle": 3}},
        _base_chain("ip", "filter", "FORWARD", "filter", "forward", 0, 1),
        {"table": {"family": "ip6", "name": "filter", "handle": 1}},
        _base_chain("ip6", "filter", "FORWARD", "filter", "forward", 0, 1),
    ]


def typical_ruleset() -> list[dict]:
    """A live aleph node: base chains, the supervisor chains, and one running
    VM (vm_index 3, guest 172.16.3.2, one tcp redirect 24000 -> 22)."""
    return bare_host_ruleset() + [
        # ip nat: the supervisor NAT and prerouting chains plus VM 3.
        _plain_chain("ip", "nat", "aleph-supervisor-nat", 10),
        _rule("ip", "nat", "POSTROUTING", 11, _jump("aleph-supervisor-nat")),
        _plain_chain("ip", "nat", "aleph-supervisor-prerouting", 12),
        _rule("ip", "nat", "PREROUTING", 13, _jump("aleph-supervisor-prerouting")),
        _plain_chain("ip", "nat", "aleph-vm-nat-3", 14),
        _rule("ip", "nat", "aleph-supervisor-nat", 15, _jump("aleph-vm-nat-3")),
        _rule("ip", "nat", "aleph-vm-nat-3", 16, _iif_oif("vmtap3", NFT_IFACE, {"masquerade": None})),
        _rule("ip", "nat", "aleph-supervisor-prerouting", 17, _dnat_rule_expr(24000, "172.16.3.2", 22, "tcp")),
        # ip filter: the supervisor filter chain plus VM 3.
        _plain_chain("ip", "filter", "aleph-supervisor-filter", 20),
        _rule("ip", "filter", "FORWARD", 21, _jump("aleph-supervisor-filter")),
        _rule("ip", "filter", "aleph-supervisor-filter", 22, _ct_established_related()),
        _plain_chain("ip", "filter", "aleph-vm-filter-3", 23),
        _rule("ip", "filter", "aleph-supervisor-filter", 24, _jump("aleph-vm-filter-3")),
        _rule("ip", "filter", "aleph-vm-filter-3", 25, _iif_oif("vmtap3", NFT_IFACE, {"accept": None})),
        _rule("ip", "filter", "aleph-vm-filter-3", 26, _forward_accept_expr(22, "tcp")),
        # ip6 filter: the supervisor filter chain plus VM 3.
        _plain_chain("ip6", "filter", "aleph-supervisor-filter", 10),
        _rule("ip6", "filter", "FORWARD", 11, _jump("aleph-supervisor-filter")),
        _rule("ip6", "filter", "aleph-supervisor-filter", 12, _ct_established_related()),
        _plain_chain("ip6", "filter", "aleph-vm-filter-3", 13),
        _rule("ip6", "filter", "aleph-supervisor-filter", 14, _jump("aleph-vm-filter-3")),
        _rule("ip6", "filter", "aleph-vm-filter-3", 15, _iif_oif("vmtap3", NFT_IFACE, {"accept": None})),
    ]


def _tap(vm_index: int) -> TapInterface:
    return TapInterface(
        f"vmtap{vm_index}",
        ip_network=IPv4NetworkWithInterfaces(f"172.16.{vm_index}.0/24"),
        ipv6_network=IPv6Network(f"fc00:1:2:3:3:aaaa:bbbb:cc{vm_index}0/124"),
        ndp_proxy=None,
    )


def _capture(ruleset: list[dict], call) -> list[list[dict]]:
    """Run one firewall.py call with the fetch/execute edges stubbed on a
    frozen ruleset; return every command batch handed to execute."""
    batches: list[list[dict]] = []

    def fake_fetch() -> list[dict]:
        return copy.deepcopy(ruleset)

    def fake_execute(commands: list[dict]) -> dict:
        batches.append(copy.deepcopy(commands))
        return {}

    with (
        mock.patch.object(firewall, "get_existing_nftables_ruleset", fake_fetch),
        mock.patch.object(firewall, "execute_json_nft_commands", fake_execute),
    ):
        call()
    return batches


def nftables_fixture_payload() -> dict:
    """The full nftables oracle payload; also imported by the conformance
    suite to detect drift between firewall.py and the committed fixture."""
    # The values the firewall module reads from settings at call time.
    settings.update(NETWORK_INTERFACE=NFT_IFACE, NFTABLES_CHAIN_PREFIX="aleph", IPV6_FORWARDING_ENABLED=True)

    rulesets: dict[str, list[dict]] = {
        "empty": [],
        "bare-host": bare_host_ruleset(),
        "typical": typical_ruleset(),
    }

    scenario_calls = {
        "initialize-empty": ("empty", firewall.initialize_nftables),
        "initialize-bare-host": ("bare-host", firewall.initialize_nftables),
        "initialize-typical": ("typical", firewall.initialize_nftables),
        "setup-vm-new": ("typical", lambda: firewall.setup_nftables_for_vm(4, _tap(4))),
        "setup-vm-existing": ("typical", lambda: firewall.setup_nftables_for_vm(3, _tap(3))),
        "add-redirect-new": ("typical", lambda: firewall.add_port_redirect_rule(3, _tap(3), 24010, 8080, "udp")),
        "add-redirect-existing": ("typical", lambda: firewall.add_port_redirect_rule(3, _tap(3), 24000, 22, "tcp")),
        "remove-redirect": ("typical", lambda: firewall.remove_port_redirect_rule(_tap(3), 24000, 22, "tcp")),
        "teardown-vm": ("typical", lambda: firewall.teardown_nftables_for_vm(3)),
        "remove-all-aleph-chains": ("typical", firewall.remove_all_aleph_chains),
    }
    scenarios = {
        name: {"ruleset": ruleset_name, "batches": _capture(rulesets[ruleset_name], call)}
        for name, (ruleset_name, call) in scenario_calls.items()
    }

    # IPv6 forwarding disabled: initialize stops after the ip phase.
    settings.update(IPV6_FORWARDING_ENABLED=False)
    scenarios["initialize-empty-no-ipv6"] = {
        "ruleset": "empty",
        "batches": _capture(rulesets["empty"], firewall.initialize_nftables),
    }
    settings.update(IPV6_FORWARDING_ENABLED=True)

    typical = rulesets["typical"]
    predicates = {
        # "forward" resolves per family, so the key is "hook/family".
        "table-for-hook": {
            name: {
                f"{hook}/{family}": firewall.get_table_for_hook(hook, family, nft_ruleset=rulesets[name])
                for hook, family in (
                    ("prerouting", "ip"),
                    ("postrouting", "ip"),
                    ("forward", "ip"),
                    ("forward", "ip6"),
                )
            }
            for name in ("bare-host", "typical")
        },
        "port-redirect-exists": [
            {"args": [24000, "172.16.3.2", 22, "tcp"], "expected": True},
            {"args": [24000, "172.16.3.2", 22, "udp"], "expected": False},
            {"args": [24010, "172.16.3.2", 8080, "udp"], "expected": False},
        ],
        "nftables-redirections": [
            {"port": 24000, "expected": True},
            {"port": 22, "expected": True},
            {"port": 24010, "expected": False},
        ],
        "all-aleph-chains": firewall.get_all_aleph_chains(nft_ruleset=typical),
    }
    for case in predicates["port-redirect-exists"]:
        assert firewall.check_port_redirect_exists(*case["args"], ruleset=typical) is case["expected"]
    with mock.patch.object(firewall, "get_existing_nftables_ruleset", lambda: copy.deepcopy(typical)):
        for case in predicates["nftables-redirections"]:
            assert firewall.check_nftables_redirections(case["port"]) is case["expected"]

    return {
        "network_interface": NFT_IFACE,
        "chain_prefix": "aleph",
        "rulesets": rulesets,
        "scenarios": scenarios,
        "predicates": predicates,
    }


def build_nftables_fixture() -> None:
    path = FIXTURES_DIR / "nftables.json"
    path.write_text(json.dumps(nftables_fixture_payload(), indent=2) + "\n")
    print(f"wrote {path}")


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    build_configurations()
    build_database()
    build_written_controller_config()
    build_nftables_fixture()


if __name__ == "__main__":
    main()
