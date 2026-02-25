import pytest

from aleph.vm.conf import settings
from aleph.vm.network import firewall
from aleph.vm.network.firewall import (
    add_entity_if_not_present,
    execute_json_nft_commands,
    get_base_chains_for_hook,
    get_existing_nftables_ruleset,
    initialize_nftables,
    setup_nftables_for_vm,
)

mock_sample_base_nftables = [
    {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
    {"table": {"family": "ip", "name": "nat", "handle": 1}},
    {"chain": {"family": "ip", "table": "nat", "name": "DOCKER", "handle": 1}},
    {
        "chain": {
            "family": "ip",
            "table": "nat",
            "name": "POSTROUTING",
            "handle": 2,
            "type": "nat",
            "hook": "postrouting",
            "prio": 100,
            "policy": "accept",
        }
    },
]


@pytest.mark.asyncio
async def test_get_base_chains_for_hook(mocker):
    mocker.patch("aleph.vm.network.firewall.get_existing_nftables_ruleset", return_value=mock_sample_base_nftables)
    r = get_base_chains_for_hook("postrouting")
    assert len(r) == 1
    assert r[0] == {
        "chain": {
            "family": "ip",
            "table": "nat",
            "name": "POSTROUTING",
            "handle": 2,
            "type": "nat",
            "hook": "postrouting",
            "prio": 100,
            "policy": "accept",
        }
    }


@pytest.mark.asyncio
async def test_add_entity_if_not_present(mocker):
    rules = [
        {"chain": {"family": "ip", "table": "nat", "name": "aleph-supervisor-nat", "handle": 17}},
    ]
    commands = add_entity_if_not_present(
        rules,
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "aleph-supervisor-nat",
                "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
            }
        },
    )
    assert commands == [
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": "nat",
                    "chain": "aleph-supervisor-nat",
                    "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
                }
            }
        }
    ]


# Full example rulset taken from a real server
_full_example_ruleset = """{"nftables": [{"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}}, {"table": {"family": "ip", "name": "nat", "handle": 1}}, {"chain": {"family": "ip", "table": "nat", "name": "DOCKER", "handle": 1}}, {"chain": {"family": "ip", "table": "nat", "name": "POSTROUTING", "handle": 2, "type": "nat", "hook": "postrouting", "prio": 100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "PREROUTING", "handle": 5, "type": "nat", "hook": "prerouting", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "OUTPUT", "handle": 7, "type": "nat", "hook": "output", "prio": -100, "policy": "accept"}}, {"chain": {"family": "ip", "table": "nat", "name": "aleph-supervisor-nat", "handle": 17}}, {"chain": {"family": "ip", "table": "nat", "name": "aleph-supervisor-prerouting", "handle": 2171}}, {"chain": {"family": "ip", "table": "nat", "name": "aleph-vm-nat-4", "handle": 2174}}, {"rule": {"family": "ip", "table": "nat", "chain": "DOCKER", "handle": 931, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"return": null}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "DOCKER", "handle": 12, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"return": null}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "DOCKER", "handle": 923, "expr": [{"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}}, {"counter": {"packets": 0, "bytes": 0}}, {"xt": {"type": "target", "name": "DNAT"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 930, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "172.19.0.0", "len": 16}}}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"xt": {"type": "target", "name": "MASQUERADE"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 11, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": {"prefix": {"addr": "172.17.0.0", "len": 16}}}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 1910, "bytes": 113828}}, {"xt": {"type": "target", "name": "MASQUERADE"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 18, "expr": [{"jump": {"target": "aleph-supervisor-nat"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "POSTROUTING", "handle": 924, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": "172.17.0.2"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "172.17.0.2"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}}, {"counter": {"packets": 0, "bytes": 0}}, {"xt": {"type": "target", "name": "MASQUERADE"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "PREROUTING", "handle": 6, "expr": [{"xt": {"type": "match", "name": "addrtype"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "PREROUTING", "handle": 2172, "expr": [{"jump": {"target": "aleph-supervisor-prerouting"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "OUTPUT", "handle": 8, "expr": [{"match": {"op": "!=", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"prefix": {"addr": "127.0.0.0", "len": 8}}}}, {"xt": {"type": "match", "name": "addrtype"}}, {"counter": {"packets": 3, "bytes": 204}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "aleph-supervisor-nat", "handle": 2175, "expr": [{"jump": {"target": "aleph-vm-nat-4"}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "aleph-supervisor-prerouting", "handle": 2177, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eno1np1"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 24000}}, {"dnat": {"addr": "172.16.4.2", "port": 22}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "aleph-supervisor-prerouting", "handle": 2178, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "eno1np1"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 24001}}, {"dnat": {"addr": "172.16.4.2", "port": 22}}]}}, {"rule": {"family": "ip", "table": "nat", "chain": "aleph-vm-nat-4", "handle": 2176, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "vmtap4"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "eno1np1"}}, {"masquerade": null}]}}, {"table": {"family": "ip", "name": "filter", "handle": 2}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 1}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-1", "handle": 2}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-2", "handle": 3}}, {"chain": {"family": "ip", "table": "filter", "name": "FORWARD", "handle": 6, "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}}, {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 22}}, {"chain": {"family": "ip", "table": "filter", "name": "aleph-supervisor-filter", "handle": 31}}, {"chain": {"family": "ip", "table": "filter", "name": "aleph-vm-filter-4", "handle": 2810}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER", "handle": 1274, "expr": [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": "172.17.0.2"}}, {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-1", "handle": 1291, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER-ISOLATION-STAGE-2"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-1", "handle": 20, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 217667, "bytes": 12111176}}, {"jump": {"target": "DOCKER-ISOLATION-STAGE-2"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-1", "handle": 4, "expr": [{"counter": {"packets": 1041469, "bytes": 4421798030}}, {"return": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-2", "handle": 1292, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"drop": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-2", "handle": 21, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"drop": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-ISOLATION-STAGE-2", "handle": 5, "expr": [{"counter": {"packets": 217667, "bytes": 12111176}}, {"return": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1293, "expr": [{"counter": {"packets": 474998, "bytes": 3456558750}}, {"jump": {"target": "DOCKER-USER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1290, "expr": [{"counter": {"packets": 474998, "bytes": 3456558750}}, {"jump": {"target": "DOCKER-ISOLATION-STAGE-1"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1289, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"xt": {"type": "match", "name": "conntrack"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1288, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1287, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 1286, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 18, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"xt": {"type": "match", "name": "conntrack"}}, {"counter": {"packets": 292989, "bytes": 3174887860}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 17, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"jump": {"target": "DOCKER"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 16, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 217667, "bytes": 12111176}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 15, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}}, {"counter": {"packets": 0, "bytes": 0}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "FORWARD", "handle": 32, "expr": [{"jump": {"target": "aleph-supervisor-filter"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "DOCKER-USER", "handle": 23, "expr": [{"counter": {"packets": 1041469, "bytes": 4421798030}}, {"return": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-supervisor-filter", "handle": 33, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-supervisor-filter", "handle": 2809, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-supervisor-filter", "handle": 2811, "expr": [{"jump": {"target": "aleph-vm-filter-4"}}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-supervisor-filter", "handle": 2814, "expr": [{"match": {"op": "in", "left": {"ct": {"key": "state"}}, "right": ["established", "related"]}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-vm-filter-4", "handle": 2812, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "vmtap4"}}, {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "eno1np1"}}, {"accept": null}]}}, {"rule": {"family": "ip", "table": "filter", "chain": "aleph-vm-filter-4", "handle": 2813, "expr": [{"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "vmtap4"}}, {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 22}}, {"accept": null}]}}]}"""


@pytest.fixture
def mock_full_ruleset():
    import json

    output = json.loads(_full_example_ruleset)
    return output["nftables"]


@pytest.mark.asyncio
async def test_add_entity_if_not_present_full(mock_full_ruleset):
    commands = add_entity_if_not_present(
        mock_full_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "POSTROUTING",
                "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
            }
        },
    )
    assert commands == []


@pytest.mark.asyncio
async def test_add_entity_if_not_present_full_recursive(mock_full_ruleset):
    commands = add_entity_if_not_present(
        mock_full_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "aleph-supervisor-filter",
                "expr": [
                    {
                        "match": {
                            "op": "in",
                            "left": {"ct": {"key": "state"}},
                            "right": ["established", "related"],
                        }
                    },
                    {"accept": None},
                ],
            }
        },
    )
    assert commands == []


@pytest.mark.asyncio
async def test_initialize_nftables_fresh(mock_full_ruleset, mocker):
    """Test nftable init with an empty nftable
    it should create every base table/chain/rule."""
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", False)
    mock_empty_nftables = [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
    ]
    mocker.patch(
        "aleph.vm.network.firewall.get_existing_nftables_ruleset",
        return_value=mock_empty_nftables,
    )
    execute_json_nft_commands = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", execute_json_nft_commands)

    initialize_nftables()
    # No commands
    assert execute_json_nft_commands.call_count == 1
    assert execute_json_nft_commands.call_args[0][0] == [
        {"add": {"table": {"family": "ip", "name": "nat"}}},
        {
            "add": {
                "chain": {
                    "family": "ip",
                    "hook": "prerouting",
                    "name": "PREROUTING",
                    "policy": "accept",
                    "prio": -100,
                    "table": "nat",
                    "type": "nat",
                }
            }
        },
        {"add": {"table": {"family": "ip", "name": "nat"}}},
        {
            "add": {
                "chain": {
                    "family": "ip",
                    "hook": "postrouting",
                    "name": "POSTROUTING",
                    "prio": 100,
                    "table": "nat",
                    "type": "filter",
                }
            }
        },
        {"add": {"table": {"family": "ip", "name": "filter"}}},
        {
            "add": {
                "chain": {
                    "family": "ip",
                    "hook": "forward",
                    "name": "FORWARD",
                    "prio": 0,
                    "table": "filter",
                    "type": "filter",
                }
            }
        },
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-nat", "table": "nat"}}},
        {
            "add": {
                "rule": {
                    "chain": "POSTROUTING",
                    "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
                    "family": "ip",
                    "table": "nat",
                }
            }
        },
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-filter", "table": "filter"}}},
        {
            "add": {
                "rule": {
                    "chain": "FORWARD",
                    "expr": [{"jump": {"target": "aleph-supervisor-filter"}}],
                    "family": "ip",
                    "table": "filter",
                }
            }
        },
        {
            "add": {
                "rule": {
                    "chain": "aleph-supervisor-filter",
                    "expr": [
                        {"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": ["established", "related"]}},
                        {"accept": None},
                    ],
                    "family": "ip",
                    "table": "filter",
                }
            }
        },
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-prerouting", "table": "nat"}}},
        {
            "add": {
                "rule": {
                    "chain": "PREROUTING",
                    "expr": [{"jump": {"target": "aleph-supervisor-prerouting"}}],
                    "family": "ip",
                    "table": "nat",
                }
            }
        },
    ]


@pytest.mark.asyncio
async def test_initialize_nftables_already_setup(mock_full_ruleset, mocker):
    """Test nftable init with a full ruleset from aleph-vm already running so it should not create any new table/chain/rule."""
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", False)
    mocker.patch("aleph.vm.network.firewall.get_existing_nftables_ruleset", return_value=mock_full_ruleset)
    execute_json_nft_commands = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", execute_json_nft_commands)

    initialize_nftables()
    # No commands
    assert execute_json_nft_commands.call_count == 1
    assert execute_json_nft_commands.call_args[0][0] == []


@pytest.mark.asyncio
async def test_get_base_chains_for_hook_full_ruleset(mock_full_ruleset, mocker):
    r = mocker.patch("aleph.vm.network.firewall.get_existing_nftables_ruleset", return_value=mock_full_ruleset)

    execute_json_nft_commands = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", execute_json_nft_commands)
    chains = firewall.get_base_chains_for_hook("postrouting")
    assert len(chains) == 1

    chains = get_base_chains_for_hook("forward")
    assert r.call_count == 2
    assert len(chains) == 1


# test regression from server with docker that broke detection
_mock_ruleset_regression = {
    "nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        {"table": {"family": "ip", "name": "nat", "handle": 1}},
        {"chain": {"family": "ip", "table": "nat", "name": "DOCKER", "handle": 1}},
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "POSTROUTING",
                "handle": 2,
                "type": "nat",
                "hook": "postrouting",
                "prio": 100,
                "policy": "accept",
            }
        },
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "PREROUTING",
                "handle": 5,
                "type": "nat",
                "hook": "prerouting",
                "prio": -100,
                "policy": "accept",
            }
        },
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "OUTPUT",
                "handle": 7,
                "type": "nat",
                "hook": "output",
                "prio": -100,
                "policy": "accept",
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "DOCKER",
                "handle": 931,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"return": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "DOCKER",
                "handle": 12,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"return": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "DOCKER",
                "handle": 923,
                "expr": [
                    {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"xt": {"type": "target", "name": "DNAT"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "POSTROUTING",
                "handle": 930,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                            "right": {"prefix": {"addr": "172.19.0.0", "len": 16}},
                        }
                    },
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"xt": {"type": "target", "name": "MASQUERADE"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "POSTROUTING",
                "handle": 11,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                            "right": {"prefix": {"addr": "172.17.0.0", "len": 16}},
                        }
                    },
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 1906, "bytes": 113590}},
                    {"xt": {"type": "target", "name": "MASQUERADE"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "POSTROUTING",
                "handle": 924,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "saddr"}},
                            "right": "172.17.0.2",
                        }
                    },
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                            "right": "172.17.0.2",
                        }
                    },
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"xt": {"type": "target", "name": "MASQUERADE"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "PREROUTING",
                "handle": 6,
                "expr": [
                    {"xt": {"type": "match", "name": "addrtype"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"jump": {"target": "DOCKER"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "nat",
                "chain": "OUTPUT",
                "handle": 8,
                "expr": [
                    {
                        "match": {
                            "op": "!=",
                            "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                            "right": {"prefix": {"addr": "127.0.0.0", "len": 8}},
                        }
                    },
                    {"xt": {"type": "match", "name": "addrtype"}},
                    {"counter": {"packets": 3, "bytes": 204}},
                    {"jump": {"target": "DOCKER"}},
                ],
            }
        },
        {"table": {"family": "ip", "name": "filter", "handle": 2}},
        {"chain": {"family": "ip", "table": "filter", "name": "DOCKER", "handle": 1}},
        {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-1", "handle": 2}},
        {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-ISOLATION-STAGE-2", "handle": 3}},
        {
            "chain": {
                "family": "ip",
                "table": "filter",
                "name": "FORWARD",
                "handle": 6,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "drop",
            }
        },
        {"chain": {"family": "ip", "table": "filter", "name": "DOCKER-USER", "handle": 22}},
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER",
                "handle": 1274,
                "expr": [
                    {
                        "match": {
                            "op": "==",
                            "left": {"payload": {"protocol": "ip", "field": "daddr"}},
                            "right": "172.17.0.2",
                        }
                    },
                    {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 4021}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-1",
                "handle": 1291,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"jump": {"target": "DOCKER-ISOLATION-STAGE-2"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-1",
                "handle": 20,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 217648, "bytes": 12108397}},
                    {"jump": {"target": "DOCKER-ISOLATION-STAGE-2"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-1",
                "handle": 4,
                "expr": [{"counter": {"packets": 1041367, "bytes": 4421770493}}, {"return": None}],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-2",
                "handle": 1292,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"drop": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-2",
                "handle": 21,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"drop": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-ISOLATION-STAGE-2",
                "handle": 5,
                "expr": [{"counter": {"packets": 217648, "bytes": 12108397}}, {"return": None}],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1293,
                "expr": [{"counter": {"packets": 474896, "bytes": 3456531213}}, {"jump": {"target": "DOCKER-USER"}}],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1290,
                "expr": [
                    {"counter": {"packets": 474896, "bytes": 3456531213}},
                    {"jump": {"target": "DOCKER-ISOLATION-STAGE-1"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1289,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"xt": {"type": "match", "name": "conntrack"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1288,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"jump": {"target": "DOCKER"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1287,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 1286,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "br-bae9a3398396"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "br-bae9a3398396"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 18,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"xt": {"type": "match", "name": "conntrack"}},
                    {"counter": {"packets": 292965, "bytes": 3174877421}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 17,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"jump": {"target": "DOCKER"}},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 16,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"match": {"op": "!=", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 217648, "bytes": 12108397}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "FORWARD",
                "handle": 15,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": "iifname"}}, "right": "docker0"}},
                    {"match": {"op": "==", "left": {"meta": {"key": "oifname"}}, "right": "docker0"}},
                    {"counter": {"packets": 0, "bytes": 0}},
                    {"accept": None},
                ],
            }
        },
        {
            "rule": {
                "family": "ip",
                "table": "filter",
                "chain": "DOCKER-USER",
                "handle": 23,
                "expr": [{"counter": {"packets": 1041367, "bytes": 4421770493}}, {"return": None}],
            }
        },
    ]
}


@pytest.mark.asyncio
async def test_initialize_nftables_regression(mocker):
    """test regression from server with docker rule that broke detection"""
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", False)
    mocker.patch(
        "aleph.vm.network.firewall.get_existing_nftables_ruleset", return_value=_mock_ruleset_regression["nftables"]
    )
    execute_json_nft_commands = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", execute_json_nft_commands)

    initialize_nftables()
    # No commands
    assert execute_json_nft_commands.call_count == 1
    assert execute_json_nft_commands.call_args[0][0] == [
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-nat", "table": "nat"}}},
        {
            "add": {
                "rule": {
                    "chain": "POSTROUTING",
                    "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
                    "family": "ip",
                    "table": "nat",
                }
            }
        },
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-filter", "table": "filter"}}},
        {
            "add": {
                "rule": {
                    "chain": "FORWARD",
                    "expr": [{"jump": {"target": "aleph-supervisor-filter"}}],
                    "family": "ip",
                    "table": "filter",
                }
            }
        },
        {
            "add": {
                "rule": {
                    "chain": "aleph-supervisor-filter",
                    "expr": [
                        {"match": {"left": {"ct": {"key": "state"}}, "op": "in", "right": ["established", "related"]}},
                        {"accept": None},
                    ],
                    "family": "ip",
                    "table": "filter",
                }
            }
        },
        {"add": {"chain": {"family": "ip", "name": "aleph-supervisor-prerouting", "table": "nat"}}},
        {
            "add": {
                "rule": {
                    "chain": "PREROUTING",
                    "expr": [{"jump": {"target": "aleph-supervisor-prerouting"}}],
                    "family": "ip",
                    "table": "nat",
                }
            }
        },
    ]


"""Tests for handling different nftables output formats.

Depending on the nftables library version, the output can be either:
- A dict (expected format)
- A JSON string that needs to be parsed
- An invalid/unexpected format
"""


def test_execute_json_nft_commands_with_dict_output(mocker):
    """Test normal case where nftables returns a dict."""
    mock_nft = mocker.Mock()
    mock_nft.json_cmd.return_value = (0, {"nftables": [{"metainfo": {}}]}, "")
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([{"list": {"ruleset": {}}}])

    assert result == {"nftables": [{"metainfo": {}}]}


def test_execute_json_nft_commands_with_json_string_output(mocker):
    """Test case where nftables returns a JSON string instead of a dict.

    Some versions of the nftables Python library return output as a JSON-encoded
    string rather than a Python dict. This test verifies that such strings are
    properly parsed.
    """
    mock_nft = mocker.Mock()
    # Simulate nftables returning a JSON string instead of a dict
    json_string_output = '{"nftables": [{"metainfo": {"version": "1.0.9"}}]}'
    mock_nft.json_cmd.return_value = (0, json_string_output, "")
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([{"list": {"ruleset": {}}}])

    assert result == {"nftables": [{"metainfo": {"version": "1.0.9"}}]}


def test_execute_json_nft_commands_with_invalid_json_string(mocker):
    """Test case where nftables returns an invalid JSON string.

    If the nftables library returns a malformed string that cannot be parsed
    as JSON, the function should return an empty dict and log an error.
    """
    mock_nft = mocker.Mock()
    # Simulate nftables returning an invalid JSON string
    mock_nft.json_cmd.return_value = (0, "not valid json {{{", "")
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([{"list": {"ruleset": {}}}])

    assert result == {}


def test_execute_json_nft_commands_with_non_dict_non_string_output(mocker):
    """Test case where nftables returns an unexpected type (not dict or string).

    If nftables returns something that is neither a dict nor a string (e.g., None,
    list, int), the function should return an empty dict.
    """
    mock_nft = mocker.Mock()
    # Simulate nftables returning None
    mock_nft.json_cmd.return_value = (0, None, "")
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([{"list": {"ruleset": {}}}])

    assert result == {}


def test_execute_json_nft_commands_with_list_output(mocker):
    """Test case where nftables returns a list instead of dict."""
    mock_nft = mocker.Mock()
    # Simulate nftables returning a list
    mock_nft.json_cmd.return_value = (0, [{"nftables": []}], "")
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([{"list": {"ruleset": {}}}])

    assert result == {}


def test_execute_json_nft_commands_with_empty_commands(mocker):
    """Test that empty command list returns empty dict without calling nftables."""
    mock_nft = mocker.Mock()
    mocker.patch("aleph.vm.network.firewall.get_customized_nftables", return_value=mock_nft)

    result = execute_json_nft_commands([])

    assert result == {}
    mock_nft.json_cmd.assert_not_called()


def test_get_existing_nftables_ruleset_with_valid_output(mocker):
    """Test normal case where execute_json_nft_commands returns valid output."""
    ip_output = {"nftables": [{"metainfo": {}}, {"table": {"family": "ip", "name": "nat"}}]}
    ip6_output = {"nftables": [{"table": {"family": "ip6", "name": "filter"}}]}
    mocker.patch(
        "aleph.vm.network.firewall.execute_json_nft_commands",
        side_effect=[ip_output, ip6_output],
    )

    result = get_existing_nftables_ruleset()

    assert result == [
        {"metainfo": {}},
        {"table": {"family": "ip", "name": "nat"}},
        {"table": {"family": "ip6", "name": "filter"}},
    ]


def test_get_existing_nftables_ruleset_with_empty_output(mocker):
    """Test case where execute_json_nft_commands returns empty dict.

    This can happen when there's an error parsing nftables output.
    """
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", return_value={})

    result = get_existing_nftables_ruleset()

    assert result == []  # Both ip and ip6 queries return empty → combined is empty


def test_get_existing_nftables_ruleset_with_missing_nftables_key(mocker):
    """Test case where output dict doesn't contain 'nftables' key.

    Some error conditions might result in a dict without the expected key.
    """
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", return_value={"error": "something"})

    result = get_existing_nftables_ruleset()

    assert result == []  # Both ip and ip6 queries lack 'nftables' key → combined is empty


# --- IPv6 tests ---


@pytest.mark.asyncio
async def test_initialize_nftables_with_ipv6_fresh(mocker):
    """Test IPv6 initialization on a fresh system with no existing ip6 rules.
    Should create ip6 filter table, FORWARD chain, supervisor-filter chain, jump rule, and established/related rule.
    """
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", True)
    mock_empty_nftables = [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
    ]
    mocker.patch(
        "aleph.vm.network.firewall.get_existing_nftables_ruleset",
        return_value=mock_empty_nftables,
    )
    mock_exec = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", mock_exec)

    initialize_nftables()

    # Should be called twice: once for IPv4 commands, once for IPv6 commands
    assert mock_exec.call_count == 2

    ip6_commands = mock_exec.call_args_list[1][0][0]

    # Should create ip6 filter table
    assert {"add": {"table": {"family": "ip6", "name": "filter"}}} in ip6_commands

    # Should create ip6 FORWARD base chain
    assert {
        "add": {
            "chain": {
                "family": "ip6",
                "table": "filter",
                "name": "FORWARD",
                "type": "filter",
                "hook": "forward",
                "prio": 0,
            }
        }
    } in ip6_commands

    # Should create aleph-supervisor-filter chain in ip6
    assert {
        "add": {
            "chain": {
                "family": "ip6",
                "table": "filter",
                "name": "aleph-supervisor-filter",
            }
        }
    } in ip6_commands

    # Should create jump rule from FORWARD to aleph-supervisor-filter
    assert {
        "add": {
            "rule": {
                "family": "ip6",
                "table": "filter",
                "chain": "FORWARD",
                "expr": [{"jump": {"target": "aleph-supervisor-filter"}}],
            }
        }
    } in ip6_commands

    # Should create established/related accept rule
    assert {
        "add": {
            "rule": {
                "family": "ip6",
                "table": "filter",
                "chain": "aleph-supervisor-filter",
                "expr": [
                    {
                        "match": {
                            "op": "in",
                            "left": {"ct": {"key": "state"}},
                            "right": ["established", "related"],
                        }
                    },
                    {"accept": None},
                ],
            }
        }
    } in ip6_commands


@pytest.mark.asyncio
async def test_initialize_nftables_with_ipv6_docker(mocker):
    """Test IPv6 initialization on a system with Docker's ip6 filter FORWARD chain (policy drop).
    Should discover Docker's existing chain and add a jump to aleph-supervisor-filter.
    """
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", True)
    # Simulate a system with Docker's ip6 filter table and FORWARD chain with policy drop
    mock_ruleset_with_docker_ip6 = [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        # IPv4 base chains (needed for IPv4 init to succeed)
        {"table": {"family": "ip", "name": "nat", "handle": 1}},
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "POSTROUTING",
                "handle": 2,
                "type": "nat",
                "hook": "postrouting",
                "prio": 100,
                "policy": "accept",
            }
        },
        {
            "chain": {
                "family": "ip",
                "table": "nat",
                "name": "PREROUTING",
                "handle": 5,
                "type": "nat",
                "hook": "prerouting",
                "prio": -100,
                "policy": "accept",
            }
        },
        {"table": {"family": "ip", "name": "filter", "handle": 2}},
        {
            "chain": {
                "family": "ip",
                "table": "filter",
                "name": "FORWARD",
                "handle": 6,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "drop",
            }
        },
        # Docker's ip6 filter table with FORWARD chain and policy drop
        {"table": {"family": "ip6", "name": "filter", "handle": 1}},
        {
            "chain": {
                "family": "ip6",
                "table": "filter",
                "name": "FORWARD",
                "handle": 1,
                "type": "filter",
                "hook": "forward",
                "prio": 0,
                "policy": "drop",
            }
        },
    ]
    mocker.patch(
        "aleph.vm.network.firewall.get_existing_nftables_ruleset",
        return_value=mock_ruleset_with_docker_ip6,
    )
    mock_exec = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", mock_exec)

    initialize_nftables()

    assert mock_exec.call_count == 2

    ip6_commands = mock_exec.call_args_list[1][0][0]

    # Should NOT create ip6 filter table (Docker already has it)
    assert {"add": {"table": {"family": "ip6", "name": "filter"}}} not in ip6_commands

    # Should NOT create ip6 FORWARD chain (Docker already has it)
    forward_chain_adds = [
        c
        for c in ip6_commands
        if "add" in c and "chain" in c["add"] and c["add"]["chain"].get("name") == "FORWARD"
    ]
    assert forward_chain_adds == []

    # Should create aleph-supervisor-filter chain in Docker's ip6 filter table
    assert {
        "add": {
            "chain": {
                "family": "ip6",
                "table": "filter",
                "name": "aleph-supervisor-filter",
            }
        }
    } in ip6_commands

    # Should create jump from Docker's FORWARD to aleph-supervisor-filter
    assert {
        "add": {
            "rule": {
                "family": "ip6",
                "table": "filter",
                "chain": "FORWARD",
                "expr": [{"jump": {"target": "aleph-supervisor-filter"}}],
            }
        }
    } in ip6_commands


@pytest.mark.asyncio
async def test_initialize_nftables_ipv6_disabled(mocker):
    """Test that no ip6 commands are generated when IPv6 forwarding is disabled."""
    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", False)
    mock_empty_nftables = [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
    ]
    mocker.patch(
        "aleph.vm.network.firewall.get_existing_nftables_ruleset",
        return_value=mock_empty_nftables,
    )
    mock_exec = mocker.Mock(return_value=[])
    mocker.patch("aleph.vm.network.firewall.execute_json_nft_commands", mock_exec)

    initialize_nftables()

    # Only IPv4 commands should be executed (single call)
    assert mock_exec.call_count == 1

    # Verify no ip6 entities in the IPv4 commands
    ipv4_commands = mock_exec.call_args_list[0][0][0]
    for cmd in ipv4_commands:
        for action in cmd.values():
            for entity in action.values():
                if isinstance(entity, dict):
                    assert entity.get("family") != "ip6", f"Unexpected ip6 entity in IPv4 commands: {cmd}"


@pytest.mark.asyncio
async def test_setup_nftables_for_vm_ipv6(mocker):
    """Test that setup_nftables_for_vm creates both ip and ip6 forward chains when IPv6 is enabled."""
    from unittest.mock import MagicMock

    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", True)

    mock_add_postrouting = mocker.patch("aleph.vm.network.firewall.add_postrouting_chain")
    mock_add_forward = mocker.patch("aleph.vm.network.firewall.add_forward_chain")
    mock_add_masq = mocker.patch("aleph.vm.network.firewall.add_masquerading_rule")
    mock_add_fwd_ext = mocker.patch("aleph.vm.network.firewall.add_forward_rule_to_external")

    mock_interface = MagicMock()
    mock_interface.device_name = "vmtap1"

    setup_nftables_for_vm(1, mock_interface)

    # IPv4 calls
    mock_add_postrouting.assert_called_once_with("aleph-vm-nat-1")
    mock_add_masq.assert_called_once_with(1, mock_interface)

    # add_forward_chain called twice: once for ip (default), once for ip6
    assert mock_add_forward.call_count == 2
    mock_add_forward.assert_any_call("aleph-vm-filter-1")
    mock_add_forward.assert_any_call("aleph-vm-filter-1", family="ip6")

    # add_forward_rule_to_external called twice: once for ip (default), once for ip6
    assert mock_add_fwd_ext.call_count == 2
    mock_add_fwd_ext.assert_any_call(1, mock_interface)
    mock_add_fwd_ext.assert_any_call(1, mock_interface, family="ip6")


@pytest.mark.asyncio
async def test_setup_nftables_for_vm_ipv6_disabled(mocker):
    """Test that setup_nftables_for_vm only creates ip chains when IPv6 is disabled."""
    from unittest.mock import MagicMock

    mocker.patch.object(settings, "IPV6_FORWARDING_ENABLED", False)

    mock_add_postrouting = mocker.patch("aleph.vm.network.firewall.add_postrouting_chain")
    mock_add_forward = mocker.patch("aleph.vm.network.firewall.add_forward_chain")
    mock_add_masq = mocker.patch("aleph.vm.network.firewall.add_masquerading_rule")
    mock_add_fwd_ext = mocker.patch("aleph.vm.network.firewall.add_forward_rule_to_external")

    mock_interface = MagicMock()
    mock_interface.device_name = "vmtap1"

    setup_nftables_for_vm(1, mock_interface)

    # Only IPv4 calls
    mock_add_forward.assert_called_once_with("aleph-vm-filter-1")
    mock_add_fwd_ext.assert_called_once_with(1, mock_interface)
