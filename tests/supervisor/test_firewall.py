import pytest

from aleph.vm.network import firewall
from aleph.vm.network.firewall import (
    add_entity_if_not_present,
    get_base_chains_for_hook,
    initialize_nftables,
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
