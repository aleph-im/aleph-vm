"""
IPv4 network setup using NFTABLES.
Add Nat to the VM in ipv4 and port forwarding for direct access.
"""

import json
import logging
from functools import lru_cache
from typing import Literal

from nftables import Nftables

from aleph.vm.conf import settings
from aleph.vm.network.interfaces import TapInterface

logger = logging.getLogger(__name__)


@lru_cache
def get_customized_nftables() -> Nftables:
    nft = Nftables()
    nft.set_json_output(True)
    nft.set_stateless_output(True)
    nft.set_service_output(False)
    nft.set_reversedns_output(False)
    nft.set_numeric_proto_output(True)
    return nft


def execute_json_nft_commands(commands: list[dict]) -> dict:
    """Executes a list of nftables commands and returns the json output"""
    nft = get_customized_nftables()
    commands_dict = {"nftables": commands}
    try:
        logger.debug("Validating nftables rules")
        nft.json_validate(commands_dict)
    except Exception as e:
        logger.error(f"Failed to verify nftables rules: {e}")

    logger.debug("Inserting nftables rules")
    return_code, output, error = nft.json_cmd(commands_dict)
    if return_code != 0:
        logger.error("Failed to add nftables rules: %s -- %s", error, json.dumps(commands, indent=4))

    return output


def get_existing_nftables_ruleset() -> list[dict]:
    """Retrieves the full nftables ruleset and returns it"""
    # List all NAT rules
    commands = [{"list": {"ruleset": {"family": "ip"}}}]

    nft_ruleset = execute_json_nft_commands(commands)
    return nft_ruleset["nftables"]


def get_base_chains_for_hook(hook: str, family: str = "ip") -> list:
    """Looks through the nftables ruleset and creates a list of
    all chains that are base chains for the specified hook"""
    nft_ruleset = get_existing_nftables_ruleset()
    chains = []

    for entry in nft_ruleset:
        if (
            not isinstance(entry, dict)
            or "chain" not in entry
            or "family" not in entry["chain"]
            or entry["chain"]["family"] != family
            or "hook" not in entry["chain"]
            or entry["chain"]["hook"] != hook
        ):
            # Ignoring all entries that are not a base chain.
            continue

        chains.append(entry)

    return chains


def get_table_for_hook(hook: str, family: str = "ip") -> str:
    chains = get_base_chains_for_hook(hook, family)
    table = chains.pop()["chain"]["table"]
    return table


EntityType = Literal["table", "rule", "chain"]


def is_entity_present(nft_ruleset: list[dict], t: EntityType, **kwargs) -> bool:
    """Is the rule/chain with these paramater present in the nft rule lists

    Note: This check if at least the passed kwargs is present but ignore additional attribute on the entity
    This avoiding problem with for e.g the handle
    But it might lead to false positive it they are unexpected parameters"""
    for entry in nft_ruleset:
        if not isinstance(entry, dict) or t not in entry:
            continue
        e = entry[t]
        if _is_superset(kwargs, e):
            return True
    return False


def _is_superset(a, b):
    for k, v in a.items():
        if b.get(k) != v:
            return False
    return True


def if_chain_exists(nft_ruleset: list[dict], family: str, table: str, name: str) -> bool:
    """Checks whether the specified table exists in the nftables ruleset"""
    return is_entity_present(
        nft_ruleset,
        t="chain",
        family=family,
        table=table,
        name=name,
    )


def add_entity_if_not_present(nft_ruleset, entity: dict[EntityType, dict]) -> list[dict]:
    """Return the nft command to create entity if it doesn't exist within the ruleset"""
    assert len(entity) == 1

    commands = []
    for k, v in entity.items():
        if not is_entity_present(nft_ruleset, k, **v):
            commands.append({"add": {k: v}})
    return commands


def add_entities_if_not_present(nft_ruleset: list[dict], entites: list[dict[EntityType, dict]]) -> list[dict]:
    """Return the nft command to create the if it doesn't exist within the ruleset"""
    commands = []
    for entity in entites:
        commands += add_entity_if_not_present(nft_ruleset, entity)
    return commands


def ensure_entities(entities: list[dict[EntityType, dict]]) -> dict:
    """Ensure entities are present in the nftables ruleset. Execute them
    Returns the output from executing the nftables commands"""
    nft_ruleset = get_existing_nftables_ruleset()
    commands = add_entities_if_not_present(nft_ruleset, entities)
    return execute_json_nft_commands(commands)


def initialize_nftables() -> None:
    """
    Initializes `nftables` configurations for managing networking rules and chains. The
    function ensures that the base chains for the relevant hooks (postrouting and forward)
    are properly set up and, if missing, creates them. Additionally, it adds the necessary
    custom chains and rules in the nftables configuration for network supervision.

    Chain aleph-vm-supervisor-nat are created and aleph-vm-supervisor-filter are created
    to contains our rules.

    """
    nft_ruleset = get_existing_nftables_ruleset()
    commands: list[dict] = []
    base_chains: dict[str, dict[str, str]] = {
        "prerouting": {},
        "postrouting": {},
        "forward": {},
    }
    for hook in base_chains:
        chains = get_base_chains_for_hook(hook)
        if len(chains) == 0:  # If no chain create it.
            default_base_chain_hook_postrouting = {
                "family": "ip",
                "table": "nat",
                "name": "POSTROUTING",
                "type": "filter",
                "hook": "postrouting",
                "prio": 100,
            }
            default_base_chain_hook_forward = {
                "family": "ip",
                "table": "filter",
                "name": "FORWARD",
                "type": "filter",
                "hook": "forward",
                "prio": 0,
            }
            chain = default_base_chain_hook_forward if hook == "forward" else default_base_chain_hook_postrouting
            # Check if table exists, if not create it.
            commands += add_entity_if_not_present(
                nft_ruleset,
                {
                    "table": {
                        "family": "ip",
                        "name": chain["table"],
                    }
                },
            )
            new_chain = {"chain": chain}
            commands.append({"add": new_chain})
            chains.append(new_chain)
        # If multiple base chain for the hook, use the less priority one
        chains.sort(key=lambda x: x["chain"]["prio"])
        base_chains[hook] = chains[0]["chain"]

    # Add chain aleph-supervisor-nat
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "chain": {
                "family": "ip",
                "table": base_chains["postrouting"]["table"],
                "name": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat",
            }
        },
    )

    # Add jump to chain aleph-supervisor-nat
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": base_chains["postrouting"]["table"],
                "chain": base_chains["postrouting"]["name"],
                "expr": [{"jump": {"target": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat"}}],
            }
        },
    )
    # Add chain aleph-supervisor-filter
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "chain": {
                "family": "ip",
                "table": base_chains["forward"]["table"],
                "name": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter",
            }
        },
    )
    # Add jump to chain aleph-supervisor-filter
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": base_chains["forward"]["table"],
                "chain": base_chains["forward"]["name"],
                "expr": [{"jump": {"target": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter"}}],
            }
        },
    )
    # Add rule to allow return traffic and already established/related connections
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": base_chains["forward"]["table"],
                "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter",
                "expr": [
                    {
                        "match": {
                            "op": "in",
                            "left": {"ct": {"key": "state"}},
                            "right": ["related", "established"],
                        }
                    },
                    {"accept": None},
                ],
            }
        },
    )

    execute_json_nft_commands(commands)


def teardown_nftables() -> None:
    """Removes all of this project's related rules in the nftables ruleset."""
    logger.debug("Tearing down nftables setup")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter")


def remove_chain(name: str) -> dict:
    """Removes all rules that jump to the chain, and then removes the chain itself.
    Returns the exit code from executing the nftables commands"""
    nft_ruleset = get_existing_nftables_ruleset()
    commands = []
    remove_chain_commands = []

    for entry in nft_ruleset:
        if (
            isinstance(entry, dict)
            and "rule" in entry
            and "expr" in entry["rule"]
            and "jump" in entry["rule"]["expr"][0]
            and entry["rule"]["expr"][0]["jump"]["target"] == name
        ):
            commands.append(
                {
                    "delete": {
                        "rule": {
                            "family": entry["rule"]["family"],
                            "table": entry["rule"]["table"],
                            "chain": entry["rule"]["chain"],
                            "handle": entry["rule"]["handle"],
                        }
                    }
                }
            )
        elif isinstance(entry, dict) and "chain" in entry and entry["chain"]["name"] == name:
            remove_chain_commands.append(
                {
                    "delete": {
                        "chain": {
                            "family": entry["chain"]["family"],
                            "table": entry["chain"]["table"],
                            "name": entry["chain"]["name"],
                        }
                    }
                }
            )

    commands += remove_chain_commands
    return execute_json_nft_commands(commands)


def add_postrouting_chain(chain_name: str) -> dict:
    """Adds a chain and creates a rule from the base chain with the forward hook.
    Returns the output from executing the nftables commands"""
    table = get_table_for_hook("postrouting")
    return ensure_entities(
        [
            # Chain for VM
            {
                "chain": {
                    "family": "ip",
                    "table": table,
                    "name": chain_name,
                }
            },
            # Jump to that chain
            {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat",
                    "expr": [{"jump": {"target": chain_name}}],
                }
            },
        ],
    )


def add_forward_chain(chain_name: str) -> dict:
    """Adds a chain and creates a rule from the base chain with the forward hook.
    Returns the output from executing the nftables commands"""
    table = get_table_for_hook("forward")
    return ensure_entities(
        [
            # Chain for VM
            {
                "chain": {
                    "family": "ip",
                    "table": table,
                    "name": chain_name,
                }
            },
            # Jump to that chain
            {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter",
                    "expr": [{"jump": {"target": chain_name}}],
                }
            },
        ],
    )


def add_masquerading_rule(vm_id: int, interface: TapInterface) -> dict:
    """Creates a rule for the VM with the specified id to allow outbound traffic to be masqueraded (NAT)
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("postrouting")
    return ensure_entities(
        [
            {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-vm-nat-{vm_id}",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": interface.device_name,
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "oifname"}},
                                "right": settings.NETWORK_INTERFACE,
                            }
                        },
                        {"masquerade": None},
                    ],
                }
            }
        ]
    )


def add_forward_rule_to_external(vm_id: int, interface: TapInterface) -> dict:
    """Creates a rule for the VM with the specified id to allow outbound traffic
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("forward")
    return ensure_entities(
        [
            {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-vm-filter-{vm_id}",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": interface.device_name,
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "oifname"}},
                                "right": settings.NETWORK_INTERFACE,
                            }
                        },
                        {"accept": None},
                    ],
                }
            }
        ]
    )


def add_or_get_prerouting_chain() -> dict:
    """Creates the prerouting chain if it doesn't exist already.

    Returns:
        int: The exit code from executing the nftables commands
    """
    # Check if prerouting chain exists by looking for chains with prerouting hook
    existing_chains = get_base_chains_for_hook("prerouting", "ip")
    if existing_chains:
        return existing_chains[0]["chain"]  # Chain already exists, nothing to do

    commands = [
        {
            "add": {
                "chain": {
                    "family": "ip",
                    "table": "nat",
                    "name": "prerouting",
                    "type": "nat",
                    "hook": "prerouting",
                    "prio": -100,
                    "policy": "accept",
                }
            }
        }
    ]
    execute_json_nft_commands(commands)
    chain = commands[0]["add"]["chain"]
    return chain


def add_port_redirect_rule(
    vm_id, interface: TapInterface, host_port: int, vm_port: int, protocol: Literal["tcp"] | Literal["udp"] = "tcp"
) -> dict:
    """Creates a rule to redirect traffic from a host port to a VM port.

    Args:
        vm_id: The ID of the VM
        interface: The TapInterface instance for the VM
        host_port: The port number on the host to listen on
        vm_port: The port number to forward to on the VM
        protocol: The protocol to use (tcp or udp, defaults to tcp)

    Returns:
        The exit code from executing the nftables commands
    """
    chain = add_or_get_prerouting_chain()
    table = get_table_for_hook("forward")

    return ensure_entities(
        [
            {
                "rule": {
                    "family": "ip",
                    "table": "nat",
                    "chain": chain["name"],
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": settings.NETWORK_INTERFACE,
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": protocol, "field": "dport"}},
                                "right": host_port,
                            }
                        },
                        {
                            "dnat": {"addr": str(interface.guest_ip.ip), "port": vm_port},
                        },
                    ],
                }
            },
            # Add rule to accept that traffic on the host interface to that destination port
            {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-vm-filter-{vm_id}",
                    "expr": [
                        {
                            "match": {
                                "op": "==",
                                "left": {"meta": {"key": "iifname"}},
                                "right": interface.device_name,
                            }
                        },
                        {
                            "match": {
                                "op": "==",
                                "left": {"payload": {"protocol": "tcp", "field": "dport"}},
                                "right": vm_port,
                            }
                        },
                        {"accept": None},
                    ],
                }
            },
        ]
    )


def remove_port_redirect_rule(interface: TapInterface, host_port: int, vm_port: int, protocol: str = "tcp") -> dict:
    """Removes a rule that redirects traffic from a host port to a VM port.

    Args:
        interface: The TapInterface instance for the VM
        host_port: The port number on the host that is listened on
        vm_port: The port number that is being forwarded to on the VM
        protocol: The protocol used (tcp or udp)

    Returns:
        The exit code from executing the nftables commands
    """
    nft_ruleset = get_existing_nftables_ruleset()
    chain = add_or_get_prerouting_chain()
    table = chain['table']

    commands = []

    for entry in nft_ruleset:
        if (
            isinstance(entry, dict)
            and "rule" in entry
            and entry["rule"].get("family") == "ip"
            and entry["rule"].get("table") == table
            and entry["rule"].get("chain") == chain["name"]
            and "expr" in entry["rule"]
        ):
            expr = entry["rule"]["expr"]
            # Check if this is our redirect rule by matching all conditions
            if (
                len(expr) == 3
                and "match" in expr[0]
                and expr[0]["match"]["left"].get("meta", {}).get("key") == "iifname"
                and expr[0]["match"]["right"] == settings.NETWORK_INTERFACE
                and "match" in expr[1]
                and expr[1]["match"]["left"].get("payload", {}).get("protocol") == protocol
                and expr[1]["match"]["left"]["payload"].get("field") == "dport"
                and expr[1]["match"]["right"] == host_port
                and "dnat" in expr[2]
                and expr[2]["dnat"].get("addr") == str(interface.guest_ip.ip)
                and expr[2]["dnat"].get("port") == vm_port
            ):
                commands.append(
                    {
                        "delete": {
                            "rule": {
                                "family": "ip",
                                "table": table,
                                "chain": chain["name"],
                                "handle": entry["rule"]["handle"],
                            }
                        }
                    }
                )

    return execute_json_nft_commands(commands)


def setup_nftables_for_vm(vm_id: int, interface: TapInterface) -> None:
    """Sets up chains for filter and nat purposes specific to this VM, and makes sure those chains are jumped to"""
    add_postrouting_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-vm-nat-{vm_id}")
    add_forward_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-vm-filter-{vm_id}")
    add_masquerading_rule(vm_id, interface)
    add_forward_rule_to_external(vm_id, interface)


def teardown_nftables_for_vm(vm_id: int) -> None:
    """Remove all nftables rules related to the specified VM"""
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-vm-nat-{vm_id}")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-vm-filter-{vm_id}")


def check_nftables_redirections(port: int) -> bool:
    """Check if there are any NAT rules redirecting to the given port.

    Args:
        port: The port number to check

    Returns:
        True if the port is being used in any NAT redirection rules
    """
    try:
        for item in get_existing_nftables_ruleset():
            if not isinstance(item, dict) or "rule" not in item:
                continue

            expr = item["rule"].get("expr", [])
            for e in expr:
                # Check destination port match
                match = e.get("match", {})
                if match.get("left", {}).get("payload", {}).get("field") == "dport" and match.get("right") == port:
                    return True

                # Check DNAT port
                if e.get("dnat", {}).get("port") == port:
                    return True

        return False

    except Exception as e:
        logger.warning(f"Error checking NAT redirections: {e}")
        return False
