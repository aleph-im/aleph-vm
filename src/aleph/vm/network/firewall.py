"""
IPv4 network setup using NFTABLES.
Add Nat to the VM in ipv4 and port forwarding for direct access.
"""

import json
import logging
import subprocess
from typing import Literal, Optional

from nftables import Nftables

from aleph.vm.conf import settings
from aleph.vm.network.interfaces import TapInterface

logger = logging.getLogger(__name__)


class NoBaseChainFound(Exception):
    hook: str

    def __init__(self, hook, message: Optional[str] = None):
        self.hook = hook
        self.message = message or f"Could not find any base chain for hook '{hook}'"
        super().__init__(message)

    def __str__(self):
        return f"Could not find any base chain for hook '{self.hook}'"


def get_customized_nftables() -> Nftables:
    """Create a new Nftables instance configured for JSON output.

    Note: We intentionally don't cache this object because the Nftables
    library can get into bad states after errors, and reusing a broken
    instance causes subsequent commands to fail.
    """
    nft = Nftables()
    nft.set_json_output(True)
    nft.set_stateless_output(True)
    nft.set_service_output(False)
    nft.set_reversedns_output(False)
    nft.set_numeric_proto_output(True)
    return nft


def execute_json_nft_commands(commands: list[dict]) -> dict:
    """Executes a list of nftables commands and returns the json output"""
    if not commands:
        return {}
    nft = get_customized_nftables()

    commands_dict = {"nftables": commands}
    try:
        logger.debug("Validating nftables rules")
        nft.json_validate(commands_dict)
    except Exception as e:
        logger.error(f"Failed to verify nftables rules: {e}")

    def _format_command_for_debug():
        l = []
        for c in commands:
            for command_name, entity in c.items():
                for entity_type, entity_args in entity.items():
                    l.append(f"{command_name} {entity_type} {entity_args.get('name', '')}")
        return ", ".join(l)

    logger.debug("Nftables commands: %s", _format_command_for_debug())
    return_code, output, error = nft.json_cmd(commands_dict)
    if return_code != 0:
        logger.error("Failed to add nftables rules: %s -- %s", error, json.dumps(commands, indent=4))

    # Handle cases where the output is a JSON string instead of a dict
    # This can happen with some versions of the nftables Python library
    if isinstance(output, str):
        try:
            output = json.loads(output)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse nftables output as JSON: {output}")
            return {}

    return output if isinstance(output, dict) else {}


def get_existing_nftables_ruleset() -> list[dict]:
    """Retrieves the full nftables ruleset and returns it"""
    # List all NAT rules
    commands = [{"list": {"ruleset": {"family": "ip"}}}]

    nft_ruleset = execute_json_nft_commands(commands)
    if not nft_ruleset or "nftables" not in nft_ruleset:
        logger.warning("Failed to retrieve nftables ruleset, returning empty list")
        return []
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
    if not chains:
        raise NoBaseChainFound(hook=hook)

    # Sort by priority, lowest-to-highest
    chains.sort(key=lambda x: x["chain"].get("prio", 0))

    if hook == "prerouting":
        # For prerouting (DNAT), we MUST use the 'nat' type hook.
        # Filter for 'nat' type chains and pick the one with the highest priority (last in list).
        nat_chains = [c for c in chains if c["chain"].get("type") == "nat"]
        if not nat_chains:
            # Fallback: maybe only the 'raw' chain exists. This will fail, but it's what the log shows.
            logger.warning(f"No 'nat' type prerouting chain found. Falling back to highest prio chain.")
            table = chains[-1]["chain"]["table"]
        else:
            table = nat_chains[-1]["chain"]["table"]  # Pick highest prio 'nat' chain
    else:
        # For forward/postrouting, use the lowest priority (earliest)
        table = chains[0]["chain"]["table"]
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
    if isinstance(a, dict) and isinstance(b, dict):
        for k, v in a.items():
            if k not in b:
                return False
            if not _is_superset(v, b[k]):
                return False
        return True
    elif isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return False
        return all(_is_superset(x, y) for x, y in zip(a, b))
    else:
        return a == b


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

    Chain aleph-vm-supervisor-nat, aleph-vm-supervisor-filter, and aleph-vm-supervisor-prerouting are created
    to contains the rules.
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
            default_base_chain_hook_prerouting = {
                "family": "ip",
                "table": "nat",
                "name": "PREROUTING",
                "type": "nat",
                "hook": "prerouting",
                "prio": -100,
                "policy": "accept",
            }
            if hook == "forward":
                chain = default_base_chain_hook_forward
            elif hook == "postrouting":
                chain = default_base_chain_hook_postrouting
            elif hook == "prerouting":
                chain = default_base_chain_hook_prerouting
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

        # Sort by priority, lowest-to-highest
        chains.sort(key=lambda x: x["chain"]["prio"])

        if hook == "prerouting":
            # For prerouting, we MUST use the 'nat' type hook which has a higher priority than the 'raw' hook,
            # We filter for 'nat' type, and if multiple, pick the one with highest priority (last in list).
            # The raw table's base chain hooks into the network stack at the earliest possible point
            # (high priority, e.g., -300). This is to allow system services or security frameworks to perform
            # early packet processing (e.g., explicitly tracking or not tracking certain local traffic) without
            # interfering with the main NAT and filtering logic.
            # For more info check the link https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks
            nat_chains = [c for c in chains if c["chain"].get("type") == "nat"]
            if not nat_chains:
                raise Exception("Failed to find or create a 'nat' type prerouting chain")
            base_chains[hook] = nat_chains[-1]["chain"]  # Pick highest prio 'nat' chain
        else:
            # For other hooks (forward, postrouting), use the original logic:
            # the one with the lowest priority (earliest).
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
                            "right": ["established", "related"],
                        }
                    },
                    {"accept": None},
                ],
            }
        },
    )

    # Add chain aleph-supervisor-prerouting
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "chain": {
                "family": "ip",
                "table": base_chains["prerouting"]["table"],
                "name": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-prerouting",
            }
        },
    )

    # Add jump to chain aleph-supervisor-prerouting
    commands += add_entity_if_not_present(
        nft_ruleset,
        {
            "rule": {
                "family": "ip",
                "table": base_chains["prerouting"]["table"],
                "chain": base_chains["prerouting"]["name"],
                "expr": [{"jump": {"target": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-prerouting"}}],
            }
        },
    )

    execute_json_nft_commands(commands)


def teardown_nftables() -> None:
    """Removes all of this project's related rules in the nftables ruleset."""
    logger.debug("Tearing down nftables setup")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-prerouting")


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
    chain_name = f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-prerouting"
    prerouting_table = get_table_for_hook("prerouting")
    forward_table = get_table_for_hook("forward")

    return ensure_entities(
        [
            {
                "rule": {
                    "family": "ip",
                    "table": prerouting_table,
                    "chain": chain_name,
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
                                "right": int(host_port),
                            }
                        },
                        {
                            "dnat": {"addr": str(interface.guest_ip.ip), "port": int(vm_port)},
                        },
                    ],
                }
            },
            # Add rule to accept that traffic on the host interface to that destination port
            {
                "rule": {
                    "family": "ip",
                    "table": forward_table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-vm-filter-{vm_id}",
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
                                "right": int(vm_port),
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
    chain_name = f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-prerouting"
    prerouting_table = get_table_for_hook("prerouting")

    commands = []

    for entry in nft_ruleset:
        if (
            isinstance(entry, dict)
            and "rule" in entry
            and entry["rule"].get("family") == "ip"
            and entry["rule"].get("table") == prerouting_table
            and entry["rule"].get("chain") == chain_name
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
                and int(expr[1]["match"]["right"]) == int(host_port)
                and "dnat" in expr[2]
                and expr[2]["dnat"].get("addr") == str(interface.guest_ip.ip)
                and int(expr[2]["dnat"].get("port")) == int(vm_port)
            ):
                rule_handle = entry["rule"]["handle"]
                commands.append(
                    {
                        "delete": {
                            "rule": {
                                "family": "ip",
                                "table": prerouting_table,
                                "chain": chain_name,
                                "handle": rule_handle,
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


def get_all_aleph_chains() -> list[str]:
    """Query nftables ruleset and return all chains created by aleph software.

    This function scans the entire nftables ruleset and identifies all chains
    whose names start with the configured NFTABLES_CHAIN_PREFIX. This includes
    both supervisor chains (e.g., aleph-supervisor-nat, aleph-supervisor-filter,
    aleph-supervisor-prerouting) and VM-specific chains (e.g., aleph-vm-nat-123,
    aleph-vm-filter-123).

    Returns:
        A list of chain names that belong to aleph software

    Raises:
        Exception: If the nftables query fails
    """
    logger.debug("Querying nftables for all aleph-related chains")
    nft_ruleset = get_existing_nftables_ruleset()
    aleph_chains = []

    for entry in nft_ruleset:
        if isinstance(entry, dict) and "chain" in entry:
            chain_name = entry["chain"].get("name", "")
            # Find all chains created by aleph software
            if chain_name.startswith(settings.NFTABLES_CHAIN_PREFIX):
                aleph_chains.append(chain_name)
                logger.debug(f"Found aleph chain: {chain_name}")

    logger.info(f"Found {len(aleph_chains)} aleph-related chains")
    return aleph_chains


def remove_all_aleph_chains() -> tuple[list[str], list[tuple[str, str]]]:
    """Remove all chains created by aleph software from the nftables ruleset.

    This function queries the nftables ruleset to find all chains that start with
    the configured NFTABLES_CHAIN_PREFIX, then attempts to remove each one. This
    ensures a clean slate by removing both tracked and untracked chains that may
    have been left behind due to software crashes or inconsistent state.

    The function uses the remove_chain() helper which handles:
    - Removing all rules that jump to the chain
    - Removing the chain itself

    Returns:
        A tuple containing:
        - List of successfully removed chain names
        - List of tuples (chain_name, error_message) for failed removals

    Example:
        removed, failed = remove_all_aleph_chains()
        if failed:
            logger.warning(f"Failed to remove {len(failed)} chains")
    """
    logger.info("Removing all aleph-related chains from nftables")
    aleph_chains = get_all_aleph_chains()

    removed_chains = []
    failed_chains = []

    for chain_name in aleph_chains:
        try:
            remove_chain(chain_name)
            removed_chains.append(chain_name)
            logger.debug(f"Successfully removed chain: {chain_name}")
        except Exception as e:
            error_msg = str(e)
            failed_chains.append((chain_name, error_msg))
            logger.warning(f"Failed to remove chain {chain_name}: {error_msg}")

    logger.info(f"Chain removal complete. Removed: {len(removed_chains)}, Failed: {len(failed_chains)}")
    return removed_chains, failed_chains


def recreate_network_for_vms(vm_configurations: list[dict]) -> tuple[list[str], list[dict]]:
    """Recreate network rules for a list of VMs.

    This function sets up nftables chains and rules for each VM in the provided list.
    For each VM, it creates:
    - NAT chain and masquerading rules for outbound traffic
    - Filter chain and forwarding rules for traffic control
    - Port forwarding rules if the VM is an instance (handled by caller)

    Args:
        vm_configurations: List of dictionaries, each containing:
            - vm_id: Integer ID of the VM
            - tap_interface: TapInterface object for the VM
            - vm_hash: ItemHash of the VM (for logging)

    Returns:
        A tuple containing:
        - List of successfully recreated VM hashes (as strings)
        - List of dictionaries with failed VMs:
          [{"vm_hash": str, "error": str}, ...]

    Example:
        vms = [
            {"vm_id": 1, "tap_interface": tap1, "vm_hash": hash1},
            {"vm_id": 2, "tap_interface": tap2, "vm_hash": hash2},
        ]
        recreated, failed = recreate_network_for_vms(vms)
    """
    logger.info(f"Recreating network rules for {len(vm_configurations)} VMs")
    recreated_vms = []
    failed_vms = []

    for vm_config in vm_configurations:
        vm_id = vm_config["vm_id"]
        tap_interface = vm_config["tap_interface"]
        vm_hash = vm_config["vm_hash"]

        try:
            # Recreate the basic VM network chains and rules
            setup_nftables_for_vm(vm_id, tap_interface)
            recreated_vms.append(str(vm_hash))
            logger.debug(f"Recreated nftables for VM {vm_hash} (vm_id={vm_id})")
        except Exception as e:
            error_msg = str(e)
            failed_vms.append({"vm_hash": str(vm_hash), "error": error_msg})
            logger.error(f"Failed to recreate network for VM {vm_hash}: {error_msg}")

    logger.info(f"VM network recreation complete. Success: {len(recreated_vms)}, Failed: {len(failed_vms)}")
    return recreated_vms, failed_vms
