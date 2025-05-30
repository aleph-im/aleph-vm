import json
import logging
from functools import lru_cache

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
    """Executes a list of nftables commands, and returns the exit status"""
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


def get_existing_nftables_ruleset() -> dict:
    """Retrieves the full nftables ruleset and returns it"""
    nft = get_customized_nftables()
    # List all NAT rules
    commands = [{"list": {"ruleset": {"family": "ip", "table": "nat"}}}]

    nft_ruleset = execute_json_nft_commands(commands)
    return nft_ruleset


def get_base_chains_for_hook(hook: str, family: str = "ip") -> list:
    """Looks through the nftables ruleset and creates a list of
    all chains that are base chains for the specified hook"""
    nft_ruleset = get_existing_nftables_ruleset()
    chains = []

    for entry in nft_ruleset["nftables"]:
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


def check_if_table_exists(family: str, table: str) -> bool:
    """Checks whether the specified table exists in the nftables ruleset"""
    nft_ruleset = get_existing_nftables_ruleset()
    for entry in nft_ruleset["nftables"]:
        if (
            isinstance(entry, dict)
            and "table" in entry
            # Key "family" was reported by users as not always present, so we use .get() instead of [].
            and entry.get("family") == family
            and entry.get("name") == table
        ):
            return True
    return False


def initialize_nftables() -> None:
    """Creates basic chains and rules in the nftables ruleset to build on further.
    Additionally, stores some information in the class for later use."""
    commands: list[dict] = []
    base_chains: dict[str, dict[str, str]] = {
        "postrouting": {},
        "forward": {},
    }
    for hook in base_chains:
        chains = get_base_chains_for_hook(hook)
        if len(chains) == 0:
            table = "nat" if hook == "postrouting" else "filter"
            chain = "POSTROUTING" if hook == "postrouting" else "FORWARD"
            prio = 100 if hook == "postrouting" else 0
            if not check_if_table_exists("ip", table):
                commands.append({"add": {"table": {"family": "ip", "name": table}}})
            new_chain = {
                "chain": {
                    "family": "ip",
                    "table": table,
                    "name": chain,
                    "type": table,
                    "hook": hook,
                    "prio": prio,
                }
            }
            commands.append({"add": new_chain})
            chains.append(new_chain)
        elif len(chains) > 1:
            msg = f"Multiple base chains for an nftables basechain are not supported: {hook}"
            raise NotImplementedError(msg)
        base_chains[hook] = chains.pop()["chain"]

    commands.append(
        _make_add_chain_command(
            "ip",
            base_chains["postrouting"]["table"],
            f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat",
        )
    )
    commands.append(
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": base_chains["postrouting"]["table"],
                    "chain": base_chains["postrouting"]["name"],
                    "expr": [{"jump": {"target": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat"}}],
                }
            }
        }
    )

    commands.append(
        _make_add_chain_command(
            "ip",
            base_chains["forward"]["table"],
            f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter",
        )
    )
    commands.append(
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": base_chains["forward"]["table"],
                    "chain": base_chains["forward"]["name"],
                    "expr": [{"jump": {"target": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter"}}],
                }
            }
        }
    )
    commands.append(
        {
            "add": {
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
            }
        }
    )

    execute_json_nft_commands(commands)


def teardown_nftables() -> None:
    """Removes all of this project's related rules in the nftables ruleset."""
    logger.debug("Tearing down nftables setup")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat")
    remove_chain(f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter")


def add_chain(family: str, table: str, name: str) -> dict:
    """Helper function to quickly create a new chain in the nftables ruleset
    Returns the exit code from executing the nftables commands"""
    commands = [_make_add_chain_command(family, table, name)]
    return execute_json_nft_commands(commands)


def _make_add_chain_command(family: str, table: str, name: str) -> dict:
    return {
        "add": {
            "chain": {
                "family": family,
                "table": table,
                "name": name,
            }
        }
    }


def remove_chain(name: str) -> dict:
    """Removes all rules that jump to the chain, and then removes the chain itself.
    Returns the exit code from executing the nftables commands"""
    nft_ruleset = get_existing_nftables_ruleset()
    commands = []
    remove_chain_commands = []

    for entry in nft_ruleset["nftables"]:
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


def add_postrouting_chain(name: str) -> dict:
    """Adds a chain and creates a rule from the base chain with the postrouting hook.
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("postrouting")
    add_chain("ip", table, name)
    command = [
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-nat",
                    "expr": [{"jump": {"target": name}}],
                }
            }
        }
    ]
    return execute_json_nft_commands(command)


def add_forward_chain(name: str) -> dict:
    """Adds a chain and creates a rule from the base chain with the forward hook.
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("forward")
    add_chain("ip", table, name)
    command = [
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": table,
                    "chain": f"{settings.NFTABLES_CHAIN_PREFIX}-supervisor-filter",
                    "expr": [{"jump": {"target": name}}],
                }
            }
        }
    ]
    return execute_json_nft_commands(command)


def add_masquerading_rule(vm_id: int, interface: TapInterface) -> dict:
    """Creates a rule for the VM with the specified id to allow outbound traffic to be masqueraded (NAT)
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("postrouting")
    command = [
        {
            "add": {
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
        }
    ]

    return execute_json_nft_commands(command)


def add_forward_rule_to_external(vm_id: int, interface: TapInterface) -> dict:
    """Creates a rule for the VM with the specified id to allow outbound traffic
    Returns the exit code from executing the nftables commands"""
    table = get_table_for_hook("forward")
    command = [
        {
            "add": {
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
        }
    ]

    return execute_json_nft_commands(command)


def add_prerouting_chain() -> dict:
    """Creates the prerouting chain if it doesn't exist already.

    Returns:
        int: The exit code from executing the nftables commands
    """
    # Check if prerouting chain exists by looking for chains with prerouting hook
    existing_chains = get_base_chains_for_hook("prerouting", "ip")
    if existing_chains:
        return 0  # Chain already exists, nothing to do

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
    return execute_json_nft_commands(commands)


def add_port_redirect_rule(interface: TapInterface, host_port: int, vm_port: int, protocol: str = "tcp") -> dict:
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
    add_prerouting_chain()
    commands = [
        {
            "add": {
                "rule": {
                    "family": "ip",
                    "table": "nat",
                    "chain": "prerouting",
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
            }
        },
    ]

    return execute_json_nft_commands(commands)


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
    commands = []

    for entry in nft_ruleset["nftables"]:
        if (
            isinstance(entry, dict)
            and "rule" in entry
            and entry["rule"].get("family") == "ip"
            and entry["rule"].get("table") == "nat"
            and entry["rule"].get("chain") == "prerouting"
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
                                "table": "nat",
                                "chain": "prerouting",
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
        rules = get_existing_nftables_ruleset()
        # Navigate through the JSON structure
        nftables = rules.get("nftables", [])

        for item in nftables:
            if "rule" not in item:
                continue

            rule = item["rule"]
            if "expr" not in rule:
                continue

            for expr in rule["expr"]:
                # Check destination port in matches
                if "match" in expr:
                    match = expr["match"]
                    if "left" in match and "payload" in match["left"]:
                        payload = match["left"]["payload"]
                        if payload.get("field") == "dport" and match.get("right") == port:
                            return True

                # Check port in dnat rules
                if "dnat" in expr:
                    dnat = expr["dnat"]
                    if dnat.get("port") == port:
                        return True

        return False

    except Exception as e:
        logger.warning(f"Error checking NAT redirections: {e}")
        return False  # Assume no redirections in case of error
