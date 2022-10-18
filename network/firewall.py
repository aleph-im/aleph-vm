import logging
import json
from typing import List, Dict

import network.network as nw
from nftables import Nftables

logger = logging.getLogger(__name__)

nft = Nftables()
nft.set_json_output(True)
nft.set_stateless_output(True)
nft.set_service_output(False)
nft.set_reversedns_output(False)
nft.set_numeric_proto_output(True)


class Firewall:
    firewall_has_been_setup = False
    postrouting_info: Dict[str, str] = {}
    forwarding_info: Dict[str, str] = {}
    vm_info: Dict[int, Dict] = {}

    @classmethod
    def execute_json_nft_commands(cls, commands: List[Dict]) -> int:
        """Executes a list of nftables commands, and returns the exit status"""
        commands_dict = {"nftables": commands}
        try:
            logger.debug("Validating nftables rules")
            nft.json_validate(commands_dict)
        except Exception as e:
            logger.error(f"Failed to verify nftables rules: {e}")

        logger.debug("Inserting nftables rules")
        rc, output, error = nft.json_cmd(commands_dict)
        if rc != 0:
            logger.error(f"Failed to add nftables rules: {error}")

        return rc

    @classmethod
    def get_existing_nftables_ruleset(cls) -> Dict:
        """Retrieves the full nftables ruleset and returns it"""
        rc, output, error = nft.cmd("list ruleset")

        if rc != 0:
            logger.error(f"Unable to get nftables ruleset: {error}")

        nft_ruleset = json.loads(output)
        return nft_ruleset

    @classmethod
    def get_base_chains_for_hook(cls, hook: str, family: str = "ip") -> List:
        """Looks through the nftables ruleset and creates a list of
        all chains that are base chains for the specified hook"""
        nft_ruleset = cls.get_existing_nftables_ruleset()
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
                continue

            chains.append(entry)

        return chains

    @classmethod
    def check_if_table_exists(cls, family: str, table: str) -> bool:
        """Checks whether the specified table exists in the nftables ruleset"""
        nft_ruleset = cls.get_existing_nftables_ruleset()
        for entry in nft_ruleset["nftables"]:
            if (
                isinstance(entry, dict)
                and "table" in entry
                and entry["family"] == family
                and entry["name"] == table
            ):
                return True
        return False

    @classmethod
    def initialize_nftables(cls) -> None:
        """Creates basic chains and rules in the nftables ruleset to build on further.
        Additionally, stores some information in the class for later use."""
        commands: List[Dict] = []
        base_chains: Dict[str, Dict[str, Dict[str, str]]] = {
            "postrouting": {},
            "forward": {},
        }
        for hook in base_chains:
            chains = cls.get_base_chains_for_hook(hook)
            if len(chains) == 0:
                table = "nat" if hook == "postrouting" else "filter"
                chain = "POSTROUTING" if hook == "postrouting" else "FORWARD"
                prio = 100 if hook == "postrouting" else 0
                if not cls.check_if_table_exists("ip", table):
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
                logger.critical(
                    f"Unsupported: Multiple base chains already defined for hook {hook}."
                )
                # TODO: gracefully exit
            base_chains[hook] = chains.pop()

        cls.forwarding_info = base_chains["forward"]["chain"]
        cls.postrouting_info = base_chains["postrouting"]["chain"]

        cls.add_chain("ip", cls.postrouting_info["table"], "aleph-supervisor-nat")
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.postrouting_info["table"],
                        "chain": cls.postrouting_info["name"],
                        "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
                    }
                }
            }
        )

        cls.add_chain("ip", cls.forwarding_info["table"], "aleph-supervisor-filter")
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.forwarding_info["table"],
                        "chain": cls.forwarding_info["name"],
                        "expr": [{"jump": {"target": "aleph-supervisor-filter"}}],
                    }
                }
            }
        )
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.forwarding_info["table"],
                        "chain": "aleph-supervisor-filter",
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

        cls.execute_json_nft_commands(commands)
        cls.firewall_has_been_setup = True
        return

    @classmethod
    def teardown_nftables(cls) -> None:
        """Removes all of this project's related rules in the nftables ruleset."""
        if not cls.firewall_has_been_setup:
            logger.debug("Firewall hasn't been set up, skipping teardown")
            return

        logger.debug("Tearing down nftables setup")
        cls.remove_chain("aleph-supervisor-nat")
        cls.postrouting_info = {}
        cls.remove_chain("aleph-supervisor-filter")
        cls.forwarding_info = {}

        return

    @classmethod
    def add_chain(cls, family: str, table: str, name: str) -> int:
        """Helper function to quickly create a new chain in the nftables ruleset
        Returns the exit code from executing the nftables commands"""
        commands = [
            {
                "add": {
                    "chain": {
                        "family": family,
                        "table": table,
                        "name": name,
                    }
                }
            }
        ]
        return cls.execute_json_nft_commands(commands)

    @classmethod
    def remove_chain(cls, name: str) -> int:
        """Removes all rules that jump to the chain, and then removes the chain itself.
        Returns the exit code from executing the nftables commands"""
        nft_ruleset = cls.get_existing_nftables_ruleset()
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
            elif (
                isinstance(entry, dict)
                and "chain" in entry
                and entry["chain"]["name"] == name
            ):
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
        return cls.execute_json_nft_commands(commands)

    @classmethod
    def add_postrouting_chain(cls, name: str) -> int:
        """Adds a chain and creates a rule from the base chain with the postrouting hook.
        Returns the exit code from executing the nftables commands"""
        cls.add_chain("ip", cls.postrouting_info["table"], name)
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.postrouting_info["table"],
                        "chain": "aleph-supervisor-nat",
                        "expr": [{"jump": {"target": name}}],
                    }
                }
            }
        ]
        return cls.execute_json_nft_commands(command)

    @classmethod
    def add_forward_chain(cls, name):
        """Adds a chain and creates a rule from the base chain with the forward hook.
        Returns the exit code from executing the nftables commands"""
        cls.add_chain("ip", cls.forwarding_info["table"], name)
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.forwarding_info["table"],
                        "chain": "aleph-supervisor-filter",
                        "expr": [{"jump": {"target": name}}],
                    }
                }
            }
        ]
        return cls.execute_json_nft_commands(command)

    @classmethod
    def add_masquerading_rule(cls, vm_id: int) -> int:
        """Creates a rule for the VM with the specified id to allow outbound traffic to be masqueraded (NAT)
        Returns the exit code from executing the nftables commands"""
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.postrouting_info["table"],
                        "chain": cls.vm_info[vm_id]["nat_chain"],
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "iifname"}},
                                    "right": nw.Network.vm_info[vm_id]["tap_interface"],
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "oifname"}},
                                    "right": nw.Network.external_interface,
                                }
                            },
                            {"masquerade": None},
                        ],
                    }
                }
            }
        ]

        return cls.execute_json_nft_commands(command)

    @classmethod
    def add_forward_rule_to_external(cls, vm_id: int) -> int:
        """Creates a rule for the VM with the specified id to allow outbound traffic
        Returns the exit code from executing the nftables commands"""
        if vm_id not in cls.vm_info:
            logger.error(f"VM ruleset not yet initialized: {vm_id}")
            return 1

        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": cls.forwarding_info["table"],
                        "chain": cls.vm_info[vm_id]["filter_chain"],
                        "expr": [
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "iifname"}},
                                    "right": nw.Network.vm_info[vm_id]["tap_interface"],
                                }
                            },
                            {
                                "match": {
                                    "op": "==",
                                    "left": {"meta": {"key": "oifname"}},
                                    "right": nw.Network.external_interface,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        ]

        return cls.execute_json_nft_commands(command)

    @classmethod
    def setup_nftables_for_vm(cls, vm_id: int) -> None:
        """Sets up chains for filter and nat purposes specific to this VM, and makes sure those chains are jumped to"""
        if vm_id in cls.vm_info:
            logger.error(f"VM already setup in firewall: {vm_id}")
            return

        cls.vm_info[vm_id] = {
            "nat_chain": f"aleph-vm-nat-{vm_id}",
            "filter_chain": f"aleph-vm-filter-{vm_id}",
        }
        cls.add_postrouting_chain(cls.vm_info[vm_id]["nat_chain"])
        cls.add_forward_chain(cls.vm_info[vm_id]["filter_chain"])
        cls.add_masquerading_rule(vm_id)
        cls.add_forward_rule_to_external(vm_id)

    @classmethod
    def teardown_nftables_for_vm(cls, vm_id: int) -> None:
        """Remove all nftables rules related to the specified VM"""
        if vm_id not in cls.vm_info:
            logger.error(f"No firewall configuration found to teardown for vm {vm_id}")
            return

        cls.remove_chain(cls.vm_info[vm_id]["nat_chain"])
        cls.remove_chain(cls.vm_info[vm_id]["filter_chain"])
