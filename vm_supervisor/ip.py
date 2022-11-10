import asyncio
import json
import logging
from subprocess import run
from typing import Iterable, Dict, List
from ipaddress import IPv4Interface, IPv4Network

from nftables import Nftables

logger = logging.getLogger(__name__)


class IPv4NetworkWithInterfaces(IPv4Network):
    def hosts(self) -> Iterable[IPv4Interface]:
        network = int(self.network_address)
        broadcast = int(self.broadcast_address)
        for x in range(network + 1, broadcast):
            yield IPv4Interface((x, self.prefixlen))

    def __getitem__(self, n) -> IPv4Interface:
        network = int(self.network_address)
        broadcast = int(self.broadcast_address)
        if n >= 0:
            if network + n > broadcast:
                raise IndexError("address out of range")
            return IPv4Interface((network + n, self.prefixlen))
        else:
            n += 1
            if broadcast + n < network:
                raise IndexError("address out of range")
            return IPv4Interface((broadcast + n, self.prefixlen))


class TapInterface:
    device_name: str
    ip_network: IPv4NetworkWithInterfaces
    used_by: Dict[int, IPv4Interface]

    @property
    def guest_ip(self) -> IPv4Interface:
        return self.ip_network[2]

    @property
    def host_ip(self) -> IPv4Interface:
        return self.ip_network[1]

    def __init__(
        self, device_name: str, ip_network: IPv4NetworkWithInterfaces
    ):
        self.device_name: str = device_name
        self.ip_network: IPv4NetworkWithInterfaces = ip_network

    def create(self):
        """Create """
        logger.debug(f"Creating network interface {self.device_name} on {self.ip_network}")

        run(["/usr/bin/ip", "tuntap", "add", self.device_name, "mode", "tap"])
        run(
            [
                "/usr/bin/ip",
                "addr",
                "add",
                str(self.host_ip.with_prefixlen),
                "dev",
                self.device_name,
            ]
        )
        run(["/usr/bin/ip", "link", "set", self.device_name, "up"])
        logger.debug(f"Network interface created: {self.device_name}")

    async def delete(self) -> None:
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        logger.debug(f"Removing interface {self.device_name}")
        await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
        run(["ip", "tuntap", "del", self.device_name, "mode", "tap"])


def get_ipv4_forwarding_state() -> int:
    """Reads the current ipv4 forwarding setting from the hosts, converts it to int and returns it"""
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        return int(f.read())


def get_customized_nftables() -> Nftables:
    nft = Nftables()
    nft.set_json_output(True)
    nft.set_stateless_output(True)
    nft.set_service_output(False)
    nft.set_reversedns_output(False)
    nft.set_numeric_proto_output(True)
    return nft


class Firewall:
    firewall_has_been_setup: bool
    postrouting_info: Dict[str, str]
    forwarding_info: Dict[str, str]
    external_interface: str
    vm_info: Dict[int, Dict]
    nft: Nftables

    def __init__(self):
        self.firewall_has_been_setup = False
        self.postrouting_info = {}
        self.forwarding_info = {}
        self.vm_info = {}
        self.external_interface = "eth0"

        self.nft = get_customized_nftables()

    def execute_json_nft_commands(self, commands: List[Dict]) -> int:
        """Executes a list of nftables commands, and returns the exit status"""
        commands_dict = {"nftables": commands}
        try:
            logger.debug("Validating nftables rules")
            self.nft.json_validate(commands_dict)
        except Exception as e:
            logger.error(f"Failed to verify nftables rules: {e}")

        logger.debug("Inserting nftables rules")
        rc, output, error = self.nft.json_cmd(commands_dict)
        if rc != 0:
            logger.error(f"Failed to add nftables rules: {error}")

        return rc

    def get_existing_nftables_ruleset(self) -> Dict:
        """Retrieves the full nftables ruleset and returns it"""
        rc, output, error = self.nft.cmd("list ruleset")

        if rc != 0:
            logger.error(f"Unable to get nftables ruleset: {error}")

        nft_ruleset = json.loads(output)
        return nft_ruleset

    def get_base_chains_for_hook(self, hook: str, family: str = "ip") -> List:
        """Looks through the nftables ruleset and creates a list of
        all chains that are base chains for the specified hook"""
        nft_ruleset = self.get_existing_nftables_ruleset()
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

    def check_if_table_exists(self, family: str, table: str) -> bool:
        """Checks whether the specified table exists in the nftables ruleset"""
        nft_ruleset = self.get_existing_nftables_ruleset()
        for entry in nft_ruleset["nftables"]:
            if (
                isinstance(entry, dict)
                and "table" in entry
                and entry["family"] == family
                and entry["name"] == table
            ):
                return True
        return False

    def initialize_nftables(self) -> None:
        """Creates basic chains and rules in the nftables ruleset to build on further.
        Additionally, stores some information in the class for later use."""
        commands: List[Dict] = []
        base_chains: Dict[str, Dict[str, Dict[str, str]]] = {
            "postrouting": {},
            "forward": {},
        }
        for hook in base_chains:
            chains = self.get_base_chains_for_hook(hook)
            if len(chains) == 0:
                table = "nat" if hook == "postrouting" else "filter"
                chain = "POSTROUTING" if hook == "postrouting" else "FORWARD"
                prio = 100 if hook == "postrouting" else 0
                if not self.check_if_table_exists("ip", table):
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

        self.forwarding_info = base_chains["forward"]["chain"]
        self.postrouting_info = base_chains["postrouting"]["chain"]

        self.add_chain("ip", self.postrouting_info["table"], "aleph-supervisor-nat")
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.postrouting_info["table"],
                        "chain": self.postrouting_info["name"],
                        "expr": [{"jump": {"target": "aleph-supervisor-nat"}}],
                    }
                }
            }
        )

        self.add_chain("ip", self.forwarding_info["table"], "aleph-supervisor-filter")
        commands.append(
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.forwarding_info["table"],
                        "chain": self.forwarding_info["name"],
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
                        "table": self.forwarding_info["table"],
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

        self.execute_json_nft_commands(commands)
        self.firewall_has_been_setup = True
        return

    def teardown_nftables(self) -> None:
        """Removes all of this project's related rules in the nftables ruleset."""
        if not self.firewall_has_been_setup:
            logger.debug("Firewall hasn't been set up, skipping teardown")
            return

        logger.debug("Tearing down nftables setup")
        self.remove_chain("aleph-supervisor-nat")
        self.postrouting_info = {}
        self.remove_chain("aleph-supervisor-filter")
        self.forwarding_info = {}

        return

    def add_chain(self, family: str, table: str, name: str) -> int:
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
        return self.execute_json_nft_commands(commands)

    def remove_chain(self, name: str) -> int:
        """Removes all rules that jump to the chain, and then removes the chain itself.
        Returns the exit code from executing the nftables commands"""
        nft_ruleset = self.get_existing_nftables_ruleset()
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
        return self.execute_json_nft_commands(commands)

    def add_postrouting_chain(self, name: str) -> int:
        """Adds a chain and creates a rule from the base chain with the postrouting hook.
        Returns the exit code from executing the nftables commands"""
        self.add_chain("ip", self.postrouting_info["table"], name)
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.postrouting_info["table"],
                        "chain": "aleph-supervisor-nat",
                        "expr": [{"jump": {"target": name}}],
                    }
                }
            }
        ]
        return self.execute_json_nft_commands(command)

    def add_forward_chain(self, name):
        """Adds a chain and creates a rule from the base chain with the forward hook.
        Returns the exit code from executing the nftables commands"""
        self.add_chain("ip", self.forwarding_info["table"], name)
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.forwarding_info["table"],
                        "chain": "aleph-supervisor-filter",
                        "expr": [{"jump": {"target": name}}],
                    }
                }
            }
        ]
        return self.execute_json_nft_commands(command)

    def add_masquerading_rule(self, vm_id: int, interface: TapInterface) -> int:
        """Creates a rule for the VM with the specified id to allow outbound traffic to be masqueraded (NAT)
        Returns the exit code from executing the nftables commands"""
        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.postrouting_info["table"],
                        "chain": self.vm_info[vm_id]["nat_chain"],
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
                                    "right": self.external_interface,
                                }
                            },
                            {"masquerade": None},
                        ],
                    }
                }
            }
        ]

        return self.execute_json_nft_commands(command)

    def add_forward_rule_to_external(self, vm_id: int, interface: TapInterface) -> int:
        """Creates a rule for the VM with the specified id to allow outbound traffic
        Returns the exit code from executing the nftables commands"""
        if vm_id not in self.vm_info:
            logger.error(f"VM ruleset not yet initialized: {vm_id}")
            return 1

        command = [
            {
                "add": {
                    "rule": {
                        "family": "ip",
                        "table": self.forwarding_info["table"],
                        "chain": self.vm_info[vm_id]["filter_chain"],
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
                                    "right": self.external_interface,
                                }
                            },
                            {"accept": None},
                        ],
                    }
                }
            }
        ]

        return self.execute_json_nft_commands(command)

    def setup_nftables_for_vm(self, vm_id: int, interface: TapInterface) -> None:
        """Sets up chains for filter and nat purposes specific to this VM, and makes sure those chains are jumped to"""
        if vm_id in self.vm_info:
            logger.error(f"VM already setup in firewall: {vm_id}")
            return

        self.vm_info[vm_id] = {
            "nat_chain": f"aleph-vm-nat-{vm_id}",
            "filter_chain": f"aleph-vm-filter-{vm_id}",
        }
        self.add_postrouting_chain(self.vm_info[vm_id]["nat_chain"])
        self.add_forward_chain(self.vm_info[vm_id]["filter_chain"])
        self.add_masquerading_rule(vm_id, interface)
        self.add_forward_rule_to_external(vm_id, interface)

    def teardown_nftables_for_vm(self, vm_id: int) -> None:
        """Remove all nftables rules related to the specified VM"""
        if vm_id not in self.vm_info:
            logger.error(f"No firewall configuration found to teardown for vm {vm_id}")
            return

        self.remove_chain(self.vm_info[vm_id]["nat_chain"])
        self.remove_chain(self.vm_info[vm_id]["filter_chain"])


class Network:
    firewall: Firewall
    address_pool: IPv4NetworkWithInterfaces
    ipv4_forward_state_before_setup = None
    network_size = 24
    network_initialized = False
    external_interface = "eth0"
    vm_info: Dict = {}

    def __init__(self):
        self.firewall = Firewall()
        self.address_pool = IPv4NetworkWithInterfaces("172.16.0.0/12")

    def get_network_for_tap(self, vm_id: int) -> IPv4NetworkWithInterfaces:
        subnets = list(self.address_pool.subnets(new_prefix=self.network_size))
        return subnets[vm_id]

    def enable_ipv4_forwarding(self) -> None:
        """Saves the hosts IPv4 forwarding state, and if it was disabled, enables it"""
        logger.debug(f"Enabling IPv4 forwarding")
        self.ipv4_forward_state_before_setup = get_ipv4_forwarding_state()
        if not self.ipv4_forward_state_before_setup:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")

    def reset_ipv4_forwarding_state(self) -> None:
        """Returns the hosts IPv4 forwarding state how it was before we enabled it"""
        logger.debug("Resetting IPv4 forwarding state to state before we enabled it")
        if self.ipv4_forward_state_before_setup != get_ipv4_forwarding_state():
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(str(self.ipv4_forward_state_before_setup))

    def initialize(
        self, vm_address_pool_range: str, vm_network_size: int, external_interface: str
    ) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        self.address_pool = IPv4NetworkWithInterfaces(vm_address_pool_range)
        if not self.address_pool.is_private:
            logger.warning(
                f"Using a network range that is not private: {self.address_pool}"
            )
        self.network_size = vm_network_size
        self.external_interface = external_interface
        self.firewall.external_interface = external_interface
        self.enable_ipv4_forwarding()
        self.firewall.initialize_nftables()
        self.network_initialized = True

    def teardown(self):
        self.firewall.teardown_nftables()
        self.reset_ipv4_forwarding_state()

    async def create_tap(self, vm_id: int) -> TapInterface:
        """Checks if a tap interface is already created. If it is, it returns it. If not, it creates on.
        Currently this will create a new tap interface for each vm, but the structure is made this way
        to facilitate future tap interface sharing.
        """
        interface = TapInterface(f"vmtap{vm_id}", self.get_network_for_tap(vm_id))
        interface.create()
        return interface
