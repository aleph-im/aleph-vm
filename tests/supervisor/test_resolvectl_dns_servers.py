# Avoid failures linked to nftables when initializing the global VmPool object
import os

from aleph.vm.orchestrator.conf import (
    resolvectl_dns_servers,
    resolvectl_dns_servers_ipv4,
)

os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"


def test_resolvectl(mocker):
    with mocker.patch(
        "aleph.vm.orchestrator.conf.check_output",
        return_value="Link 2 (eth0): 109.88.203.3 62.197.111.140\n",
    ):
        servers = {"109.88.203.3", "62.197.111.140"}

        dns_servers = set(resolvectl_dns_servers("eth0"))
        assert dns_servers == servers

        dns_servers_ipv4 = set(resolvectl_dns_servers_ipv4("eth0"))
        assert dns_servers_ipv4 == servers


def test_resolvectl_ipv6(mocker):
    with mocker.patch(
        "aleph.vm.orchestrator.conf.check_output",
        return_value="Link 2 (eth0): 109.88.203.3 62.197.111.140 2a02:2788:fff0:7::3\n        2a02:2788:fff0:5::140\n",
    ):
        ipv4_servers = {"109.88.203.3", "62.197.111.140"}
        ipv6_servers = {"2a02:2788:fff0:7::3", "2a02:2788:fff0:5::140"}

        dns_servers = set(resolvectl_dns_servers("eth0"))
        assert dns_servers == ipv4_servers | ipv6_servers

        dns_servers_ipv4 = set(resolvectl_dns_servers_ipv4("eth0"))
        assert dns_servers_ipv4 == ipv4_servers
