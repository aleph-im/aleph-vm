# Avoid failures linked to nftables when initializing the global VmPool object
import os
from unittest import mock

from aleph.vm.conf import resolvectl_dns_servers

os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"


def test_resolvectl():
    with mock.patch(
        "aleph.vm.conf.check_output",
        return_value="Link 2 (eth0): 109.88.203.3 62.197.111.140\n",
    ):
        servers = {"109.88.203.3", "62.197.111.140"}

        dns_servers = set(resolvectl_dns_servers("eth0"))
        assert dns_servers == servers


def test_resolvectl_ipv6():
    with mock.patch(
        "aleph.vm.conf.check_output",
        return_value="Link 2 (eth0): 109.88.203.3 62.197.111.140 2a02:2788:fff0:7::3\n        2a02:2788:fff0:5::140\n",
    ):
        ipv4_servers = {"109.88.203.3", "62.197.111.140"}
        ipv6_servers = {"2a02:2788:fff0:7::3", "2a02:2788:fff0:5::140"}

        dns_servers = set(resolvectl_dns_servers("eth0"))
        assert dns_servers == ipv4_servers | ipv6_servers
