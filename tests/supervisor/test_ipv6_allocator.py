import os

from aleph.vm.orchestrator.network.hostnetwork import StaticIPv6Allocator
from aleph.vm.orchestrator.vm.vm_type import VmType

# Avoid failures linked to settings when initializing the global VmPool object
os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"

from ipaddress import IPv6Network

from aleph_message.models import ItemHash


def test_static_ipv6_allocator():
    allocator = StaticIPv6Allocator(ipv6_range=IPv6Network("1111:2222:3333:4444::/64"), subnet_prefix=124)
    ip_subnet = allocator.allocate_vm_ipv6_subnet(
        vm_id=3,
        vm_hash=ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446"),
        vm_type=VmType.microvm,
    )
    assert ip_subnet == IPv6Network("1111:2222:3333:4444:0001:8920:215b:2e90/124")
