import os

from aleph.vm.conf import IPv6AllocationPolicy, settings
from aleph.vm.network.hostnetwork import StaticIPv6Allocator, compute_requested_ipv6
from aleph.vm.vm_type import VmType

# Avoid failures linked to settings when initializing the global VmPool object
os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"

from ipaddress import IPv6Network

from aleph_message.models import ItemHash


def test_static_ipv6_allocator():
    allocator = StaticIPv6Allocator(ipv6_range=IPv6Network("1111:2222:3333:4444::/64"), subnet_prefix=124)
    ip_subnet = allocator.allocate_vm_ipv6_subnet(
        vm_index=3,
        vm_hash=ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446"),
        vm_type=VmType.microvm,
    )
    assert ip_subnet == IPv6Network("1111:2222:3333:4444:0001:8920:215b:2e90/124")


def test_static_ipv6_allocator_v_program_prefix():
    allocator = StaticIPv6Allocator(ipv6_range=IPv6Network("1111:2222:3333:4444::/64"), subnet_prefix=124)
    ip_subnet = allocator.allocate_vm_ipv6_subnet(
        vm_index=3,
        vm_hash=ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446"),
        vm_type=VmType.v_program,
    )
    # 16-bit VM-type field = 4: must mirror scheduler-events VmType::ipv6_value()
    assert ip_subnet == IPv6Network("1111:2222:3333:4444:0004:8920:215b:2e90/124")


def test_compute_requested_ipv6_static(monkeypatch):
    # The agent computes the static /124 upfront and hands it to the supervisor
    # as the str(IPv6Network) CIDR plus the prefix length.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "2a01:240:2:c8::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.instance)

    # This exact string is what the supervisor daemon's ipv6_static_assignment
    # produces for the same (pool, vm_hash, vm_type); the Rust test
    # `a_requested_ipv6_round_trips_to_the_static_address` pins the same literal
    # on the other side of the boundary. Keep the two in sync.
    assert cidr == "2a01:240:2:c8:3:abcd:ef01:2340/124"
    assert prefix_len == 124


def test_compute_requested_ipv6_matches_the_allocator(monkeypatch):
    # The helper must return exactly str(allocate_vm_ipv6_subnet(...)): the
    # daemon parses that string back into the guest address, so any divergence
    # would move an existing VM's address.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "1111:2222:3333:4444::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446")
    allocator = StaticIPv6Allocator(ipv6_range=IPv6Network("1111:2222:3333:4444::/64"), subnet_prefix=124)
    expected = allocator.allocate_vm_ipv6_subnet(vm_index=0, vm_hash=vm_hash, vm_type=VmType.instance)

    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.instance)
    assert cidr == str(expected)
    assert prefix_len == expected.prefixlen


def test_compute_requested_ipv6_dynamic_is_empty(monkeypatch):
    # Under the dynamic policy the address depends on a supervisor-side ordinal
    # the agent cannot know, so it defers to the daemon.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.dynamic)

    vm_hash = ItemHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    assert compute_requested_ipv6(vm_hash, VmType.instance) == ("", 0)
