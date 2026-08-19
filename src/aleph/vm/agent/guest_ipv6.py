"""Agent-side static guest IPv6 computation.

The agent computes a guest's static IPv6 upfront (the address does not depend on
the vm_index) and hands it to the supervisor, which is told the address rather
than deriving the Aleph scheme itself. This keeps the agent self-contained: it
talks to the supervisor only through the supervisor interface and does not import
the supervisor-side network package.

The pure address math below is duplicated on purpose with the supervisor daemon
(Rust world::ipv6_static_assignment) and the legacy supervisor allocator
(network.hostnetwork.StaticIPv6Allocator). Byte-identity across the three is
pinned by tests/supervisor/test_guest_ipv6.py, which shares one literal address
with the Rust parity test on the other side of the boundary.
"""

from __future__ import annotations

from ipaddress import IPv6Network

from aleph_message.models import ItemHash

from aleph.vm.conf import IPv6AllocationPolicy, settings
from aleph.vm.vm_type import VmType

# The 16-bit VM-type field of the static IPv6 scheme. Must match the supervisor
# allocator and the scheduler's VmType::ipv6_value().
_VM_TYPE_PREFIX = {
    VmType.microvm: "1",
    VmType.persistent_program: "2",
    VmType.instance: "3",
    VmType.v_program: "4",
}


def compute_requested_ipv6(vm_hash: ItemHash, vm_type: VmType) -> tuple[str, int]:
    """The static IPv6 /124 the agent hands to the supervisor for a guest.

    Returns the ``str`` of the /124 IPv6Network and its prefix length (124) under
    the static policy. Under the dynamic policy the address depends on a
    supervisor-side ordinal the agent cannot know, so it returns ``("", 0)`` and
    the supervisor assigns the address itself.
    """
    if settings.IPV6_ALLOCATION_POLICY != IPv6AllocationPolicy.static:
        return "", 0

    # The pool's first 64 bits, then the VM-type nibble, then 44 bits of the item
    # hash; the last nibble stays 0 so the guest owns the trailing /124.
    elems = IPv6Network(settings.IPV6_ADDRESS_POOL).exploded.split(":")[:4]
    elems.append(_VM_TYPE_PREFIX[vm_type])
    elems += [vm_hash[0:4], vm_hash[4:8], vm_hash[8:11] + "0"]
    subnet = IPv6Network(":".join(elems) + "/124")
    return str(subnet), subnet.prefixlen
