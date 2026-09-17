"""Agent-side guest IPv6 allocation.

The agent owns every guest IPv6 address and hands it to the supervisor, which
stores and serves it but never derives one itself: a networked create without
``requested_ipv6`` is refused. This keeps the agent self-contained: it talks to
the supervisor only through the supervisor interface.

Two policies, selected by ``IPV6_ALLOCATION_POLICY``:

- static: a pure function of the VM type and item hash
  (:func:`compute_requested_ipv6`), computed when the spec is built. The
  scheduler computes the same address, so the static scheme must not drift.
- dynamic: the first free ``/IPV6_SUBNET_PREFIX`` subnet of the pool, decided
  right before the create (:func:`create_vm_with_ipv6`) because it depends on
  what the supervisor already holds.
"""

from __future__ import annotations

import asyncio
import logging
import weakref
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from ipaddress import IPv6Network

from aleph_message.models import ItemHash

from aleph.vm.conf import IPv6AllocationPolicy, settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError,
    SupervisorError,
    VmSetupError,
)
from aleph.vm.supervisor_interface.types import Backend, CreateVmSpec, VmId, VmInfo
from aleph.vm.vm_type import VmType

logger = logging.getLogger(__name__)

# The 16-bit VM-type field of the static IPv6 scheme. Must match the scheduler's
# VmType::ipv6_value().
_VM_TYPE_PREFIX = {
    VmType.microvm: "1",
    VmType.persistent_program: "2",
    VmType.instance: "3",
    VmType.v_program: "4",
}

# Dynamic allocations are serialised: two concurrent creates must never read
# the same free subnet. A subnet stays reserved here from its allocation until
# its create returned (by then the supervisor lists it) or failed. One lock per
# event loop: an asyncio.Lock binds to the loop it first waits on.
_allocation_locks: weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, asyncio.Lock] = weakref.WeakKeyDictionary()
_in_flight: dict[object, IPv6Network] = {}


def _allocation_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock = _allocation_locks.get(loop)
    if lock is None:
        lock = _allocation_locks[loop] = asyncio.Lock()
    return lock


def compute_requested_ipv6(vm_hash: ItemHash, vm_type: VmType) -> tuple[str, int]:
    """The static IPv6 /124 the agent hands to the supervisor for a guest.

    Returns the ``str`` of the /124 IPv6Network and its prefix length (124) under
    the static policy. Under the dynamic policy the address depends on what the
    supervisor already holds, so it returns ``("", 0)`` here and
    :func:`create_vm_with_ipv6` fills it in right before the create.
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


def _parse_network(cidr: str) -> IPv6Network | None:
    if not cidr:
        return None
    try:
        return IPv6Network(cidr)
    except ValueError:
        logger.warning("Ignoring an unparseable IPv6 network %r reported by the supervisor", cidr)
        return None


async def _network_of(supervisor: Supervisor, info: VmInfo) -> IPv6Network | None:
    """The guest network a VM holds: its live assignment, or for a VM without
    one (stopped) the address it was created with, which it gets back on start."""
    live = _parse_network(info.ipv6.network_cidr)
    if live is not None:
        return live
    try:
        spec = await supervisor.get_vm_spec(info.vm_id)
    except SupervisorError as error:
        logger.debug("No spec for %s while collecting held IPv6 networks: %s", info.vm_id, error)
        return None
    return _parse_network(spec.network.requested_ipv6)


def _first_free_subnet(held: list[IPv6Network]) -> IPv6Network:
    pool = IPv6Network(settings.IPV6_ADDRESS_POOL)
    prefix = settings.IPV6_SUBNET_PREFIX
    if not pool.prefixlen <= prefix <= 126:
        msg = f"IPV6_SUBNET_PREFIX /{prefix} cannot split the IPv6 pool {pool} into guest networks"
        raise VmSetupError(msg)
    size = 1 << (128 - prefix)
    count = 1 << (prefix - pool.prefixlen)
    base = int(pool.network_address)
    # Subnet 0 is the host's. Every held network blocks at most one candidate
    # run, so this ends after at most len(held) + 1 candidates.
    index = 1
    while index < count:
        candidate = IPv6Network((base + index * size, prefix))
        blocker = next((network for network in held if network.overlaps(candidate)), None)
        if blocker is None:
            return candidate
        # Skip past the blocker in one step (it may be wider than a subnet).
        blocker_end = int(blocker.broadcast_address) + 1
        index = max(index + 1, -(-(blocker_end - base) // size))
    msg = f"The IPv6 pool {pool} has no free /{prefix} subnet left"
    raise InsufficientResourcesError(msg)


async def allocate_dynamic_ipv6(supervisor: Supervisor, vm_id: VmId) -> IPv6Network:
    """The dynamic-policy subnet for ``vm_id``. Callers hold the allocation lock.

    A VM the supervisor already knows keeps its address (an idempotent retry or
    a rebuild must not move it). Otherwise the first free subnet of the pool,
    skipping the host's subnet 0, every network a known VM holds and every
    allocation still in flight.
    """
    held: list[IPv6Network] = list(_in_flight.values())
    for info in await supervisor.list_vms():
        network = await _network_of(supervisor, info)
        if network is None:
            continue
        if info.vm_id == vm_id:
            return network
        held.append(network)
    return _first_free_subnet(held)


def _needs_dynamic_ipv6(spec: CreateVmSpec) -> bool:
    if settings.IPV6_ALLOCATION_POLICY != IPv6AllocationPolicy.dynamic or not settings.ALLOW_VM_NETWORKING:
        return False
    if spec.network.requested_ipv6:
        return False
    # A QEMU VM always gets a tap; a Firecracker program only with internet.
    return spec.backend == Backend.QEMU or spec.network.internet_access


@asynccontextmanager
async def reserved_ipv6(supervisor: Supervisor, spec: CreateVmSpec) -> AsyncIterator[CreateVmSpec]:
    """``spec`` with its dynamic-policy IPv6 filled in, reserved while in use.

    A spec that already carries an address (static policy) or needs none comes
    back unchanged.
    """
    if not _needs_dynamic_ipv6(spec):
        yield spec
        return
    token = object()
    async with _allocation_lock():
        subnet = await allocate_dynamic_ipv6(supervisor, spec.vm_id)
        _in_flight[token] = subnet
    try:
        logger.debug("Allocated IPv6 network %s to %s", subnet, spec.vm_id)
        yield replace(
            spec,
            network=replace(spec.network, requested_ipv6=str(subnet), ipv6_prefix_len=subnet.prefixlen),
        )
    finally:
        del _in_flight[token]


async def lacks_known_ipv6(supervisor: Supervisor, vm_id: VmId) -> bool:
    """Whether a stopped VM has no guest IPv6 the supervisor could restore.

    True only for a networked VM whose spec (the supervisor's reconstruction
    from its config) carries no address: a config written by an older
    supervisor that did not persist it. The supervisor refuses to start such a
    VM, so the caller rebuilds it through a fresh create instead.
    """
    if not settings.ALLOW_VM_NETWORKING:
        return False
    try:
        spec = await supervisor.get_vm_spec(vm_id)
    except SupervisorError as error:
        logger.debug("No spec for %s, starting it as is: %s", vm_id, error)
        return False
    if spec.network.requested_ipv6:
        return False
    return spec.backend == Backend.QEMU or spec.network.internet_access


async def create_vm_with_ipv6(supervisor: Supervisor, spec: CreateVmSpec) -> VmInfo:
    """``supervisor.create_vm`` with the guest IPv6 allocated first when the
    dynamic policy leaves it to this moment. Every agent create goes through
    here: the supervisor refuses a networked spec without an address."""
    async with reserved_ipv6(supervisor, spec) as allocated:
        return await supervisor.create_vm(allocated)
