import asyncio
import os
from pathlib import Path

import pytest

from aleph.vm.agent import guest_ipv6
from aleph.vm.agent.guest_ipv6 import (
    compute_requested_ipv6,
    create_vm_with_ipv6,
    lacks_known_ipv6,
)
from aleph.vm.conf import IPv6AllocationPolicy, settings
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    IpAssignment,
    NetworkConfig,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.vm_type import VmType

# Avoid failures linked to settings when initializing the global VmPool object
os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"

from ipaddress import IPv6Network

from aleph_message.models import ItemHash


def test_compute_requested_ipv6_static(monkeypatch):
    # The agent computes the static /124 upfront and hands it to the supervisor
    # as the str(IPv6Network) CIDR plus the prefix length.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "2a01:240:2:c8::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.instance)

    # The scheduler computes the same address; the static scheme must not drift.
    assert cidr == "2a01:240:2:c8:3:abcd:ef01:2340/124"
    assert prefix_len == 124


def test_compute_requested_ipv6_v_program_hextet(monkeypatch):
    # V-PROGRAMs carry the 0x4 VM-type field, mirroring the scheduler and the
    # daemon; only that nibble differs from an instance with the same hash.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "2a01:240:2:c8::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.v_program)
    assert cidr == "2a01:240:2:c8:4:abcd:ef01:2340/124"
    assert prefix_len == 124


def test_compute_requested_ipv6_microvm_hextet(monkeypatch):
    # Firecracker programs (persistent or not) carry the 0x1 microvm field: the
    # daemon and the scheduler have no persistent_program hextet, so the program
    # path pins microvm and must produce the same 0x1 address the daemon does.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "1111:2222:3333:4444::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446")
    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.microvm)
    # Matches StaticIPv6Allocator(VmType.microvm) in test_ipv6_allocator.py
    # (str() compresses the 0x1 hextet to `1`).
    assert cidr == "1111:2222:3333:4444:1:8920:215b:2e90/124"
    assert prefix_len == 124


def test_compute_requested_ipv6_matches_the_scheme(monkeypatch):
    # The helper must return the /124 network the static scheme defines: the
    # daemon parses that string back into the guest address, so any divergence
    # would move an existing VM's address.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "1111:2222:3333:4444::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)

    vm_hash = ItemHash("8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446")
    expected = IPv6Network("1111:2222:3333:4444:0003:8920:215b:2e90/124")

    cidr, prefix_len = compute_requested_ipv6(vm_hash, VmType.instance)
    assert cidr == str(expected)
    assert prefix_len == expected.prefixlen


def test_compute_requested_ipv6_dynamic_is_empty(monkeypatch):
    # Under the dynamic policy the address depends on what the supervisor
    # holds, so it is decided right before the create, not at spec build time.
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.dynamic)

    vm_hash = ItemHash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    assert compute_requested_ipv6(vm_hash, VmType.instance) == ("", 0)


# ── dynamic allocation ──────────────────────────────────────────────────


def _spec(vm_id: str, *, backend: Backend = Backend.QEMU, internet: bool = True, requested: str = "") -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(vm_id),
        backend=backend,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=Path("/tmp/rootfs"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=1,
        memory_mib=256,
        tee=None,
        network=NetworkConfig(
            internet_access=internet, requested_ipv6=requested, ipv6_prefix_len=124 if requested else 0
        ),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _info(vm_id: str, network: str = "", status: VmStatus = VmStatus.RUNNING) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_id),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(network_cidr=network, address="", gateway=""),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


class FakeSupervisor:
    """Lists VMs with their live networks; stopped VMs report theirs only
    through their spec, like the daemon. create_vm records the VM, yielding
    first so concurrent creates interleave."""

    def __init__(self, live: dict[str, str] | None = None, stopped: dict[str, str] | None = None):
        self.live = dict(live or {})
        self.stopped = dict(stopped or {})
        self.created: list[CreateVmSpec] = []
        self.fail_create = False

    async def list_vms(self) -> list[VmInfo]:
        return [_info(vm_id, network) for vm_id, network in self.live.items()] + [
            _info(vm_id, status=VmStatus.STOPPED) for vm_id in self.stopped
        ]

    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        if vm_id in self.stopped:
            return _spec(vm_id, requested=self.stopped[vm_id])
        if vm_id in self.live:
            return _spec(vm_id, requested=self.live[vm_id])
        raise VmNotFoundError(vm_id)

    async def create_vm(self, spec: CreateVmSpec) -> VmInfo:
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        if self.fail_create:
            msg = "boom"
            raise RuntimeError(msg)
        self.created.append(spec)
        self.live[spec.vm_id] = spec.network.requested_ipv6
        return _info(spec.vm_id, spec.network.requested_ipv6)


@pytest.fixture
def dynamic(monkeypatch):
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.dynamic)
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "fc00:1:2:3::/64")
    monkeypatch.setattr(settings, "IPV6_SUBNET_PREFIX", 124)
    monkeypatch.setattr(settings, "ALLOW_VM_NETWORKING", True)
    assert guest_ipv6._in_flight == {}


@pytest.mark.asyncio
async def test_dynamic_allocation_picks_the_first_subnet_after_the_host_one(dynamic):
    supervisor = FakeSupervisor()
    await create_vm_with_ipv6(supervisor, _spec("a"))
    spec = supervisor.created[0]
    # Subnet 0 (fc00:1:2:3::/124) is the host's.
    assert spec.network.requested_ipv6 == "fc00:1:2:3::10/124"
    assert spec.network.ipv6_prefix_len == 124


@pytest.mark.asyncio
async def test_dynamic_allocation_skips_held_subnets(dynamic):
    # ::10 is live, ::20 belongs to a stopped VM (known only from its spec),
    # ::40/122 is a wider network covering ::40 to ::7f.
    supervisor = FakeSupervisor(
        live={"a": "fc00:1:2:3::10/124", "c": "fc00:1:2:3::40/122"},
        stopped={"b": "fc00:1:2:3::20/124"},
    )
    await create_vm_with_ipv6(supervisor, _spec("d"))
    await create_vm_with_ipv6(supervisor, _spec("e"))
    assert [spec.network.requested_ipv6 for spec in supervisor.created] == [
        "fc00:1:2:3::30/124",
        "fc00:1:2:3::80/124",
    ]


@pytest.mark.asyncio
async def test_dynamic_allocation_ignores_foreign_networks(dynamic):
    # A static-scheme address in the pool far away, and one outside the pool,
    # do not push the allocation anywhere.
    supervisor = FakeSupervisor(live={"a": "fc00:1:2:3:3:dead:beef:aa0/124", "b": "2001:db8::10/124"})
    await create_vm_with_ipv6(supervisor, _spec("c"))
    assert supervisor.created[0].network.requested_ipv6 == "fc00:1:2:3::10/124"


@pytest.mark.asyncio
async def test_dynamic_allocation_reuses_the_vms_existing_address(dynamic):
    # An idempotent retry of a running VM, and a rebuild of a stopped one,
    # keep their address instead of moving to the first free subnet.
    supervisor = FakeSupervisor(live={"a": "fc00:1:2:3::b0/124"}, stopped={"b": "fc00:1:2:3::c0/124"})
    await create_vm_with_ipv6(supervisor, _spec("a"))
    await create_vm_with_ipv6(supervisor, _spec("b"))
    assert [spec.network.requested_ipv6 for spec in supervisor.created] == [
        "fc00:1:2:3::b0/124",
        "fc00:1:2:3::c0/124",
    ]


@pytest.mark.asyncio
async def test_concurrent_dynamic_allocations_do_not_collide(dynamic):
    supervisor = FakeSupervisor(live={"x": "fc00:1:2:3::20/124"})
    await asyncio.gather(*(create_vm_with_ipv6(supervisor, _spec(f"vm{i}")) for i in range(5)))
    networks = [spec.network.requested_ipv6 for spec in supervisor.created]
    assert len(set(networks)) == 5
    assert "fc00:1:2:3::20/124" not in networks
    assert set(networks) == {f"fc00:1:2:3::{n}0/124" for n in (1, 3, 4, 5, 6)}
    assert guest_ipv6._in_flight == {}


@pytest.mark.asyncio
async def test_a_failed_create_releases_its_reservation(dynamic):
    supervisor = FakeSupervisor()
    supervisor.fail_create = True
    with pytest.raises(RuntimeError):
        await create_vm_with_ipv6(supervisor, _spec("a"))
    assert guest_ipv6._in_flight == {}
    supervisor.fail_create = False
    await create_vm_with_ipv6(supervisor, _spec("a"))
    assert supervisor.created[0].network.requested_ipv6 == "fc00:1:2:3::10/124"


@pytest.mark.asyncio
async def test_pool_exhaustion_errors_cleanly(dynamic, monkeypatch):
    # A /120 pool split into /124s: 16 subnets, the first is the host's.
    monkeypatch.setattr(settings, "IPV6_ADDRESS_POOL", "fc00:1:2:3::/120")
    supervisor = FakeSupervisor(live={f"vm{i}": f"fc00:1:2:3::{i:x}0/124" for i in range(1, 16)})
    with pytest.raises(InsufficientResourcesError):
        await create_vm_with_ipv6(supervisor, _spec("new"))
    assert supervisor.created == []
    assert guest_ipv6._in_flight == {}


@pytest.mark.asyncio
async def test_dynamic_allocation_leaves_specs_that_need_none_alone(dynamic):
    supervisor = FakeSupervisor()
    # Already addressed, a program without internet.
    await create_vm_with_ipv6(supervisor, _spec("a", requested="fc00:1:2:3::f0/124"))
    await create_vm_with_ipv6(supervisor, _spec("b", backend=Backend.FIRECRACKER, internet=False))
    assert supervisor.created[0].network.requested_ipv6 == "fc00:1:2:3::f0/124"
    assert supervisor.created[1].network.requested_ipv6 == ""
    # A program with internet gets one.
    await create_vm_with_ipv6(supervisor, _spec("c", backend=Backend.FIRECRACKER, internet=True))
    assert supervisor.created[2].network.requested_ipv6 == "fc00:1:2:3::10/124"


@pytest.mark.asyncio
async def test_the_static_policy_never_asks_the_supervisor(monkeypatch):
    monkeypatch.setattr(settings, "IPV6_ALLOCATION_POLICY", IPv6AllocationPolicy.static)

    class CreateOnly:
        def __init__(self):
            self.created: list[CreateVmSpec] = []

        async def create_vm(self, spec):
            self.created.append(spec)

    supervisor = CreateOnly()
    spec = _spec("a", requested="fc00:1:2:3:3:dead:beef:aa0/124")
    await create_vm_with_ipv6(supervisor, spec)
    assert supervisor.created == [spec]


@pytest.mark.asyncio
async def test_lacks_known_ipv6(dynamic):
    supervisor = FakeSupervisor(stopped={"legacy": "", "fine": "fc00:1:2:3::10/124"})
    assert await lacks_known_ipv6(supervisor, VmId("legacy")) is True
    assert await lacks_known_ipv6(supervisor, VmId("fine")) is False
    # No spec to judge by: start it as is and let the supervisor answer.
    assert await lacks_known_ipv6(supervisor, VmId("gone")) is False


@pytest.mark.asyncio
async def test_lacks_known_ipv6_ignores_vms_without_a_tap(dynamic, monkeypatch):
    supervisor = FakeSupervisor()

    async def program_spec(vm_id):
        return _spec(vm_id, backend=Backend.FIRECRACKER, internet=False)

    supervisor.get_vm_spec = program_spec
    assert await lacks_known_ipv6(supervisor, VmId("p")) is False
    monkeypatch.setattr(settings, "ALLOW_VM_NETWORKING", False)
    supervisor.get_vm_spec = FakeSupervisor(stopped={"legacy": ""}).get_vm_spec
    assert await lacks_known_ipv6(supervisor, VmId("legacy")) is False
