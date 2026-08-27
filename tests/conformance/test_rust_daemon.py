"""Conformance seed for the Rust supervisor daemon (increment 1).

Boots the compiled `aleph-vm-supervisor` binary on a temporary socket and
drives it with the production Python client (GrpcSupervisor). The Python
daemon's ``LocalSupervisor.get_host_info`` was the parity oracle (that daemon
was removed in 2026-08); the expectations are computed from the same primary
sources it read (os.cpu_count, psutil MemTotal, os.uname, the addresses of
the default-route interface via ``ip -4 addr``, shutil.disk_usage, lspci).

Opt-in: the suite runs only with ALEPH_VM_CONFORMANCE=1 and cargo on PATH,
so the regular Python CI job never pays for a Rust build.
"""

import ipaddress
import os
import shutil
import signal
import stat
import subprocess
from pathlib import Path

import psutil
import pytest
from conftest import cargo_missing

from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import HealthStatus, VmId

HAVE_LSPCI = shutil.which("lspci") is not None

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(cargo_missing(), reason="cargo is not on PATH"),
]

# Exercise the lspci inventory whenever the tool exists; without vfio
# devices both daemons serve an empty list, which is still a comparison.
GPU_ENV = {"ALEPH_VM_ENABLE_GPU_SUPPORT": "1" if HAVE_LSPCI else "0"}


@pytest.fixture
def rust_daemon(start_daemon, execution_root: Path):
    with start_daemon(execution_root, GPU_ENV) as started:
        yield started


def _interface_ipv4_addresses(interface: str) -> list[ipaddress.IPv4Address]:
    """Every IPv4 address configured on *interface*, via ip(8)."""
    out = subprocess.run(
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ipaddress.IPv4Address(line.split()[3].split("/")[0]) for line in out.splitlines() if line.strip()]


def default_route_interface() -> str | None:
    """conf.py get_default_interface(), inlined to avoid importing the full
    settings module (and its system dependencies) in this test."""
    with open("/proc/net/route") as route_table:
        for line in route_table.readlines():
            parts = line.strip().split()
            if parts[1] == "00000000":
                return parts[0]
    return None


@pytest.mark.asyncio
async def test_health_matches_the_python_daemon(rust_daemon):
    _, socket_path = rust_daemon
    client = GrpcSupervisor(socket_path)
    try:
        health = await client.health()
    finally:
        await client.close()
    # LocalSupervisor.health: always OK, vm_count = number of executions
    # (zero on a fresh daemon with an empty EXECUTION_ROOT).
    assert health.status is HealthStatus.OK
    assert health.vm_count == 0


@pytest.mark.asyncio
async def test_get_host_info_matches_the_python_sources(rust_daemon):
    _, socket_path = rust_daemon
    execution_root = socket_path.parent
    client = GrpcSupervisor(socket_path)
    try:
        info = await client.get_host_info()
    finally:
        await client.close()

    # Stable fields: exact equality with what LocalSupervisor serves.
    assert info.cpu_count == os.cpu_count()
    assert info.memory_mib == int(psutil.virtual_memory().total / (1024 * 1024))
    assert info.kernel_version == os.uname().release
    assert info.hostname == os.uname().nodename

    # host_ipv4: the default-route interface address, global scope preferred
    # (resolved at daemon startup). Validate against the interface's own
    # addresses: an address of that interface, global scope when it has one.
    interface = default_route_interface()
    assert interface is not None, "the daemon started, so a default interface must exist"
    reported = ipaddress.IPv4Address(info.host_ipv4)
    addresses = _interface_ipv4_addresses(interface)
    assert reported in addresses, f"{reported} is not an address of {interface}: {addresses}"
    if any(a.is_global for a in addresses):
        assert reported.is_global, f"{interface} has a global address but the daemon reported {reported}"

    # The daemon must have created the volumes dir (settings.setup parity),
    # and available disk is statvfs free on it. Inherently racy: allow a
    # small relative delta.
    volumes_dir = execution_root / "volumes" / "persistent"
    assert volumes_dir.is_dir()
    assert info.available_disk_bytes == pytest.approx(shutil.disk_usage(volumes_dir).free, rel=0.05)

    # GPU inventory: same lspci parsing, order-insensitive (the Python side
    # builds a set). Fresh daemon, no VMs: available equals inventory.
    if HAVE_LSPCI:
        from aleph.vm.resources import get_gpu_devices

        expected_gpus = {
            (gpu.vendor, gpu.device_name, gpu.device_class.value, gpu.pci_host, gpu.device_id)
            for gpu in get_gpu_devices()
        }
        served_gpus = {
            (gpu["vendor"], gpu["device_name"], gpu["device_class"], gpu["pci_host"], gpu["device_id"])
            for gpu in info.gpu_inventory
        }
        assert served_gpus == expected_gpus
    else:
        assert info.gpu_inventory == []
    assert info.available_gpus == info.gpu_inventory

    # Fields the Python daemon does not fill today must stay at their
    # defaults in the Rust daemon too.
    assert info.cpu_architecture == ""
    assert info.cpu_vendor == ""
    assert info.cpu_model == ""
    assert info.cpu_frequency_mhz == 0
    assert info.memory_type == ""
    assert info.memory_clock_mhz == 0
    assert info.gpus == []
    assert info.sev_supported is False
    assert info.sev_es_supported is False
    assert info.sev_snp_supported is False
    assert info.tdx_supported is False

    # NUMA topology reporting is a Rust-only addition (increment C1): the Python
    # daemon has no NUMA source, so this is verified against the same primary
    # source the Rust daemon reads, /sys/devices/system/node, rather than the
    # pre-C1 empty placeholder. A CONFIG_NUMA host (the CI default) has node0.
    node_dirs = sorted(p for p in Path("/sys/devices/system/node").glob("node[0-9]*") if p.is_dir())
    assert [n.index for n in info.numa_nodes] == sorted(int(p.name.removeprefix("node")) for p in node_dirs)
    if node_dirs:
        # Compare each node's reported cpu_count against a parse of the SAME
        # nodeN/cpulist the daemon read, keyed by index (robust to node order).
        # os.cpu_count() is a different measure whose relation to node cpulists
        # shifts with offline CPUs and can be None; os.sched_getaffinity is the
        # process's (possibly cgroup-restricted) affinity, not the host count.
        def cpulist_count(node_dir: Path) -> int:
            total = 0
            for part in filter(None, (node_dir / "cpulist").read_text().strip().split(",")):
                if "-" in part:
                    lo, hi = part.split("-")
                    total += int(hi) - int(lo) + 1
                else:
                    total += 1
            return total

        cpus_by_index = {int(p.name.removeprefix("node")): cpulist_count(p) for p in node_dirs}
        for node in info.numa_nodes:
            assert node.cpu_count == cpus_by_index[node.index], (
                f"node {node.index}: reported {node.cpu_count}, " f"cpulist has {cpus_by_index[node.index]}"
            )
        assert all(n.memory_mib > 0 for n in info.numa_nodes)


@pytest.mark.asyncio
async def test_guest_quiescence_answers_without_root(rust_daemon):
    # The supervisor's only part in a backup is FreezeGuest/ThawGuest; the
    # archives are the agent's. The no-root slice: an unknown VM is
    # VmNotFoundError for both (the world view has no such entry).
    _, socket_path = rust_daemon
    client = GrpcSupervisor(socket_path)
    try:
        with pytest.raises(VmNotFoundError):
            await client.freeze_guest(VmId("a" * 64))
        with pytest.raises(VmNotFoundError):
            await client.thaw_guest(VmId("a" * 64))
    finally:
        await client.close()


def test_sigterm_unlinks_the_socket(start_daemon, execution_root: Path):
    with start_daemon(execution_root, GPU_ENV) as (process, socket_path):
        # Day-one hardening: the socket is chmod 0700.
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o700
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        assert not socket_path.exists()
