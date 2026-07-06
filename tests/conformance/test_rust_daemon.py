"""Conformance seed for the Rust supervisor daemon (increment 1).

Boots the compiled `aleph-vm-supervisor` binary on a temporary socket and
drives it with the production Python client (GrpcSupervisor). The Python
in-process implementation (LocalSupervisor.get_host_info) is the parity
oracle; since it needs a full VmPool, the expectations are computed from the
same primary sources it reads (os.cpu_count, psutil MemTotal, os.uname,
netifaces on the default route interface, shutil.disk_usage, lspci).

Opt-in: the suite runs only with ALEPH_VM_CONFORMANCE=1 and cargo on PATH,
so the regular Python CI job never pays for a Rust build.
"""

import ipaddress
import os
import shutil
import signal
import stat
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import psutil
import pytest

from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.errors import NotImplementedSupervisorError
from aleph.vm.supervisor_interface.types import HealthStatus, VmId

REPO_ROOT = Path(__file__).resolve().parents[2]
RUST_DIR = REPO_ROOT / "rust"
DAEMON_BINARY = RUST_DIR / "target" / "debug" / "aleph-vm-supervisor"

HAVE_LSPCI = shutil.which("lspci") is not None

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(shutil.which("cargo") is None, reason="cargo is not on PATH"),
]


@pytest.fixture(scope="session")
def daemon_binary() -> Path:
    # cwd=RUST_DIR so rustup picks up rust/rust-toolchain.toml; the target
    # directory is reused across runs.
    subprocess.run(["cargo", "build", "--locked"], cwd=RUST_DIR, check=True)
    assert DAEMON_BINARY.exists()
    return DAEMON_BINARY


@contextmanager
def running_daemon(binary: Path, execution_root: Path):
    """Start the daemon on a fresh EXECUTION_ROOT and wait for its socket."""
    # Drop every ALEPH_VM_* variable of the outer test environment (e.g. the
    # ALEPH_VM_EXECUTION_ROOT the Python suite uses) so the daemon sees only
    # the conformance configuration.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("ALEPH_VM_")}
    env["ALEPH_VM_EXECUTION_ROOT"] = str(execution_root)
    # Exercise the lspci inventory whenever the tool exists; without vfio
    # devices both daemons serve an empty list, which is still a comparison.
    env["ALEPH_VM_ENABLE_GPU_SUPPORT"] = "1" if HAVE_LSPCI else "0"
    env.setdefault("RUST_LOG", "info")

    socket_path = execution_root / "supervisor.sock"
    process = subprocess.Popen([str(binary)], env=env)
    try:
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            if process.poll() is not None:
                msg = f"daemon exited early with code {process.returncode}"
                raise RuntimeError(msg)
            if time.monotonic() > deadline:
                msg = "daemon socket did not appear within 10s"
                raise RuntimeError(msg)
            time.sleep(0.02)
        yield process, socket_path
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@pytest.fixture
def rust_daemon(daemon_binary: Path, tmp_path: Path):
    with running_daemon(daemon_binary, tmp_path) as started:
        yield started


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
    # (zero on a fresh daemon).
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
    # (Network.__init__ resolves it through netifaces at startup).
    interface = default_route_interface()
    assert interface is not None, "the daemon started, so a default interface must exist"
    try:
        from aleph.vm.network.get_interface_ipv4 import get_interface_ipv4

        assert info.host_ipv4 == get_interface_ipv4(interface)
    except ImportError:
        # netifaces missing in this environment: validate the shape only.
        ipaddress.IPv4Address(info.host_ipv4)

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
    assert info.numa_nodes == []
    assert info.gpus == []
    assert info.sev_supported is False
    assert info.sev_es_supported is False
    assert info.sev_snp_supported is False
    assert info.tdx_supported is False


@pytest.mark.asyncio
async def test_unported_rpcs_raise_not_implemented(rust_daemon):
    _, socket_path = rust_daemon
    client = GrpcSupervisor(socket_path)
    try:
        with pytest.raises(NotImplementedSupervisorError):
            await client.get_vm(VmId("a" * 64))
    finally:
        await client.close()


def test_sigterm_unlinks_the_socket(daemon_binary: Path, tmp_path: Path):
    with running_daemon(daemon_binary, tmp_path) as (process, socket_path):
        # Day-one hardening: the socket is chmod 0700.
        assert stat.S_IMODE(socket_path.stat().st_mode) == 0o700
        process.send_signal(signal.SIGTERM)
        assert process.wait(timeout=10) == 0
        assert not socket_path.exists()
