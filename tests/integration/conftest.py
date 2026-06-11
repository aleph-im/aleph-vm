"""Supervisor integration tests: a real supervisor daemon driven over gRPC,
exactly as the agent process would, but agent-free.

Opt-in: set AVM_ITEST=1 (the suite is skipped entirely otherwise, so the
unit-test CI never boots VMs).

Requirements per backend:

- Firecracker tests: /dev/kvm, the firecracker binary, a kernel
  (AVM_ITEST_FC_KERNEL, default /opt/firecracker/vmlinux.bin) and a runtime
  squashfs (AVM_ITEST_FC_RUNTIME, default: the local fake-data runtime build
  under runtimes/aleph-debian-12-python). They run unprivileged: the guest is
  reached over the vsock guest channel, not IP.
- QEMU tests: root (TAP networking and systemd controller units) and a
  cloud-init-enabled qcow2 cloud image (AVM_ITEST_QEMU_IMAGE, default: first
  of runtimes/instance-rootfs/{debian13,ubuntu26,debian12}.img).

When run as root the harness installs a systemd drop-in for
aleph-vm-controller@.service (in /run/systemd/system, removed on teardown)
that points the controller at this source tree and the test execution root,
so persistent VMs run the code under test rather than whatever is installed
in /opt/aleph-vm.

Typical runs are `just itest` (unprivileged, Firecracker only) and
`just itest-root` (sudo, full set), or directly:
  AVM_ITEST=1 venv/bin/python -m pytest tests/integration -v          # FC only
  sudo AVM_ITEST=1 venv/bin/python -m pytest tests/integration -v     # full set
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import pytest_asyncio

from aleph.vm.supervisor.errors import SupervisorError
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GuestChannelSpec,
    NetworkConfig,
    VmId,
)

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]

INTEGRATION = os.environ.get("AVM_ITEST") == "1"
IS_ROOT = os.geteuid() == 0
HAS_KVM = os.access("/dev/kvm", os.R_OK | os.W_OK)

FC_KERNEL = Path(os.environ.get("AVM_ITEST_FC_KERNEL", "/opt/firecracker/vmlinux.bin"))
FC_RUNTIME = Path(
    os.environ.get(
        "AVM_ITEST_FC_RUNTIME",
        REPO_ROOT / "runtimes" / "aleph-debian-12-python" / "rootfs.squashfs",
    )
)


def _default_qemu_image() -> Path | None:
    for name in ("debian13.img", "ubuntu26.img", "debian12.img"):
        candidate = REPO_ROOT / "runtimes" / "instance-rootfs" / name
        if candidate.exists():
            return candidate
    return None


_qemu_image_env = os.environ.get("AVM_ITEST_QEMU_IMAGE")
QEMU_IMAGE: Path | None = Path(_qemu_image_env) if _qemu_image_env else _default_qemu_image()

FC_READY = HAS_KVM and FC_KERNEL.exists() and FC_RUNTIME.exists()
QEMU_READY = HAS_KVM and IS_ROOT and QEMU_IMAGE is not None and QEMU_IMAGE.exists()

requires_fc = pytest.mark.skipif(
    not FC_READY,
    reason=f"needs /dev/kvm, a kernel ({FC_KERNEL}) and a runtime squashfs ({FC_RUNTIME})",
)
requires_qemu = pytest.mark.skipif(
    not QEMU_READY,
    reason="needs root, /dev/kvm and a cloud image (AVM_ITEST_QEMU_IMAGE)",
)
requires_root = pytest.mark.skipif(not IS_ROOT, reason="needs root (TAP networking / nftables)")


def pytest_collection_modifyitems(config, items):
    if INTEGRATION:
        return
    skip = pytest.mark.skip(reason="integration suite is opt-in: set AVM_ITEST=1")
    for item in items:
        if Path(item.fspath).parent == HERE:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# The supervisor daemon under test
# ---------------------------------------------------------------------------

_CONTROLLER_UNIT = Path("/run/systemd/system/aleph-vm-controller@.service")
_CONTROLLER_DROPIN_DIR = Path("/run/systemd/system/aleph-vm-controller@.service.d")
_CONTROLLER_DROPIN = _CONTROLLER_DROPIN_DIR / "99-avm-itest.conf"

_BASE_UNIT = """\
[Unit]
Description=Aleph VM %i Controller (integration-test fallback unit)

[Service]
Type=simple
RestartSec=5s
ExecStart=/bin/false
KillMode=mixed
TimeoutStopSec=30
"""


def _install_controller_unit(exec_root: Path) -> list[Path]:
    """Point aleph-vm-controller@ at this source tree and *exec_root*.

    A drop-in overrides ExecStart/PYTHONPATH of whatever unit is installed;
    a fallback unit in /run covers hosts with no aleph-vm package at all
    (/etc and /usr/lib unit files take precedence over /run, so the fallback
    is inert when a packaged unit exists).
    """
    created: list[Path] = []
    packaged = any(
        Path(base, "aleph-vm-controller@.service").exists()
        for base in ("/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system")
    )
    if not packaged:
        _CONTROLLER_UNIT.write_text(_BASE_UNIT)
        created.append(_CONTROLLER_UNIT)
    _CONTROLLER_DROPIN_DIR.mkdir(parents=True, exist_ok=True)
    _CONTROLLER_DROPIN.write_text(
        "[Service]\n"
        f"Environment=PYTHONPATH={REPO_ROOT / 'src'}\n"
        f"WorkingDirectory={REPO_ROOT}\n"
        "ExecStart=\n"
        f"ExecStart={sys.executable} -m aleph.vm.controllers --config={exec_root}/%i-controller.json\n"
    )
    created.append(_CONTROLLER_DROPIN)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    return created


def _remove_controller_unit(created: list[Path]) -> None:
    for path in created:
        path.unlink(missing_ok=True)
    if _CONTROLLER_DROPIN_DIR.exists() and not any(_CONTROLLER_DROPIN_DIR.iterdir()):
        _CONTROLLER_DROPIN_DIR.rmdir()
    subprocess.run(["systemctl", "daemon-reload"], check=False)


_SYSTEM_MODULE_GLOBS = {
    # The supervisor daemon needs the distro's C-extension modules that venvs
    # typically lack; glob patterns cover the compiled extension files.
    "systemd": ("systemd",),
    "dbus": ("dbus", "_dbus_bindings*.so", "_dbus_glib_bindings*.so"),
    "nftables": ("nftables",),
}


def _system_module_shim(root: Path) -> Path | None:
    """A PYTHONPATH dir with just the system modules the venv is missing.

    Symlinking only what is needed (instead of putting all of
    /usr/lib/python3/dist-packages on PYTHONPATH) avoids shadowing venv
    packages such as aiohttp or pydantic with the distro's versions.
    """
    dist_packages = Path("/usr/lib/python3/dist-packages")
    if not dist_packages.exists():
        return None
    missing: list[str] = []
    for module, globs in _SYSTEM_MODULE_GLOBS.items():
        try:
            __import__(module)
        except ImportError:
            missing.extend(globs)
    if not missing:
        return None
    shim = root / "system-modules"
    shim.mkdir()
    for pattern in missing:
        for source in dist_packages.glob(pattern):
            (shim / source.name).symlink_to(source)
    return shim


class Daemon:
    """Handle on the supervisor daemon process and its private roots."""

    def __init__(self, process: subprocess.Popen, socket_path: Path, root: Path):
        self.process = process
        self.socket_path = socket_path
        self.root = root
        self.exec_root = root / "exec"
        self.cache_root = root / "cache"
        self.log_path = root / "daemon.log"

    def log_tail(self, lines: int = 50) -> str:
        if not self.log_path.exists():
            return "<no daemon log>"
        return "\n".join(self.log_path.read_text(errors="replace").splitlines()[-lines:])


async def _health_once(socket_path: Path) -> None:
    client = GrpcSupervisor(socket_path)
    try:
        await client.health()
    finally:
        await client.close()


async def _delete_all_vms(socket_path: Path) -> None:
    client = GrpcSupervisor(socket_path)
    try:
        for info in await client.list_vms():
            try:
                await client.delete_vm(info.vm_id)
            except SupervisorError:
                pass
    finally:
        await client.close()


@pytest.fixture(scope="session")
def daemon(tmp_path_factory):
    root = tmp_path_factory.mktemp("avm-itest")
    (root / "exec").mkdir()
    (root / "cache").mkdir()
    socket_path = root / "supervisor.sock"

    python_path = [str(REPO_ROOT / "src")]
    if os.environ.get("PYTHONPATH"):
        python_path.append(os.environ["PYTHONPATH"])
    shim = _system_module_shim(root)
    if shim is not None:
        python_path.append(str(shim))

    env = dict(os.environ)
    env.update(
        {
            "PYTHONPATH": os.pathsep.join(python_path),
            "ALEPH_VM_CACHE_ROOT": str(root / "cache"),
            "ALEPH_VM_EXECUTION_ROOT": str(root / "exec"),
            "ALEPH_VM_USE_JAILER": "False",
            "ALEPH_VM_ALLOW_VM_NETWORKING": "True" if IS_ROOT else "False",
            "ALEPH_VM_PRINT_SYSTEM_LOGS": "True",
        }
    )

    unit_files = _install_controller_unit(root / "exec") if IS_ROOT else []

    log_file = (root / "daemon.log").open("wb")
    process = subprocess.Popen(
        [sys.executable, "-m", "aleph.vm.supervisor", "--socket", str(socket_path)],
        env=env,
        stdout=log_file,
        stderr=subprocess.STDOUT,
        cwd=REPO_ROOT,
    )
    handle = Daemon(process, socket_path, root)

    deadline = time.monotonic() + 60
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log_file.close()
            _remove_controller_unit(unit_files)
            pytest.fail(f"supervisor daemon exited at startup:\n{handle.log_tail()}")
        if socket_path.exists():
            try:
                asyncio.run(_health_once(socket_path))
                break
            except Exception as exc:
                last_error = exc
        time.sleep(0.5)
    else:
        process.kill()
        log_file.close()
        _remove_controller_unit(unit_files)
        pytest.fail(f"supervisor daemon never became healthy ({last_error}):\n{handle.log_tail()}")

    yield handle

    try:
        asyncio.run(_delete_all_vms(socket_path))
    except Exception:
        pass
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)
    log_file.close()
    _remove_controller_unit(unit_files)


@pytest_asyncio.fixture
async def supervisor(daemon):
    """A fresh gRPC client per test (channels are bound to the event loop)."""
    client = GrpcSupervisor(daemon.socket_path)
    try:
        yield client
    finally:
        await client.close()


# ---------------------------------------------------------------------------
# Spec builders (the agent's job, done inline: resolved local paths only)
# ---------------------------------------------------------------------------


def fresh_vm_id() -> VmId:
    """A unique, ItemHash-shaped (64 hex chars) VM id per test VM."""
    return VmId(secrets.token_hex(32))


def fc_program_spec(
    vm_id: VmId,
    *,
    internet: bool = False,
    vcpus: int = 1,
    memory_mib: int = 256,
    ready_timeout_secs: int = 120,
) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=vm_id,
        backend=Backend.FIRECRACKER,
        kernel_path=FC_KERNEL,
        initrd_path=Path(""),
        disks=[DiskSpec(path=FC_RUNTIME, readonly=True, format=DiskFormat.SQUASHFS, role=DiskRole.ROOTFS)],
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=False,
        guest_channel=GuestChannelSpec(ready_port=52, ready_timeout_secs=ready_timeout_secs),
    )


def make_qemu_rootfs(daemon: Daemon, vm_id: VmId) -> Path:
    """A per-VM qcow2 overlay of the base cloud image (copy-on-write)."""
    assert QEMU_IMAGE is not None
    disks = daemon.root / "disks"
    disks.mkdir(exist_ok=True)
    overlay = disks / f"{vm_id}-rootfs.qcow2"
    info = json.loads(
        subprocess.run(
            ["qemu-img", "info", "--output=json", str(QEMU_IMAGE)],
            check=True,
            capture_output=True,
        ).stdout
    )
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            str(QEMU_IMAGE),
            "-F",
            info["format"],
            str(overlay),
        ],
        check=True,
        capture_output=True,
    )
    return overlay


def qemu_instance_spec(
    vm_id: VmId,
    rootfs: Path,
    *,
    ssh_pubkey: str = "",
    hostname: str = "",
    vcpus: int = 1,
    memory_mib: int = 768,
) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=vm_id,
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[DiskSpec(path=rootfs, readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)],
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
        ssh_authorized_keys=[ssh_pubkey] if ssh_pubkey else [],
        hostname=hostname or f"itest-{vm_id[:12]}",
    )


@pytest.fixture(scope="session")
def ssh_keypair(tmp_path_factory) -> tuple[Path, str]:
    """(private_key_path, public_key_line) for guest SSH access."""
    key_dir = tmp_path_factory.mktemp("avm-itest-ssh")
    key_path = key_dir / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-N", "", "-q", "-f", str(key_path)],
        check=True,
    )
    return key_path, (key_dir / "id_ed25519.pub").read_text().strip()


# ---------------------------------------------------------------------------
# Host-side probes
# ---------------------------------------------------------------------------


async def wait_for_tcp_banner(host: str, port: int, timeout: float = 240.0) -> bytes:
    """Poll until a TCP connect to host:port yields some bytes (e.g. the SSH
    banner); proves guest boot + IP networking end to end."""
    deadline = asyncio.get_event_loop().time() + timeout
    last_error: Exception | None = None
    while asyncio.get_event_loop().time() < deadline:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
            try:
                banner = await asyncio.wait_for(reader.read(64), timeout=10)
                if banner:
                    return banner
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as exc:
            last_error = exc
        await asyncio.sleep(2)
    raise TimeoutError(f"no TCP banner from {host}:{port} after {timeout}s ({last_error})")


async def eventually(predicate, *, timeout: float = 60.0, interval: float = 1.0, message: str = ""):
    """Await a (possibly async) predicate until truthy; returns its value."""
    deadline = asyncio.get_event_loop().time() + timeout
    while True:
        result = predicate()
        if asyncio.iscoroutine(result):
            result = await result
        if result:
            return result
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError(message or f"condition not met after {timeout}s")
        await asyncio.sleep(interval)


def list_tap_interfaces() -> set[str]:
    out = subprocess.run(["ip", "-o", "link", "show"], check=True, capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        name = line.split(": ", 2)[1].split("@", 1)[0]
        if name.startswith(("vmtap", "tap")):
            names.add(name)
    return names


def nftables_ruleset() -> str:
    if not IS_ROOT:
        return ""
    nft = shutil.which("nft") or "/usr/sbin/nft"
    return subprocess.run([nft, "list", "ruleset"], check=True, capture_output=True, text=True).stdout


def vm_processes(vm_id: VmId) -> list[str]:
    """Command lines of live processes that reference this VM id (works for
    QEMU/controller processes, whose command lines carry per-VM paths)."""
    result = subprocess.run(["pgrep", "-a", "-f", str(vm_id)], capture_output=True, text=True)
    return [line for line in result.stdout.splitlines() if line.strip()]


def hypervisor_children(daemon: Daemon) -> list[int]:
    """PIDs of hypervisor processes spawned by the daemon. Unjailed
    Firecracker command lines carry no VM id, so ephemeral VMs are counted
    as daemon children instead."""
    import psutil

    try:
        parent = psutil.Process(daemon.process.pid)
    except psutil.NoSuchProcess:
        return []
    pids = []
    for child in parent.children(recursive=True):
        try:
            if child.name() in ("firecracker", "qemu-system-x86_64"):
                pids.append(child.pid)
        except psutil.NoSuchProcess:
            continue
    return pids


async def delete_quietly(supervisor, vm_id: VmId) -> None:
    """Cleanup helper: delete if still present, swallow supervisor errors so
    a failed assertion does not cascade into the next test."""
    try:
        await supervisor.delete_vm(vm_id)
    except SupervisorError:
        pass


def execution_files(daemon: Daemon, vm_id: VmId) -> list[Path]:
    return sorted(p for p in daemon.exec_root.rglob(f"*{vm_id}*"))


def systemd_unit_active(unit: str) -> bool:
    return subprocess.run(["systemctl", "is-active", "--quiet", unit], check=False).returncode == 0


def ssh_exec(key_path: Path, host: str, command: str, timeout: float = 60) -> subprocess.CompletedProcess:
    """Run *command* in the guest as root (cloud-init adds the test key to
    root because user-data sets disable_root: false)."""
    return subprocess.run(
        [
            "ssh",
            "-i",
            str(key_path),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "BatchMode=yes",
            f"root@{host}",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


async def wait_for_ssh(key_path: Path, host: str, timeout: float = 300) -> None:
    """Until key auth works: sshd answering is earlier than cloud-init having
    installed the authorized key."""
    await eventually(
        lambda: ssh_exec(key_path, host, "true").returncode == 0,
        timeout=timeout,
        interval=5,
        message=f"SSH key auth to {host} never came up",
    )
