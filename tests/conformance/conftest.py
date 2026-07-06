"""Shared machinery for the Rust-daemon conformance suite.

Builds the daemon binary once per session and provides a factory fixture
that boots it on a fresh EXECUTION_ROOT and waits for its socket. The
suite is opt-in (ALEPH_VM_CONFORMANCE=1 plus cargo on PATH); the skip
guards live in each test module's pytestmark.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUST_DIR = REPO_ROOT / "rust"
DAEMON_BINARY = RUST_DIR / "target" / "debug" / "aleph-vm-supervisor"


@pytest.fixture(scope="session")
def daemon_binary() -> Path:
    # cwd=RUST_DIR so rustup picks up rust/rust-toolchain.toml; the target
    # directory is reused across runs.
    subprocess.run(["cargo", "build", "--locked"], cwd=RUST_DIR, check=True)
    assert DAEMON_BINARY.exists()
    return DAEMON_BINARY


def _hypervisor_stub_env(execution_root: Path) -> dict[str, str]:
    """Stub FIRECRACKER_PATH/JAILER_PATH/LINUX_PATH files for settings.check().

    The daemon runs the Python `settings.check()` slice at startup since
    increment 3; like Python, it only tests `isfile` on these paths, so
    stub files keep the suite hermetic on runners without /opt/firecracker.
    """
    stub_dir = execution_root / "hypervisor-stubs"
    stub_dir.mkdir(parents=True, exist_ok=True)
    env = {}
    for setting, name in (
        ("ALEPH_VM_FIRECRACKER_PATH", "firecracker"),
        ("ALEPH_VM_JAILER_PATH", "jailer"),
        ("ALEPH_VM_LINUX_PATH", "vmlinux.bin"),
    ):
        stub = stub_dir / name
        stub.write_bytes(b"stub")
        env[setting] = str(stub)
    return env


@contextmanager
def _running_daemon(binary: Path, execution_root: Path, extra_env: dict[str, str] | None = None):
    """Start the daemon on a fresh EXECUTION_ROOT and wait for its socket."""
    # Drop every ALEPH_VM_* variable of the outer test environment (e.g. the
    # ALEPH_VM_EXECUTION_ROOT the Python suite uses) so the daemon sees only
    # the conformance configuration.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("ALEPH_VM_")}
    env["ALEPH_VM_EXECUTION_ROOT"] = str(execution_root)
    env.update(_hypervisor_stub_env(execution_root))
    env.setdefault("RUST_LOG", "info")
    env.update(extra_env or {})

    def is_socket(path: Path) -> bool:
        # A stale regular file may sit at the path until the daemon replaces
        # it; readiness means an actual socket, like the Rust integration
        # test's is_socket() check.
        try:
            return stat.S_ISSOCK(path.stat().st_mode)
        except OSError:
            return False

    socket_path = execution_root / "supervisor.sock"
    process = subprocess.Popen([str(binary)], env=env)
    try:
        deadline = time.monotonic() + 10
        while not is_socket(socket_path):
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
def start_daemon(daemon_binary: Path):
    """Factory: `with start_daemon(root, extra_env) as (process, socket):`."""

    @contextmanager
    def _start(execution_root: Path, extra_env: dict[str, str] | None = None):
        with _running_daemon(daemon_binary, execution_root, extra_env) as started:
            yield started

    return _start


@pytest.fixture
def execution_root():
    """A SHORT execution root instead of pytest's tmp_path: EXECUTION_ROOT
    prefixes qemu's control socket paths and sun_path caps them at 108
    bytes; settings.check() (ported in increment 3) rejects pytest's long
    tmp paths, exactly like the Python daemon would."""
    root = Path(tempfile.mkdtemp(prefix="avm-conf-", dir="/tmp"))
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)
