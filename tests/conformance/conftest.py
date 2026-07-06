"""Shared machinery for the Rust-daemon conformance suite.

Builds the daemon binary once per session and provides a factory fixture
that boots it on a fresh EXECUTION_ROOT and waits for its socket. The
suite is opt-in (ALEPH_VM_CONFORMANCE=1 plus cargo on PATH); the skip
guards live in each test module's pytestmark.
"""

from __future__ import annotations

import os
import stat
import subprocess
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


@contextmanager
def _running_daemon(binary: Path, execution_root: Path, extra_env: dict[str, str] | None = None):
    """Start the daemon on a fresh EXECUTION_ROOT and wait for its socket."""
    # Drop every ALEPH_VM_* variable of the outer test environment (e.g. the
    # ALEPH_VM_EXECUTION_ROOT the Python suite uses) so the daemon sees only
    # the conformance configuration.
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith("ALEPH_VM_")}
    env["ALEPH_VM_EXECUTION_ROOT"] = str(execution_root)
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
