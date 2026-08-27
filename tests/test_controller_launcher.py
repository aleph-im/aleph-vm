"""Dispatch tests for packaging/controller-launcher.

The launcher is the exact artifact that flips the production cutover, and it
is on the critical path for the DEFAULT (rust) install too (the systemd unit
execs the launcher, not the binary directly). These tests EXEC the real script
(not a reimplementation) so a dispatch regression cannot ship green.

The launcher hardcodes /opt/aleph-vm paths in production. To exercise it
without an install, the script exposes a minimal, production-safe seam: the
target paths default to the production paths but are overridable via
ALEPH_VM_CONTROLLER_BIN / ALEPH_VM_CONTROLLER_PYTHON. The tests point those at
marker scripts that record their argv, then assert the right target fired and
that the --config argument was forwarded through "$@".

Runs in the normal (non-KVM) unit-test job, so the dispatch is always
exercised (the integration harness only mirrors it).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = REPO_ROOT / "packaging" / "controller-launcher"

# The four operator-visible cases the case-statement must cover, and the
# target each one selects. "rust" is both the explicit value and the default
# for "unset" and any unknown value (an operator typo must not brick the
# node): the Python controller only ever runs when asked for by name.
_CASES = [
    pytest.param("rust", "rust", id="rust->rust"),
    pytest.param("python", "python", id="python->python"),
    pytest.param(None, "rust", id="unset->rust"),
    pytest.param("bogus", "rust", id="bogus->rust"),
]


def _make_marker(path: Path, name: str) -> None:
    """A marker script that appends '<name>\\t<argv>' to $LAUNCHER_TEST_LOG."""
    path.write_text(f'#!/bin/sh\nprintf "%s\\t%s\\n" "{name}" "$*" >> "$LAUNCHER_TEST_LOG"\n')
    path.chmod(0o755)


@pytest.mark.parametrize(("impl", "expected"), _CASES)
def test_controller_launcher_dispatch(tmp_path, impl, expected):
    rust_marker = tmp_path / "rust-controller"
    python_marker = tmp_path / "python-controller"
    _make_marker(rust_marker, "rust")
    _make_marker(python_marker, "python")
    log = tmp_path / "dispatch.log"

    env = {
        "PATH": "/usr/bin:/bin",
        "LAUNCHER_TEST_LOG": str(log),
        # Point both targets at markers so no /opt/aleph-vm install is needed.
        "ALEPH_VM_CONTROLLER_BIN": str(rust_marker),
        "ALEPH_VM_CONTROLLER_PYTHON": str(python_marker),
    }
    if impl is not None:
        env["ALEPH_VM_SUPERVISOR_IMPL"] = impl

    # Invoke via /bin/sh so the test does not depend on the checkout's exec bit.
    result = subprocess.run(
        ["/bin/sh", str(LAUNCHER), "--config=/some/path"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"launcher exited {result.returncode}: {result.stderr}"

    recorded = log.read_text().splitlines()
    assert len(recorded) == 1, f"exactly one target must fire, got: {recorded}"
    fired, argv = recorded[0].split("\t", 1)
    assert fired == expected, f"impl={impl!r} selected {fired!r}, expected {expected!r}"
    # "$@" (the --config argument) must be forwarded unchanged to the target.
    assert "--config=/some/path" in argv, f"config not forwarded to {fired}: {argv!r}"
    # The python branch forwards through `-m aleph.vm.supervisor.controllers`.
    if expected == "python":
        assert "-m aleph.vm.supervisor.controllers" in argv, argv


def test_controller_launcher_production_defaults_unchanged():
    """The seam must keep the production target paths byte-identical: with the
    override vars unset, the exec lines are exactly what shipped before it."""
    text = LAUNCHER.read_text()
    assert "${ALEPH_VM_CONTROLLER_BIN:=/opt/aleph-vm/bin/aleph-vm-controller}" in text
    assert "${ALEPH_VM_CONTROLLER_PYTHON:=/usr/bin/python3}" in text
    assert 'exec "$ALEPH_VM_CONTROLLER_BIN" "$@"' in text
    assert 'exec "$ALEPH_VM_CONTROLLER_PYTHON" -m aleph.vm.supervisor.controllers "$@"' in text
