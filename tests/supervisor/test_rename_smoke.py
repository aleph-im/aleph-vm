"""Smoke test: the renamed module and class exist (Phase 1 P1.1 rename)."""

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_local_supervisor_subclasses_supervisor():
    assert issubclass(LocalSupervisor, Supervisor)
