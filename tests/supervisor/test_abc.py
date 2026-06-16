"""Network capability of the Supervisor ABC (Phase 1 P1.6a)."""

import inspect

from aleph.vm.supervisor.abc import NetworkOps, Supervisor


def test_recreate_network_is_abstract():
    assert "recreate_network" in Supervisor.__abstractmethods__
    assert inspect.iscoroutinefunction(Supervisor.recreate_network)


def test_recreate_network_belongs_to_network_ops():
    assert "recreate_network" in NetworkOps.__abstractmethods__
