"""Network and reservation capabilities of the Supervisor ABC (Phase 1 P1.6a/P1.5)."""

import inspect

from aleph.vm.supervisor.abc import NetworkOps, ReservationOps, Supervisor


def test_recreate_network_is_abstract():
    assert "recreate_network" in Supervisor.__abstractmethods__
    assert inspect.iscoroutinefunction(Supervisor.recreate_network)


def test_recreate_network_belongs_to_network_ops():
    assert "recreate_network" in NetworkOps.__abstractmethods__


def test_reserve_resources_is_abstract():
    assert "reserve_resources" in Supervisor.__abstractmethods__
    assert inspect.iscoroutinefunction(Supervisor.reserve_resources)


def test_reserve_resources_belongs_to_reservation_ops():
    assert "reserve_resources" in ReservationOps.__abstractmethods__
