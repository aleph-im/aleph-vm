"""Capstone guard: the agent never touches the VmPool.

After P1.7, every agent endpoint reaches VMs through the Supervisor interface
only. This reads the source of the agent's view/run modules and asserts none of
them reference the raw pool (require_vm_pool, the app["vm_pool"] key, or the
pool's .executions attribute). The supervisor's embedded engine and the
process-lifecycle wiring (daemon, CLI, startup/shutdown hooks) legitimately keep
the pool and are out of scope here.
"""

from __future__ import annotations

import inspect

import pytest

import aleph.vm.orchestrator.views as views_init
from aleph.vm.orchestrator import resources, run
from aleph.vm.orchestrator.views import migration, operator

_FORBIDDEN = ('require_vm_pool', 'request.app["vm_pool"]', 'app["vm_pool"]', ".executions")

_MODULES = [views_init, operator, migration, resources, run]


@pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__)
def test_agent_module_is_pool_free(module):
    source = inspect.getsource(module)
    for token in _FORBIDDEN:
        assert token not in source, f"{module.__name__} must not reference {token!r}"
