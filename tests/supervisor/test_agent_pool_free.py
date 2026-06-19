"""Capstone guard: the agent never touches the VmPool.

Every agent endpoint reaches VMs through the Supervisor interface only. The
legacy create_a_vm pool bridge is gone, so the agent is provably pool-free: this
reads the source of the agent's view/run/resources modules and asserts none of
them reference the raw pool in any form - the require_vm_pool helper, the
app["vm_pool"] / request.app["vm_pool"] keys, the pool's .executions attribute,
the create_a_vm create path, the run-side _engine_pool helper, the embedded
supervisor.pool, or a direct `from aleph.vm.pool import`. The supervisor's
embedded engine and the process-lifecycle wiring (daemon, CLI, startup/shutdown
hooks) legitimately keep the pool and are out of scope here.
"""

from __future__ import annotations

import inspect

import pytest

import aleph.vm.agent.views as views_init
from aleph.vm.agent import resources, run
from aleph.vm.agent.views import migration, operator

_FORBIDDEN = (
    "require_vm_pool",
    'app["vm_pool"]',
    'request.app["vm_pool"]',
    ".executions",
    "create_a_vm",
    "_engine_pool",
    "supervisor.pool",
    "from aleph.vm.pool import",
)

_MODULES = [views_init, operator, migration, resources, run]


@pytest.mark.parametrize("module", _MODULES, ids=lambda m: m.__name__)
def test_agent_module_is_pool_free(module):
    source = inspect.getsource(module)
    for token in _FORBIDDEN:
        assert token not in source, f"{module.__name__} must not reference {token!r}"
