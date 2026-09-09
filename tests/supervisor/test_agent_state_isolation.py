"""The agent's process-wide storage state does not survive a test.

Every global the ``clean_agent_state`` fixture is responsible for is leaked
here on purpose, then the fixture's own reset is called, then the emptiness it
promises is asserted. One test rather than a leaking one followed by a checking
one: that pair only held while pytest ran the module in definition order, and
went silently green under any plugin that shuffles tests.
"""

from __future__ import annotations

from pathlib import Path

from conftest import reset_agent_state

import aleph.vm.agent.vm.cache as cache_module
import aleph.vm.agent.vm.reclaimable as reclaimable_module
import aleph.vm.agent.vm.reconciler as reconciler_module
import aleph.vm.storage as storage_module
from aleph.vm.hooks import AgentHooks, current_hooks, install_hooks

LEAKED = "f" * 64


def test_the_reset_empties_everything_a_test_can_leak():
    cache_module._live_snapshot = frozenset({LEAKED})
    reconciler_module._last_supervisor_hashes = {LEAKED}
    reconciler_module._creating[LEAKED] = reconciler_module._CreateState(creates=1)
    reclaimable_module._reclaimable_cache[None] = (0.0, (), 1234)
    storage_module.reserve_download(Path("/nowhere/leaked.part"), 4096, measured=True)
    install_hooks(AgentHooks(room_maker=lambda pool, needed: 0))
    assert reconciler_module.is_creating(LEAKED)

    reset_agent_state()

    assert cache_module._live_snapshot is None
    assert reconciler_module._last_supervisor_hashes == set()
    assert not reconciler_module.is_creating(LEAKED)
    assert reclaimable_module._reclaimable_cache == {}
    assert storage_module.reserved_downloads() == {}
    assert current_hooks() == AgentHooks()
