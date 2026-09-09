"""The agent's process-wide storage state does not survive a test.

The two cases below are one test: the first leaks every global the
``clean_agent_state`` fixture is responsible for, the second checks that none
of it arrived. They are deliberately ordered (pytest runs a module's tests in
definition order), which is the only way to pin isolation from inside the
suite it protects.
"""

from __future__ import annotations

from pathlib import Path

import aleph.vm.agent.vm.cache as cache_module
import aleph.vm.agent.vm.reclaimable as reclaimable_module
import aleph.vm.agent.vm.reconciler as reconciler_module
import aleph.vm.storage as storage_module

LEAKED = "f" * 64


def test_agent_state_left_behind_by_a_test():
    cache_module._live_snapshot = frozenset({LEAKED})
    reconciler_module._last_supervisor_hashes = {LEAKED}
    reconciler_module._creating[LEAKED] = 1
    reclaimable_module._reclaimable_cache[None] = (0.0, (), 1234)
    storage_module.reserve_download(Path("/nowhere/leaked.part"), 4096, measured=True)

    assert reconciler_module.is_creating(LEAKED)


def test_the_next_test_starts_from_an_empty_agent():
    assert cache_module._live_snapshot is None
    assert reconciler_module._last_supervisor_hashes == set()
    assert not reconciler_module.is_creating(LEAKED)
    assert reclaimable_module._reclaimable_cache == {}
    assert storage_module.reserved_downloads() == {}
