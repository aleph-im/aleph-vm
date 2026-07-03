"""Developer and CI harnesses that wire BOTH sides of the agent/supervisor
boundary in a single process.

Nothing in ``aleph.vm.agent`` or ``aleph.vm.supervisor`` may import this
package at module scope except as a composition root: ``aleph.vm.agent.cli``
loads :mod:`aleph.vm.testing.harness` lazily, only when one of the
``--benchmark`` / ``--run-test-instance`` / ``--run-fake-instance`` flags is
given. The production agent never builds a pool or a ``LocalSupervisor``.
"""
