"""Structural assertions on the spec-only VmExecution surface.

The former message-built program executions (test_create_execution*,
which built an AlephFirecrackerProgram from a PROGRAM message and ran it
through prepare()/create()/start()) have been removed: VmExecution is now
spec-only and AlephFirecrackerProgram is deleted. Spec-path create/prepare
coverage lives in test_supervisor_spec_execution.py.
"""

from aleph.vm.models import VmExecution


def test_vm_execution_has_no_update_watch_api():
    # Update-watching moved to the agent-side UpdateWatcher (design 2026-06-09).
    for gone in ("start_watching_for_updates", "watch_for_updates", "cancel_update"):
        assert not hasattr(VmExecution, gone), f"{gone} should be removed from VmExecution"


def test_vm_execution_has_no_payment_api():
    """Payment tier is agent knowledge (AgentVmRecord), not a hypervisor-object concern."""
    assert not hasattr(VmExecution, "uses_payment_stream")
    assert not hasattr(VmExecution, "uses_payment_credit")
