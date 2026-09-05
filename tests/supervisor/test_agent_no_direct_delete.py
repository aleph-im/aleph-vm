"""Every agent delete goes through retire_vm.

A call site that reaches supervisor.delete_vm directly has no reason, and a
delete without a reason is how disks leaked (spec S1). retire.py is the one
allowed caller."""

from __future__ import annotations

from pathlib import Path

import pytest

import aleph.vm.agent as agent_package

AGENT_ROOT = Path(agent_package.__file__).parent
ALLOWED = {AGENT_ROOT / "vm" / "retire.py"}


@pytest.mark.parametrize(
    "path",
    sorted(p for p in AGENT_ROOT.rglob("*.py") if p not in ALLOWED and "migrations" not in p.parts),
    ids=lambda p: str(p.relative_to(AGENT_ROOT)),
)
def test_agent_module_never_calls_delete_vm_directly(path):
    source = path.read_text()
    assert ".delete_vm(" not in source, f"{path.relative_to(AGENT_ROOT)} must retire VMs through retire_vm"
