"""Instances are QEMU-only: VmExecution.hypervisor never resolves to Firecracker
for an instance, even if the message carries hypervisor=firecracker."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from aleph_message.models import InstanceContent
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.models import VmExecution

# The hypervisor property reads is_program (False for an instance) then returns
# QEMU unconditionally. We exercise it on a minimal stub so the test stays free
# of the heavy resource/network fixtures a full VmExecution would require.
_hypervisor = VmExecution.hypervisor.fget
_is_program = VmExecution.is_program.fget


def _instance_execution(hypervisor: HypervisorType | None) -> SimpleNamespace:
    message = MagicMock()
    message.__class__ = InstanceContent  # satisfy isinstance(..., InstanceContent)
    message.environment = SimpleNamespace(hypervisor=hypervisor)
    spec = SimpleNamespace(message=message)
    # Not a CreateVmSpec, so the message branch of the property is taken.
    # is_program is False for an instance (the property reads it as an attribute).
    return SimpleNamespace(spec=spec, is_program=False)


def test_instance_resolves_to_qemu_by_default() -> None:
    execution = _instance_execution(hypervisor=None)
    assert not _is_program(execution)
    assert _hypervisor(execution) == HypervisorType.qemu


def test_instance_with_firecracker_field_still_resolves_to_qemu() -> None:
    """A message that explicitly carries hypervisor=firecracker still resolves to
    QEMU: instances do not run on Firecracker. The create path additionally
    rejects such a message at build_create_vm_spec (see test_supervisor_translate)."""
    execution = _instance_execution(hypervisor=HypervisorType.firecracker)
    assert not _is_program(execution)
    assert _hypervisor(execution) == HypervisorType.qemu
