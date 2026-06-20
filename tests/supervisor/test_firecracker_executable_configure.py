"""Regression test for AlephFirecrackerExecutable.configure().

The persistent-VM config-write path builds a ``Configuration`` and persists it
to ``<vm_hash>-controller.json``. The pydantic model field is ``vm_id: int``
(an on-disk JSON key, read back on supervisor restart); the executable holds the
numeric value as ``self.vm_index``. The keyword passed to ``Configuration`` must
therefore be ``vm_id=self.vm_index``. Passing ``vm_index=`` would be silently
dropped (pydantic v2 ``extra="ignore"``) and raise ``ValidationError`` for the
missing required ``vm_id`` -- crashing every persistent Firecracker VM on the
configure path. This path is otherwise only exercised under root/integration.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.supervisor.controllers.firecracker import executable as executable_module
from aleph.vm.supervisor.controllers.firecracker.executable import (
    AlephFirecrackerExecutable,
)
from aleph.vm.supervisor_interface.configuration import Configuration

_VM_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
_VM_INDEX = 7


def _persistent_executable() -> AlephFirecrackerExecutable:
    """A bare executable carrying only what ``configure()`` reads.

    Built via ``__new__`` to skip the heavyweight ``__init__`` (which spawns a
    real MicroVM); ``configure()`` only touches the attributes set below.
    """
    executable = AlephFirecrackerExecutable.__new__(AlephFirecrackerExecutable)
    executable.persistent = True
    executable.vm_index = _VM_INDEX
    executable.vm_hash = _VM_HASH
    executable._firecracker_config = object()

    fvm = MagicMock()
    fvm.save_configuration_file = AsyncMock(return_value=Path("/tmp/firecracker-config.json"))
    fvm.firecracker_bin_path = Path("/usr/bin/firecracker")
    fvm.use_jailer = False
    fvm.jailer_bin_path = Path("/usr/bin/jailer")
    fvm.init_timeout = 5.0
    executable.fvm = fvm
    return executable


@pytest.mark.asyncio
async def test_configure_persists_vm_index_as_configuration_vm_id(mocker):
    executable = _persistent_executable()
    save_mock = mocker.patch.object(executable_module, "save_controller_configuration")

    # Must not raise pydantic ValidationError on the Configuration build.
    await executable.configure()

    save_mock.assert_called_once()
    saved_vm_hash, configuration = save_mock.call_args.args
    assert saved_vm_hash == _VM_HASH
    assert isinstance(configuration, Configuration)
    # The numeric index lands in Configuration.vm_id (the serialized field).
    assert configuration.vm_id == _VM_INDEX
    assert configuration.vm_hash == _VM_HASH


@pytest.mark.asyncio
async def test_configure_noop_when_not_persistent(mocker):
    executable = _persistent_executable()
    executable.persistent = False
    save_mock = mocker.patch.object(executable_module, "save_controller_configuration")

    await executable.configure()

    save_mock.assert_not_called()
