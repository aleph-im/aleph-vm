"""Unit tests for the export-stop step of P2P migration on LocalSupervisor.

Migration rides the standard lifecycle RPCs (create_vm / start_vm / delete_vm);
the one step that cannot is the export-time stop, which needs a guest powerdown
(not the systemd teardown stop_vm performs) so the exported overlay is
consistent on the destination. That is the only surviving MigrationOps method.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.conf import settings
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor.types import VmId

_VM_ID = VmId("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


@pytest.mark.asyncio
async def test_stop_vm_for_export_stops_and_returns_volumes_dir(mocker, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    graceful = mocker.patch("aleph.vm.supervisor.local.graceful_shutdown", AsyncMock())

    execution = MagicMock()
    pool = MagicMock(executions={_VM_ID: execution})
    sup = LocalSupervisor(pool)

    volumes_dir = await sup.stop_vm_for_export(_VM_ID)

    graceful.assert_awaited_once_with(execution)
    assert Path(volumes_dir) == tmp_path / str(_VM_ID)


@pytest.mark.asyncio
async def test_stop_vm_for_export_missing_vm_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    sup = LocalSupervisor(MagicMock(executions={}))
    with pytest.raises(VmNotFoundError):
        await sup.stop_vm_for_export(_VM_ID)
