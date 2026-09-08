"""Migration cleanup retires the migrated-away source as GONE.

Split out of the old ``tests/supervisor/views/test_migration.py``, which was
removed with the Python supervisor daemon: this case only ever needed a
``Supervisor``, so it drives ``setup_webapp`` with a mock of that interface.
"""

from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp.test_utils import TestClient
from aleph_message.models import ItemHash

from aleph.vm.agent.migration.jobs import MigrationState
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmNotFoundError


def _migration_supervisor(get_vm=None, **overrides):
    """A MagicMock supervisor wired with the migration-relevant methods.

    get_vm defaults to raising VmNotFoundError (no VM present); pass an
    AsyncMock to model a present VM. Override any method via keyword.
    """
    sup = MagicMock()
    sup.get_vm = get_vm if get_vm is not None else AsyncMock(side_effect=VmNotFoundError("absent"))
    sup.stop_vm = AsyncMock()
    sup.start_vm = AsyncMock()
    sup.create_vm = AsyncMock(return_value=MagicMock())
    sup.delete_vm = AsyncMock()
    for name, value in overrides.items():
        setattr(sup, name, value)
    return sup


@pytest.fixture(autouse=True)
def _clear_migration_registries():
    from aleph.vm.agent.migration.jobs import export_jobs, import_jobs

    export_jobs.clear()
    import_jobs.clear()
    yield
    export_jobs.clear()
    import_jobs.clear()


@pytest.fixture
def mock_scheduler_auth(mocker):
    """Mock the scheduler authentication to always pass.

    The migration handlers wrap themselves with @requires_allocation_auth, which
    looks up authenticate_api_request in its own module
    (aleph.vm.agent.views.allocation_auth) - patch there.
    """
    mocker.patch(
        "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
        new_callable=AsyncMock,
        return_value=True,
    )


@pytest.fixture
def mock_vm_hash():
    """Return a valid VM hash for testing."""
    return ItemHash(settings.FAKE_INSTANCE_ID)


@pytest.mark.asyncio
async def test_cleanup_success(aiohttp_client, mocker, mock_scheduler_auth, mock_vm_hash):
    """Test successful cleanup when an EXPORTED job is present."""
    from datetime import datetime, timezone

    from aleph.vm.agent.migration.jobs import ExportJob, export_jobs
    from aleph.vm.agent.vm.retire import RetireReason

    export_jobs[mock_vm_hash] = ExportJob(
        vm_hash=mock_vm_hash,
        state=MigrationState.EXPORTED,
        started_at=datetime.now(timezone.utc),
    )

    supervisor = _migration_supervisor()
    app = setup_webapp(supervisor=supervisor)
    app["supervisor"] = supervisor
    retire = mocker.patch("aleph.vm.agent.views.migration.retire_vm", new_callable=AsyncMock)
    client: TestClient = await aiohttp_client(app)

    response = await client.post(f"/control/machine/{mock_vm_hash}/migration/cleanup")

    assert response.status == HTTPStatus.OK
    data = await response.json()
    assert data["status"] == "completed"
    # Cleanup retires the migrated-away source as GONE: the destination
    # owns the data now, so under VOLUME_RETENTION=reap the disks go.
    retire.assert_awaited_once()
    args, kwargs = retire.await_args
    assert args[0] == mock_vm_hash
    assert args[1] is RetireReason.GONE
    assert kwargs["supervisor"] is supervisor
