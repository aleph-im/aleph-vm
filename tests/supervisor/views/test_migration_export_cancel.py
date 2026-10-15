"""The scheduler can call off an export it no longer wants."""

import asyncio
from datetime import datetime, timezone
from http import HTTPStatus
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.migration.jobs import ExportJob, MigrationState, export_jobs
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.conf import settings


@pytest.fixture(autouse=True)
def _clear_export_jobs():
    export_jobs.clear()
    yield
    export_jobs.clear()


@pytest.fixture
def mock_scheduler_auth(mocker):
    mocker.patch(
        "aleph.vm.agent.views.allocation_auth.authenticate_api_request",
        new_callable=AsyncMock,
        return_value=True,
    )


@pytest.fixture
def vm_hash():
    return ItemHash(settings.FAKE_INSTANCE_ID)


async def _client(aiohttp_client, supervisor):
    app = setup_webapp(supervisor=supervisor)
    app["supervisor"] = supervisor
    return await aiohttp_client(app)


def _job(vm_hash, tmp_path, state=MigrationState.EXPORTING):
    staged = tmp_path / "rootfs.qcow2.export.qcow2"
    staged.write_bytes(b"partial")
    return ExportJob(vm_hash=vm_hash, state=state, started_at=datetime.now(timezone.utc), export_paths=[staged])


@pytest.mark.asyncio
async def test_cancel_ends_the_export_and_restarts_the_vm(aiohttp_client, mock_scheduler_auth, vm_hash, tmp_path):
    job = _job(vm_hash, tmp_path)
    job.task = asyncio.create_task(asyncio.Event().wait())
    export_jobs[vm_hash] = job
    supervisor = MagicMock(start_vm=AsyncMock())
    client = await _client(aiohttp_client, supervisor)

    response = await client.post(f"/control/machine/{vm_hash}/migration/export/cancel")

    assert response.status == HTTPStatus.OK
    assert (await response.json())["status"] == "cancelled"
    assert job.task.cancelled()
    assert job.state is MigrationState.EXPORT_FAILED
    assert not job.export_paths[0].exists()
    assert vm_hash not in export_jobs
    supervisor.start_vm.assert_awaited_once_with(vm_hash)


@pytest.mark.asyncio
async def test_cancel_without_a_job_is_404(aiohttp_client, mock_scheduler_auth, vm_hash):
    client = await _client(aiohttp_client, MagicMock(start_vm=AsyncMock()))

    response = await client.post(f"/control/machine/{vm_hash}/migration/export/cancel")

    assert response.status == HTTPStatus.NOT_FOUND


@pytest.mark.asyncio
async def test_cancel_refuses_during_a_download(aiohttp_client, mock_scheduler_auth, vm_hash, tmp_path):
    """The destination is pulling a disk: pulling the file and restarting the
    source under it would hand the destination a torn image."""
    job = _job(vm_hash, tmp_path, state=MigrationState.EXPORTED)
    job.active_downloads = 1
    export_jobs[vm_hash] = job
    supervisor = MagicMock(start_vm=AsyncMock())
    client = await _client(aiohttp_client, supervisor)

    response = await client.post(f"/control/machine/{vm_hash}/migration/export/cancel")

    assert response.status == HTTPStatus.CONFLICT
    assert job.export_paths[0].exists()
    assert vm_hash in export_jobs
    supervisor.start_vm.assert_not_awaited()
