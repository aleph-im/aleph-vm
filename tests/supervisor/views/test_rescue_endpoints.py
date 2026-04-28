"""Tests for rescue mode HTTP endpoints (POST/GET/DELETE /control/machine/{ref}/rescue)."""

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.orchestrator.views.operator import RescueState, _security_aggregate_cache

MOCK_ADDRESS = "mock_address"
MOCK_HASH = "fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_fake_vm_"


@pytest.fixture(autouse=True)
def _clear_caches():
    _security_aggregate_cache.clear()
    yield
    _security_aggregate_cache.clear()


def _make_execution(mocker, *, mode="normal", persistent=True, resources=True, is_running=True):
    resources_mock = mocker.Mock() if resources else None
    if resources_mock:
        resources_mock.rootfs_path = "/var/lib/aleph/vm/volumes/persistent/fake/rootfs.qcow2"
    return mocker.Mock(
        vm_hash=MOCK_HASH,
        message=mocker.Mock(address=MOCK_ADDRESS),
        mode=mode,
        persistent=persistent,
        resources=resources_mock,
        is_running=is_running,
        vm=mocker.Mock(),
    )


def _make_pool(mocker, execution):
    pool = mocker.AsyncMock()
    pool.executions = {MOCK_HASH: execution}
    pool.network = None
    pool.systemd_manager = mocker.Mock()
    return pool


async def _setup_client(aiohttp_client, mocker, pool):
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=MOCK_ADDRESS,
    )
    app = setup_webapp(pool=pool)
    return await aiohttp_client(app), app


# ---- POST /control/machine/{ref}/rescue ----


@pytest.mark.asyncio
async def test_rescue_enter_already_in_rescue_mode(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 409
    body = await response.json()
    assert "already in rescue mode" in body["error"].lower()


@pytest.mark.asyncio
async def test_rescue_enter_not_persistent(aiohttp_client, mocker):
    execution = _make_execution(mocker, persistent=False)
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 400


@pytest.mark.asyncio
async def test_rescue_enter_no_resources(aiohttp_client, mocker):
    execution = _make_execution(mocker, resources=False)
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 400


@pytest.mark.asyncio
async def test_rescue_enter_task_already_in_progress(aiohttp_client, mocker):
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    app["rescue_state"].tasks[MOCK_HASH] = MagicMock()

    response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 202
    body = await response.json()
    assert body["status"] == "in_progress"


@pytest.mark.asyncio
async def test_rescue_enter_no_aggregate_runtime(aiohttp_client, mocker):
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    with patch(
        "aleph.vm.orchestrator.views.operator.get_default_runtime",
        new=AsyncMock(return_value=None),
    ):
        response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")

    assert response.status == 503


@pytest.mark.asyncio
async def test_rescue_enter_schedules_background_task(aiohttp_client, mocker):
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    mock_runtime = {"id": "debian-12-rescue", "item_hash": "ddd444", "sha256": None}
    with (
        patch(
            "aleph.vm.orchestrator.views.operator.get_default_runtime",
            new=AsyncMock(return_value=mock_runtime),
        ),
        patch("aleph.vm.orchestrator.views.operator.asyncio.create_task") as mock_create_task,
    ):
        mock_create_task.return_value = MagicMock()
        response = await client.post(f"/control/machine/{MOCK_HASH}/rescue")

    assert response.status == 202
    body = await response.json()
    assert body["status"] == "in_progress"
    assert mock_create_task.called


@pytest.mark.asyncio
async def test_rescue_enter_with_custom_item_hash(aiohttp_client, mocker):
    """User-provided item_hash bypasses aggregate lookup and skips SHA256 verification."""
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    mock_get_default = AsyncMock()
    with (
        patch(
            "aleph.vm.orchestrator.views.operator.asyncio.create_task",
            return_value=MagicMock(),
        ),
        patch(
            "aleph.vm.orchestrator.views.operator.get_default_runtime",
            new=mock_get_default,
        ),
    ):
        response = await client.post(
            f"/control/machine/{MOCK_HASH}/rescue",
            params={"item_hash": "custom_rescue_hash_abc123"},
        )

    assert response.status == 202
    # aggregate lookup must NOT be called when item_hash is provided
    mock_get_default.assert_not_called()


# ---- GET /control/machine/{ref}/rescue ----


@pytest.mark.asyncio
async def test_rescue_status_task_in_progress(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    app["rescue_state"].tasks[MOCK_HASH] = MagicMock()

    response = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 202
    body = await response.json()
    assert body["status"] == "in_progress"


@pytest.mark.asyncio
async def test_rescue_status_success_result(aiohttp_client, mocker):
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    from aleph.vm.orchestrator.views.operator import _RESCUE_ACTIVE_RESPONSE

    app["rescue_state"].results[MOCK_HASH] = (time.time(), _RESCUE_ACTIVE_RESPONSE)

    response = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 200
    body = await response.json()
    assert body["status"] == "rescue"


@pytest.mark.asyncio
async def test_rescue_status_failure_result(aiohttp_client, mocker):
    execution = _make_execution(mocker)
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    app["rescue_state"].results[MOCK_HASH] = (time.time(), ValueError("download failed"))

    response = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 500


@pytest.mark.asyncio
async def test_rescue_status_mode_rescue_no_task(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 200
    body = await response.json()
    assert body["status"] == "rescue"


@pytest.mark.asyncio
async def test_rescue_status_no_operation(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="normal")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 409


@pytest.mark.asyncio
async def test_rescue_status_result_and_mode_match(aiohttp_client, mocker):
    """Both the cached result and the mode fallback return the same body."""
    from aleph.vm.orchestrator.views.operator import _RESCUE_ACTIVE_RESPONSE

    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)

    # First request: result from cache
    client, app = await _setup_client(aiohttp_client, mocker, pool)
    app["rescue_state"].results[MOCK_HASH] = (time.time(), _RESCUE_ACTIVE_RESPONSE)
    response1 = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    body1 = await response1.json()

    # Second request: falls through to mode check
    response2 = await client.get(f"/control/machine/{MOCK_HASH}/rescue")
    body2 = await response2.json()

    assert body1 == body2


# ---- DELETE /control/machine/{ref}/rescue ----


@pytest.mark.asyncio
async def test_rescue_exit_not_in_rescue_mode(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="normal")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.delete(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 409
    body = await response.json()
    assert "not in rescue mode" in body["error"].lower()


@pytest.mark.asyncio
async def test_rescue_exit_task_in_progress(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, app = await _setup_client(aiohttp_client, mocker, pool)

    app["rescue_state"].tasks[MOCK_HASH] = MagicMock()

    response = await client.delete(f"/control/machine/{MOCK_HASH}/rescue")
    assert response.status == 202
    body = await response.json()
    assert body["status"] == "in_progress"


@pytest.mark.asyncio
async def test_rescue_exit_success(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    with patch(
        "aleph.vm.orchestrator.views.operator._restart_persistent_vm",
        new=AsyncMock(),
    ):
        response = await client.delete(f"/control/machine/{MOCK_HASH}/rescue")

    assert response.status == 200
    body = await response.json()
    assert body["status"] == "normal"
    assert execution.mode == "normal"


# ---- Guards: erase and reinstall blocked in rescue mode ----


@pytest.mark.asyncio
async def test_erase_blocked_in_rescue_mode(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.post(f"/control/machine/{MOCK_HASH}/erase")
    assert response.status == 409
    body = await response.json()
    assert "rescue" in body["error"].lower()


@pytest.mark.asyncio
async def test_reinstall_blocked_in_rescue_mode(aiohttp_client, mocker):
    execution = _make_execution(mocker, mode="rescue")
    pool = _make_pool(mocker, execution)
    client, _ = await _setup_client(aiohttp_client, mocker, pool)

    response = await client.post(f"/control/machine/{MOCK_HASH}/reinstall")
    assert response.status == 409
    body = await response.json()
    assert "rescue" in body["error"].lower()
