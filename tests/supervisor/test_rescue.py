"""Tests for rescue mode, execution events, and runtimes aggregate."""

import json
from unittest import mock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aleph.vm.orchestrator.metrics import (
    Base,
    ExecutionEvent,
    get_execution_events,
    record_event,
)
from aleph.vm.orchestrator.utils import (
    get_default_runtime,
    get_runtime_by_id,
    get_runtimes,
)

# ---- Fixtures ----


SAMPLE_RUNTIMES = [
    {
        "id": "debian-12-fc",
        "name": "Debian 12 (Firecracker)",
        "type": "program",
        "item_hash": "aaa111",
        "default": True,
    },
    {
        "id": "debian-12-qemu",
        "name": "Debian 12",
        "type": "instance",
        "item_hash": "bbb222",
        "default": True,
    },
    {
        "id": "ubuntu-24-qemu",
        "name": "Ubuntu 24.04",
        "type": "instance",
        "item_hash": "ccc333",
        "default": False,
    },
    {
        "id": "debian-12-rescue",
        "name": "Debian 12 (Rescue)",
        "type": "rescue",
        "item_hash": "ddd444",
        "default": True,
    },
    {
        "id": "ubuntu-24-rescue",
        "name": "Ubuntu 24.04 (Rescue)",
        "type": "rescue",
        "item_hash": "eee555",
        "default": False,
    },
    {
        "id": "ovmf-sev",
        "name": "OVMF SEV Firmware",
        "type": "firmware",
        "item_hash": "fff666",
        "firmware_hash": "ggg777",
        "default": True,
    },
]


@pytest_asyncio.fixture
async def async_session():
    """Create an in-memory SQLite DB with all tables."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    yield session_factory
    await engine.dispose()


@pytest_asyncio.fixture
async def _patch_session_maker(async_session, monkeypatch):
    """Redirect AsyncSessionMaker in metrics module to the in-memory DB."""
    import aleph.vm.orchestrator.metrics as metrics_mod

    monkeypatch.setattr(metrics_mod, "AsyncSessionMaker", async_session)


# ---- Execution events tests ----


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_record_and_retrieve_events():
    vm_hash = "abc123"
    await record_event(vm_hash, "created")
    await record_event(vm_hash, "started")
    await record_event(vm_hash, "stopped")

    events = await get_execution_events(vm_hash)
    assert len(events) == 3
    assert [e.event_type for e in events] == ["created", "started", "stopped"]
    assert all(e.vm_hash == vm_hash for e in events)
    assert all(e.timestamp is not None for e in events)


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_record_event_with_detail():
    vm_hash = "def456"
    detail = json.dumps({"runtime_id": "debian-12-rescue", "image_hash": "ddd444"})
    await record_event(vm_hash, "rescue_entered", detail=detail)

    events = await get_execution_events(vm_hash)
    assert len(events) == 1
    assert events[0].event_type == "rescue_entered"
    parsed = json.loads(events[0].detail_json)
    assert parsed["runtime_id"] == "debian-12-rescue"
    assert parsed["image_hash"] == "ddd444"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_events_isolated_by_vm_hash():
    await record_event("vm-a", "created")
    await record_event("vm-b", "created")
    await record_event("vm-a", "started")

    events_a = await get_execution_events("vm-a")
    events_b = await get_execution_events("vm-b")
    assert len(events_a) == 2
    assert len(events_b) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_events_ordered_by_timestamp():
    vm_hash = "ordered"
    await record_event(vm_hash, "created")
    await record_event(vm_hash, "started")
    await record_event(vm_hash, "rescue_entered")
    await record_event(vm_hash, "rescue_exited")
    await record_event(vm_hash, "stopped")

    events = await get_execution_events(vm_hash)
    types = [e.event_type for e in events]
    assert types == ["created", "started", "rescue_entered", "rescue_exited", "stopped"]
    timestamps = [e.timestamp for e in events]
    assert timestamps == sorted(timestamps)


# ---- Runtimes aggregate tests ----


@pytest.mark.asyncio
async def test_get_default_runtime_program(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_default_runtime("program")
    assert result is not None
    assert result["id"] == "debian-12-fc"
    assert result["default"] is True


@pytest.mark.asyncio
async def test_get_default_runtime_rescue(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_default_runtime("rescue")
    assert result is not None
    assert result["id"] == "debian-12-rescue"
    assert result["item_hash"] == "ddd444"


@pytest.mark.asyncio
async def test_get_default_runtime_instance(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_default_runtime("instance")
    assert result is not None
    assert result["id"] == "debian-12-qemu"


@pytest.mark.asyncio
async def test_get_default_runtime_firmware(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_default_runtime("firmware")
    assert result is not None
    assert result["id"] == "ovmf-sev"
    assert result["firmware_hash"] == "ggg777"


@pytest.mark.asyncio
async def test_get_runtime_by_id(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_runtime_by_id("ubuntu-24-rescue")
    assert result is not None
    assert result["name"] == "Ubuntu 24.04 (Rescue)"
    assert result["item_hash"] == "eee555"
    assert result["default"] is False


@pytest.mark.asyncio
async def test_get_runtime_by_id_not_found(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_runtime_by_id("nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_get_default_runtime_missing_type(monkeypatch):
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: SAMPLE_RUNTIMES))

    result = await get_default_runtime("nonexistent_type")
    assert result is None


@pytest.mark.asyncio
async def test_get_default_runtime_fallback_to_first(monkeypatch):
    """When no entry is marked default, fall back to the first of that type."""
    import aleph.vm.orchestrator.utils as utils_mod

    runtimes_no_default = [
        {"id": "r1", "name": "Rescue 1", "type": "rescue", "item_hash": "h1", "default": False},
        {"id": "r2", "name": "Rescue 2", "type": "rescue", "item_hash": "h2", "default": False},
    ]
    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: runtimes_no_default))

    result = await get_default_runtime("rescue")
    assert result is not None
    assert result["id"] == "r1"


@pytest.mark.asyncio
async def test_get_runtimes_returns_empty_on_fetch_failure(monkeypatch):
    """When the aggregate fetch fails, get_runtimes returns an empty list."""
    import aleph.vm.orchestrator.utils as utils_mod

    monkeypatch.setattr(utils_mod, "_runtimes_cache", mock.MagicMock(get=lambda _: None))
    monkeypatch.setattr(utils_mod, "fetch_runtimes_aggregate", mock.AsyncMock(side_effect=Exception("network error")))

    result = await get_runtimes()
    assert result == []


# ---- Rescue mode state tests ----


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_execution_record_mode_default(async_session):
    """New ExecutionRecord defaults to mode='normal'."""
    from aleph.vm.orchestrator.metrics import ExecutionRecord, save_record

    record = ExecutionRecord(
        uuid="test-uuid-1",
        vm_hash="vm-hash-1",
        vm_id=1,
        time_defined="2026-01-01T00:00:00Z",
        vcpus=2,
        memory=2048,
    )
    await save_record(record)

    from aleph.vm.orchestrator.metrics import get_last_record_for_vm

    loaded = await get_last_record_for_vm("vm-hash-1")
    assert loaded is not None
    assert loaded.mode == "normal"


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_execution_record_mode_rescue(async_session):
    """ExecutionRecord persists mode='rescue'."""
    from aleph.vm.orchestrator.metrics import ExecutionRecord, save_record

    record = ExecutionRecord(
        uuid="test-uuid-2",
        vm_hash="vm-hash-2",
        vm_id=2,
        time_defined="2026-01-01T00:00:00Z",
        vcpus=2,
        memory=2048,
        mode="rescue",
    )
    await save_record(record)

    from aleph.vm.orchestrator.metrics import get_last_record_for_vm

    loaded = await get_last_record_for_vm("vm-hash-2")
    assert loaded is not None
    assert loaded.mode == "rescue"
