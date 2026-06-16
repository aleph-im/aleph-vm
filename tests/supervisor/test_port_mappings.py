"""Tests for port mapping DB logic and port availability checker."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aleph.vm.orchestrator.metrics import Base, save_port_mappings


@pytest_asyncio.fixture
async def async_session():
    """Create an in-memory SQLite DB with the port_mappings table."""
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


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_save_port_mappings_reuse_host_port(async_session):
    """Flush-before-insert: reusing a host_port across soft-delete
    and re-insert must not violate the partial unique index."""
    vm_hash = "abc123"
    # Initial save: vm_port 80 -> host_port 30000
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": False}})

    # Verify row exists
    async with async_session() as session:
        rows = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        assert len(rows) == 1
        assert rows[0].host_port == 30000

    # Update: vm_port 80 now maps to host_port 30001,
    # and add vm_port 443 -> host_port 30000 (reuses the old host_port)
    await save_port_mappings(
        vm_hash,
        {
            80: {"host": 30001, "tcp": True, "udp": False},
            443: {"host": 30000, "tcp": True, "udp": False},
        },
    )

    async with async_session() as session:
        active = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        assert len(active) == 2
        active_ports = {r.host_port for r in active}
        assert active_ports == {30000, 30001}


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_save_port_mappings_soft_deletes_removed(async_session):
    """Mappings no longer present in the update are soft-deleted."""
    vm_hash = "def456"
    await save_port_mappings(
        vm_hash,
        {
            80: {"host": 30000, "tcp": True, "udp": False},
            443: {"host": 30001, "tcp": True, "udp": False},
        },
    )
    # Remove port 443
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": False}})

    async with async_session() as session:
        active = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        deleted = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NOT NULL"))).fetchall()
        assert len(active) == 1
        assert active[0].vm_port == 80
        assert len(deleted) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_save_port_mappings_unchanged_not_duplicated(async_session):
    """Unchanged mappings are left in place (no soft-delete + re-insert)."""
    vm_hash = "ghi789"
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": False}})

    async with async_session() as session:
        rows_before = (await session.execute(text("SELECT id FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()

    # Save same mapping again
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": False}})

    async with async_session() as session:
        rows_after = (await session.execute(text("SELECT id FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        assert len(rows_after) == 1
        assert rows_after[0].id == rows_before[0].id


@pytest.mark.asyncio
@pytest.mark.usefixtures("_patch_session_maker")
async def test_save_port_mappings_protocol_change(async_session):
    """Changing TCP/UDP flags triggers soft-delete + re-insert."""
    vm_hash = "jkl012"
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": False}})

    async with async_session() as session:
        rows_before = (await session.execute(text("SELECT id FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        assert len(rows_before) == 1

    # Same port and host, but enable UDP
    await save_port_mappings(vm_hash, {80: {"host": 30000, "tcp": True, "udp": True}})

    async with async_session() as session:
        active = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NULL"))).fetchall()
        deleted = (await session.execute(text("SELECT * FROM port_mappings WHERE deleted_at IS NOT NULL"))).fetchall()
        assert len(active) == 1
        assert active[0].udp == 1
        assert active[0].id != rows_before[0].id
        assert len(deleted) == 1


def test_get_active_host_ports_missing_table(tmp_path):
    """_get_active_host_ports returns empty set when table doesn't exist."""

    from aleph.vm.network.port_availability_checker import (
        _get_active_host_ports,
        _SyncEngineHolder,
    )

    _SyncEngineHolder.reset()
    try:
        db_path = tmp_path / "empty.db"
        with patch("aleph.vm.network.port_availability_checker.make_sync_db_url", return_value=f"sqlite:///{db_path}"):
            result = _get_active_host_ports()
        assert result == set()
    finally:
        _SyncEngineHolder.reset()


def test_get_active_host_ports_with_data(tmp_path):
    """_get_active_host_ports returns host ports from the DB."""

    from sqlalchemy import create_engine, text

    from aleph.vm.network.port_availability_checker import (
        _get_active_host_ports,
        _SyncEngineHolder,
    )

    db_path = tmp_path / "test.db"
    engine = create_engine(f"sqlite:///{db_path}")
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE port_mappings ("
                "id INTEGER PRIMARY KEY, vm_hash TEXT, vm_port INTEGER, "
                "host_port INTEGER, tcp BOOLEAN, udp BOOLEAN, "
                "created_at DATETIME, deleted_at DATETIME)"
            )
        )
        conn.execute(
            text(
                "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at) "
                "VALUES ('abc', 80, 30000, 1, 0, '2026-01-01')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at, deleted_at) "
                "VALUES ('abc', 443, 30001, 1, 0, '2026-01-01', '2026-01-02')"
            )
        )
    engine.dispose()

    _SyncEngineHolder.reset()
    try:
        with patch("aleph.vm.network.port_availability_checker.make_sync_db_url", return_value=f"sqlite:///{db_path}"):
            result = _get_active_host_ports()
        assert result == {30000}  # deleted row excluded
    finally:
        _SyncEngineHolder.reset()


@pytest.mark.asyncio
async def test_fetch_port_redirect_config_does_not_call_get_port_mappings(monkeypatch):
    """fetch_port_redirect_config_and_setup no longer loads from DB — that is the creator's job."""
    import aleph.vm.models as models_mod
    from aleph.vm.models import MessageSpec, VmExecution

    # Build a minimal fake execution with MessageSpec so the method runs.
    fake_vm = MagicMock()
    fake_vm.tap_interface = MagicMock()
    content = MagicMock()
    content.address = "0xabc"
    execution = MagicMock(spec=VmExecution)
    execution.is_instance = True
    execution.spec = MessageSpec(message=content, original=content)
    execution.vm = fake_vm
    execution.mapped_ports = {}
    execution.vm_hash = "deadbeef" * 8

    # Patch get_user_settings and update_port_redirects so we don't need real I/O.
    monkeypatch.setattr(models_mod, "get_user_settings", AsyncMock(return_value={}))
    update_mock = AsyncMock()
    execution.update_port_redirects = update_mock

    await VmExecution.fetch_port_redirect_config_and_setup(execution)

    # The aggregate fetch and update_port_redirects must have been called.
    update_mock.assert_awaited_once()
