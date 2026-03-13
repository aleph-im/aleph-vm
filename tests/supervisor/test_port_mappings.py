"""Tests for port mapping DB logic and port availability checker."""

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aleph.vm.orchestrator.metrics import Base, PortMapping, save_port_mappings


@pytest.fixture
async def async_session():
    """Create an in-memory SQLite DB with the port_mappings table."""
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    yield session_factory
    await engine.dispose()


@pytest.fixture
def _patch_session_maker(async_session, monkeypatch):
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
        assert len(deleted) >= 1


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


def test_get_active_host_ports_missing_table(tmp_path):
    """_get_active_host_ports returns empty set when table doesn't exist."""
    from unittest.mock import patch

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
    from unittest.mock import patch

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
