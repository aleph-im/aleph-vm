"""Tests for port mapping DB logic and port availability checker."""

from contextlib import closing
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from aleph.vm.supervisor.networking_db import Base, save_port_mappings


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
    """Redirect SupervisorSessionMaker in the networking_db module to the in-memory DB."""
    from aleph.vm.supervisor import networking_db

    # raising=False: SupervisorSessionMaker is a bare module annotation until
    # setup_supervisor_engine() binds it, so whether the attribute already exists
    # depends on test order. Redirect it regardless of any prior setup call.
    monkeypatch.setattr(networking_db, "SupervisorSessionMaker", async_session, raising=False)


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
        with patch(
            "aleph.vm.network.port_availability_checker.make_supervisor_sync_db_url",
            return_value=f"sqlite:///{db_path}",
        ):
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
        with patch(
            "aleph.vm.network.port_availability_checker.make_supervisor_sync_db_url",
            return_value=f"sqlite:///{db_path}",
        ):
            result = _get_active_host_ports()
        assert result == {30000}  # deleted row excluded
    finally:
        _SyncEngineHolder.reset()


_PM_SCHEMA = (
    "CREATE TABLE port_mappings ("
    "id INTEGER PRIMARY KEY, vm_hash TEXT, vm_port INTEGER, host_port INTEGER, "
    "tcp BOOLEAN, udp BOOLEAN, created_at DATETIME, deleted_at DATETIME)"
)


def test_migrate_port_mappings_copies_active_rows(tmp_path, monkeypatch):
    """The upgrade migration copies active rows from the legacy agent DB into
    the supervisor DB, skips soft-deleted rows, and is idempotent."""
    import sqlite3

    from aleph.vm.conf import settings
    from aleph.vm.supervisor.networking_db import migrate_port_mappings_from_legacy_db

    legacy = tmp_path / "executions.sqlite3"
    target = tmp_path / "supervisor.sqlite3"
    with closing(sqlite3.connect(legacy)) as c:
        c.execute(_PM_SCHEMA)
        c.execute(
            "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at) VALUES (?,?,?,?,?,?)",
            ("abc", 80, 30000, 1, 0, "2026-01-01"),
        )
        c.execute(
            "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at, deleted_at) "
            "VALUES (?,?,?,?,?,?,?)",
            ("abc", 443, 30001, 1, 0, "2026-01-01", "2026-01-02"),
        )
        c.commit()
    with closing(sqlite3.connect(target)) as c:
        c.execute(_PM_SCHEMA)
        c.commit()

    monkeypatch.setattr(settings, "EXECUTION_DATABASE", legacy)
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", target)

    assert migrate_port_mappings_from_legacy_db() == 1
    with closing(sqlite3.connect(target)) as c:
        rows = c.execute("SELECT vm_hash, host_port FROM port_mappings WHERE deleted_at IS NULL").fetchall()
    assert rows == [("abc", 30000)]
    # Idempotent: the target is now populated, so a second run copies nothing.
    assert migrate_port_mappings_from_legacy_db() == 0


def test_migrate_port_mappings_noop_when_target_table_missing(tmp_path, monkeypatch):
    """A target DB file without the port_mappings table (schema not created
    yet) must make the migration skip cleanly instead of crashing."""
    import sqlite3

    from aleph.vm.conf import settings
    from aleph.vm.supervisor.networking_db import migrate_port_mappings_from_legacy_db

    legacy = tmp_path / "executions.sqlite3"
    target = tmp_path / "supervisor.sqlite3"
    with closing(sqlite3.connect(legacy)) as c:
        c.execute(_PM_SCHEMA)
        c.execute(
            "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at) VALUES (?,?,?,?,?,?)",
            ("abc", 80, 30000, 1, 0, "2026-01-01"),
        )
        c.commit()
    # Create the target DB file without any tables.
    with closing(sqlite3.connect(target)):
        pass

    monkeypatch.setattr(settings, "EXECUTION_DATABASE", legacy)
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", target)

    assert migrate_port_mappings_from_legacy_db() == 0


def test_migrate_port_mappings_noop_when_same_file(tmp_path, monkeypatch):
    from aleph.vm.conf import settings
    from aleph.vm.supervisor.networking_db import migrate_port_mappings_from_legacy_db

    same = tmp_path / "db.sqlite3"
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", same)
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", same)
    assert migrate_port_mappings_from_legacy_db() == 0


def test_migrate_port_mappings_noop_when_legacy_missing(tmp_path, monkeypatch):
    from aleph.vm.conf import settings
    from aleph.vm.supervisor.networking_db import migrate_port_mappings_from_legacy_db

    monkeypatch.setattr(settings, "EXECUTION_DATABASE", tmp_path / "nope.sqlite3")
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", tmp_path / "supervisor.sqlite3")
    assert migrate_port_mappings_from_legacy_db() == 0


@pytest.mark.asyncio
async def test_vm_pool_setup_binds_supervisor_engine(tmp_path, monkeypatch):
    """VmPool.setup() must bind SupervisorSessionMaker and create the schema:
    any process that runs the pool without it hits a NameError on the first
    port-mapping access (regression: the run-instances CLI path)."""
    import sqlite3

    from aleph.vm.conf import settings
    from aleph.vm.pool import VmPool
    from aleph.vm.supervisor import networking_db

    monkeypatch.setattr(settings, "ALLOW_VM_NETWORKING", False)
    monkeypatch.setattr(settings, "ENABLE_GPU_SUPPORT", False)
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", tmp_path / "executions.sqlite3")
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", tmp_path / "supervisor.sqlite3")
    monkeypatch.delattr(networking_db, "SupervisorSessionMaker", raising=False)

    pool = VmPool()
    await pool.setup()

    # The session maker is bound and usable.
    assert isinstance(networking_db.SupervisorSessionMaker, async_sessionmaker)
    assert await networking_db.get_port_mappings("no-such-vm") == {}
    # The schema exists in the supervisor DB file.
    with closing(sqlite3.connect(tmp_path / "supervisor.sqlite3")) as c:
        assert c.execute("SELECT COUNT(*) FROM port_mappings").fetchone() == (0,)
