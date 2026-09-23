"""The agent-DB ``port_mappings`` drop migration (revision f1a2b3c4d5e6).

Drives the real Alembic runner the agent uses at startup against throwaway
SQLite files. The migration must only drop the legacy table once the
supervisor's one-time copy can no longer need it, and must fail loudly
(leaving the table and the revision stamp untouched) otherwise.
"""

import asyncio
import sqlite3
from contextlib import closing
from pathlib import Path

import alembic.command
import alembic.config
import pytest
from sqlalchemy.ext.asyncio import create_async_engine

from aleph.vm.agent import cli
from aleph.vm.conf import make_db_url, settings

PREVIOUS = "a1b2c3d4e5f6"
DROP = "f1a2b3c4d5e6"

# The migrations open a sync engine on the async URL and only work inside
# the greenlet context the agent runs them in (conn.run_sync), so mirror
# cli.run_async_db_migrations rather than calling alembic directly.


def _run_alembic(command: str, revision: str) -> None:
    def _inner(_connection) -> None:
        cfg = alembic.config.Config("alembic.ini")
        cfg.attributes["configure_logger"] = False
        with cli.change_dir(Path(cli.__file__).parent):
            getattr(alembic.command, command)(cfg, revision)

    async def _go() -> None:
        engine = create_async_engine(make_db_url(), echo=False)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(_inner)
        finally:
            await engine.dispose()

    asyncio.run(_go())


def _query(path: Path, sql: str):
    with closing(sqlite3.connect(path)) as conn:
        return conn.execute(sql).fetchall()


def _version(path: Path) -> str:
    return _query(path, "SELECT version_num FROM alembic_version")[0][0]


def _has_table(path: Path, name: str) -> bool:
    rows = _query(path, f"SELECT 1 FROM sqlite_master WHERE type='table' AND name='{name}'")
    return bool(rows)


def _insert_legacy_row(path: Path, host_port: int, deleted: bool = False) -> None:
    deleted_at = "'2026-01-02 00:00:00'" if deleted else "NULL"
    with closing(sqlite3.connect(path)) as conn:
        conn.execute(
            "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at, deleted_at) "
            f"VALUES ('abc', 22, {host_port}, 1, 0, '2026-01-01 00:00:00', {deleted_at})"
        )
        conn.commit()


def _create_supervisor_store(path: Path, rows: int) -> None:
    """A supervisor.sqlite3 with the port_mappings schema and ``rows`` active rows."""
    with closing(sqlite3.connect(path)) as conn:
        conn.executescript(
            "CREATE TABLE port_mappings ("
            "id INTEGER NOT NULL PRIMARY KEY, vm_hash VARCHAR NOT NULL, vm_port INTEGER NOT NULL, "
            "host_port INTEGER NOT NULL, tcp BOOLEAN NOT NULL DEFAULT 0, udp BOOLEAN NOT NULL DEFAULT 0, "
            "created_at DATETIME NOT NULL, deleted_at DATETIME);"
        )
        for i in range(rows):
            conn.execute(
                "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at) "
                f"VALUES ('abc', 22, {24000 + i}, 1, 0, '2026-01-01 00:00:00')"
            )
        conn.commit()


@pytest.fixture
def legacy_db(tmp_path, monkeypatch) -> Path:
    """An agent DB upgraded to the revision just before the drop, with the
    legacy port_mappings table present, and a supervisor DB path that does
    not exist yet."""
    legacy = tmp_path / "executions.sqlite3"
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", legacy)
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", tmp_path / "supervisor.sqlite3")
    _run_alembic("upgrade", PREVIOUS)
    assert _has_table(legacy, "port_mappings")
    assert _version(legacy) == PREVIOUS
    return legacy


def test_refuses_to_drop_when_supervisor_db_is_absent(legacy_db):
    _insert_legacy_row(legacy_db, 24001)

    with pytest.raises(RuntimeError, match="port_mappings"):
        _run_alembic("upgrade", "head")

    assert _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == PREVIOUS
    assert _query(legacy_db, "SELECT host_port FROM port_mappings") == [(24001,)]


def test_refuses_to_drop_when_supervisor_table_is_empty(legacy_db):
    _insert_legacy_row(legacy_db, 24001)
    _create_supervisor_store(settings.SUPERVISOR_DATABASE, rows=0)

    with pytest.raises(RuntimeError, match="port_mappings"):
        _run_alembic("upgrade", "head")

    assert _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == PREVIOUS


def test_drops_once_supervisor_store_holds_rows(legacy_db):
    _insert_legacy_row(legacy_db, 24001)
    _create_supervisor_store(settings.SUPERVISOR_DATABASE, rows=1)

    _run_alembic("upgrade", "head")

    assert not _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == DROP


def test_drops_when_legacy_table_has_no_active_rows(legacy_db):
    # Only soft-deleted rows: the copy would never pick them up, nothing to lose.
    _insert_legacy_row(legacy_db, 24001, deleted=True)

    _run_alembic("upgrade", "head")

    assert not _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == DROP


def test_drops_when_legacy_table_is_empty(legacy_db):
    _run_alembic("upgrade", "head")

    assert not _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == DROP


def test_keeps_table_when_both_databases_are_the_same_file(legacy_db, monkeypatch):
    # With a single shared file the table IS the supervisor's live store.
    monkeypatch.setattr(settings, "SUPERVISOR_DATABASE", legacy_db)
    _insert_legacy_row(legacy_db, 24001)

    _run_alembic("upgrade", "head")

    assert _has_table(legacy_db, "port_mappings")
    assert _version(legacy_db) == DROP
    assert _query(legacy_db, "SELECT host_port FROM port_mappings") == [(24001,)]


def test_downgrade_recreates_the_canonical_table(legacy_db):
    before = _query(legacy_db, "SELECT type, name, sql FROM sqlite_master WHERE tbl_name='port_mappings' ORDER BY name")
    _run_alembic("upgrade", "head")
    assert not _has_table(legacy_db, "port_mappings")

    _run_alembic("downgrade", PREVIOUS)

    after = _query(legacy_db, "SELECT type, name, sql FROM sqlite_master WHERE tbl_name='port_mappings' ORDER BY name")
    assert after == before
    assert _version(legacy_db) == PREVIOUS
