"""Supervisor-owned persistence: the host port-mapping store.

Port mappings are hypervisor state (host DNAT forwards), so they live in the
supervisor's own database (``settings.SUPERVISOR_DATABASE``), separate from the
agent's executions database. This module owns the engine, the schema, and the
CRUD the pool/controllers use.

The process that runs the VM pool (the gRPC daemon, or the agent in-process)
sets the engine up via :func:`setup_supervisor_engine` inside ``VmPool.setup``.
"""

from __future__ import annotations

import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String, select, update
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sqlalchemy.orm import declarative_base

from aleph.vm.conf import make_supervisor_db_url, settings

logger = logging.getLogger(__name__)

SupervisorSessionMaker: async_sessionmaker[AsyncSession]

Base: Any = declarative_base()


def setup_supervisor_engine() -> AsyncEngine:
    global SupervisorSessionMaker
    engine = create_async_engine(make_supervisor_db_url(), echo=False)
    SupervisorSessionMaker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine


async def create_supervisor_tables(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class PortMapping(Base):
    __tablename__ = "port_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vm_hash = Column(String, nullable=False, index=True)
    vm_port = Column(Integer, nullable=False)
    host_port = Column(Integer, nullable=False)
    tcp = Column(Boolean, default=False, nullable=False)
    udp = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index(
            "ix_port_mappings_host_port_active",
            host_port,
            unique=True,
            sqlite_where=deleted_at.is_(None),
        ),
    )

    def __repr__(self):
        return f"<PortMapping(vm_hash={self.vm_hash}, vm_port={self.vm_port}, host_port={self.host_port})>"


async def save_port_mappings(vm_hash: str, mapped_ports: dict[int, dict]) -> None:
    """Persist port mappings for a VM.

    Only touches rows that actually changed — unchanged mappings are
    left in place so the audit trail stays meaningful.
    SQLite serializes writes, so concurrent calls for the same vm_hash
    are safe.
    """
    now = datetime.now(tz=timezone.utc)
    async with SupervisorSessionMaker() as session:
        result = await session.execute(
            select(PortMapping).where(
                PortMapping.vm_hash == vm_hash,
                PortMapping.deleted_at.is_(None),
            )
        )
        existing = {row.vm_port: row for row in result.scalars().all()}

        new_mappings: list[dict] = []
        for vm_port, details in mapped_ports.items():
            port = int(vm_port)
            host_port = int(details["host"])
            tcp = bool(details.get("tcp", False))
            udp = bool(details.get("udp", False))

            old = existing.pop(port, None)
            if old and old.host_port == host_port and old.tcp == tcp and old.udp == udp:
                continue
            # Soft-delete the stale row if it existed
            if old:
                old.deleted_at = now
            new_mappings.append({"vm_port": port, "host_port": host_port, "tcp": tcp, "udp": udp})

        # Soft-delete mappings that are no longer present
        for old in existing.values():
            old.deleted_at = now

        # Flush soft-deletes first so the partial unique index on
        # host_port (WHERE deleted_at IS NULL) is freed before
        # inserting new rows that may reuse the same host_port.
        await session.flush()

        for mapping in new_mappings:
            session.add(
                PortMapping(
                    vm_hash=vm_hash,
                    vm_port=mapping["vm_port"],
                    host_port=mapping["host_port"],
                    tcp=mapping["tcp"],
                    udp=mapping["udp"],
                    created_at=now,
                )
            )

        await session.commit()


async def get_port_mappings(vm_hash: str) -> dict[int, dict]:
    """Load active port mappings for a VM.

    Returns dict mapping vm_port -> {host, tcp, udp}.
    """
    async with SupervisorSessionMaker() as session:
        result = await session.execute(
            select(PortMapping).where(
                PortMapping.vm_hash == vm_hash,
                PortMapping.deleted_at.is_(None),
            )
        )
        rows = result.scalars().all()
        return {
            row.vm_port: {
                "host": row.host_port,
                "tcp": row.tcp,
                "udp": row.udp,
            }
            for row in rows
        }


async def delete_port_mappings(vm_hash: str) -> None:
    """Soft-delete all active port mappings for a VM."""
    now = datetime.now(tz=timezone.utc)
    async with SupervisorSessionMaker() as session:
        await session.execute(
            update(PortMapping)
            .where(PortMapping.vm_hash == vm_hash, PortMapping.deleted_at.is_(None))
            .values(deleted_at=now)
        )
        await session.commit()


def migrate_port_mappings_from_legacy_db() -> int:
    """One-time upgrade migration: copy active port mappings from the pre-split
    agent DB into the supervisor DB so live VMs keep their host-port forwards.

    Idempotent and self-skipping: does nothing when the two DBs are the same
    file, the legacy DB is absent, either table is missing, or the supervisor
    table already holds rows. Returns the number of rows copied. The supervisor
    schema is expected to exist (created in ``VmPool.setup``) for the copy to
    happen; without it the migration skips.

    Both stores are SQLite files, so this copies rows verbatim (sync sqlite3),
    preserving created_at; ``id`` is left to autoincrement fresh.
    """
    legacy = Path(settings.EXECUTION_DATABASE)
    target = Path(settings.SUPERVISOR_DATABASE)
    if legacy == target or not legacy.exists():
        return 0

    with closing(sqlite3.connect(target)) as tgt:
        try:
            if tgt.execute("SELECT 1 FROM port_mappings LIMIT 1").fetchone():
                return 0  # already migrated / populated
        except sqlite3.OperationalError:
            return 0  # supervisor schema not created yet, nothing to copy into
        with closing(sqlite3.connect(f"file:{legacy}?mode=ro", uri=True)) as src:
            try:
                rows = src.execute(
                    "SELECT vm_hash, vm_port, host_port, tcp, udp, created_at, deleted_at "
                    "FROM port_mappings WHERE deleted_at IS NULL"
                ).fetchall()
            except sqlite3.OperationalError:
                return 0  # legacy DB predates the port_mappings table
        if not rows:
            return 0
        tgt.executemany(
            "INSERT INTO port_mappings (vm_hash, vm_port, host_port, tcp, udp, created_at, deleted_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        tgt.commit()

    logger.info("Migrated %d port mapping(s) from the legacy agent DB into the supervisor DB", len(rows))
    return len(rows)
