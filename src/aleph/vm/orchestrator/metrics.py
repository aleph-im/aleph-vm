import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    delete,
    select,
    update,
)
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base

from aleph.vm.conf import make_db_url, settings

AsyncSessionMaker: async_sessionmaker[AsyncSession]

logger = logging.getLogger(__name__)

Base: Any = declarative_base()


def setup_engine():
    global AsyncSessionMaker
    engine = create_async_engine(make_db_url(), echo=False)
    AsyncSessionMaker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return engine


async def create_tables(engine: AsyncEngine):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


class ExecutionRecord(Base):
    __tablename__ = "executions"

    uuid = Column(String, primary_key=True)
    vm_hash = Column(String, nullable=False)
    vm_id = Column(Integer, nullable=True)

    time_defined = Column(DateTime, nullable=False)
    time_prepared = Column(DateTime)
    time_started = Column(DateTime)
    time_stopping = Column(DateTime)

    cpu_time_user = Column(Float, nullable=True)
    cpu_time_system = Column(Float, nullable=True)

    io_read_count = Column(Integer, nullable=True)
    io_write_count = Column(Integer, nullable=True)
    io_read_bytes = Column(Integer, nullable=True)
    io_write_bytes = Column(Integer, nullable=True)

    vcpus = Column(Integer, nullable=False)
    memory = Column(Integer, nullable=False)
    network_tap = Column(String, nullable=True)

    message = Column(JSON, nullable=True)
    original_message = Column(JSON, nullable=True)
    persistent = Column(Boolean, nullable=True)

    gpus = Column(JSON, nullable=True)
    mapped_ports = Column(JSON, nullable=True)

    def __repr__(self):
        return f"<ExecutionRecord(uuid={self.uuid}, vm_hash={self.vm_hash}, vm_id={self.vm_id})>"

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.c}


async def save_execution_data(execution_uuid: UUID, execution_data: str):
    """Save the execution data in a file on disk"""
    directory = Path(settings.EXECUTION_LOG_DIRECTORY)
    directory.mkdir(exist_ok=True)
    (directory / f"{execution_uuid}.json").write_text(execution_data)


async def save_record(record: ExecutionRecord):
    """Record the resource usage in database"""
    async with AsyncSessionMaker() as session:  # Use AsyncSession in a context manager
        session.add(record)
        await session.commit()  # Use await for commit


async def delete_record(execution_uuid: str):
    """Delete the resource usage in database"""
    async with AsyncSessionMaker() as session:
        try:
            statement = delete(ExecutionRecord).where(ExecutionRecord.uuid == execution_uuid)
            await session.execute(statement)
            await session.commit()
        finally:
            await session.close()


async def get_execution_records() -> Iterable[ExecutionRecord]:
    """Get the execution records from the database."""
    async with AsyncSessionMaker() as session:  # Use AsyncSession in a context manager
        result = await session.execute(
            select(ExecutionRecord).order_by(ExecutionRecord.time_defined.desc())
        )  # Use execute for querying
        executions = result.scalars().all()
        await session.commit()
        return executions


async def get_last_record_for_vm(vm_hash) -> ExecutionRecord | None:
    """Get the execution records from the database."""
    async with AsyncSessionMaker() as session:  # Use AsyncSession in a context manager
        result = await session.execute(
            select(ExecutionRecord).where(ExecutionRecord.vm_hash == vm_hash).limit(1)
        )  # Use execute for querying
        return result.scalar()


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
        return f"<PortMapping(vm_hash={self.vm_hash}, " f"vm_port={self.vm_port}, host_port={self.host_port})>"


async def save_port_mappings(vm_hash: str, mapped_ports: dict[int, dict]) -> None:
    """Persist port mappings for a VM.

    Only touches rows that actually changed — unchanged mappings are
    left in place so the audit trail stays meaningful.
    SQLite serializes writes, so concurrent calls for the same vm_hash
    are safe.
    """
    now = datetime.now(tz=timezone.utc)
    async with AsyncSessionMaker() as session:
        result = await session.execute(
            select(PortMapping).where(
                PortMapping.vm_hash == vm_hash,
                PortMapping.deleted_at.is_(None),
            )
        )
        existing = {row.vm_port: row for row in result.scalars().all()}

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
            session.add(
                PortMapping(
                    vm_hash=vm_hash,
                    vm_port=port,
                    host_port=host_port,
                    tcp=tcp,
                    udp=udp,
                    created_at=now,
                )
            )

        # Soft-delete mappings that are no longer present
        for old in existing.values():
            old.deleted_at = now

        await session.commit()


async def get_port_mappings(vm_hash: str) -> dict[int, dict]:
    """Load active port mappings for a VM.

    Returns dict mapping vm_port -> {host, tcp, udp}.
    """
    async with AsyncSessionMaker() as session:
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
    async with AsyncSessionMaker() as session:
        await session.execute(
            update(PortMapping)
            .where(PortMapping.vm_hash == vm_hash, PortMapping.deleted_at.is_(None))
            .values(deleted_at=now)
        )
        await session.commit()
