import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    Integer,
    String,
    create_engine,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

try:
    from sqlalchemy.orm import declarative_base
except ImportError:
    from sqlalchemy.ext.declarative import declarative_base

from aleph.vm.conf import make_db_url, settings

Session: sessionmaker

logger = logging.getLogger(__name__)

Base: Any = declarative_base()


def setup_engine():
    global Session
    engine = create_engine(make_db_url(), echo=True)
    Session = sessionmaker(bind=engine)
    return engine


def create_tables(engine: Engine):
    Base.metadata.create_all(engine)


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
    session = Session()  # undefined name 'Session'
    try:
        session.add(record)
        session.commit()
    finally:
        session.close()


async def delete_record(execution_uuid: str):
    """Delete the resource usage in database"""
    session = Session()  # undefined name 'Session'
    try:
        session.query(ExecutionRecord).filter(ExecutionRecord.uuid == execution_uuid).delete()
        session.commit()
    finally:
        session.close()


async def delete_all_records():
    """Delete all the resource usage in database"""
    session = Session()  # undefined name 'Session'
    try:
        session.query(ExecutionRecord).delete()
        session.commit()
    finally:
        session.close()


async def get_execution_records() -> Iterable[ExecutionRecord]:
    """Get the execution records from the database."""
    session = Session()  # undefined name 'Session'
    try:
        return session.query(ExecutionRecord).all()
    finally:
        session.close()
