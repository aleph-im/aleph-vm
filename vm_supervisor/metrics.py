import logging
from pathlib import Path
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import Column, DateTime, Float, Integer, String, create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .conf import make_db_url, settings

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
    __tablename__ = "records"

    uuid = Column(String, primary_key=True)

    execution_uuid = Column(String, nullable=False)
    vm_hash = Column(String, nullable=False)

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

    def __repr__(self):
        return f"<ExecutionRecord(uuid={self.uuid}, vm_hash={self.vm_hash})>"

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.c}


async def save_execution_data(execution_uuid: UUID, execution_data: str):
    """Save the execution data in a file on disk"""
    directory = Path(settings.EXECUTION_LOG_DIRECTORY)
    directory.mkdir(exist_ok=True)
    (directory / f"{execution_uuid}.json").write_text(execution_data)


async def save_record(record: ExecutionRecord):
    """Record the resource usage in database"""
    session = Session()
    try:
        session.add(record)
        session.commit()
    finally:
        session.close()


async def get_execution_records() -> Iterable[ExecutionRecord]:
    """Get the execution records from the database."""
    session = Session()
    try:
        return session.query(ExecutionRecord).all()
    finally:
        session.close()
