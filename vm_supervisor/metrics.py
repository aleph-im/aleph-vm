import logging
import os
from os.path import join
from typing import Optional, Iterable
from uuid import UUID

from sqlalchemy import Column, Integer, String, Float, DateTime
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from .conf import settings

logger = logging.getLogger(__name__)


Base = declarative_base()
session_maker: Optional[sessionmaker] = None


def get_database_sessionmaker() -> sessionmaker:
    global session_maker
    if session_maker:
        return session_maker

    # engine = create_engine('sqlite:///:memory:', echo=True)
    engine = create_engine(f"sqlite:///{settings.EXECUTION_DATABASE}", echo=True)
    Base.metadata.create_all(engine)
    session_maker = sessionmaker(bind=engine)
    return session_maker


class ExecutionRecord(Base):
    __tablename__ = "records"

    uuid = Column(String, primary_key=True)
    vm_hash = Column(String)

    time_defined = Column(DateTime)
    time_prepared = Column(DateTime)
    time_started = Column(DateTime)
    time_stopping = Column(DateTime)

    cpu_time_user = Column(Float)
    cpu_time_system = Column(Float)

    io_read_count = Column(Integer)
    io_write_count = Column(Integer)
    io_read_bytes = Column(Integer)
    io_write_bytes = Column(Integer)

    vcpus = Column(Integer)
    memory = Column(Integer)
    network_tap = Column(String, nullable=True)

    def __repr__(self):
        return f"<ExecutionRecord(uuid={self.uuid}, vm_hash={self.vm_hash})>"

    def to_dict(self):
        return {
            "uuid": self.uuid,
            "vm_hash": self.vm_hash,
            "time_defined": self.time_defined,
            "time_prepared": self.time_prepared,
            "time_started": self.time_started,
            "time_stopping": self.time_stopping,
            "cpu_time_user": self.cpu_time_user,
            "cpu_time_system": self.cpu_time_system,
            "io_read_count": self.io_read_count,
            "io_write_count": self.io_write_count,
            "io_read_bytes": self.io_read_bytes,
            "io_write_bytes": self.io_write_bytes,
            "vcpus": self.vcpus,
            "memory": self.memory,
            "network_tap": self.network_tap,
        }


async def save_execution_data(execution_uuid: UUID, execution_data: str):
    """Save the execution data in a file on disk"""
    os.makedirs(settings.EXECUTION_LOG_DIRECTORY, exist_ok=True)
    filepath = join(settings.EXECUTION_LOG_DIRECTORY, f"{execution_uuid}.json")
    with open(filepath, "w") as fd:
        fd.write(execution_data)


async def save_record(record: ExecutionRecord):
    """Record the resource usage in database"""
    sessionmaker = get_database_sessionmaker()
    session = sessionmaker()
    session.add(record)
    session.commit()


async def get_execution_records() -> Iterable[ExecutionRecord]:
    """Get the execution records from the database."""
    sessionmaker = get_database_sessionmaker()
    session = sessionmaker()
    return session.query(ExecutionRecord).all()
