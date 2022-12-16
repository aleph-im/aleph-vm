from typing import List
from enum import Enum

from aars import Record


class UserInfo(Record):
    datasetIDs: List[str]
    executionIDs: List[str]
    algorithmIDs: List[str]
    username: str
    bio: str


class Timeseries(Record):
    name: str
    desc: str
    owner: str
    data: List[float]


class Dataset(Record):
    name: str
    desc: str
    creator: str
    creatorIsOwner: bool
    timeseriesIDs: List[str]


class Algorithm(Record):
    name: str
    desc: str
    owner: str
    code: str
    executionIDs: List[str]


class ExecutionStatus(Enum):
    REQUESTED = "REQUESTED"
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class Execution(Record):
    algorithmID: str
    datasetID: str
    owner: str
    status: ExecutionStatus
    exitCode: int


class PermissionStatus(Enum):
    REQUESTED = "REQUESTED"
    GRANTED = "GRANTED"
    DENIED = "DENIED"


class Permission(Record):
    timeseriesID: str
    algorithmID: str
    owner: str
    reader: str
    status: PermissionStatus
    executionCount: int
