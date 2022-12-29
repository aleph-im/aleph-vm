from typing import List, Tuple, Optional
from enum import Enum

from aars import Record, Index


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
    data: List[Tuple[int, float]]


class Dataset(Record):
    name: str
    desc: str
    owner: str
    ownsAllTimeseries: bool
    timeseriesIDs: List[str]


class Algorithm(Record):
    name: str
    desc: str
    owner: str
    code: str
    executionIDs: List[str] = []


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
    status: ExecutionStatus = ExecutionStatus.REQUESTED
    exitCode: Optional[int]


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
    maxExecutionCount: Optional[int]


# indexes to fetch by owner
Index(Dataset, 'owner')
Index(Algorithm, 'owner')
Index(Execution, 'owner')
Index(Permission, 'owner')

# index to fetch permissions by timeseriesID and reader
Index(Permission, ['reader', 'timeseriesID'])

Index(Execution, 'datasetID')
