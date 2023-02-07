from enum import Enum
from typing import List, Tuple, Optional

from aars import Record, Index


class UserInfo(Record):
    datasetIDs: List[str]
    executionIDs: List[str]
    algorithmIDs: List[str]
    username: str
    bio: str


class Timeseries(Record):
    name: str
    owner: str
    desc: Optional[str]
    available: bool = True
    data: List[Tuple[int, float]]


class Dataset(Record):
    name: str
    owner: str
    desc: Optional[str]
    available: bool = True
    ownsAllTimeseries: bool
    timeseriesIDs: List[str]


class Algorithm(Record):
    name: str
    desc: str
    owner: str
    code: str
    executionIDs: List[str] = []


class ExecutionStatus(str, Enum):
    REQUESTED = "REQUESTED"
    PENDING = "PENDING"
    DENIED = "DENIED"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class Execution(Record):
    algorithmID: str
    datasetID: str
    owner: str
    status: ExecutionStatus = ExecutionStatus.REQUESTED
    resultID: Optional[str]


class PermissionStatus(str, Enum):
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


class Result(Record):
    executionID: str
    data: str


# indexes to fetch by owner
Index(Dataset, 'owner')
Index(Algorithm, 'owner')
Index(Execution, 'owner')
Index(Permission, 'owner')
Index(Timeseries, 'owner')

# index to fetch permissions by timeseriesID and reader
Index(Permission, ['reader', 'timeseriesID', 'status'])
Index(Permission, 'id_hash')
Index(Permission, 'status')
Index(Dataset, "id_hash")

# index to fetch execution by the status
Index(Execution, 'status')
