from model import Timeseries, Dataset, Algorithm, Execution, Permission, UserInfo
from typing import List, Optional
from aars import Record


class UploadDatasetRequest(Record):
    name: str
    desc: str
    timeseries: List[Timeseries]
    owner: str


class UploadAlgorithmRequest(Record):
    name: str
    desc: str
    code: str
    owner: str
