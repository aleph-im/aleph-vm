from typing import List, Optional, Tuple

from pydantic import BaseModel

from fishnet_cod import Execution, Permission, Timeseries, Dataset, Algorithm


class TimeseriesItem(BaseModel):
    id_hash: Optional[str]
    name: str
    owner: str
    desc: Optional[str]
    data: List[Tuple[int, float]]


class UploadTimeseriesRequest(BaseModel):
    timeseries: List[TimeseriesItem]


class UploadDatasetRequest(BaseModel):
    id_hash: Optional[str]
    name: str
    desc: Optional[str]
    owner: str
    ownsAllTimeseries: bool
    timeseriesIDs: List[str]


class UploadAlgorithmRequest(BaseModel):
    id_hash: Optional[str]
    name: str
    desc: str
    owner: str
    code: str


class RequestExecutionRequest(BaseModel):
    algorithmID: str
    datasetID: str
    owner: str
    status: Optional[str]


class RequestExecutionResponse(BaseModel):
    execution: Execution
    permissionRequests: Optional[List[Permission]]
    unavailableTimeseries: Optional[List[Timeseries]]


class FishnetResponseDataset(BaseModel):
    success: bool
    message: Optional[List[Dataset]]
    message: Optional[List[Permission]]
    message: Optional[List[Execution]]
    message: Optional[List[Dataset]]
    message: Optional[List[Algorithm]]
    message: Optional[List[Timeseries]]
