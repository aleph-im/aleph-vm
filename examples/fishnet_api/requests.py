from typing import List, Optional

from pydantic import BaseModel


class UploadTimeseriesRequest(BaseModel):
    id_hash: Optional[str]
    name: str
    owner: str
    desc: Optional[str]
    data: List[List[float]]


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


class DenyPermissionsResponse(BaseModel):
    success: bool
    message: str