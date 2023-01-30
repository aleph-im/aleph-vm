from typing import List

from pydantic import BaseModel


class UploadDatasetRequest(BaseModel):
    name: str
    desc: str
    owner: str
    ownsAllTimeseries: bool
    timeseriesIDs: List[str]


class DenyPermissionsResponse(BaseModel):
    success: bool
    message: str