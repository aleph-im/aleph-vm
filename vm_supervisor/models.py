from enum import Enum
from typing import NewType, Optional

from pydantic import BaseModel

FilePath = NewType("FilePath", str)


class Encoding(str, Enum):
    plain = "plain"
    zip = "zip"
    targz = "tar.gzip"


class CodeContent(BaseModel):
    encoding: Encoding
    entrypoint: str
    ref: str
    latest_amend: bool = True


class DataContent(BaseModel):
    encoding: Encoding
    mount: str
    ref: str
    latest_amend: bool = True


class FunctionTriggers(BaseModel):
    http: bool


class FunctionEnvironment(BaseModel):
    reproducible: bool = False
    internet: bool = False
    aleph_api: bool = False


class FunctionResources(BaseModel):
    vcpus: int = 1
    memory: int = 128
    seconds: int = 1


class FunctionRuntime(BaseModel):
    ref: str
    latest_amend: bool = True
    comment: str


class FunctionContent(BaseModel):
    code: CodeContent
    data: Optional[DataContent]
    on: FunctionTriggers
    environment: FunctionEnvironment
    resources: FunctionResources
    runtime: FunctionRuntime


class FunctionMessage(BaseModel):
    type: str
    address: str
    content: FunctionContent
    time: float
