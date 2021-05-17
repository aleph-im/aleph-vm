from enum import Enum
from typing import NewType, Optional

from pydantic import BaseModel

FilePath = NewType("FilePath", str)


class HashableModel(BaseModel):
    def __hash__(self):
        return hash(self.__class__) + hash(tuple(self.__dict__.values()))


class Encoding(str, Enum):
    plain = "plain"
    zip = "zip"
    targz = "tar.gzip"


class CodeContent(HashableModel):
    encoding: Encoding
    entrypoint: str
    ref: str
    latest_amend: bool = True


class DataContent(HashableModel):
    encoding: Encoding
    mount: str
    ref: str
    latest_amend: bool = True


class FunctionTriggers(HashableModel):
    http: bool


class FunctionEnvironment(HashableModel):
    reproducible: bool = False
    internet: bool = False
    aleph_api: bool = False


class FunctionResources(HashableModel):
    vcpus: int = 1
    memory: int = 128
    seconds: int = 1


class FunctionRuntime(HashableModel):
    ref: str
    latest_amend: bool = True
    comment: str


class FunctionContent(HashableModel):
    code: CodeContent
    data: Optional[DataContent]
    on: FunctionTriggers
    environment: FunctionEnvironment
    resources: FunctionResources
    runtime: FunctionRuntime


class FunctionMessage(HashableModel):
    type: str
    address: str
    content: FunctionContent
    time: float
