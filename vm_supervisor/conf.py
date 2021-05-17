import logging
import os
from os.path import isfile, join
from typing import NewType

from pydantic import BaseSettings
from .models import FilePath

logger = logging.getLogger(__name__)

Url = NewType("Url", str)


class Settings(BaseSettings):
    START_ID_INDEX: int = 4
    PREALLOC_VM_COUNT: int = 0
    REUSE_TIMEOUT: float = 60 * 60.0

    API_SERVER: str = "https://api2.aleph.im"
    USE_JAILER: bool = True
    # System logs make boot ~2x slower
    PRINT_SYSTEM_LOGS: bool = False
    # Networking does not work inside Docker/Podman
    ALLOW_VM_NETWORKING: bool = True
    FIRECRACKER_PATH: str = "/opt/firecracker/firecracker"
    JAILER_PATH: str = "/opt/firecracker/jailer"
    LINUX_PATH: str = os.path.abspath("./kernels/vmlinux.bin")

    CONNECTOR_URL: Url = Url("http://localhost:8000")

    CACHE_ROOT: FilePath = FilePath("/tmp/aleph/vm_supervisor")
    MESSAGE_CACHE: FilePath = FilePath(join(CACHE_ROOT, "message"))
    CODE_CACHE: FilePath = FilePath(join(CACHE_ROOT, "code"))
    RUNTIME_CACHE: FilePath = FilePath(join(CACHE_ROOT, "runtime"))
    DATA_CACHE: FilePath = FilePath(join(CACHE_ROOT, "data"))

    FAKE_DATA: bool = False

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key != key.upper():
                logger.warning(f"Setting {key} is not uppercase")
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")

    def check(self):
        assert isfile(self.FIRECRACKER_PATH)
        assert isfile(self.JAILER_PATH)
        assert isfile(self.LINUX_PATH)
        assert self.CONNECTOR_URL.startswith(
            "http://"
        ) or self.CONNECTOR_URL.startswith("https://")

    def setup(self):
        os.makedirs(self.MESSAGE_CACHE, exist_ok=True)
        os.makedirs(self.CODE_CACHE, exist_ok=True)
        os.makedirs(self.RUNTIME_CACHE, exist_ok=True)
        os.makedirs(self.DATA_CACHE, exist_ok=True)

    def display(self) -> str:
        return "\n".join(
            f"{annotation:<17} = {getattr(self, annotation)}"
            for annotation, value in self.__annotations__.items()
        )

    class Config:
        env_prefix = "ALEPH_VM_"
        case_sensitive = False


# Settings singleton
settings = Settings()
