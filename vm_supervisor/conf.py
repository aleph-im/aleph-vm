import os
from os import getenv
from os.path import isfile, join
from typing import NewType

from .models import FilePath

Url = NewType("Url", str)


class Settings:
    VM_ID_START_INDEX: int = int(getenv("ALEPH_VM_START_ID_INDEX", 4))
    PREALLOC_VM_COUNT: int = int(getenv("ALEPH_PREALLOC_VM_COUNT", 0))
    API_SERVER: str = getenv("ALEPH_API_SERVER", "https://api2.aleph.im")
    USE_JAILER: bool = getenv("ALEPH_USER_JAILER", "true") == "true"
    # System logs make boot ~2x slower
    PRINT_SYSTEM_LOGS: bool = getenv("ALEPH_PRINT_SYSTEM_LOGS", "false") == "true"
    # Networking does not work inside Docker/Podman
    ALLOW_VM_NETWORKING: bool = getenv("ALEPH_PRINT_SYSTEM_LOGS", "true") == "true"
    FIRECRACKER_PATH: str = getenv(
        "ALEPH_FIRECRACKER_PATH", "/opt/firecracker/firecracker"
    )
    JAILER_PATH: str = getenv("ALEPH_JAILER_PATH", "/opt/firecracker/jailer")
    LINUX_PATH: str = getenv(
        "ALEPH_LINUX_PATH", os.path.abspath("./kernels/vmlinux.bin")
    )

    CONNECTOR_URL: Url = Url(getenv("ALEPH_CONNECTOR_URL", "http://localhost:8000"))

    CACHE_ROOT: FilePath = FilePath(
        getenv("ALEPH_CACHE_ROOT", "/tmp/aleph/vm_supervisor")
    )
    MESSAGE_CACHE: FilePath = FilePath(
        getenv("ALEPH_MESSAGE_CACHE", join(CACHE_ROOT, "message"))
    )
    CODE_CACHE: FilePath = FilePath(
        getenv("ALEPH_CODE_CACHE", join(CACHE_ROOT, "code"))
    )
    RUNTIME_CACHE: FilePath = FilePath(
        getenv("ALEPH_RUNTIME_CACHE", join(CACHE_ROOT, "runtime"))
    )
    DATA_CACHE: FilePath = FilePath(
        getenv("ALEPH_DATA_CACHE", join(CACHE_ROOT, "data"))
    )

    FAKE_DATA: bool = getenv("ALEPH_FAKE_DATA", "false") == "true"

    def update(self, **kwargs):
        for key, value in kwargs.items():
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


# Settings singleton
settings = Settings()
