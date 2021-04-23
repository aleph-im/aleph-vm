from os import getenv
from typing import NewType

Url = NewType("Url", str)


class Settings:
    ALEPH_SERVER: Url = getenv("ALEPH_API_SERVER", "https://api2.aleph.im")
    IPFS_SERVER: Url = getenv("ALEPH_IPFS_SERVER", "https://ipfs.aleph.im/ipfs")
    OFFLINE_TEST_MODE: bool = getenv("ALEPH_OFFLINE_TEST_MODE", "true") == "true"

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")


# Settings singleton
settings = Settings()
