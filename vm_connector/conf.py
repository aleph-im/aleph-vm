import logging
from typing import NewType

from pydantic_settings import BaseSettings

logger = logging.getLogger(__name__)

Url = NewType("Url", str)


class ConnectorSettings(BaseSettings):
    API_SERVER: Url = Url("https://official.aleph.cloud")
    IPFS_SERVER: Url = Url("https://ipfs.aleph.im/ipfs")
    OFFLINE_TEST_MODE: bool = False

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key != key.upper():
                logger.warning(f"Setting {key} is not uppercase")
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")

    def display(self) -> str:
        return "\n".join(
            f"{annotation:<17} = {getattr(self, annotation)}" for annotation, value in self.__annotations__.items()
        )

    class Config:
        env_prefix = "ALEPH_"
        case_sensitive = False
        env_file = ".env"


# Settings singleton
settings = ConnectorSettings()
