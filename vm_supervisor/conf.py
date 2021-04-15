from os import getenv
from os.path import isfile


class Settings:
    VM_ID_START_INDEX: int = int(getenv('ALEPH_VM_START_ID_INDEX', 4))
    PREALLOC_VM_COUNT: int = int(getenv('ALEPH_PREALLOC_VM_COUNT', 0))
    API_SERVER: str = getenv('ALEPH_API_SERVER', 'https://api2.aleph.im')
    USE_JAILER: bool = getenv('ALEPH_USER_JAILER', 'true') == 'true'
    # System logs make boot ~2x slower
    PRINT_SYSTEM_LOGS: bool = getenv('ALEPH_PRINT_SYSTEM_LOGS', 'true') == 'false'
    FIRECRACKER_PATH: str = getenv('ALEPH_FIRECRACKER_PATH', '/opt/firecracker/firecracker')
    JAILER_PATH: str = getenv('ALEPH_JAILER_PATH', '/opt/firecracker/jailer')

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")

    def check(self):
        assert isfile(self.FIRECRACKER_PATH)
        assert isfile(self.JAILER_PATH)

# Settings singleton
settings = Settings()
