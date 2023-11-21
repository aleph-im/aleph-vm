from pathlib import Path

from pydantic import BaseModel

from aleph.vm.conf import Settings


class VMConfiguration(BaseModel):
    use_jailer: bool
    firecracker_bin_path: Path
    jailer_bin_path: Path
    config_file_path: Path
    init_timeout: float


class Configuration(BaseModel):
    vm_id: int
    settings: Settings
    vm_configuration: VMConfiguration
