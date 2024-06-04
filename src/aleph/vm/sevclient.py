from pathlib import Path

from aleph.vm.utils import run_in_subprocess


class SevClient:
    def __init__(self, sev_dir: Path):
        self.sev_dir = sev_dir
        self.certificates_dir = sev_dir / "platform"
        self.certificates_dir.mkdir(exist_ok=True, parents=True)
        self.certificates_archive = self.certificates_dir / "certs_export.cert"

    async def sevctl_cmd(self, *args) -> bytes:
        result = await run_in_subprocess(
            ["sevctl", *args],
            check=True,
        )

        return result

    async def export_certificates(self):
        _ = await self.sevctl_cmd("export", self.certificates_archive)
