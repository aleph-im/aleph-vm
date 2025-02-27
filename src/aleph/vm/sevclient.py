from pathlib import Path

from aleph.vm.utils import run_in_subprocess


class SevClient:
    sev_dir: Path
    sev_ctl_executable: Path
    certificates_dir: Path
    certificates_archive: Path

    def __init__(self, sev_dir: Path, sev_ctl_executable: Path):
        self.sev_dir = sev_dir
        self.sev_ctl_executable = sev_ctl_executable
        self.certificates_dir = sev_dir / "platform"
        self.certificates_dir.mkdir(exist_ok=True, parents=True)
        self.certificates_archive = self.certificates_dir / "certs_export.cert"

    async def sev_ctl_cmd(self, *args) -> bytes:
        """Run a command of the 'sevctl' tool."""
        return await run_in_subprocess(
            [str(self.sev_ctl_executable), *args],
            check=True,
        )

    async def get_certificates(self) -> Path:
        if not self.certificates_archive.is_file():
            _ = await self.sev_ctl_cmd("export", str(self.certificates_archive))

        return self.certificates_archive
