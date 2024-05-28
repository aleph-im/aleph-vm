import subprocess
from pathlib import Path


class SevClient:
    def __init__(self, sev_dir: Path):
        self.sev_dir = sev_dir
        self.certificates_dir = sev_dir / "platform"
        self.certificates_dir.mkdir(exist_ok=True, parents=True)
        self.certificates_archive = self.certificates_dir / "certs_export.cert"

    def sevctl_cmd(self, *args) -> subprocess.CompletedProcess:
        result = subprocess.run(
            ["sevctl", *args],
            capture_output=True,
            text=True,
        )

        return result

    def export_certificates(self):
        _ = self.sevctl_cmd("export", self.certificates_archive)
