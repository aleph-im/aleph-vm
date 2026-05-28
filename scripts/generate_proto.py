#!/usr/bin/env python3
"""Generate Python bindings for proto/hypervisor.proto.

Idempotent. Run from the repo root: `python scripts/generate_proto.py`.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROTO_DIR = REPO / "proto"
OUT_DIR = REPO / "src" / "aleph" / "vm" / "hypervisor" / "_pb"
PROTO_FILE = PROTO_DIR / "hypervisor.proto"


def main() -> int:
    if not PROTO_FILE.exists():
        print(f"proto file not found: {PROTO_FILE}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "grpc_tools.protoc",
        f"--proto_path={PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        f"--mypy_out={OUT_DIR}",  # requires mypy-protobuf installed
        str(PROTO_FILE),
    ]
    # Ensure the venv bin (where protoc-gen-mypy lives) is on PATH.
    env = os.environ.copy()
    venv_bin = Path(sys.executable).parent
    env["PATH"] = str(venv_bin) + os.pathsep + env.get("PATH", "")

    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO, env=env)
    if result.returncode != 0:
        return result.returncode

    # The grpc plugin emits a `from hypervisor_pb2 import ...` line that
    # breaks when the package is imported via its dotted name. Rewrite
    # to a relative import.
    grpc_file = OUT_DIR / "hypervisor_pb2_grpc.py"
    text = grpc_file.read_text()
    text = text.replace(
        "import hypervisor_pb2 as hypervisor__pb2",
        "from . import hypervisor_pb2 as hypervisor__pb2",
    )
    grpc_file.write_text(text)
    print(f"rewrote {grpc_file} to use relative import")

    return 0


if __name__ == "__main__":
    sys.exit(main())
