"""Directory-based VM export/import: the manifest format.

The migration contract (ExportVm / ImportVm) moves a VM through a
host-local directory: export writes standalone disk images plus a
manifest; import verifies the disks against it and recreates the VM from
the spec it records. Moving the directory between hosts is the caller's
business (the agent, or an external orchestrator).

The spec is serialized through its proto encoding (CreateVmSpec ⇄
pb.CreateVmSpec ⇄ JSON): the proto already is the cross-version schema of
the spec, so the manifest inherits its compatibility story instead of
inventing a second serialization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from google.protobuf import json_format

from aleph.vm.supervisor import proto_convert as conv
from aleph.vm.supervisor._pb import supervisor_pb2 as pb
from aleph.vm.supervisor.errors import InternalSupervisorError, MigrationNotFoundError
from aleph.vm.supervisor.types import CreateVmSpec, VmId

MANIFEST_NAME = "manifest.json"
MANIFEST_FORMAT = 1


@dataclass(frozen=True)
class ManifestDisk:
    """One exported disk file, in spec order (index i is spec.disks[i])."""

    name: str
    sha256: str
    size_bytes: int


def disk_file_name(index: int, fmt_value: str) -> str:
    """The on-disk name of exported disk *index* (e.g. ``disk0.qcow2``)."""
    return f"disk{index}.{fmt_value}"


def write_manifest(destination_dir: Path, spec: CreateVmSpec, disks: list[ManifestDisk]) -> Path:
    manifest = {
        "format": MANIFEST_FORMAT,
        "vm_id": str(spec.vm_id),
        "spec": json_format.MessageToDict(conv.create_vm_spec_to_pb(spec)),
        "disks": [{"name": d.name, "sha256": d.sha256, "size_bytes": d.size_bytes} for d in disks],
    }
    path = destination_dir / MANIFEST_NAME
    path.write_text(json.dumps(manifest, indent=2))
    return path


def read_manifest(source_dir: Path, vm_id: VmId) -> tuple[CreateVmSpec, list[ManifestDisk]]:
    """Load and validate the manifest of an exported VM directory.

    Raises MigrationNotFoundError when the directory holds no manifest,
    InternalSupervisorError when it is malformed or for another VM.
    """
    path = source_dir / MANIFEST_NAME
    if not path.exists():
        raise MigrationNotFoundError(f"no migration manifest in {source_dir}")
    try:
        manifest = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        msg = f"unreadable migration manifest {path}: {exc}"
        raise InternalSupervisorError(msg) from exc

    if manifest.get("format") != MANIFEST_FORMAT:
        msg = f"unsupported migration manifest format {manifest.get('format')!r} (expected {MANIFEST_FORMAT})"
        raise InternalSupervisorError(msg)
    if manifest.get("vm_id") != str(vm_id):
        msg = f"migration manifest in {source_dir} is for VM {manifest.get('vm_id')!r}, not {vm_id}"
        raise InternalSupervisorError(msg)

    try:
        spec_pb = json_format.ParseDict(manifest["spec"], pb.CreateVmRequest())
        spec = conv.create_vm_spec_from_pb(spec_pb)
        disks = [
            ManifestDisk(name=d["name"], sha256=d["sha256"], size_bytes=int(d["size_bytes"])) for d in manifest["disks"]
        ]
    except (KeyError, TypeError, ValueError, json_format.ParseError) as exc:
        msg = f"malformed migration manifest {path}: {exc}"
        raise InternalSupervisorError(msg) from exc

    if len(disks) != len(spec.disks):
        msg = f"migration manifest {path} lists {len(disks)} disk files for {len(spec.disks)} spec disks"
        raise InternalSupervisorError(msg)
    return spec, disks
