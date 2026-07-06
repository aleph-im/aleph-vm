"""Generate the Rust daemon's test fixtures from the actual Python models.

Writes, under rust/crates/supervisor-daemon/tests/fixtures/:
- three controller configuration JSONs (plain QEMU, QEMU with GPU,
  confidential QEMU), serialized by the pydantic ``Configuration`` model
  exactly as ``save_controller_configuration`` writes them;
- ``supervisor.sqlite3``, a port-mapping store created and populated by the
  SQLAlchemy ``PortMapping`` model (same schema, same datetime encoding as
  a live node's database).

The fixtures are committed; regenerate them after a model change with:

    venv/bin/python scripts/generate_rust_fixtures.py

The VM hashes are sha256("rust-fixture-<name>") and must match the
constants in rust/crates/supervisor-daemon/src/test_fixtures.rs.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from aleph.vm.supervisor.networking_db import Base, PortMapping
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    ControllerSettings,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "rust/crates/supervisor-daemon/tests/fixtures"

EXECUTION_ROOT = Path("/var/lib/aleph/vm")
VOLUMES_DIR = EXECUTION_ROOT / "volumes/persistent"


def fixture_hash(name: str) -> str:
    return hashlib.sha256(f"rust-fixture-{name}".encode()).hexdigest()


QEMU_HASH = fixture_hash("qemu")
GPU_HASH = fixture_hash("gpu")
CONFIDENTIAL_HASH = fixture_hash("confidential")
PORTS_ONLY_HASH = fixture_hash("ports-only")


def qemu_vm_configuration(vm_hash: str, **overrides) -> dict:
    base = {
        "qemu_bin_path": "/usr/bin/qemu-system-x86_64",
        "cloud_init_drive_path": str(EXECUTION_ROOT / f"cloud-init-{vm_hash}.img"),
        "image_path": str(VOLUMES_DIR / vm_hash / "rootfs.qcow2"),
        "monitor_socket_path": EXECUTION_ROOT / f"{vm_hash}-monitor.socket",
        "qmp_socket_path": EXECUTION_ROOT / f"{vm_hash}-qmp.socket",
        "qga_socket_path": EXECUTION_ROOT / f"{vm_hash}-qga.socket",
        "vcpu_count": 2,
        "mem_size_mb": 2048,
        "interface_name": "vmtap3",
        "host_volumes": [],
        "gpus": [],
    }
    base.update(overrides)
    return base


def write_configuration(vm_hash: str, configuration: Configuration) -> None:
    # Same serialization as save_controller_configuration.
    path = FIXTURES_DIR / f"{vm_hash}-controller.json"
    path.write_text(configuration.model_dump_json(by_alias=True, exclude_none=True, indent=4))
    print(f"wrote {path}")


def build_configurations() -> None:
    settings_slice = ControllerSettings()

    write_configuration(
        QEMU_HASH,
        Configuration(
            vm_id=3,
            vm_hash=QEMU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **qemu_vm_configuration(
                    QEMU_HASH,
                    host_volumes=[
                        QemuVMHostVolume(
                            mount="",
                            path_on_host=VOLUMES_DIR / QEMU_HASH / "data.qcow2",
                            read_only=False,
                        )
                    ],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )

    write_configuration(
        GPU_HASH,
        Configuration(
            vm_id=4,
            vm_hash=GPU_HASH,
            settings=settings_slice,
            vm_configuration=QemuVMConfiguration(
                **qemu_vm_configuration(
                    GPU_HASH,
                    interface_name="vmtap4",
                    gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True)],
                )
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )

    session_dir = Path("/var/lib/aleph/vm/confidential_sessions") / CONFIDENTIAL_HASH
    write_configuration(
        CONFIDENTIAL_HASH,
        Configuration(
            vm_id=5,
            vm_hash=CONFIDENTIAL_HASH,
            settings=settings_slice,
            vm_configuration=QemuConfidentialVMConfiguration(
                **qemu_vm_configuration(CONFIDENTIAL_HASH, interface_name="vmtap5"),
                ovmf_path=Path("/opt/aleph-vm/firmware/OVMF_CSV.fd"),
                sev_session_file=session_dir / "vm_session.b64",
                sev_dh_cert_file=session_dir / "vm_godh.b64",
                # NO_DBG | SEV_ES: the SEV-ES bit (0x4) must be set so the
                # Rust confidential_mode mapping is exercised.
                sev_policy=0x5,
            ),
            hypervisor=HypervisorType.qemu,
        ),
    )


def build_database() -> None:
    db_path = FIXTURES_DIR / "supervisor.sqlite3"
    db_path.unlink(missing_ok=True)
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    # A fixed instant keeps regeneration byte-stable: rerunning the script
    # must produce a zero diff on the committed sqlite file.
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    with Session(engine) as session:
        # A soft-deleted mapping: must never surface.
        session.add(
            PortMapping(
                vm_hash=QEMU_HASH,
                vm_port=22,
                host_port=24022,
                tcp=True,
                udp=False,
                created_at=now,
                deleted_at=now,
            )
        )
        # The active mappings of the QEMU fixture VM.
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=22, host_port=24000, tcp=True, udp=False, created_at=now))
        session.add(PortMapping(vm_hash=QEMU_HASH, vm_port=8080, host_port=24001, tcp=True, udp=True, created_at=now))
        # A mapping for a VM with no controller config: the world view must
        # never surface it.
        session.add(
            PortMapping(
                vm_hash=PORTS_ONLY_HASH,
                vm_port=443,
                host_port=24002,
                tcp=True,
                udp=False,
                created_at=now,
            )
        )
        session.commit()
    print(f"wrote {db_path}")


def main() -> None:
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    build_configurations()
    build_database()


if __name__ == "__main__":
    main()
