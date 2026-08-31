"""Frozen Python oracles for the Rust-daemon conformance suite.

These were the Python supervisor daemon's own code (``networking_db.py`` and
``qemu_build.spec_from_controller_configuration``), copied verbatim when the
Python daemon was removed so the conformance assertions keep their meaning:
the Rust daemon must still read the exact SQLAlchemy-defined port_mappings
schema (same DDL, same partial unique index) and still serve the exact
CreateVmSpec reconstruction for a persisted controller configuration.

Nothing under src/ uses this module; edit it only to record a deliberate
schema or reconstruction change on the Rust side.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import DirectoryPath
from sqlalchemy import Boolean, Column, DateTime, Index, Integer, String
from sqlalchemy.orm import declarative_base

from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    QemuConfidentialVMConfiguration,
    QemuVMConfiguration,
)
from aleph.vm.supervisor_interface.errors import InvalidBackendError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    TeeBackend,
    TeeConfig,
    VmId,
)

Base: Any = declarative_base()


class PortMapping(Base):
    """The supervisor.sqlite3 port_mappings table as the Python daemon defined it."""

    __tablename__ = "port_mappings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vm_hash = Column(String, nullable=False, index=True)
    vm_port = Column(Integer, nullable=False)
    host_port = Column(Integer, nullable=False)
    tcp = Column(Boolean, default=False, nullable=False)
    udp = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, nullable=False)
    deleted_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index(
            "ix_port_mappings_host_port_active",
            host_port,
            unique=True,
            sqlite_where=deleted_at.is_(None),
        ),
    )

    def __repr__(self):
        return f"<PortMapping(vm_hash={self.vm_hash}, vm_port={self.vm_port}, host_port={self.host_port})>"


def spec_from_controller_configuration(config: Configuration) -> CreateVmSpec:
    """Reconstruct a CreateVmSpec from an on-disk controller Configuration.

    The inverse of the Python daemon's build_qemu_configuration /
    build_qemu_confidential_configuration, used by reboot-recovery to reattach
    a running VM message-free. Plain and confidential (SEV) QEMU configs are
    both supported; the difference is the reconstructed TeeConfig.
    """
    vm_cfg = config.vm_configuration
    if not isinstance(vm_cfg, QemuVMConfiguration | QemuConfidentialVMConfiguration):
        msg = f"Reattach supports QEMU configurations only, got {type(vm_cfg).__name__}"
        raise InvalidBackendError(msg)

    disks: list[DiskSpec] = [
        DiskSpec(
            path=Path(vm_cfg.image_path),
            readonly=False,
            format=DiskFormat.QCOW2,
            role=DiskRole.ROOTFS,
        )
    ] + [
        DiskSpec(
            path=v.path_on_host,
            readonly=v.read_only,
            format=DiskFormat.RAW,
            role=DiskRole.EXTRA,
        )
        for v in vm_cfg.host_volumes
    ]

    gpus = [GpuSpec(pci_host=PciAddress(g.pci_host), supports_x_vga=g.supports_x_vga) for g in vm_cfg.gpus]

    tee: TeeConfig | None = None
    if isinstance(vm_cfg, QemuConfidentialVMConfiguration):
        # The on-disk OVMF path is the resolved firmware, the SEV policy
        # crosses back as a hex string (matching the message path's
        # hex(trusted_execution.policy)), and the session dir is where the
        # owner's uploaded certs already live.
        tee = TeeConfig(
            backend=TeeBackend.SEV,
            policy=hex(vm_cfg.sev_policy),
            session_dir=DirectoryPath(vm_cfg.sev_session_file.parent),
            firmware_path=Path(vm_cfg.ovmf_path),
        )

    return CreateVmSpec(
        vm_id=VmId(str(config.vm_hash)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=vm_cfg.vcpu_count,
        memory_mib=vm_cfg.mem_size_mb.count,
        tee=tee,
        network=NetworkConfig(
            internet_access=bool(vm_cfg.interface_name),
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=gpus,
        numa_node=None,
        persistent=True,
    )
