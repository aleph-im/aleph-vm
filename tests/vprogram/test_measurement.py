"""Tests for the transient sev-snp-measure launch-measurement wrapper.

The `sev-snp-measure` library validates real firmware structure (OVMF footer
GUID table + SEV metadata section describing where kernel/initrd/cmdline
hashes live), so a genuinely trivial OVMF blob is rejected. `_build_fake_ovmf`
constructs the minimal binary structure the library requires -- a page-sized
firmware image with a valid GUID footer table (SEV_ES_RESET_BLOCK,
SEV_HASH_TABLE_RV, OVMF_SEV_META_DATA entries) and one SNP_KERNEL_HASHES
metadata section -- so the determinism and cmdline-sensitivity checks below
exercise the real digest computation rather than being skipped.
"""

import struct
import uuid
from pathlib import Path

import pytest

from aleph.vm.vprogram.measurement import compute_snp_measurement

sevsnpmeasure = pytest.importorskip("sevsnpmeasure")

_PAGE = 4096
_ENTRY_HEADER_SIZE = 18  # OvmfFooterTableEntry: uint16 size + 16-byte GUID
_OVMF_TABLE_FOOTER_GUID = "96b582de-1fb2-45f7-baea-a366c55a082d"
_SEV_HASH_TABLE_RV_GUID = "7255371f-3a3b-4b04-927b-1da6efa8d454"
_SEV_ES_RESET_BLOCK_GUID = "00f771de-1a7e-4fcb-890e-68c77e2fb44e"
_OVMF_SEV_META_DATA_GUID = "dc886566-984a-4798-a75e-5585a7bf67cc"
_SNP_KERNEL_HASHES_SECTION_TYPE = 0x10


def _footer_entry(guid: str, data: bytes) -> bytes:
    """One GUID-tagged entry in the OVMF footer table: [data][size:u16][guid:16]."""
    size = len(data) + _ENTRY_HEADER_SIZE
    return data + struct.pack("<H", size) + uuid.UUID(guid).bytes_le


def _build_fake_ovmf(tmp_path: Path, *, kernel_hashes_gpa: int = 0x800000) -> Path:
    """A minimal-but-structurally-valid fake OVMF firmware image: one page,
    with just enough GUID footer table + SEV metadata for sev-snp-measure's
    SNP code path (kernel/initrd/cmdline hashing) to run without real
    firmware content."""
    total_size = _PAGE

    # SEV metadata blob (OvmfSevMetadataHeader + one section descriptor),
    # placed at file offset 0: signature 'ASEV', version 1, one
    # SNP_KERNEL_HASHES section.
    metadata = b"ASEV" + struct.pack("<III", 16 + 12, 1, 1)
    metadata += struct.pack("<III", kernel_hashes_gpa, _PAGE, _SNP_KERNEL_HASHES_SECTION_TYPE)

    entries = (
        _footer_entry(_SEV_ES_RESET_BLOCK_GUID, struct.pack("<I", 0x10000))
        + _footer_entry(_SEV_HASH_TABLE_RV_GUID, struct.pack("<I", kernel_hashes_gpa))
        + _footer_entry(_OVMF_SEV_META_DATA_GUID, struct.pack("<I", total_size))
    )
    footer = struct.pack("<H", len(entries) + _ENTRY_HEADER_SIZE) + uuid.UUID(_OVMF_TABLE_FOOTER_GUID).bytes_le
    tail = entries + footer + bytes(32)  # 32 reserved bytes after the footer entry

    data = bytearray(total_size)
    data[: len(metadata)] = metadata
    data[total_size - len(tail) :] = tail

    path = tmp_path / "OVMF.fd"
    path.write_bytes(bytes(data))
    return path


@pytest.fixture()
def fixtures(tmp_path: Path) -> dict[str, Path]:
    ovmf = _build_fake_ovmf(tmp_path)
    kernel = tmp_path / "bzImage"
    kernel.write_bytes(b"fake-kernel-bytes")
    initrd = tmp_path / "initrd"
    initrd.write_bytes(b"fake-initrd-bytes")
    return {"ovmf": ovmf, "kernel": kernel, "initrd": initrd}


def test_measurement_is_deterministic_and_96_hex(fixtures: dict[str, Path]) -> None:
    kwargs = {
        "ovmf": fixtures["ovmf"],
        "kernel": fixtures["kernel"],
        "initrd": fixtures["initrd"],
        "cmdline": "console=ttyS0",
        "vcpus": 2,
        "vcpu_type": "EPYC-v4",
    }
    first = compute_snp_measurement(**kwargs)
    second = compute_snp_measurement(**kwargs)

    assert first == second
    assert len(first) == 96
    assert first == first.lower()
    assert all(c in "0123456789abcdef" for c in first)


def test_cmdline_changes_measurement(fixtures: dict[str, Path]) -> None:
    base = {
        "ovmf": fixtures["ovmf"],
        "kernel": fixtures["kernel"],
        "initrd": fixtures["initrd"],
        "vcpus": 2,
        "vcpu_type": "EPYC-v4",
    }
    first = compute_snp_measurement(cmdline="console=ttyS0 root=/dev/vda", **base)
    second = compute_snp_measurement(cmdline="console=ttyS0 root=/dev/vdb", **base)

    assert first != second
