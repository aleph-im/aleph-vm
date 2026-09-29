"""Intel TDX boot measurement prediction: MRTD, RTMR1, RTMR2 and MRCONFIGID.

Replays what the TDX module and the edk2 IntelTdxX64 TDVF extend when QEMU
direct-boots a kernel, so the registers can be pinned from the published
runtime files alone:

- MRTD: the TDVF metadata walk, one TDH.MEM.PAGE.ADD per 4 KiB page and one
  TDH.MR.EXTEND per 256 B chunk of the measured sections.
- RTMR1: the Authenticode SHA-384 of the raw kernel PE (QEMU does not patch
  the setup header under confidential-guest-support), then four constant
  edk2 boot events.
- RTMR2: the kernel LoadOptions (`initrd=initrd ` prefixed to the cmdline,
  UTF-16LE, NUL-terminated) then the initrd bytes.
- MRCONFIGID: SHA-384 of the per-deployment descriptor suffix.

Mirror of `aleph_tee::tdx::measure` (rust/crates/aleph-tee/src/tdx/measure.rs);
both are tested on the same synthetic vectors. Standard library only, so nix
can run this file as a plain script against the built TDVF, kernel and initrd:

    python -m aleph.vm.vprogram.tdx_measurement --tdvf OVMF.fd --kernel bzImage \\
        --initrd initrd --cmdline "console=ttyS0 ..."
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

DIGEST_SIZE = 48
_PAGE_SIZE = 0x1000
_MR_EXTEND_CHUNK = 0x100

_ATTR_MR_EXTEND = 0x1
_ATTR_PAGE_AUG = 0x2

_TABLE_FOOTER_GUID = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d")
_TDX_METADATA_OFFSET_GUID = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2")
_FOOTER_ENTRY_HEADER = 18  # u16 size + 16-byte GUID
_BYTES_AFTER_FOOTER = 32
_TDVF_DESCRIPTOR_HEADER = 16
_TDVF_SECTION_SIZE = 32

_PE_SIGNATURE = b"PE\0\0"
_PE32_PLUS_MAGIC = 0x20B
_DIRECTORY_ENTRY_SECURITY = 4
_SECTION_HEADER_SIZE = 40

# edk2 TdTcg2Dxe events after the kernel image measurement, in extend order.
RTMR1_TAIL_EVENTS: tuple[bytes, ...] = (
    b"Calling EFI Application from Boot Option",
    b"\x00\x00\x00\x00",
    b"Exit Boot Services Invocation",
    b"Exit Boot Services Returned with Success",
)


def _sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def rtmr_replay(digests: Iterable[bytes]) -> bytes:
    """Extend a zeroed RTMR with each event digest: new = sha384(old || digest)."""
    register = bytes(DIGEST_SIZE)
    for digest in digests:
        if len(digest) != DIGEST_SIZE:
            msg = f"event digest must be {DIGEST_SIZE} bytes, got {len(digest)}"
            raise ValueError(msg)
        register = _sha384(register + digest)
    return register


# --- MRTD -------------------------------------------------------------------


@dataclass(frozen=True)
class _TdvfSection:
    data_offset: int
    raw_data_size: int
    memory_address: int
    memory_data_size: int
    section_type: int
    attributes: int


def _find_footer_entry(fw: bytes, guid: uuid.UUID) -> bytes:
    """Locate one GUID-tagged entry of the OVMF footer table: [data][size:u16][guid:16]
    entries laid back to back, closed by the footer entry 32 bytes before EOF."""
    footer_end = len(fw) - _BYTES_AFTER_FOOTER
    footer_start = footer_end - _FOOTER_ENTRY_HEADER
    if footer_start < 0:
        msg = "firmware too small for an OVMF footer table"
        raise ValueError(msg)
    (footer_size,) = struct.unpack_from("<H", fw, footer_start)
    if fw[footer_start + 2 : footer_end] != _TABLE_FOOTER_GUID.bytes_le:
        msg = "OVMF footer table GUID not found"
        raise ValueError(msg)
    table_size = footer_size - _FOOTER_ENTRY_HEADER
    if table_size < 0 or table_size > footer_start:
        msg = "invalid OVMF footer table length"
        raise ValueError(msg)
    table = fw[footer_start - table_size : footer_start]
    while len(table) >= _FOOTER_ENTRY_HEADER:
        (entry_size,) = struct.unpack_from("<H", table, len(table) - _FOOTER_ENTRY_HEADER)
        entry_guid = table[len(table) - 16 :]
        if entry_size < _FOOTER_ENTRY_HEADER or entry_size > len(table):
            msg = "invalid OVMF footer table entry length"
            raise ValueError(msg)
        if entry_guid == guid.bytes_le:
            return table[len(table) - entry_size : len(table) - _FOOTER_ENTRY_HEADER]
        table = table[: len(table) - entry_size]
    msg = f"OVMF footer table has no {guid} entry"
    raise ValueError(msg)


def _tdvf_descriptor(fw: bytes) -> int:
    """Offset of the TDVF descriptor, reached through the footer table's
    metadata-offset entry (a u32 counted back from the end of the firmware)."""
    offset_entry = _find_footer_entry(fw, _TDX_METADATA_OFFSET_GUID)
    if len(offset_entry) != struct.calcsize("<I"):
        msg = "TDX metadata offset entry is not a u32"
        raise ValueError(msg)
    (from_end,) = struct.unpack("<I", offset_entry)
    if from_end == 0 or from_end > len(fw) or len(fw) - from_end + _TDVF_DESCRIPTOR_HEADER > len(fw):
        msg = "TDX metadata offset points outside the firmware"
        raise ValueError(msg)
    return len(fw) - from_end


def _check_section(fw: bytes, i: int, section: _TdvfSection) -> None:
    if section.memory_address % _PAGE_SIZE or section.memory_data_size % _PAGE_SIZE:
        msg = f"TDVF section {i} is not page aligned"
        raise ValueError(msg)
    if section.raw_data_size > section.memory_data_size:
        msg = f"TDVF section {i} raw data exceeds its memory size"
        raise ValueError(msg)
    # A measured section must be fully backed by file bytes (BFV and CFV are).
    if section.attributes & _ATTR_MR_EXTEND and section.raw_data_size != section.memory_data_size:
        msg = f"TDVF section {i} is measured but only partly backed by file data"
        raise ValueError(msg)
    if section.data_offset + section.raw_data_size > len(fw):
        msg = f"TDVF section {i} raw data extends past the firmware"
        raise ValueError(msg)


def parse_tdvf_sections(fw: bytes) -> list[_TdvfSection]:
    """The TDVF descriptor's section table."""
    desc = _tdvf_descriptor(fw)
    signature, _length, version, count = struct.unpack_from("<4sIII", fw, desc)
    if signature != b"TDVF":
        msg = "TDVF descriptor signature not found"
        raise ValueError(msg)
    if version != 1:
        msg = f"unsupported TDVF descriptor version {version}"
        raise ValueError(msg)
    table_start = desc + _TDVF_DESCRIPTOR_HEADER
    if table_start + count * _TDVF_SECTION_SIZE > len(fw):
        msg = "TDVF section table extends past the firmware"
        raise ValueError(msg)
    sections = []
    for i in range(count):
        fields = struct.unpack_from("<IIQQII", fw, table_start + i * _TDVF_SECTION_SIZE)
        section = _TdvfSection(*fields)
        _check_section(fw, i, section)
        sections.append(section)
    return sections


def mrtd(tdvf: bytes) -> bytes:
    """MRTD of a TD launched from this TDVF binary."""
    hasher = hashlib.sha384()
    for section in parse_tdvf_sections(tdvf):
        # PAGE_AUG sections are accepted by the guest later, nothing is added at build.
        page_add = not section.attributes & _ATTR_PAGE_AUG
        extend = bool(section.attributes & _ATTR_MR_EXTEND)
        if not (page_add or extend):
            continue
        for page in range(section.memory_data_size // _PAGE_SIZE):
            gpa = section.memory_address + page * _PAGE_SIZE
            if page_add:
                hasher.update(_op_buffer(b"MEM.PAGE.ADD", gpa))
            if extend:
                for chunk in range(_PAGE_SIZE // _MR_EXTEND_CHUNK):
                    hasher.update(_op_buffer(b"MR.EXTEND", gpa + chunk * _MR_EXTEND_CHUNK))
                    start = section.data_offset + page * _PAGE_SIZE + chunk * _MR_EXTEND_CHUNK
                    hasher.update(tdvf[start : start + _MR_EXTEND_CHUNK])
    return hasher.digest()


def _op_buffer(op: bytes, gpa: int) -> bytes:
    """The 128-byte buffer the TDX module hashes for one SEAMCALL: the
    operation name at 0 and the guest physical address at 16, zero elsewhere."""
    return op.ljust(16, b"\0") + struct.pack("<Q", gpa) + bytes(104)


# --- RTMR1 ------------------------------------------------------------------


def _hash_pe_headers(pe: bytes, hasher: hashlib._Hash) -> tuple[int, int, list[tuple[int, int]]]:
    """Hash the PE headers minus CheckSum and the security data directory.
    Returns SizeOfHeaders, the certificate table size and the (offset, size)
    of every non-empty section, in file order."""
    pe_offset = _unpack_at(pe, "<I", 0x3C)
    if pe[pe_offset : pe_offset + 4] != _PE_SIGNATURE:
        msg = "not a PE image"
        raise ValueError(msg)
    coff = pe_offset + 4
    num_sections = _unpack_at(pe, "<H", coff + 2)
    optional_header_size = _unpack_at(pe, "<H", coff + 16)
    optional = coff + 20
    pe32_plus = _unpack_at(pe, "<H", optional) == _PE32_PLUS_MAGIC
    checksum = optional + 64
    size_of_headers = _unpack_at(pe, "<I", optional + 60)
    num_rva_and_sizes = _unpack_at(pe, "<I", optional + (108 if pe32_plus else 92))
    security_dir = optional + (112 if pe32_plus else 96) + _DIRECTORY_ENTRY_SECURITY * 8
    if size_of_headers > len(pe):
        msg = "PE SizeOfHeaders exceeds the image"
        raise ValueError(msg)

    hasher.update(pe[:checksum])
    if num_rva_and_sizes <= _DIRECTORY_ENTRY_SECURITY:
        if size_of_headers < checksum + 4:
            msg = "PE SizeOfHeaders ends inside the optional header"
            raise ValueError(msg)
        cert_size = 0
        hasher.update(pe[checksum + 4 : size_of_headers])
    else:
        if size_of_headers < security_dir + 8:
            msg = "PE SizeOfHeaders ends inside the data directory"
            raise ValueError(msg)
        cert_size = _unpack_at(pe, "<I", security_dir + 4)
        hasher.update(pe[checksum + 4 : security_dir])
        hasher.update(pe[security_dir + 8 : size_of_headers])

    section_table = optional + optional_header_size
    sections = []
    for i in range(num_sections):
        header = section_table + i * _SECTION_HEADER_SIZE
        size_of_raw_data = _unpack_at(pe, "<I", header + 16)
        pointer_to_raw_data = _unpack_at(pe, "<I", header + 20)
        if size_of_raw_data:
            sections.append((pointer_to_raw_data, size_of_raw_data))
    # Stable sort by file offset, as edk2's insertion sort orders them.
    sections.sort(key=lambda s: s[0])
    return size_of_headers, cert_size, sections


def authenticode_sha384(pe: bytes) -> bytes:
    """Authenticode digest of a PE/COFF image, as edk2's MeasurePeImageAndExtend
    computes it: headers minus CheckSum and the security data directory,
    sections in file order, then any trailing data minus the certificate table."""
    hasher = hashlib.sha384()
    hashed, cert_size, sections = _hash_pe_headers(pe, hasher)
    for pointer, size in sections:
        if pointer + size > len(pe):
            msg = "PE section extends past the image"
            raise ValueError(msg)
        hasher.update(pe[pointer : pointer + size])
        hashed += size
    if len(pe) > hashed:
        if len(pe) < hashed + cert_size:
            msg = "PE certificate table larger than the trailing data"
            raise ValueError(msg)
        hasher.update(pe[hashed : len(pe) - cert_size])
    return hasher.digest()


def _unpack_at(data: bytes, fmt: str, offset: int) -> int:
    if offset < 0 or offset + struct.calcsize(fmt) > len(data):
        msg = f"PE header field at {offset:#x} is outside the image"
        raise ValueError(msg)
    (value,) = struct.unpack_from(fmt, data, offset)
    return value


def rtmr1(kernel: bytes) -> bytes:
    """RTMR1 after edk2 loaded and ran the kernel EFI stub."""
    events = [authenticode_sha384(kernel), *(_sha384(event) for event in RTMR1_TAIL_EVENTS)]
    return rtmr_replay(events)


# --- RTMR2 ------------------------------------------------------------------


def load_options_digest(cmdline: str) -> bytes:
    """Digest of the kernel LoadOptions edk2 measures: the initrd token first,
    then the cmdline, UTF-16LE with the terminating NUL."""
    return _sha384(("initrd=initrd " + cmdline).encode("utf-16-le") + b"\x00\x00")


def rtmr2(cmdline: str, initrd: bytes) -> bytes:
    """RTMR2 after edk2 measured the kernel command line and the initrd."""
    return rtmr_replay([load_options_digest(cmdline), _sha384(initrd)])


# --- MRCONFIGID -------------------------------------------------------------


def mrconfigid(suffix: str) -> bytes:
    """MRCONFIGID binding a deployment: SHA-384 of its rendered cmdline suffix."""
    return _sha384(suffix.encode())


# --- runtime triple ---------------------------------------------------------


@dataclass(frozen=True)
class TdxMeasurements:
    mrtd: bytes
    rtmr1: bytes
    rtmr2: bytes

    def to_dict(self) -> dict[str, str]:
        return {"mrtd": self.mrtd.hex(), "rtmr1": self.rtmr1.hex(), "rtmr2": self.rtmr2.hex()}


def measure_runtime(*, tdvf: bytes, kernel: bytes, cmdline: str, initrd: bytes) -> TdxMeasurements:
    """The per-runtime register triple for a TDVF + kernel + cmdline + initrd."""
    return TdxMeasurements(mrtd=mrtd(tdvf), rtmr1=rtmr1(kernel), rtmr2=rtmr2(cmdline, initrd))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Predict the TDX MRTD/RTMR1/RTMR2 of a direct-boot runtime.")
    parser.add_argument("--tdvf", type=Path, required=True, help="TDVF firmware (IntelTdxX64 OVMF.fd)")
    parser.add_argument("--kernel", type=Path, required=True, help="kernel bzImage")
    parser.add_argument("--initrd", type=Path, required=True, help="initrd image")
    parser.add_argument("--cmdline", required=True, help="kernel command line, without the initrd token")
    args = parser.parse_args(argv)
    measurements = measure_runtime(
        tdvf=args.tdvf.read_bytes(),
        kernel=args.kernel.read_bytes(),
        cmdline=args.cmdline,
        initrd=args.initrd.read_bytes(),
    )
    json.dump(measurements.to_dict(), sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
