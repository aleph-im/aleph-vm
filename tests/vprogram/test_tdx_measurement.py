"""Tests for the TDX measurement predictor.

The synthetic PE and TDVF built here are byte-identical to the ones in
rust/crates/aleph-tee/src/tdx/measure.rs's tests, and the pinned digests are
shared, so the two implementations cannot drift apart unnoticed. The
hardware vectors (QEMU 10.2.4 + edk2 202602 TDVF + Ubuntu 7.0.0-34 kernel)
live in rust/crates/aleph-tee/tests/fixtures/tdx/README.md; the ones that
need no multi-megabyte input are asserted here too.
"""

import hashlib
import json
import struct
import uuid
from pathlib import Path

import pytest

from aleph.vm.vprogram import tdx_measurement as m

HW_CMDLINE = "root=LABEL=cloudimg-rootfs ro console=ttyS0"
HW_LOAD_OPTIONS = "b8c85d40a1d555a451571e24d7d7c4c331bc15721d6e4b2a5cb5093214c44174822a0916aa4d622d4309644de99cd59c"
HW_INITRD_SHA384 = "88de90bedcc560064688c74ccd6609a25ed9d48b0a0e13d8b2a558212724d8755b2c8114dcf04b8d51ea4cf7782e3091"
HW_RTMR2 = "972547466cb6bcb8a23cd479e9258c3affbbc4f0ba2805d732477200d0dff8432447c7a775e70453cdb51f018a306ece"

# Pinned in the Rust tests as well.
SYNTHETIC_PE_AUTHENTICODE = (
    "27ca0b497c08dcf49e302a2dd4bbe74889b19d0d1af84364c8cad3472d5ba1bfda1e7cfe7fb94848d491cdfd2a163410"
)
SYNTHETIC_MRTD = "168f5582b72265ed01aad1edd402f5d096c12d95385b5f38959b5cc8c128e6efe6e13e854e211a1ee4e4a4eeafa36fa6"

PE_SIZE_OF_HEADERS = 0x200
PE_CHECKSUM = 0x58 + 64
PE_SECURITY_DIR = 0x58 + 112 + 32


def sha384(data: bytes) -> bytes:
    return hashlib.sha384(data).digest()


def _build_pe(num_rva_and_sizes: int = 16, cert_size: int = 0x20) -> bytes:
    """PE32+ with two sections listed out of file order, 32 B of trailing data
    and a 32 B certificate table; every non-header byte follows a pattern so
    range mistakes change the digest."""
    pe = bytearray(((i * 7 + 3) & 0xFF) for i in range(0x440))
    pe[:64] = bytes(64)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x40)
    pe[0x40:0x44] = b"PE\0\0"
    coff = 0x44
    pe[coff : coff + 20] = bytes(20)
    struct.pack_into("<HH", pe, coff, 0x8664, 2)
    struct.pack_into("<H", pe, coff + 16, 240)
    opt = coff + 20
    pe[opt : opt + 240] = bytes(240)
    struct.pack_into("<H", pe, opt, 0x20B)
    struct.pack_into("<I", pe, opt + 60, PE_SIZE_OF_HEADERS)
    struct.pack_into("<I", pe, opt + 64, 0x12345678)
    struct.pack_into("<I", pe, opt + 108, num_rva_and_sizes)
    struct.pack_into("<II", pe, opt + 112 + 32, 0x420, cert_size)
    table = opt + 240
    pe[table : table + 80] = bytes(80)
    for i, (name, ptr) in enumerate(((b".text\0\0\0", 0x300), (b".data\0\0\0", 0x200))):
        hdr = table + i * 40
        pe[hdr : hdr + 8] = name
        struct.pack_into("<II", pe, hdr + 16, 0x100, ptr)
    return bytes(pe)


def _footer_entry(guid: bytes, data: bytes) -> bytes:
    return data + struct.pack("<H", len(data) + 18) + guid


def _section(*fields: int) -> bytes:
    """data_offset, raw_data_size, memory_address, memory_data_size, type, attributes."""
    return struct.pack("<IIQQII", *fields)


def _build_tdvf() -> bytes:
    """Three-page firmware: pages 0 and 1 are a measured BFV and CFV, page 2
    holds the TDVF descriptor and the footer table. TD_HOB gets two PAGE.ADDs,
    TEMP_MEM is PAGE_AUG (nothing)."""
    fw = bytearray(((i * 13 + 5) & 0xFF) for i in range(0x3000))
    desc = b"TDVF" + struct.pack("<III", 16 + 4 * 32, 1, 4)
    desc += _section(0x0000, 0x1000, 0xFFFFF000, 0x1000, 0, 0x1)
    desc += _section(0x1000, 0x1000, 0xFFFFE000, 0x1000, 1, 0x1)
    desc += _section(0, 0, 0x00809000, 0x2000, 2, 0)
    desc += _section(0, 0, 0x0080B000, 0x1000, 3, 0x2)
    desc_at = 0x2000
    fw[desc_at : desc_at + len(desc)] = desc
    metadata_guid = uuid.UUID("e47a6535-984a-4798-865e-4685a7bf8ec2").bytes_le
    footer_guid = uuid.UUID("96b582de-1fb2-45f7-baea-a366c55a082d").bytes_le
    entries = (
        _footer_entry(bytes([0x11]) * 16, b"unrelated")
        + _footer_entry(metadata_guid, struct.pack("<I", len(fw) - desc_at))
        + _footer_entry(bytes([0x22]) * 16, bytes([0xAB]) * 4)
    )
    tail = entries + struct.pack("<H", len(entries) + 18) + footer_guid + bytes(32)
    fw[len(fw) - len(tail) :] = tail
    return bytes(fw)


def test_rtmr_replay_starts_at_zero_and_chains() -> None:
    assert m.rtmr_replay([]) == bytes(48)
    a, b = sha384(b"a"), sha384(b"b")
    expect = sha384(sha384(bytes(48) + a) + b)
    assert m.rtmr_replay([a, b]) == expect
    assert m.rtmr_replay([b, a]) != expect
    with pytest.raises(ValueError, match="48 bytes"):
        m.rtmr_replay([b"short"])


def test_rtmr1_tail_event_digests() -> None:
    expected = [
        "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
        "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
        "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
        "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
    ]
    assert [sha384(e).hex() for e in m.RTMR1_TAIL_EVENTS] == expected


def test_load_options_prefix_initrd_and_terminate() -> None:
    assert m.load_options_digest("x") == sha384("initrd=initrd x".encode("utf-16-le") + b"\0\0")
    assert m.load_options_digest(HW_CMDLINE).hex() == HW_LOAD_OPTIONS


def test_rtmr2_matches_hardware_from_component_digests() -> None:
    assert m.rtmr_replay([bytes.fromhex(HW_LOAD_OPTIONS), bytes.fromhex(HW_INITRD_SHA384)]).hex() == HW_RTMR2
    assert m.rtmr2("c", b"i") == m.rtmr_replay([m.load_options_digest("c"), sha384(b"i")])


def test_mrconfigid_is_sha384_of_the_suffix() -> None:
    assert m.mrconfigid("") == sha384(b"")
    suffix = "workload_roothash=00ff swiotlb=262144"
    assert m.mrconfigid(suffix) == sha384(suffix.encode())


def test_authenticode_skips_checksum_security_dir_and_cert_table() -> None:
    pe = _build_pe()
    expected = sha384(
        pe[:PE_CHECKSUM]
        + pe[PE_CHECKSUM + 4 : PE_SECURITY_DIR]
        + pe[PE_SECURITY_DIR + 8 : PE_SIZE_OF_HEADERS]
        + pe[0x200:0x300]  # .data, listed second, comes first in the file
        + pe[0x300:0x400]  # .text
        + pe[0x400:0x420]  # trailing data before the certificate table
    )
    got = m.authenticode_sha384(pe)
    assert got == expected
    assert got.hex() == SYNTHETIC_PE_AUTHENTICODE


def test_authenticode_without_data_directories_hashes_all_trailing_data() -> None:
    pe = _build_pe(num_rva_and_sizes=4)
    expected = sha384(pe[:PE_CHECKSUM] + pe[PE_CHECKSUM + 4 : PE_SIZE_OF_HEADERS] + pe[0x200:0x440])
    assert m.authenticode_sha384(pe) == expected


def test_authenticode_rejects_bad_images() -> None:
    with pytest.raises(ValueError, match="outside the image"):
        m.authenticode_sha384(b"short")
    pe = bytearray(_build_pe())
    pe[0x40] = ord("X")
    with pytest.raises(ValueError, match="not a PE"):
        m.authenticode_sha384(bytes(pe))
    with pytest.raises(ValueError, match="certificate table"):
        m.authenticode_sha384(_build_pe(cert_size=0x41))
    pe = bytearray(_build_pe())
    struct.pack_into("<I", pe, 0x58 + 240 + 20, 0x400)
    with pytest.raises(ValueError, match="section"):
        m.authenticode_sha384(bytes(pe))


def test_rtmr1_chains_kernel_digest_and_tail_events() -> None:
    pe = _build_pe()
    events = [m.authenticode_sha384(pe), *(sha384(e) for e in m.RTMR1_TAIL_EVENTS)]
    assert m.rtmr1(pe) == m.rtmr_replay(events)


def test_mrtd_walks_measured_sections_only() -> None:
    fw = _build_tdvf()
    base = m.mrtd(fw)
    assert base.hex() == SYNTHETIC_MRTD

    def flipped(offset: int, mask: int = 1) -> bytes:
        fw2 = bytearray(fw)
        fw2[offset] ^= mask
        return bytes(fw2)

    # A measured byte moves it; a byte in the descriptor page outside the
    # descriptor and table does not.
    assert m.mrtd(flipped(0x123)) != base
    assert m.mrtd(flipped(0x2800)) == base
    # The TD_HOB address is part of every PAGE.ADD.
    assert m.mrtd(flipped(0x2000 + 16 + 2 * 32 + 9, 0x10)) != base
    # The PAGE_AUG section contributes nothing: moving it changes nothing.
    assert m.mrtd(flipped(0x2000 + 16 + 3 * 32 + 9, 0x10)) == base


def test_mrtd_rejects_firmware_without_tdx_metadata() -> None:
    fw = bytearray(_build_tdvf())
    at = len(fw) - 32 - 18 - (4 + 18) - 16
    fw[at : at + 16] = bytes([0x33]) * 16
    with pytest.raises(ValueError, match="has no"):
        m.mrtd(bytes(fw))
    with pytest.raises(ValueError, match="footer table GUID"):
        m.mrtd(bytes(100))
    with pytest.raises(ValueError, match="too small"):
        m.mrtd(b"tiny")
    fw = bytearray(_build_tdvf())
    fw[0x2000:0x2004] = b"XXXX"
    with pytest.raises(ValueError, match="signature"):
        m.mrtd(bytes(fw))
    fw = bytearray(_build_tdvf())
    struct.pack_into("<I", fw, 0x2000 + 16 + 32 + 4, 0x800)
    with pytest.raises(ValueError, match="partly backed"):
        m.mrtd(bytes(fw))


def test_measure_runtime_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    fw, pe, initrd, cmdline = _build_tdvf(), _build_pe(), b"initrd", "console=ttyS0"
    got = m.measure_runtime(tdvf=fw, kernel=pe, cmdline=cmdline, initrd=initrd)
    assert got == m.TdxMeasurements(mrtd=m.mrtd(fw), rtmr1=m.rtmr1(pe), rtmr2=m.rtmr2(cmdline, initrd))

    (tmp_path / "OVMF.fd").write_bytes(fw)
    (tmp_path / "bzImage").write_bytes(pe)
    (tmp_path / "initrd").write_bytes(initrd)
    argv = ["--tdvf", str(tmp_path / "OVMF.fd"), "--kernel", str(tmp_path / "bzImage")]
    argv += ["--initrd", str(tmp_path / "initrd"), "--cmdline", cmdline]
    assert m.main(argv) == 0
    assert json.loads(capsys.readouterr().out) == got.to_dict()
    assert set(got.to_dict()) == {"mrtd", "rtmr1", "rtmr2"}
    assert all(len(v) == 96 for v in got.to_dict().values())
