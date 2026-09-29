//! Boot measurement prediction for a direct-booted TD: MRTD, RTMR1, RTMR2
//! and MRCONFIGID from the runtime files alone.
//!
//! Replays what the TDX module and the edk2 IntelTdxX64 TDVF extend when
//! QEMU direct-boots a kernel:
//!
//! - MRTD: the TDVF metadata walk, one TDH.MEM.PAGE.ADD per 4 KiB page and
//!   one TDH.MR.EXTEND per 256 B chunk of the measured sections.
//! - RTMR1: the Authenticode SHA-384 of the raw kernel PE (QEMU does not
//!   patch the setup header under confidential-guest-support), then four
//!   constant edk2 boot events.
//! - RTMR2: the kernel LoadOptions (`initrd=initrd ` prefixed to the
//!   cmdline, UTF-16LE, NUL-terminated) then the initrd bytes.
//! - MRCONFIGID: SHA-384 of the per-deployment descriptor suffix.
//!
//! RTMR0 (TD HOB, CFV, ACPI, boot variables) is deliberately not modelled:
//! it depends on the VM shape and is not pinned.
//!
//! `src/aleph/vm/vprogram/tdx_measurement.py` is the Python mirror; both are
//! tested on the same synthetic vectors.

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha384};

/// A SHA-384 register or event digest.
pub type Digest48 = [u8; 48];

const PAGE_SIZE: u64 = 0x1000;
const MR_EXTEND_CHUNK: usize = 0x100;
const ATTR_MR_EXTEND: u32 = 0x1;
const ATTR_PAGE_AUG: u32 = 0x2;

/// OVMF GUIDed footer table: `96b582de-1fb2-45f7-baea-a366c55a082d`, bytes_le.
const TABLE_FOOTER_GUID: [u8; 16] = [
    0xde, 0x82, 0xb5, 0x96, 0xb2, 0x1f, 0xf7, 0x45, 0xba, 0xea, 0xa3, 0x66, 0xc5, 0x5a, 0x08, 0x2d,
];
/// TDX metadata offset entry: `e47a6535-984a-4798-865e-4685a7bf8ec2`, bytes_le.
const TDX_METADATA_OFFSET_GUID: [u8; 16] = [
    0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
];
const FOOTER_ENTRY_HEADER: usize = 18;
const BYTES_AFTER_FOOTER: usize = 32;
const TDVF_DESCRIPTOR_HEADER: usize = 16;
const TDVF_SECTION_SIZE: usize = 32;

const PE_SIGNATURE: &[u8; 4] = b"PE\0\0";
const PE32_PLUS_MAGIC: u16 = 0x20b;
const DIRECTORY_ENTRY_SECURITY: usize = 4;
const SECTION_HEADER_SIZE: usize = 40;

/// edk2 TdTcg2Dxe events after the kernel image measurement, in extend order.
pub const RTMR1_TAIL_EVENTS: [&[u8]; 4] = [
    b"Calling EFI Application from Boot Option",
    &[0, 0, 0, 0],
    b"Exit Boot Services Invocation",
    b"Exit Boot Services Returned with Success",
];

fn sha384(data: &[u8]) -> Digest48 {
    Sha384::digest(data).into()
}

/// Extend a zeroed RTMR with each event digest: `new = sha384(old || digest)`.
pub fn rtmr_replay<I: IntoIterator<Item = Digest48>>(digests: I) -> Digest48 {
    let mut register = [0u8; 48];
    for digest in digests {
        let mut h = Sha384::new();
        h.update(register);
        h.update(digest);
        register = h.finalize().into();
    }
    register
}

// --- MRTD -------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct TdvfSection {
    data_offset: u32,
    raw_data_size: u32,
    memory_address: u64,
    memory_data_size: u64,
    attributes: u32,
}

fn le_u16(data: &[u8], at: usize) -> Result<u16> {
    let b = data
        .get(at..at + 2)
        .with_context(|| format!("u16 at {at:#x} is outside the image"))?;
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn le_u32(data: &[u8], at: usize) -> Result<u32> {
    let b = data
        .get(at..at + 4)
        .with_context(|| format!("u32 at {at:#x} is outside the image"))?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn le_u64(data: &[u8], at: usize) -> Result<u64> {
    let b = data
        .get(at..at + 8)
        .with_context(|| format!("u64 at {at:#x} is outside the image"))?;
    Ok(u64::from_le_bytes(b.try_into().expect("8-byte slice")))
}

/// One GUID-tagged entry of the OVMF footer table: `[data][size:u16][guid:16]`
/// entries laid back to back, closed by the footer entry 32 bytes before EOF.
fn footer_entry<'a>(fw: &'a [u8], guid: &[u8; 16]) -> Result<&'a [u8]> {
    let footer_start = fw
        .len()
        .checked_sub(BYTES_AFTER_FOOTER + FOOTER_ENTRY_HEADER)
        .context("firmware too small for an OVMF footer table")?;
    let footer_end = footer_start + FOOTER_ENTRY_HEADER;
    ensure!(
        fw[footer_start + 2..footer_end] == TABLE_FOOTER_GUID,
        "OVMF footer table GUID not found"
    );
    let footer_size = le_u16(fw, footer_start)? as usize;
    let table_size = footer_size
        .checked_sub(FOOTER_ENTRY_HEADER)
        .filter(|size| *size <= footer_start)
        .context("invalid OVMF footer table length")?;
    let mut table = &fw[footer_start - table_size..footer_start];
    while table.len() >= FOOTER_ENTRY_HEADER {
        let entry_size = le_u16(table, table.len() - FOOTER_ENTRY_HEADER)? as usize;
        ensure!(
            (FOOTER_ENTRY_HEADER..=table.len()).contains(&entry_size),
            "invalid OVMF footer table entry length"
        );
        if table[table.len() - 16..] == *guid {
            return Ok(&table[table.len() - entry_size..table.len() - FOOTER_ENTRY_HEADER]);
        }
        table = &table[..table.len() - entry_size];
    }
    bail!("OVMF footer table has no {} entry", hex::encode(guid))
}

/// The TDVF descriptor's section table, reached through the footer table's
/// metadata-offset entry (a u32 counted back from the end of the firmware).
fn parse_tdvf_sections(fw: &[u8]) -> Result<Vec<TdvfSection>> {
    let entry = footer_entry(fw, &TDX_METADATA_OFFSET_GUID)?;
    ensure!(entry.len() == 4, "TDX metadata offset entry is not a u32");
    let from_end = le_u32(entry, 0)? as usize;
    let desc = fw
        .len()
        .checked_sub(from_end)
        .filter(|desc| from_end > 0 && desc + TDVF_DESCRIPTOR_HEADER <= fw.len())
        .context("TDX metadata offset points outside the firmware")?;
    ensure!(
        &fw[desc..desc + 4] == b"TDVF",
        "TDVF descriptor signature not found"
    );
    let version = le_u32(fw, desc + 8)?;
    ensure!(
        version == 1,
        "unsupported TDVF descriptor version {version}"
    );
    let count = le_u32(fw, desc + 12)? as usize;
    let table_start = desc + TDVF_DESCRIPTOR_HEADER;
    ensure!(
        count
            .checked_mul(TDVF_SECTION_SIZE)
            .and_then(|len| table_start.checked_add(len))
            .is_some_and(|end| end <= fw.len()),
        "TDVF section table extends past the firmware"
    );
    let mut sections = Vec::with_capacity(count);
    for i in 0..count {
        let at = table_start + i * TDVF_SECTION_SIZE;
        let s = TdvfSection {
            data_offset: le_u32(fw, at)?,
            raw_data_size: le_u32(fw, at + 4)?,
            memory_address: le_u64(fw, at + 8)?,
            memory_data_size: le_u64(fw, at + 16)?,
            attributes: le_u32(fw, at + 28)?,
        };
        ensure!(
            s.memory_address.is_multiple_of(PAGE_SIZE)
                && s.memory_data_size.is_multiple_of(PAGE_SIZE),
            "TDVF section {i} is not page aligned"
        );
        ensure!(
            u64::from(s.raw_data_size) <= s.memory_data_size,
            "TDVF section {i} raw data exceeds its memory size"
        );
        // A measured section must be fully backed by file bytes (BFV and CFV are).
        ensure!(
            s.attributes & ATTR_MR_EXTEND == 0 || u64::from(s.raw_data_size) == s.memory_data_size,
            "TDVF section {i} is measured but only partly backed by file data"
        );
        ensure!(
            (s.data_offset as usize)
                .checked_add(s.raw_data_size as usize)
                .is_some_and(|end| end <= fw.len()),
            "TDVF section {i} raw data extends past the firmware"
        );
        sections.push(s);
    }
    Ok(sections)
}

/// MRTD of a TD launched from this TDVF binary.
pub fn mrtd(tdvf: &[u8]) -> Result<Digest48> {
    let mut h = Sha384::new();
    for s in parse_tdvf_sections(tdvf)? {
        // PAGE_AUG sections are accepted by the guest later, nothing is added at build.
        let page_add = s.attributes & ATTR_PAGE_AUG == 0;
        let extend = s.attributes & ATTR_MR_EXTEND != 0;
        if !(page_add || extend) {
            continue;
        }
        for page in 0..s.memory_data_size / PAGE_SIZE {
            let gpa = s.memory_address + page * PAGE_SIZE;
            if page_add {
                h.update(op_buffer(b"MEM.PAGE.ADD", gpa));
            }
            if extend {
                for chunk in 0..PAGE_SIZE as usize / MR_EXTEND_CHUNK {
                    h.update(op_buffer(
                        b"MR.EXTEND",
                        gpa + (chunk * MR_EXTEND_CHUNK) as u64,
                    ));
                    let start = s.data_offset as usize
                        + (page * PAGE_SIZE) as usize
                        + chunk * MR_EXTEND_CHUNK;
                    h.update(&tdvf[start..start + MR_EXTEND_CHUNK]);
                }
            }
        }
    }
    Ok(h.finalize().into())
}

/// The 128-byte buffer the TDX module hashes for one SEAMCALL: the operation
/// name at 0 and the guest physical address at 16, zero elsewhere.
fn op_buffer(op: &[u8], gpa: u64) -> [u8; 128] {
    let mut buf = [0u8; 128];
    buf[..op.len()].copy_from_slice(op);
    buf[16..24].copy_from_slice(&gpa.to_le_bytes());
    buf
}

// --- RTMR1 ------------------------------------------------------------------

/// Authenticode digest of a PE/COFF image, as edk2's `MeasurePeImageAndExtend`
/// computes it: headers minus CheckSum and the security data directory,
/// sections in file order, then any trailing data minus the certificate table.
pub fn authenticode_sha384(pe: &[u8]) -> Result<Digest48> {
    let pe_offset = le_u32(pe, 0x3c)? as usize;
    ensure!(
        pe.get(pe_offset..pe_offset + 4) == Some(PE_SIGNATURE.as_slice()),
        "not a PE image"
    );
    let coff = pe_offset + 4;
    let num_sections = le_u16(pe, coff + 2)? as usize;
    let optional_header_size = le_u16(pe, coff + 16)? as usize;
    let optional = coff + 20;
    let pe32_plus = le_u16(pe, optional)? == PE32_PLUS_MAGIC;
    let checksum = optional + 64;
    let size_of_headers = le_u32(pe, optional + 60)? as usize;
    let num_rva_and_sizes = le_u32(pe, optional + if pe32_plus { 108 } else { 92 })? as usize;
    let data_directory = optional + if pe32_plus { 112 } else { 96 };
    let security_dir = data_directory + DIRECTORY_ENTRY_SECURITY * 8;
    ensure!(
        size_of_headers <= pe.len(),
        "PE SizeOfHeaders exceeds the image"
    );

    let mut h = Sha384::new();
    h.update(&pe[..checksum]);
    let cert_size = if num_rva_and_sizes <= DIRECTORY_ENTRY_SECURITY {
        ensure!(
            size_of_headers >= checksum + 4,
            "PE SizeOfHeaders ends inside the optional header"
        );
        h.update(&pe[checksum + 4..size_of_headers]);
        0
    } else {
        ensure!(
            size_of_headers >= security_dir + 8,
            "PE SizeOfHeaders ends inside the data directory"
        );
        h.update(&pe[checksum + 4..security_dir]);
        h.update(&pe[security_dir + 8..size_of_headers]);
        le_u32(pe, security_dir + 4)? as usize
    };

    let section_table = optional + optional_header_size;
    let mut sections = Vec::with_capacity(num_sections);
    for i in 0..num_sections {
        let header = section_table + i * SECTION_HEADER_SIZE;
        let size_of_raw_data = le_u32(pe, header + 16)? as usize;
        let pointer_to_raw_data = le_u32(pe, header + 20)? as usize;
        if size_of_raw_data != 0 {
            sections.push((pointer_to_raw_data, size_of_raw_data));
        }
    }
    // Stable sort by file offset, as edk2's insertion sort orders them.
    sections.sort_by_key(|&(pointer, _)| pointer);

    let mut hashed = size_of_headers;
    for (pointer, size) in sections {
        let end = pointer
            .checked_add(size)
            .filter(|end| *end <= pe.len())
            .context("PE section extends past the image")?;
        h.update(&pe[pointer..end]);
        hashed += size;
    }

    if pe.len() > hashed {
        ensure!(
            pe.len() >= hashed + cert_size,
            "PE certificate table larger than the trailing data"
        );
        h.update(&pe[hashed..pe.len() - cert_size]);
    }
    Ok(h.finalize().into())
}

/// RTMR1 after edk2 loaded and ran the kernel EFI stub.
pub fn rtmr1(kernel: &[u8]) -> Result<Digest48> {
    let image = authenticode_sha384(kernel).context("kernel image")?;
    Ok(rtmr_replay(std::iter::once(image).chain(
        RTMR1_TAIL_EVENTS.iter().map(|event| sha384(event)),
    )))
}

// --- RTMR2 ------------------------------------------------------------------

/// Digest of the kernel LoadOptions edk2 measures: the initrd token first,
/// then the cmdline, UTF-16LE with the terminating NUL.
pub fn load_options_digest(cmdline: &str) -> Digest48 {
    let mut h = Sha384::new();
    for unit in "initrd=initrd "
        .encode_utf16()
        .chain(cmdline.encode_utf16())
    {
        h.update(unit.to_le_bytes());
    }
    h.update([0, 0]);
    h.finalize().into()
}

/// RTMR2 after edk2 measured the kernel command line and the initrd.
pub fn rtmr2(cmdline: &str, initrd: &[u8]) -> Digest48 {
    rtmr_replay([load_options_digest(cmdline), sha384(initrd)])
}

// --- MRCONFIGID -------------------------------------------------------------

/// MRCONFIGID binding a deployment: SHA-384 of its rendered cmdline suffix.
pub fn mrconfigid(suffix: &str) -> Digest48 {
    sha384(suffix.as_bytes())
}

// --- runtime triple ---------------------------------------------------------

/// The per-runtime register triple a TDX runtime manifest publishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TdxMeasurements {
    pub mrtd: Digest48,
    pub rtmr1: Digest48,
    pub rtmr2: Digest48,
}

/// Predict the triple for a TDVF + kernel + cmdline + initrd.
pub fn measure_runtime(
    tdvf: &[u8],
    kernel: &[u8],
    cmdline: &str,
    initrd: &[u8],
) -> Result<TdxMeasurements> {
    Ok(TdxMeasurements {
        mrtd: mrtd(tdvf).context("TDVF")?,
        rtmr1: rtmr1(kernel)?,
        rtmr2: rtmr2(cmdline, initrd),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Digest48 {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // Hardware vectors (QEMU 10.2.4, edk2 202602 TDVF, Ubuntu vmlinuz-7.0.0-34-generic,
    // cmdline "root=LABEL=cloudimg-rootfs ro console=ttyS0"), see tests/fixtures/tdx/README.md.
    const HW_CMDLINE: &str = "root=LABEL=cloudimg-rootfs ro console=ttyS0";
    const HW_LOAD_OPTIONS: &str = "b8c85d40a1d555a451571e24d7d7c4c331bc15721d6e4b2a5cb5093214c44174822a0916aa4d622d4309644de99cd59c";
    const HW_INITRD_SHA384: &str = "88de90bedcc560064688c74ccd6609a25ed9d48b0a0e13d8b2a558212724d8755b2c8114dcf04b8d51ea4cf7782e3091";
    const HW_RTMR2: &str = "972547466cb6bcb8a23cd479e9258c3affbbc4f0ba2805d732477200d0dff8432447c7a775e70453cdb51f018a306ece";

    #[test]
    fn rtmr_replay_starts_at_zero_and_chains() {
        assert_eq!(rtmr_replay([]), [0u8; 48]);
        let a = sha384(b"a");
        let b = sha384(b"b");
        let mut expect = [0u8; 48];
        expect = sha384(&[expect.as_slice(), a.as_slice()].concat());
        expect = sha384(&[expect.as_slice(), b.as_slice()].concat());
        assert_eq!(rtmr_replay([a, b]), expect);
        assert_ne!(rtmr_replay([b, a]), expect, "extend order matters");
    }

    #[test]
    fn rtmr1_tail_event_digests() {
        let expected = [
            "77a0dab2312b4e1e57a84d865a21e5b2ee8d677a21012ada819d0a98988078d3d740f6346bfe0abaa938ca20439a8d71",
            "394341b7182cd227c5c6b07ef8000cdfd86136c4292b8e576573ad7ed9ae41019f5818b4b971c9effc60e1ad9f1289f0",
            "214b0bef1379756011344877743fdc2a5382bac6e70362d624ccf3f654407c1b4badf7d8f9295dd3dabdef65b27677e0",
            "0a2e01c85deae718a530ad8c6d20a84009babe6c8989269e950d8cf440c6e997695e64d455c4174a652cd080f6230b74",
        ];
        for (event, want) in RTMR1_TAIL_EVENTS.iter().zip(expected) {
            assert_eq!(hex::encode(sha384(event)), want);
        }
    }

    #[test]
    fn load_options_prefix_initrd_and_terminate() {
        // utf16le("initrd=initrd x") + 0x0000
        let mut raw = Vec::new();
        for c in "initrd=initrd x".encode_utf16() {
            raw.extend_from_slice(&c.to_le_bytes());
        }
        raw.extend_from_slice(&[0, 0]);
        assert_eq!(load_options_digest("x"), sha384(&raw));
        assert_eq!(
            hex::encode(load_options_digest(HW_CMDLINE)),
            HW_LOAD_OPTIONS
        );
    }

    #[test]
    fn rtmr2_matches_hardware_from_component_digests() {
        let got = rtmr_replay([h(HW_LOAD_OPTIONS), h(HW_INITRD_SHA384)]);
        assert_eq!(hex::encode(got), HW_RTMR2);
        // The public entry point produces the same chain shape.
        assert_eq!(
            rtmr2("c", b"i"),
            rtmr_replay([load_options_digest("c"), sha384(b"i")])
        );
    }

    #[test]
    fn mrconfigid_is_sha384_of_the_suffix() {
        assert_eq!(mrconfigid(""), sha384(b""));
        let suffix = "workload_roothash=00ff swiotlb=262144";
        assert_eq!(mrconfigid(suffix), sha384(suffix.as_bytes()));
    }

    // --- synthetic PE -------------------------------------------------------

    const PE_SIZE_OF_HEADERS: usize = 0x200;
    const PE_CHECKSUM: usize = 0x58 + 64;
    const PE_SECURITY_DIR: usize = 0x58 + 112 + 32;

    /// PE32+ with two sections listed out of file order, 32 B of trailing
    /// data and a 32 B certificate table; every non-header byte follows a
    /// pattern so range mistakes change the digest. Byte-identical to the
    /// Python test's `_build_pe`.
    fn build_pe(num_rva_and_sizes: u32, cert_size: u32) -> Vec<u8> {
        let mut pe: Vec<u8> = (0..0x440u32).map(|i| ((i * 7 + 3) & 0xff) as u8).collect();
        pe[..64].fill(0);
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(PE_SIGNATURE);
        let coff = 0x44;
        pe[coff..coff + 20].fill(0);
        pe[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        pe[opt..opt + 240].fill(0);
        pe[opt..opt + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        pe[opt + 60..opt + 64].copy_from_slice(&(PE_SIZE_OF_HEADERS as u32).to_le_bytes());
        pe[opt + 64..opt + 68].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        pe[opt + 108..opt + 112].copy_from_slice(&num_rva_and_sizes.to_le_bytes());
        let sec_dir = opt + 112 + 32;
        pe[sec_dir..sec_dir + 4].copy_from_slice(&0x420u32.to_le_bytes());
        pe[sec_dir + 4..sec_dir + 8].copy_from_slice(&cert_size.to_le_bytes());
        let table = opt + 240;
        pe[table..table + 80].fill(0);
        for (i, (name, ptr)) in [(b".text\0\0\0", 0x300u32), (b".data\0\0\0", 0x200u32)]
            .into_iter()
            .enumerate()
        {
            let hdr = table + i * SECTION_HEADER_SIZE;
            pe[hdr..hdr + 8].copy_from_slice(name);
            pe[hdr + 16..hdr + 20].copy_from_slice(&0x100u32.to_le_bytes());
            pe[hdr + 20..hdr + 24].copy_from_slice(&ptr.to_le_bytes());
        }
        pe
    }

    #[test]
    fn authenticode_skips_checksum_security_dir_and_cert_table() {
        let pe = build_pe(16, 0x20);
        let expected = sha384(
            &[
                &pe[..PE_CHECKSUM],
                &pe[PE_CHECKSUM + 4..PE_SECURITY_DIR],
                &pe[PE_SECURITY_DIR + 8..PE_SIZE_OF_HEADERS],
                &pe[0x200..0x300], // .data, listed second, comes first in the file
                &pe[0x300..0x400], // .text
                &pe[0x400..0x420], // trailing data before the certificate table
            ]
            .concat(),
        );
        let got = authenticode_sha384(&pe).unwrap();
        assert_eq!(got, expected);
        // Pinned for parity with the Python mirror.
        assert_eq!(
            hex::encode(got),
            "27ca0b497c08dcf49e302a2dd4bbe74889b19d0d1af84364c8cad3472d5ba1bfda1e7cfe7fb94848d491cdfd2a163410"
        );
    }

    #[test]
    fn authenticode_without_data_directories_hashes_all_trailing_data() {
        // NumberOfRvaAndSizes <= 4: no security entry to skip, no cert table to drop.
        let pe = build_pe(4, 0x20);
        let expected = sha384(
            &[
                &pe[..PE_CHECKSUM],
                &pe[PE_CHECKSUM + 4..PE_SIZE_OF_HEADERS],
                &pe[0x200..0x400],
                &pe[0x400..0x440],
            ]
            .concat(),
        );
        assert_eq!(authenticode_sha384(&pe).unwrap(), expected);
    }

    #[test]
    fn authenticode_rejects_bad_images() {
        assert!(authenticode_sha384(b"short").is_err());
        let mut pe = build_pe(16, 0x20);
        pe[0x40] = b'X';
        assert!(
            authenticode_sha384(&pe)
                .unwrap_err()
                .to_string()
                .contains("not a PE")
        );
        // Certificate table claiming more than the trailing bytes.
        let pe = build_pe(16, 0x41);
        assert!(
            authenticode_sha384(&pe)
                .unwrap_err()
                .to_string()
                .contains("certificate table")
        );
        // Section past EOF.
        let mut pe = build_pe(16, 0x20);
        let hdr = 0x58 + 240;
        pe[hdr + 20..hdr + 24].copy_from_slice(&0x400u32.to_le_bytes());
        assert!(
            authenticode_sha384(&pe)
                .unwrap_err()
                .to_string()
                .contains("section")
        );
    }

    #[test]
    fn rtmr1_chains_kernel_digest_and_tail_events() {
        let pe = build_pe(16, 0x20);
        let mut events = vec![authenticode_sha384(&pe).unwrap()];
        events.extend(RTMR1_TAIL_EVENTS.iter().map(|e| sha384(e)));
        assert_eq!(rtmr1(&pe).unwrap(), rtmr_replay(events));
    }

    // --- synthetic TDVF -----------------------------------------------------

    fn footer_entry_bytes(guid: &[u8; 16], data: &[u8]) -> Vec<u8> {
        let mut e = data.to_vec();
        e.extend_from_slice(&((data.len() + FOOTER_ENTRY_HEADER) as u16).to_le_bytes());
        e.extend_from_slice(guid);
        e
    }

    fn section(data_offset: u32, raw: u32, addr: u64, mem: u64, ty: u32, attrs: u32) -> Vec<u8> {
        let mut s = Vec::with_capacity(32);
        s.extend_from_slice(&data_offset.to_le_bytes());
        s.extend_from_slice(&raw.to_le_bytes());
        s.extend_from_slice(&addr.to_le_bytes());
        s.extend_from_slice(&mem.to_le_bytes());
        s.extend_from_slice(&ty.to_le_bytes());
        s.extend_from_slice(&attrs.to_le_bytes());
        s
    }

    /// Three-page firmware: pages 0 and 1 are a measured BFV and CFV, page 2
    /// holds the TDVF descriptor and the footer table. TD_HOB gets two
    /// PAGE.ADDs, TEMP_MEM is PAGE_AUG (nothing). Byte-identical to the Python
    /// test's `_build_tdvf`.
    fn build_tdvf() -> Vec<u8> {
        let mut fw: Vec<u8> = (0..0x3000u32)
            .map(|i| ((i * 13 + 5) & 0xff) as u8)
            .collect();
        let mut desc = Vec::new();
        desc.extend_from_slice(b"TDVF");
        desc.extend_from_slice(&(16u32 + 4 * 32).to_le_bytes());
        desc.extend_from_slice(&1u32.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend(section(
            0x0000,
            0x1000,
            0xFFFF_F000,
            0x1000,
            0,
            ATTR_MR_EXTEND,
        ));
        desc.extend(section(
            0x1000,
            0x1000,
            0xFFFF_E000,
            0x1000,
            1,
            ATTR_MR_EXTEND,
        ));
        desc.extend(section(0, 0, 0x0080_9000, 0x2000, 2, 0));
        desc.extend(section(0, 0, 0x0080_B000, 0x1000, 3, ATTR_PAGE_AUG));
        let desc_at = 0x2000;
        fw[desc_at..desc_at + desc.len()].copy_from_slice(&desc);
        let from_end = (fw.len() - desc_at) as u32;
        let entries = [
            footer_entry_bytes(&[0x11; 16], b"unrelated"),
            footer_entry_bytes(&TDX_METADATA_OFFSET_GUID, &from_end.to_le_bytes()),
            footer_entry_bytes(&[0x22; 16], &[0xAB; 4]),
        ]
        .concat();
        let mut tail = entries.clone();
        tail.extend_from_slice(&((entries.len() + FOOTER_ENTRY_HEADER) as u16).to_le_bytes());
        tail.extend_from_slice(&TABLE_FOOTER_GUID);
        tail.extend_from_slice(&[0u8; BYTES_AFTER_FOOTER]);
        let at = fw.len() - tail.len();
        fw[at..].copy_from_slice(&tail);
        fw
    }

    #[test]
    fn mrtd_walks_measured_sections_only() {
        let fw = build_tdvf();
        let base = mrtd(&fw).unwrap();
        // Pinned for parity with the Python mirror.
        assert_eq!(
            hex::encode(base),
            "168f5582b72265ed01aad1edd402f5d096c12d95385b5f38959b5cc8c128e6efe6e13e854e211a1ee4e4a4eeafa36fa6"
        );

        // A measured byte moves it; a byte in the descriptor page outside the
        // descriptor and table does not.
        let mut fw2 = fw.clone();
        fw2[0x123] ^= 1;
        assert_ne!(mrtd(&fw2).unwrap(), base);
        let mut fw3 = fw.clone();
        fw3[0x2800] ^= 1;
        assert_eq!(mrtd(&fw3).unwrap(), base);
        // The TD_HOB address is part of every PAGE.ADD.
        let mut fw5 = fw.clone();
        fw5[0x2000 + 16 + 2 * 32 + 9] ^= 0x10;
        assert_ne!(mrtd(&fw5).unwrap(), base);
        // The PAGE_AUG section contributes nothing: moving it changes nothing.
        let mut fw6 = fw.clone();
        fw6[0x2000 + 16 + 3 * 32 + 9] ^= 0x10;
        assert_eq!(mrtd(&fw6).unwrap(), base);
    }

    #[test]
    fn mrtd_rejects_firmware_without_tdx_metadata() {
        let mut fw = build_tdvf();
        // Overwrite the metadata entry GUID: the table is intact, the entry is gone.
        let at =
            fw.len() - BYTES_AFTER_FOOTER - FOOTER_ENTRY_HEADER - (4 + FOOTER_ENTRY_HEADER) - 16;
        fw[at..at + 16].copy_from_slice(&[0x33; 16]);
        assert!(mrtd(&fw).unwrap_err().to_string().contains("has no"));
        assert!(
            mrtd(&[0u8; 100])
                .unwrap_err()
                .to_string()
                .contains("footer table GUID")
        );
        assert!(mrtd(b"tiny").is_err());
        let mut fw = build_tdvf();
        fw[0x2000..0x2004].copy_from_slice(b"XXXX");
        assert!(mrtd(&fw).unwrap_err().to_string().contains("signature"));
        // A measured section only half backed by file bytes is refused, not guessed.
        let mut fw = build_tdvf();
        fw[0x2000 + 16 + 32 + 4..0x2000 + 16 + 32 + 8].copy_from_slice(&0x800u32.to_le_bytes());
        assert!(mrtd(&fw).unwrap_err().to_string().contains("partly backed"));
    }

    #[test]
    fn measure_runtime_bundles_the_three_registers() {
        let fw = build_tdvf();
        let pe = build_pe(16, 0x20);
        let m = measure_runtime(&fw, &pe, "console=ttyS0", b"initrd").unwrap();
        assert_eq!(m.mrtd, mrtd(&fw).unwrap());
        assert_eq!(m.rtmr1, rtmr1(&pe).unwrap());
        assert_eq!(m.rtmr2, rtmr2("console=ttyS0", b"initrd"));
    }
}
