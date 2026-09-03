//! TDX quote parsing, versions 4 and 5.
//!
//! A quote is: 48-byte header, then the TD report body, then a u32
//! signature-data length and the signature data itself (ECDSA signature,
//! attestation public key, QE report, and the PCK certificate chain nested
//! inside certification-data envelopes).
//!
//! Version 5 interposes a body descriptor (u16 type, u32 size) between the
//! header and the body, so the body starts at offset 54 instead of 48. This
//! is easy to get wrong SILENTLY: every field in the body is fixed-size
//! opaque bytes, so parsing a v5 quote at the v4 offset shifts every
//! register by six bytes and still yields plausible-looking digests. The
//! parser dispatches on the header version before touching the body, and the
//! fixture tests pin exact register values from v5 quotes to catch any
//! regression here.
//!
//! Everything is bounds-checked; nothing in the quote is trusted at this
//! layer. Parsing establishes structure only. Whether the signatures
//! actually verify, whether the PCK chain roots in Intel, and whether the
//! TCB is acceptable are all decided by the verification layer.

use anyhow::{Context, Result, bail};

/// `tee_type` value identifying a TDX quote (SGX quotes carry 0).
pub const TEE_TYPE_TDX: u32 = 0x0000_0081;

/// The only attestation key type Intel issues for TDX quotes today:
/// ECDSA-256 with a P-256 attestation key.
pub const ATTESTATION_KEY_TYPE_ECDSA_P256: u16 = 2;

/// Intel's Quoting Enclave vendor id. Carried in every genuine quote header;
/// the verification layer rejects other vendors.
pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
];

const HEADER_SIZE: usize = 48;
const TD_REPORT10_SIZE: usize = 584;
const TD_REPORT15_SIZE: usize = 648;

/// v5 body-descriptor types. Type 1 is an SGX enclave report, which this
/// parser rejects: it never carries a TD report.
const BODY_TYPE_TD_REPORT10: u16 = 2;
const BODY_TYPE_TD_REPORT15: u16 = 3;

/// Certification-data types (the two levels this parser accepts). The outer
/// level of an Intel-QE quote is always type 6 (QE report certification
/// data); nested inside it, type 5 (the PCK certificate chain, PEM).
const CERT_DATA_QE_REPORT: u16 = 6;
const CERT_DATA_PCK_CHAIN: u16 = 5;

/// Size of an SGX enclave report (the QE report embedded in the quote).
pub const QE_REPORT_SIZE: usize = 384;

/// The 48-byte quote header, common to versions 4 and 5.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteHeader {
    pub version: u16,
    pub attestation_key_type: u16,
    pub tee_type: u32,
    /// Reserved in TDX quotes (QE/PCE SVNs in SGX quotes).
    pub reserved: [u8; 4],
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

/// Fields a TD report 1.5 body adds over 1.0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReport15Extension {
    pub tee_tcb_svn2: [u8; 16],
    pub mrservicetd: [u8; 48],
}

/// The TD report body: the measured identity of the TD and its TCB.
///
/// A v4 quote always carries the 1.0 body (584 bytes); a v5 quote declares
/// the body type in its descriptor, and the 1.5 body (648 bytes) appends
/// [`TdReport15Extension`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReportBody {
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub seam_attributes: [u8; 8],
    pub td_attributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    pub report_data: [u8; 64],
    /// Present only in a TD report 1.5 body.
    pub v15: Option<TdReport15Extension>,
}

/// The quote's signature data, structure only: none of it is verified here.
///
/// The QE report is kept as opaque bytes; the verification layer parses the
/// fields it needs (its `report_data` binds the attestation key, the rest
/// feeds the QE identity check).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureData {
    /// ECDSA P-256 signature (r || s) over the signed region.
    pub quote_signature: [u8; 64],
    /// The attestation public key, an uncompressed P-256 point (x || y)
    /// without the 0x04 prefix.
    pub attestation_key: [u8; 64],
    /// The QE report (SGX enclave report), opaque at this layer.
    pub qe_report: [u8; QE_REPORT_SIZE],
    /// ECDSA signature over the QE report, under the PCK key.
    pub qe_report_signature: [u8; 64],
    /// QE authentication data, hashed together with the attestation key
    /// into the QE report's `report_data`.
    pub qe_auth_data: Vec<u8>,
    /// The PCK certificate chain, concatenated PEM, leaf first.
    pub pck_chain_pem: Vec<u8>,
}

/// A parsed TDX quote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuote {
    pub header: QuoteHeader,
    pub body: TdReportBody,
    pub signature: SignatureData,
    /// The exact bytes the quote signature covers: everything before the
    /// signature-data length field. For v4 that is header || body; for v5
    /// the body descriptor sits in between and IS signed. Verifiers must
    /// check the signature over these bytes, never over a reconstruction.
    pub signed_region: Vec<u8>,
}

/// The measurement registers a TDX message pins: code identity plus the
/// per-deployment `mrconfigid` binding.
///
/// `rtmr0` is deliberately absent: TDVF extends the VMM-supplied memory
/// layout and variable store into it, which is deployment configuration,
/// not code identity. `rtmr3` too: it is reserved for a launch-TCB
/// commitment the guest derives at boot, so no message ever declares it.
/// Both remain readable on [`TdReportBody`] for gates that want them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxRegisters {
    pub mrtd: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub mrconfigid: [u8; 48],
}

/// Bounds-checked little-endian reader with field names in every error.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn take(&mut self, n: usize, what: &str) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).context("length overflow")?;
        if end > self.buf.len() {
            // "input", not "quote": this cursor also walks the nested
            // signature-data buffer, where offsets are relative to that
            // buffer rather than the quote.
            bail!(
                "truncated input: {what} needs {n} bytes at offset {}, only {} remain",
                self.pos,
                self.buf.len() - self.pos
            );
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N]> {
        let slice = self.take(N, what)?;
        Ok(slice.try_into().expect("take returned N bytes"))
    }

    fn u16_le(&mut self, what: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(self.array::<2>(what)?))
    }

    fn u32_le(&mut self, what: &str) -> Result<u32> {
        Ok(u32::from_le_bytes(self.array::<4>(what)?))
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
}

/// Parse a raw TDX quote (version 4 or 5).
///
/// Bytes after the end of the signature data are ignored: quotes commonly
/// arrive in fixed-size buffers with padding, and nothing after the
/// signature data can influence any verified value (the signed region and
/// every certificate lie before it).
pub fn parse_tdx_quote(raw: &[u8]) -> Result<TdxQuote> {
    let mut cur = Cursor::new(raw);

    // --- Header ---
    let version = cur.u16_le("header version")?;
    let attestation_key_type = cur.u16_le("attestation key type")?;
    let tee_type = cur.u32_le("tee type")?;
    let reserved = cur.array::<4>("header reserved bytes")?;
    let qe_vendor_id = cur.array::<16>("QE vendor id")?;
    let user_data = cur.array::<20>("header user data")?;

    if version != 4 && version != 5 {
        bail!("unsupported quote version {version}: only 4 and 5 are supported");
    }
    if tee_type != TEE_TYPE_TDX {
        bail!("not a TDX quote: tee_type {tee_type:#010x}, expected {TEE_TYPE_TDX:#010x}");
    }
    if attestation_key_type != ATTESTATION_KEY_TYPE_ECDSA_P256 {
        bail!(
            "unsupported attestation key type {attestation_key_type}: \
             only ECDSA-256 with P-256 ({ATTESTATION_KEY_TYPE_ECDSA_P256}) is supported"
        );
    }
    debug_assert_eq!(cur.pos, HEADER_SIZE);

    let header = QuoteHeader {
        version,
        attestation_key_type,
        tee_type,
        reserved,
        qe_vendor_id,
        user_data,
    };

    // --- Body (v5: preceded by a body descriptor) ---
    let body_size = if version == 5 {
        let body_type = cur.u16_le("body descriptor type")?;
        let declared = cur.u32_le("body descriptor size")? as usize;
        let expected = match body_type {
            BODY_TYPE_TD_REPORT10 => TD_REPORT10_SIZE,
            BODY_TYPE_TD_REPORT15 => TD_REPORT15_SIZE,
            other => bail!("unsupported v5 body type {other}: expected a TD report (2 or 3)"),
        };
        if declared != expected {
            bail!(
                "v5 body descriptor declares {declared} bytes for body type {body_type}, expected {expected}"
            );
        }
        declared
    } else {
        TD_REPORT10_SIZE
    };

    let body = parse_td_report_body(&mut cur, body_size)?;

    // The quote signature covers everything before the signature-data
    // length field (header, v5 body descriptor if any, body).
    let signed_region = raw[..cur.pos].to_vec();

    // --- Signature data ---
    let sig_data_len = cur.u32_le("signature data length")? as usize;
    let sig_data = cur.take(sig_data_len, "signature data")?;
    let signature = parse_signature_data(sig_data)?;

    Ok(TdxQuote {
        header,
        body,
        signature,
        signed_region,
    })
}

fn parse_td_report_body(cur: &mut Cursor<'_>, body_size: usize) -> Result<TdReportBody> {
    let start = cur.pos;
    let mut body = TdReportBody {
        tee_tcb_svn: cur.array("tee_tcb_svn")?,
        mrseam: cur.array("mrseam")?,
        mrsignerseam: cur.array("mrsignerseam")?,
        seam_attributes: cur.array("seam_attributes")?,
        td_attributes: cur.array("td_attributes")?,
        xfam: cur.array("xfam")?,
        mrtd: cur.array("mrtd")?,
        mrconfigid: cur.array("mrconfigid")?,
        mrowner: cur.array("mrowner")?,
        mrownerconfig: cur.array("mrownerconfig")?,
        rtmr0: cur.array("rtmr0")?,
        rtmr1: cur.array("rtmr1")?,
        rtmr2: cur.array("rtmr2")?,
        rtmr3: cur.array("rtmr3")?,
        report_data: cur.array("report_data")?,
        v15: None,
    };
    if body_size == TD_REPORT15_SIZE {
        body.v15 = Some(TdReport15Extension {
            tee_tcb_svn2: cur.array("tee_tcb_svn2")?,
            mrservicetd: cur.array("mrservicetd")?,
        });
    }
    debug_assert_eq!(cur.pos - start, body_size);
    Ok(body)
}

fn parse_signature_data(data: &[u8]) -> Result<SignatureData> {
    let mut cur = Cursor::new(data);

    let quote_signature = cur.array::<64>("quote signature")?;
    let attestation_key = cur.array::<64>("attestation key")?;

    // Outer certification data: must be the QE-report envelope, and must
    // consume the rest of the signature data exactly. A size that does not
    // line up means the quote's own framing is inconsistent; reject rather
    // than guess.
    let cert_type = cur.u16_le("certification data type")?;
    if cert_type != CERT_DATA_QE_REPORT {
        bail!(
            "unsupported certification data type {cert_type}: expected QE report ({CERT_DATA_QE_REPORT})"
        );
    }
    let cert_size = cur.u32_le("certification data size")? as usize;
    if cert_size != cur.remaining() {
        bail!(
            "certification data size {cert_size} does not match the {} bytes remaining in the signature data",
            cur.remaining()
        );
    }

    let qe_report = cur.array::<QE_REPORT_SIZE>("QE report")?;
    let qe_report_signature = cur.array::<64>("QE report signature")?;
    let auth_len = cur.u16_le("QE auth data length")? as usize;
    let qe_auth_data = cur.take(auth_len, "QE auth data")?.to_vec();

    // Nested certification data: the PCK certificate chain, again required
    // to consume the envelope exactly.
    let inner_type = cur.u16_le("nested certification data type")?;
    if inner_type != CERT_DATA_PCK_CHAIN {
        bail!(
            "unsupported nested certification data type {inner_type}: expected PCK chain ({CERT_DATA_PCK_CHAIN})"
        );
    }
    let inner_size = cur.u32_le("nested certification data size")? as usize;
    if inner_size != cur.remaining() {
        bail!(
            "PCK chain size {inner_size} does not match the {} bytes remaining in the certification data",
            cur.remaining()
        );
    }
    let pck_chain_pem = cur.take(inner_size, "PCK chain")?.to_vec();

    Ok(SignatureData {
        quote_signature,
        attestation_key,
        qe_report,
        qe_report_signature,
        qe_auth_data,
        pck_chain_pem,
    })
}

/// Extract the 64-byte `report_data` field from a parsed body.
pub fn extract_report_data(body: &TdReportBody) -> [u8; 64] {
    body.report_data
}

/// Extract the message-pinnable registers from a parsed body.
pub fn extract_registers(body: &TdReportBody) -> TdxRegisters {
    TdxRegisters {
        mrtd: body.mrtd,
        rtmr1: body.rtmr1,
        rtmr2: body.rtmr2,
        mrconfigid: body.mrconfigid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // Provenance and licences: tests/fixtures/tdx/README.md.
    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");
    const QUOTE_V5: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v5.bin");

    fn assert_structure(quote: &TdxQuote) {
        assert_eq!(quote.header.tee_type, TEE_TYPE_TDX);
        assert_eq!(
            quote.header.attestation_key_type,
            ATTESTATION_KEY_TYPE_ECDSA_P256
        );
        assert_eq!(quote.header.qe_vendor_id, INTEL_QE_VENDOR_ID);
        // The PCK chain is three PEM certificates: leaf, intermediate, root.
        let pem = String::from_utf8_lossy(&quote.signature.pck_chain_pem);
        assert_eq!(pem.matches("-----BEGIN CERTIFICATE-----").count(), 3);
        // The QE report binds the attestation key: its report_data opens
        // with SHA-256(attestation_key || qe_auth_data). Genuine fixtures
        // satisfy it, so a parse that misplaced any of the three fields
        // cannot pass this.
        let mut hasher = Sha256::new();
        hasher.update(quote.signature.attestation_key);
        hasher.update(&quote.signature.qe_auth_data);
        let bound: [u8; 32] = hasher.finalize().into();
        assert_eq!(quote.signature.qe_report[320..352], bound);
    }

    #[test]
    fn quote_signature_verifies_over_signed_region() {
        // Pins the framing contract in CI: the quote's ECDSA P-256
        // signature covers exactly signed_region, which for v5 includes
        // the body descriptor. A signed_region off by even one byte fails
        // here for both fixtures.
        use openssl::bn::BigNum;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::ecdsa::EcdsaSig;
        use openssl::nid::Nid;

        for (name, raw) in [("v4", QUOTE_V4), ("v5", QUOTE_V5)] {
            let quote = parse_tdx_quote(raw).expect(name);
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let x = BigNum::from_slice(&quote.signature.attestation_key[..32]).unwrap();
            let y = BigNum::from_slice(&quote.signature.attestation_key[32..]).unwrap();
            let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y).unwrap();
            let r = BigNum::from_slice(&quote.signature.quote_signature[..32]).unwrap();
            let s = BigNum::from_slice(&quote.signature.quote_signature[32..]).unwrap();
            let sig = EcdsaSig::from_private_components(r, s).unwrap();
            let digest: [u8; 32] = Sha256::digest(&quote.signed_region).into();
            assert!(
                sig.verify(&digest, &key).unwrap(),
                "{name}: signature must verify over signed_region"
            );
            let truncated: [u8; 32] =
                Sha256::digest(&quote.signed_region[..quote.signed_region.len() - 1]).into();
            assert!(
                !sig.verify(&truncated, &key).unwrap(),
                "{name}: any other framing must not verify"
            );
        }
    }

    #[test]
    fn parses_v4_quote() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("v4 quote parses");
        assert_eq!(quote.header.version, 4);
        assert!(quote.body.v15.is_none());
        assert_eq!(quote.signed_region.len(), 48 + 584);
        assert_eq!(&quote.signed_region[..], &QUOTE_V4[..632]);
        assert_structure(&quote);
        assert_eq!(
            hex::encode(quote.body.mrtd),
            "91eb2b44d141d4ece09f0c75c2c53d247a3c68edd7fafe8a3520c942a604a407de03ae6dc5f87f27428b2538873118b7"
        );
        assert_eq!(
            hex::encode(quote.body.rtmr1),
            "0084452c01668329d4bc06acdf58a7205c26743304509973949e5619bf81a6a7aea8c323c173019b3093d54e579e9378"
        );
        assert_eq!(
            hex::encode(quote.body.rtmr2),
            "d833feef2cd945148aa38ead2c53e9b7f138190aaaebfc551dccd829fc207aa3ba80b70870d7330733642e01d48c3132"
        );
    }

    #[test]
    fn ignores_trailing_bytes_after_the_signature_data() {
        // Quotes commonly arrive in fixed-size padded buffers, and some
        // producers append arbitrary data; the parse must be identical
        // with and without it.
        let mut raw = QUOTE_V4.to_vec();
        raw.extend_from_slice(b"extra bytes(only for testing purpose)");
        let quote = parse_tdx_quote(&raw).expect("trailing bytes are ignored");
        assert_eq!(quote, parse_tdx_quote(QUOTE_V4).expect("baseline"));
    }

    #[test]
    fn padding_tolerance_starts_exactly_at_the_signature_data_end() {
        // The v4 fixture carries zero padding after the signature data.
        // Derive the boundary from the length field instead of hardcoding
        // it: the largest prefix ending inside the signature data must
        // fail, and the prefix ending exactly at its end must parse.
        let sig_len = u32::from_le_bytes(QUOTE_V4[632..636].try_into().unwrap()) as usize;
        let sig_end = 636 + sig_len;
        assert!(
            sig_end < QUOTE_V4.len(),
            "fixture must carry trailing padding"
        );
        assert!(parse_tdx_quote(&QUOTE_V4[..sig_end - 1]).is_err());
        assert!(parse_tdx_quote(&QUOTE_V4[..sig_end]).is_ok());
    }

    #[test]
    fn parses_v5_quote_at_descriptor_offset() {
        // The v5 body sits at offset 54, after the body descriptor. A parser
        // that reads it at the v4 offset (48) shifts every register by six
        // bytes and still produces plausible digests, so pin exact values.
        let quote = parse_tdx_quote(QUOTE_V5).expect("v5 quote parses");
        assert_eq!(quote.header.version, 5);
        assert_eq!(quote.signed_region.len(), 54 + 648);
        assert_structure(&quote);
        assert_eq!(
            hex::encode(quote.body.mrtd),
            "157768a71a6a31f5561978c4cde665809d22976ef5dead2952839b7b3ea23b6c2931c9148fe1d117c99faefac18bb73b"
        );
        assert_eq!(
            hex::encode(quote.body.rtmr2),
            "f5902739f8e3f2adef35391d7a3c8237da62ab25c75857953d547ad249270d76c1be21bf6a8aec2a22852e972c537c7f"
        );
        let v15 = quote.body.v15.expect("TD report 1.5 body");
        assert_eq!(
            hex::encode(v15.mrservicetd),
            "383c87d3bbb047b2d171eaca95312ede99f258088dc788f6ae2ccf8b6dd848fe8d47629e08b3f6cbd4a00dd47a5a033d"
        );
    }

    #[test]
    fn parses_v5_quote_with_td_report_10_body() {
        // The one accepted format combination no public fixture carries (a
        // TDX 1.0 platform emitting a v5 quote), so splice one: the same
        // header, a descriptor declaring TD report 1.0, the first 584 body
        // bytes, and the original signature section. Structure only; its
        // signature cannot verify.
        let mut raw = Vec::new();
        raw.extend_from_slice(&QUOTE_V5[..48]);
        raw.extend_from_slice(&BODY_TYPE_TD_REPORT10.to_le_bytes());
        raw.extend_from_slice(&(TD_REPORT10_SIZE as u32).to_le_bytes());
        raw.extend_from_slice(&QUOTE_V5[54..54 + 584]);
        raw.extend_from_slice(&QUOTE_V5[54 + 648..]);
        let quote = parse_tdx_quote(&raw).expect("v5 quote with TD report 1.0 parses");
        assert_eq!(quote.header.version, 5);
        assert!(quote.body.v15.is_none());
        assert_eq!(quote.signed_region.len(), 54 + 584);
        let full = parse_tdx_quote(QUOTE_V5).expect("baseline");
        assert_eq!(quote.body.mrtd, full.body.mrtd);
        assert_eq!(quote.body.report_data, full.body.report_data);
    }

    #[test]
    fn extractors_return_body_fields() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        assert_eq!(extract_report_data(&quote.body), quote.body.report_data);
        let registers = extract_registers(&quote.body);
        assert_eq!(registers.mrtd, quote.body.mrtd);
        assert_eq!(registers.rtmr1, quote.body.rtmr1);
        assert_eq!(registers.rtmr2, quote.body.rtmr2);
        // Both fixtures leave mrconfigid and rtmr3 zero (no
        // deployment binding, no launch-TCB commitment).
        assert_eq!(registers.mrconfigid, [0u8; 48]);
        assert_eq!(quote.body.rtmr3, [0u8; 48]);
    }

    #[test]
    fn rejects_sgx_quote() {
        // Flip tee_type to 0 (SGX).
        let mut raw = QUOTE_V4.to_vec();
        raw[4..8].copy_from_slice(&0u32.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("not a TDX quote"), "got: {err}");
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut raw = QUOTE_V4.to_vec();
        raw[0..2].copy_from_slice(&3u16.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("unsupported quote version 3"), "got: {err}");
    }

    #[test]
    fn rejects_unsupported_attestation_key_type() {
        let mut raw = QUOTE_V4.to_vec();
        raw[2..4].copy_from_slice(&3u16.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("attestation key type"), "got: {err}");
    }

    #[test]
    fn rejects_v5_sgx_body_descriptor() {
        let mut raw = QUOTE_V5.to_vec();
        raw[48..50].copy_from_slice(&1u16.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("body type 1"), "got: {err}");
    }

    #[test]
    fn rejects_v5_descriptor_size_mismatch() {
        let mut raw = QUOTE_V5.to_vec();
        raw[50..54].copy_from_slice(&584u32.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(
            err.contains("declares 584 bytes for body type 3"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_truncation_everywhere() {
        // Any prefix of a valid quote must fail with an error, never panic
        // or return a partial parse. Step through representative lengths in
        // every region: header, body, length fields, signature data.
        for len in [0, 1, 47, 48, 100, 631, 632, 635, 700, 1500] {
            let result = parse_tdx_quote(&QUOTE_V4[..len]);
            assert!(result.is_err(), "prefix of {len} bytes must not parse");
        }
    }

    #[test]
    fn rejects_truncation_everywhere_v5() {
        // v5-specific offsets the v4 sweep never reaches: inside the body
        // descriptor (48..54), the body across its 1.5 extension tail, and
        // the signature-data length field at 702.
        for len in [49, 53, 54, 100, 640, 653, 690, 701, 702, 706] {
            let result = parse_tdx_quote(&QUOTE_V5[..len]);
            assert!(result.is_err(), "prefix of {len} bytes must not parse");
        }
    }

    #[test]
    fn rejects_certification_size_mismatch() {
        // Shrink the outer certification data size by one: the envelope no
        // longer covers the remaining signature data exactly.
        let mut raw = QUOTE_V5.to_vec();
        let cert_size_off = 54 + 648 + 4 + 64 + 64 + 2;
        let declared =
            u32::from_le_bytes(raw[cert_size_off..cert_size_off + 4].try_into().unwrap());
        raw[cert_size_off..cert_size_off + 4].copy_from_slice(&(declared - 1).to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("certification data size"), "got: {err}");
    }

    #[test]
    fn rejects_oversized_signature_length() {
        // A signature-data length running past the end of the buffer.
        let mut raw = QUOTE_V4.to_vec();
        raw[632..636].copy_from_slice(&u32::MAX.to_le_bytes());
        let err = parse_tdx_quote(&raw).unwrap_err().to_string();
        assert!(err.contains("signature data"), "got: {err}");
    }
}
