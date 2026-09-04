//! The platform identity carried in a PCK certificate's Intel SGX extension.
//!
//! The extension (OID `1.2.840.113741.1.13.1`) is a SEQUENCE of (OID, value)
//! pairs. The TCB walk needs three of them: the FMSPC (which platform family
//! this is, matched against the TCB Info), and inside the nested TCB
//! structure the CPUSVN (the 16 SGX TCB component SVNs) and the PCESVN. The
//! rest of the extension is ignored.
//!
//! A minimal, fully bounds-checked DER walk rather than a general ASN.1
//! parser: the structure is fixed and the inputs are untrusted.

use anyhow::{Context, Result, bail};
use openssl::x509::X509;

/// OID `1.2.840.113741.1.13.1`, the Intel SGX extension.
const OID_SGX_EXT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01];
/// OID `...13.1.2`, the nested TCB structure.
const OID_TCB: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02];
/// OID `...13.1.2.17`, PCESVN (an INTEGER inside the TCB structure).
const OID_PCESVN: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x11,
];
/// OID `...13.1.2.18`, CPUSVN (a 16-byte OCTET STRING inside the TCB).
const OID_CPUSVN: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x02, 0x12,
];
/// OID `...13.1.4`, FMSPC (a 6-byte OCTET STRING).
const OID_FMSPC: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf8, 0x4d, 0x01, 0x0d, 0x01, 0x04];

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;

/// The platform identity the TCB walk consumes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PckPlatform {
    /// Platform family, matched against the TCB Info's `fmspc`.
    pub fmspc: [u8; 6],
    /// The 16 SGX TCB component SVNs, compared position-wise against a TCB
    /// level's `sgxtcbcomponents`.
    pub cpusvn: [u8; 16],
    /// PCE SVN, compared against a TCB level's `pcesvn`.
    pub pcesvn: u16,
}

/// A DER tag with its content, from a bounds-checked walk.
struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
}

/// Read one DER TLV at the front of `buf`, returning it and the remainder.
/// Only the short form and the two-byte long form of the length are needed
/// for these certificates; anything larger is rejected.
fn read_tlv(buf: &[u8]) -> Result<(Tlv<'_>, &[u8])> {
    if buf.len() < 2 {
        bail!("truncated DER: need at least a tag and length");
    }
    let tag = buf[0];
    let len_byte = buf[1];
    let (len, header) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 2 {
            bail!("unsupported DER length form ({n} length bytes)");
        }
        let mut len = 0usize;
        for &b in &buf[2..2 + n.min(buf.len().saturating_sub(2))] {
            len = (len << 8) | b as usize;
        }
        if buf.len() < 2 + n {
            bail!("truncated DER length");
        }
        (len, 2 + n)
    };
    let end = header.checked_add(len).context("DER length overflow")?;
    if end > buf.len() {
        bail!("DER content runs past the buffer");
    }
    Ok((
        Tlv {
            tag,
            content: &buf[header..end],
        },
        &buf[end..],
    ))
}

/// Iterate the (OID, value) member pairs of a SEQUENCE-of-SEQUENCE body,
/// calling `f` with each member's OID and value TLV.
fn for_each_member(
    mut body: &[u8],
    mut f: impl FnMut(&[u8], &Tlv<'_>) -> Result<()>,
) -> Result<()> {
    while !body.is_empty() {
        let (member, rest) = read_tlv(body)?;
        body = rest;
        if member.tag != TAG_SEQUENCE {
            bail!("expected a SEQUENCE member in the SGX extension");
        }
        let (oid, after_oid) = read_tlv(member.content)?;
        if oid.tag != TAG_OID {
            bail!("expected an OID at the start of a SGX extension member");
        }
        let (value, _) = read_tlv(after_oid)?;
        f(oid.content, &value)?;
    }
    Ok(())
}

fn octet_string<const N: usize>(what: &str, tlv: &Tlv<'_>) -> Result<[u8; N]> {
    if tlv.tag != TAG_OCTET_STRING {
        bail!("{what} is not an OCTET STRING");
    }
    tlv.content
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} is {} bytes, expected {N}", tlv.content.len()))
}

/// Read a DER INTEGER as a u16 (PCESVN fits in 16 bits).
fn integer_u16(tlv: &Tlv<'_>) -> Result<u16> {
    if tlv.tag != TAG_INTEGER {
        bail!("PCESVN is not an INTEGER");
    }
    // DER integers are big-endian two's complement; PCESVN is small and
    // non-negative, so a leading 0x00 padding byte is the only width past
    // two bytes we accept.
    let bytes = match tlv.content {
        [] => bail!("empty PCESVN integer"),
        [0x00, rest @ ..] => rest,
        all => all,
    };
    if bytes.len() > 2 {
        bail!("PCESVN does not fit in u16");
    }
    let mut v = 0u16;
    for &b in bytes {
        v = (v << 8) | b as u16;
    }
    Ok(v)
}

/// Extract the platform identity from a PCK leaf certificate's SGX
/// extension.
pub fn parse_pck_platform(leaf: &X509) -> Result<PckPlatform> {
    let der = leaf.to_der().context("failed to DER-encode the PCK leaf")?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow::anyhow!("failed to parse the PCK leaf: {e}"))?;

    let ext = cert
        .extensions()
        .iter()
        .find(|e| e.oid.as_bytes() == OID_SGX_EXT)
        .context("the PCK leaf carries no Intel SGX extension")?;

    let mut fmspc: Option<[u8; 6]> = None;
    let mut cpusvn: Option<[u8; 16]> = None;
    let mut pcesvn: Option<u16> = None;

    // The extension value is the outer SEQUENCE; iterate its members.
    let (outer, _) = read_tlv(ext.value)?;
    if outer.tag != TAG_SEQUENCE {
        bail!("the SGX extension value is not a SEQUENCE");
    }
    for_each_member(outer.content, |oid, value| {
        if oid == OID_FMSPC {
            fmspc = Some(octet_string::<6>("FMSPC", value)?);
        } else if oid == OID_TCB {
            if value.tag != TAG_SEQUENCE {
                bail!("the TCB member is not a SEQUENCE");
            }
            for_each_member(value.content, |inner_oid, inner| {
                if inner_oid == OID_CPUSVN {
                    cpusvn = Some(octet_string::<16>("CPUSVN", inner)?);
                } else if inner_oid == OID_PCESVN {
                    pcesvn = Some(integer_u16(inner)?);
                }
                Ok(())
            })?;
        }
        Ok(())
    })?;

    Ok(PckPlatform {
        fmspc: fmspc.context("the SGX extension carries no FMSPC")?,
        cpusvn: cpusvn.context("the SGX extension carries no CPUSVN")?,
        pcesvn: pcesvn.context("the SGX extension carries no PCESVN")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::quote::parse_tdx_quote;

    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");
    const QUOTE_OUTDATED: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_outdated.bin");

    fn pck_leaf(raw: &[u8]) -> X509 {
        let quote = parse_tdx_quote(raw).expect("quote parses");
        let chain = X509::stack_from_pem(&quote.signature.pck_chain_pem).expect("chain parses");
        chain.into_iter().next().expect("leaf present")
    }

    #[test]
    fn parses_v4_pck_platform() {
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).expect("extension parses");
        assert_eq!(hex::encode(platform.fmspc), "b0c06f000000");
        assert_eq!(
            hex::encode(platform.cpusvn),
            "03030202040100050000000000000000"
        );
        assert_eq!(platform.pcesvn, 11);
    }

    #[test]
    fn parses_outdated_pck_platform() {
        let platform = parse_pck_platform(&pck_leaf(QUOTE_OUTDATED)).expect("extension parses");
        assert_eq!(hex::encode(platform.fmspc), "90c06f000000");
        assert_eq!(
            hex::encode(platform.cpusvn),
            "03030202040100030000000000000000"
        );
        assert_eq!(platform.pcesvn, 13);
    }
}
