//! Intel Provisioning Certification Service (PCS) client: fetches the DCAP
//! collateral a TDX quote is verified against and shapes it into the
//! [`TdxCollateral`] the verifier consumes.
//!
//! The trust path never depends on who served the collateral: every piece
//! is checked against the pinned Intel root by `certs` and `tcb`. What this
//! module guarantees is only that the bytes handed to the verifier are the
//! bytes Intel signed, in particular that the TCB Info and QE Identity
//! bodies are sliced out of the response verbatim (the detached signature
//! covers the exact JSON text, so re-serializing would break it).
//!
//! Responses are cached on disk under the documents' own validity windows
//! (`nextUpdate` for the signed documents, `nextUpdate` of the CRLs), so a
//! verifier hammering the same platform does not hit Intel's rate limit.
//! An expired cached copy is refetched, and if the refetch fails the error
//! propagates: an out-of-window collateral is not evidence.

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use super::pck_extension::parse_pck_platform;
use super::tcb::parse_rfc3339_z;
use crate::pki::{parse_cert, parse_crl, pem_certs_to_der, single_common_name, unix_seconds};

/// Which Intel CA issued a platform's PCK certificates. Intel runs two,
/// and the PCK CRL is served per CA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PckCa {
    Platform,
    Processor,
}

impl PckCa {
    // Not called until the HTTP client half of this module builds PCS URLs.
    #[allow(dead_code)]
    fn query_value(self) -> &'static str {
        match self {
            PckCa::Platform => "platform",
            PckCa::Processor => "processor",
        }
    }

    fn from_common_name(common_name: &str) -> Result<Self> {
        match common_name {
            "Intel SGX PCK Platform CA" => Ok(PckCa::Platform),
            "Intel SGX PCK Processor CA" => Ok(PckCa::Processor),
            other => bail!("the PCK intermediate CA {other:?} is not one of Intel's two PCK CAs"),
        }
    }
}

/// What identifies the collateral a quote needs, read off its PCK chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CollateralRequest {
    pub fmspc: [u8; 6],
    pub pck_ca: PckCa,
}

/// Read the FMSPC and PCK CA out of a quote's embedded PCK chain.
///
/// The chain is not verified here: these two values only select URLs, and
/// collateral fetched for a lying chain simply fails to verify against
/// that chain later (FMSPC mismatch, CRL under the wrong CA).
pub fn collateral_request(pck_chain_pem: &[u8]) -> Result<CollateralRequest> {
    let chain = pem_certs_to_der("the PCK chain PEM", pck_chain_pem)?;
    if chain.len() != 3 {
        bail!(
            "expected 3 certificates in the PCK chain (leaf, intermediate, root), got {}",
            chain.len()
        );
    }
    let fmspc = parse_pck_platform(&chain[0])?.fmspc;
    let intermediate = parse_cert("the intermediate CA certificate", &chain[1])?;
    let common_name =
        single_common_name("the intermediate CA certificate", intermediate.subject())?;
    Ok(CollateralRequest {
        fmspc,
        pck_ca: PckCa::from_common_name(common_name)?,
    })
}

/// Slice the value of a top-level `key` out of a JSON object, verbatim.
///
/// Walks the text with a depth counter that understands strings and
/// escapes, so the returned slice is exactly the bytes between the value's
/// braces as they appear in the response.
// Not called until the HTTP client half of this module slices response bodies.
#[allow(dead_code)]
pub(crate) fn extract_top_level_object<'a>(json: &'a str, key: &str) -> Result<&'a str> {
    /// Index one past the closing quote of the string opening at `open`.
    fn string_end(bytes: &[u8], open: usize) -> Result<usize> {
        let mut j = open + 1;
        while j < bytes.len() {
            match bytes[j] {
                b'\\' => j += 2,
                b'"' => return Ok(j + 1),
                _ => j += 1,
            }
        }
        bail!("unterminated string in the PCS response")
    }

    /// Index of the brace closing the object opening at `open`.
    fn object_end(bytes: &[u8], open: usize) -> Result<usize> {
        let mut depth = 0usize;
        let mut k = open;
        while k < bytes.len() {
            match bytes[k] {
                b'"' => {
                    k = string_end(bytes, k)?;
                    continue;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(k);
                    }
                }
                _ => {}
            }
            k += 1;
        }
        bail!("unterminated object in the PCS response")
    }

    let bytes = json.as_bytes();
    // The scan stays at depth 1 (inside the envelope) and skips nested
    // values whole, so a same-named key deeper down is never matched.
    let mut depth = 0usize;
    let mut i = 0usize;
    let mut last_string: Option<&str> = None;
    let mut pending_key: Option<&str> = None;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => {
                let end = string_end(bytes, i)?;
                last_string = Some(&json[i + 1..end - 1]);
                i = end;
                continue;
            }
            b':' if depth == 1 => pending_key = last_string,
            b',' if depth == 1 => pending_key = None,
            b'{' if depth == 1 && pending_key == Some(key) => {
                let end = object_end(bytes, i)?;
                return Ok(&json[i..=end]);
            }
            b'{' => {
                depth += 1;
                pending_key = None;
            }
            b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        i += 1;
    }
    bail!("the PCS response carries no top-level {key:?} object")
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct SignedEnvelope {
    signature: String,
}

/// The detached hex signature a PCS signed-document response carries.
// Not called until the HTTP client half of this module reads a response.
#[allow(dead_code)]
pub(crate) fn signature_of(json: &str) -> Result<String> {
    let envelope: SignedEnvelope =
        serde_json::from_str(json).context("failed to parse the PCS response envelope")?;
    Ok(envelope.signature)
}

/// Decode the percent-encoding Intel applies to PEM chains in response
/// headers (`%0A` newlines, `%20` spaces).
// Not called until the HTTP client half of this module reads response headers.
#[allow(dead_code)]
pub(crate) fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .context("truncated percent-escape in a PCS header")?;
            let hex = std::str::from_utf8(hex).context("non-ASCII percent-escape")?;
            out.push(u8::from_str_radix(hex, 16).context("invalid percent-escape")?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).context("a PCS header decoded to non-UTF-8")
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct Window {
    next_update: String,
}

/// Whether a signed document's own `nextUpdate` is still ahead of `now`.
// Not called until the HTTP client half of this module decides whether a
// cached copy is still current.
#[allow(dead_code)]
pub(crate) fn document_is_current(body: &str, now: i64) -> Result<bool> {
    let window: Window = serde_json::from_str(body).context("signed document has no nextUpdate")?;
    let next_update = unix_seconds(parse_rfc3339_z(&window.next_update)?)?;
    Ok(now <= next_update)
}

/// Whether a CRL's `nextUpdate` is still ahead of `now`.
// Not called until the HTTP client half of this module decides whether a
// cached copy is still current.
#[allow(dead_code)]
pub(crate) fn crl_is_current(der: &[u8], now: i64) -> Result<bool> {
    let crl = parse_crl("cached CRL", der)?;
    let next_update = crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .context("cached CRL carries no nextUpdate")?;
    Ok(now <= next_update.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::collateral::TdxCollateral;
    use crate::tdx::quote::parse_tdx_quote;

    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");
    const COLLATERAL_V4: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_collateral.json");

    fn collateral() -> TdxCollateral {
        TdxCollateral::from_json(COLLATERAL_V4).unwrap()
    }

    #[test]
    fn collateral_request_reads_fmspc_and_ca_from_the_v4_chain() {
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let request = collateral_request(&quote.signature.pck_chain_pem).unwrap();
        assert_eq!(hex::encode(request.fmspc), "b0c06f000000");
        assert_eq!(request.pck_ca, PckCa::Platform);
    }

    /// The body must come back byte-identical whatever the envelope's key
    /// order or whitespace: the detached signature covers those bytes.
    #[test]
    fn extract_top_level_object_returns_the_exact_bytes() {
        let c = collateral();
        let sig = &c.tcb_info_signature;
        let body = &c.tcb_info;
        let compact = format!(r#"{{"tcbInfo":{body},"signature":"{sig}"}}"#);
        assert_eq!(extract_top_level_object(&compact, "tcbInfo").unwrap(), body);
        assert_eq!(signature_of(&compact).unwrap(), *sig);

        let reordered = format!("{{ \"signature\" : \"{sig}\" ,\n \"tcbInfo\" : {body} }}");
        assert_eq!(
            extract_top_level_object(&reordered, "tcbInfo").unwrap(),
            body
        );

        // A nested key of the same name must not be picked up.
        let decoy = format!(r#"{{"other":{{"tcbInfo":{{}}}},"tcbInfo":{body}}}"#);
        assert_eq!(extract_top_level_object(&decoy, "tcbInfo").unwrap(), body);

        // Braces inside strings do not count.
        let tricky = r#"{"a":"}{","tcbInfo":{"s":"{"}}"#;
        assert_eq!(
            extract_top_level_object(tricky, "tcbInfo").unwrap(),
            r#"{"s":"{"}"#
        );

        assert!(extract_top_level_object(r#"{"tcbInfo":"not an object"}"#, "tcbInfo").is_err());
        assert!(extract_top_level_object(r#"{"x":{}}"#, "tcbInfo").is_err());
    }

    #[test]
    fn percent_decode_handles_intel_headers() {
        assert_eq!(
            percent_decode("-----BEGIN%20CERTIFICATE-----%0AMIIC%0A-----END%20CERTIFICATE-----%0A")
                .unwrap(),
            "-----BEGIN CERTIFICATE-----\nMIIC\n-----END CERTIFICATE-----\n"
        );
        assert_eq!(percent_decode("plain").unwrap(), "plain");
        assert!(percent_decode("bad%2").is_err());
        assert!(percent_decode("bad%zz").is_err());
    }

    #[test]
    fn currency_follows_next_update() {
        let c = collateral();
        // The v4 TCB Info's nextUpdate is 2025-07-19; 2025-06-20 is inside.
        assert!(document_is_current(&c.tcb_info, 1_750_377_600).unwrap());
        assert!(!document_is_current(&c.tcb_info, 1_760_000_000).unwrap());
        let crl = c.pck_crl_der().unwrap();
        assert!(crl_is_current(&crl, 1_750_377_600).unwrap());
        assert!(!crl_is_current(&crl, 1_760_000_000).unwrap());
        assert!(document_is_current(r#"{"x":1}"#, 0).is_err());
    }
}
