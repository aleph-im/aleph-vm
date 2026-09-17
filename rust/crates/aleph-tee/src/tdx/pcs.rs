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

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::collateral::TdxCollateral;
use super::pck_extension::parse_pck_platform;
use super::tcb::parse_rfc3339_z;
use crate::fetch::{cache_dir, read_body_capped, read_cached, write_cache};
use crate::pki::{parse_cert, parse_crl, pem_certs_to_der, single_common_name, unix_seconds};

/// Which Intel CA issued a platform's PCK certificates. Intel runs two,
/// and the PCK CRL is served per CA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PckCa {
    Platform,
    Processor,
}

impl PckCa {
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

/// Split a PCS signed-document envelope into the verbatim bytes of its
/// top-level `key` object and the detached hex signature.
///
/// The body comes back as a slice of the response text: `RawValue` borrows
/// the value's exact span from the input, so the bytes the signature covers
/// are never re-serialized.
pub(crate) fn split_envelope<'a>(json: &'a str, key: &str) -> Result<(&'a str, String)> {
    let envelope: BTreeMap<String, &'a RawValue> =
        serde_json::from_str(json).context("failed to parse the PCS response envelope")?;
    let body = envelope
        .get(key)
        .with_context(|| format!("the PCS response carries no top-level {key:?} object"))?
        .get();
    if !body.starts_with('{') {
        bail!("the PCS response's top-level {key:?} is not an object");
    }
    let signature = envelope
        .get("signature")
        .context("the PCS response carries no signature")?;
    let signature: String = serde_json::from_str(signature.get())
        .context("the PCS response's signature is not a string")?;
    Ok((body, signature))
}

/// Decode the percent-encoding Intel applies to PEM chains in response
/// headers (`%0A` newlines, `%20` spaces).
pub(crate) fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .context("truncated percent-escape in a PCS header")?;
            // from_str_radix would also take a sign; only two hex digits will do.
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                bail!("invalid percent-escape in a PCS header");
            }
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
struct Window {
    next_update: String,
}

/// Whether a signed document's own `nextUpdate` is still ahead of `now`.
pub(crate) fn document_is_current(body: &str, now: i64) -> Result<bool> {
    let window: Window = serde_json::from_str(body).context("signed document has no nextUpdate")?;
    let next_update = unix_seconds(parse_rfc3339_z(&window.next_update)?)?;
    Ok(now <= next_update)
}

/// Whether a CRL's `nextUpdate` is still ahead of `now`.
pub(crate) fn crl_is_current(der: &[u8], now: i64) -> Result<bool> {
    let crl = parse_crl("cached CRL", der)?;
    let next_update = crl
        .tbs_cert_list
        .next_update
        .as_ref()
        .context("cached CRL carries no nextUpdate")?;
    Ok(now <= next_update.timestamp())
}

const INTEL_PCS_BASE_URL: &str = "https://api.trustedservices.intel.com";
const INTEL_ROOT_CA_CRL_URL: &str =
    "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der";

/// Cap on one PCS response body. PCK CRLs run to a few hundred KiB.
const MAX_PCS_RESPONSE_BYTES: usize = 1024 * 1024;

const TCB_INFO_ISSUER_CHAIN_HEADER: &str = "TCB-Info-Issuer-Chain";
const QE_IDENTITY_ISSUER_CHAIN_HEADER: &str = "SGX-Enclave-Identity-Issuer-Chain";
const PCK_CRL_ISSUER_CHAIN_HEADER: &str = "SGX-PCK-CRL-Issuer-Chain";

/// A client for one PCS deployment: Intel's, or a local PCCS mirror that
/// serves the same API.
#[derive(Clone, Debug)]
pub struct PcsClient {
    /// Base URL of the certification API, without a trailing slash.
    pub base_url: String,
    /// URL of the root CA CRL, which Intel serves off a different host.
    pub root_ca_crl_url: String,
    /// Where fetched material is cached; `None` disables the cache.
    pub cache_dir: Option<PathBuf>,
}

impl PcsClient {
    /// Intel's public PCS, cached under the user's cache directory.
    pub fn intel() -> Self {
        PcsClient {
            base_url: INTEL_PCS_BASE_URL.to_string(),
            root_ca_crl_url: INTEL_ROOT_CA_CRL_URL.to_string(),
            cache_dir: cache_dir("pcs"),
        }
    }

    pub fn with_cache_dir(mut self, dir: Option<PathBuf>) -> Self {
        self.cache_dir = dir;
        self
    }

    /// Fetch the collateral for `request`, through the cache. `now` decides
    /// whether a cached copy is still inside its window.
    pub async fn fetch(
        &self,
        request: &CollateralRequest,
        now: SystemTime,
    ) -> Result<TdxCollateral> {
        let now = unix_seconds(now)?;
        let fmspc = hex::encode(request.fmspc);
        let ca = request.pck_ca.query_value();

        let tcb_info = self
            .signed_document(
                &format!("tcb-{fmspc}.json"),
                &format!("{}/tdx/certification/v4/tcb?fmspc={fmspc}", self.base_url),
                TCB_INFO_ISSUER_CHAIN_HEADER,
                "tcbInfo",
                now,
            )
            .await
            .context("failed to obtain the TCB Info")?;
        let qe_identity = self
            .signed_document(
                "qe-identity.json",
                &format!("{}/tdx/certification/v4/qe/identity", self.base_url),
                QE_IDENTITY_ISSUER_CHAIN_HEADER,
                "enclaveIdentity",
                now,
            )
            .await
            .context("failed to obtain the QE Identity")?;
        let pck_crl = self
            .crl(
                &format!("pckcrl-{ca}.json"),
                &format!(
                    "{}/sgx/certification/v4/pckcrl?ca={ca}&encoding=der",
                    self.base_url
                ),
                Some(PCK_CRL_ISSUER_CHAIN_HEADER),
                now,
            )
            .await
            .context("failed to obtain the PCK CRL")?;
        let root_ca_crl = self
            .crl("rootcrl.json", &self.root_ca_crl_url, None, now)
            .await
            .context("failed to obtain the root CA CRL")?;

        Ok(TdxCollateral {
            pck_crl_issuer_chain: pck_crl.chain,
            root_ca_crl: root_ca_crl.der_hex,
            pck_crl: pck_crl.der_hex,
            tcb_info_issuer_chain: tcb_info.chain,
            tcb_info: tcb_info.body,
            tcb_info_signature: tcb_info.signature,
            qe_identity_issuer_chain: qe_identity.chain,
            qe_identity: qe_identity.body,
            qe_identity_signature: qe_identity.signature,
        })
    }

    async fn signed_document(
        &self,
        cache_file: &str,
        url: &str,
        chain_header: &str,
        key: &str,
        now: i64,
    ) -> Result<SignedDocument> {
        let cache_path = self.cache_dir.as_ref().map(|dir| dir.join(cache_file));
        if let Some(path) = &cache_path
            && let Some(bytes) = read_cached(path)
            && let Ok(cached) = serde_json::from_slice::<SignedDocument>(&bytes)
            && document_is_current(&cached.body, now).unwrap_or(false)
        {
            return Ok(cached);
        }

        let (text, headers) = self.get(url).await?;
        let chain = header_chain(&headers, chain_header)?;
        let (body, signature) = split_envelope(&text, key)?;
        let document = SignedDocument {
            body: body.to_string(),
            signature,
            chain,
        };
        if let Some(path) = &cache_path {
            write_cache(path, &serde_json::to_vec(&document)?);
        }
        Ok(document)
    }

    async fn crl(
        &self,
        cache_file: &str,
        url: &str,
        chain_header: Option<&str>,
        now: i64,
    ) -> Result<CachedCrl> {
        let cache_path = self.cache_dir.as_ref().map(|dir| dir.join(cache_file));
        if let Some(path) = &cache_path
            && let Some(bytes) = read_cached(path)
            && let Ok(cached) = serde_json::from_slice::<CachedCrl>(&bytes)
            && let Ok(der) = hex::decode(&cached.der_hex)
            && crl_is_current(&der, now).unwrap_or(false)
        {
            return Ok(cached);
        }

        let (der, headers) = self.get_bytes(url).await?;
        let chain = match chain_header {
            Some(name) => header_chain(&headers, name)?,
            None => String::new(),
        };
        let crl = CachedCrl {
            der_hex: hex::encode(der),
            chain,
        };
        if let Some(path) = &cache_path {
            write_cache(path, &serde_json::to_vec(&crl)?);
        }
        Ok(crl)
    }

    async fn get_bytes(&self, url: &str) -> Result<(Vec<u8>, reqwest::header::HeaderMap)> {
        let response = crate::fetch::http_client()
            .get(url)
            .send()
            .await
            .with_context(|| format!("failed to fetch {url}"))?;
        let status = response.status();
        if !status.is_success() {
            bail!("PCS returned HTTP {status} for {url}");
        }
        let headers = response.headers().clone();
        let body = read_body_capped("PCS", response, MAX_PCS_RESPONSE_BYTES).await?;
        Ok((body, headers))
    }

    async fn get(&self, url: &str) -> Result<(String, reqwest::header::HeaderMap)> {
        let (bytes, headers) = self.get_bytes(url).await?;
        let text = String::from_utf8(bytes).context("PCS response is not UTF-8")?;
        Ok((text, headers))
    }
}

/// Fetch through Intel's public PCS with the default cache.
pub async fn fetch_collateral(
    request: &CollateralRequest,
    now: SystemTime,
) -> Result<TdxCollateral> {
    PcsClient::intel().fetch(request, now).await
}

fn header_chain(headers: &reqwest::header::HeaderMap, name: &str) -> Result<String> {
    let value = headers
        .get(name)
        .with_context(|| format!("PCS response carries no {name} header"))?
        .to_str()
        .with_context(|| format!("the {name} header is not ASCII"))?;
    percent_decode(value)
}

/// A signed document as cached: the verbatim body, its detached signature
/// and the issuer chain that came with it.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct SignedDocument {
    body: String,
    signature: String,
    chain: String,
}

/// A CRL as cached: hex DER (the shape `TdxCollateral` wants) and the
/// issuer chain that came with it, empty for the root CA CRL.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedCrl {
    der_hex: String,
    chain: String,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
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
    fn split_envelope_returns_the_exact_bytes() {
        let c = collateral();
        let sig = &c.tcb_info_signature;
        let body = &c.tcb_info;
        let compact = format!(r#"{{"tcbInfo":{body},"signature":"{sig}"}}"#);
        assert_eq!(
            split_envelope(&compact, "tcbInfo").unwrap(),
            (body.as_str(), sig.clone())
        );

        let reordered = format!("{{ \"signature\" : \"{sig}\" ,\n \"tcbInfo\" : {body} }}");
        assert_eq!(split_envelope(&reordered, "tcbInfo").unwrap().0, body);

        // Whitespace inside the body is part of what Intel signed.
        let spaced = format!("{{\"tcbInfo\": {{ \"a\" : [1, 2] }} ,\"signature\":\"{sig}\"}}");
        assert_eq!(
            split_envelope(&spaced, "tcbInfo").unwrap().0,
            "{ \"a\" : [1, 2] }"
        );

        // A nested key of the same name must not be picked up.
        let decoy =
            format!(r#"{{"other":{{"tcbInfo":{{}}}},"tcbInfo":{body},"signature":"{sig}"}}"#);
        assert_eq!(split_envelope(&decoy, "tcbInfo").unwrap().0, body);

        // Braces inside strings do not count.
        let tricky = r#"{"a":"}{","tcbInfo":{"s":"{"},"signature":"00"}"#;
        assert_eq!(split_envelope(tricky, "tcbInfo").unwrap().0, r#"{"s":"{"}"#);

        assert!(
            split_envelope(r#"{"tcbInfo":"not an object","signature":"00"}"#, "tcbInfo").is_err()
        );
        assert!(split_envelope(r#"{"x":{},"signature":"00"}"#, "tcbInfo").is_err());
        assert!(split_envelope(r#"{"tcbInfo":{}}"#, "tcbInfo").is_err());
        assert!(split_envelope(r#"{"tcbInfo":{},"signature":1}"#, "tcbInfo").is_err());
        assert!(split_envelope("not json", "tcbInfo").is_err());
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
        assert!(percent_decode("bad%+5").is_err());
        assert!(percent_decode("bad%").is_err());
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

    /// Seed a cache directory from the fixture collateral, the way a
    /// previous fetch would have left it.
    fn seed_cache(dir: &Path) {
        // `impl Trait` is not allowed in closure parameters on stable Rust,
        // so this is a plain generic function rather than the closure the
        // brief sketched; the cache layout it produces is unchanged.
        fn write<T: Serialize>(dir: &Path, name: &str, value: &T) {
            write_cache(&dir.join(name), &serde_json::to_vec(value).unwrap());
        }

        let c = collateral();
        write(
            dir,
            "tcb-b0c06f000000.json",
            &SignedDocument {
                body: c.tcb_info.clone(),
                signature: c.tcb_info_signature.clone(),
                chain: c.tcb_info_issuer_chain.clone(),
            },
        );
        write(
            dir,
            "qe-identity.json",
            &SignedDocument {
                body: c.qe_identity.clone(),
                signature: c.qe_identity_signature.clone(),
                chain: c.qe_identity_issuer_chain.clone(),
            },
        );
        write(
            dir,
            "pckcrl-platform.json",
            &CachedCrl {
                der_hex: c.pck_crl.clone(),
                chain: c.pck_crl_issuer_chain.clone(),
            },
        );
        write(
            dir,
            "rootcrl.json",
            &CachedCrl {
                der_hex: c.root_ca_crl.clone(),
                chain: String::new(),
            },
        );
    }

    /// A client whose every network request is refused immediately (port 9
    /// on the loopback is closed), so tests never leave the machine.
    fn offline_client(cache: &Path) -> PcsClient {
        PcsClient {
            base_url: "http://127.0.0.1:9".to_string(),
            root_ca_crl_url: "http://127.0.0.1:9/rootcrl".to_string(),
            cache_dir: Some(cache.to_path_buf()),
        }
    }

    fn now_v4() -> SystemTime {
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_750_377_600)
    }

    #[tokio::test]
    async fn cached_collateral_is_served_and_verifies_the_quote() {
        use crate::tdx::tcb::{TcbStatus, TdxTcbPolicy};
        use crate::tdx::verify::verify_tdx_quote;

        let dir = tempfile::tempdir().unwrap();
        seed_cache(dir.path());
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let request = collateral_request(&quote.signature.pck_chain_pem).unwrap();
        let fetched = offline_client(dir.path())
            .fetch(&request, now_v4())
            .await
            .expect("the cache satisfies every item");
        let verified = verify_tdx_quote(&quote, &fetched, now_v4(), &TdxTcbPolicy::default())
            .expect("assembled collateral verifies the fixture quote");
        assert_eq!(verified.tcb.status, TcbStatus::UpToDate);
    }

    #[tokio::test]
    async fn expired_cache_is_refetched_and_a_failed_refetch_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        seed_cache(dir.path());
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let request = collateral_request(&quote.signature.pck_chain_pem).unwrap();
        // 2026-01-01: past every nextUpdate in the fixture.
        let later = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600);
        let err = offline_client(dir.path())
            .fetch(&request, later)
            .await
            .expect_err("an expired cache must not be served");
        assert!(
            format!("{err:#}").contains("failed to obtain the TCB Info"),
            "got: {err:#}"
        );
    }

    #[tokio::test]
    async fn no_cache_and_no_network_is_an_error() {
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let request = collateral_request(&quote.signature.pck_chain_pem).unwrap();
        let client = PcsClient {
            base_url: "http://127.0.0.1:9".to_string(),
            root_ca_crl_url: "http://127.0.0.1:9/rootcrl".to_string(),
            cache_dir: None,
        };
        assert!(client.fetch(&request, now_v4()).await.is_err());
    }

    /// Live: Intel's PCS serves collateral for the fixture platform, and the
    /// issuer chains it returns verify to the pinned root today.
    #[tokio::test]
    #[ignore = "network: hits Intel PCS; run explicitly with --ignored"]
    async fn live_intel_pcs_serves_verifiable_collateral() {
        use crate::tdx::certs::verify_signer_chain;
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let request = collateral_request(&quote.signature.pck_chain_pem).unwrap();
        let now = SystemTime::now();
        let dir = tempfile::tempdir().unwrap();
        let fetched = PcsClient::intel()
            .with_cache_dir(Some(dir.path().to_path_buf()))
            .fetch(&request, now)
            .await
            .expect("live fetch");
        verify_signer_chain(fetched.tcb_info_issuer_chain.as_bytes(), now).expect("TCB Info chain");
        verify_signer_chain(fetched.qe_identity_issuer_chain.as_bytes(), now)
            .expect("QE Identity chain");
        assert!(document_is_current(&fetched.tcb_info, unix_seconds(now).unwrap()).unwrap());
    }
}
