use std::collections::HashMap;
use std::sync::Arc;

use aleph_tee::report_data::fresh_report_data;
use aleph_tee::sev_snp::verify::verify_sev_snp_report;
use aleph_tee::types::AttestationReport;
use anyhow::{Context, Result, bail};
use rand::Rng;
use serde::Deserialize;

use crate::verify::SnpCertVerifier;

/// The result of an attested HTTP request, combining the HTTP response
/// with attestation verification information.
pub struct AttestedResponse {
    /// Whether the attestation report was cryptographically valid.
    pub attestation_valid: bool,
    /// A human-readable summary of the attestation verification.
    pub attestation_summary: String,
    /// The TEE measurement (launch digest) from the attestation report.
    pub measurement: Vec<u8>,
    /// The HTTP status code of the response.
    pub status: u16,
    /// The HTTP response body as a string.
    pub body: String,
}

#[derive(Deserialize)]
pub struct InjectSecretResponse {
    pub injected: Vec<String>,
}

/// Build a reqwest client with our custom TLS verifier.
fn build_attested_client(verifier: &Arc<SnpCertVerifier>) -> Result<reqwest::Client> {
    let tls_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .build()
        .context("failed to build HTTP client with custom TLS config")
}

/// Verify that a fresh attestation report is bound to BOTH the served TLS public
/// key AND the caller's nonce, under the canonical domain-separated
/// `fresh_report_data` scheme.
///
/// Binding the served key (channel binding) is what defeats the relay /
/// attested-key-confusion attack that increment B2a fixed: a fresh report
/// obtained against one TLS channel cannot be replayed against a different key,
/// and the distinct domain tag means it can never collide with a key-binding
/// report. The raw nonce is never compared verbatim; both sides hash it under
/// the domain, so this compares the domain-tagged digests.
fn verify_fresh_binding(
    report: &AttestationReport,
    server_public_key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    let expected = fresh_report_data(server_public_key, nonce);
    if report.report_data[..48] != expected[..48] {
        bail!(
            "fresh attestation binding failed: report_data does not match \
             fresh_report_data(server_key, nonce). Expected {}, got {}",
            hex::encode(&expected[..48]),
            hex::encode(&report.report_data[..48]),
        );
    }
    Ok(())
}

/// Layer 2: Make an API call with TLS-bound attestation verification.
///
/// During the TLS handshake, the verifier checks:
/// - The server cert contains an attestation extension
/// - The report_data is bound to the server's TLS public key under the canonical
///   domain-separated `key_bound_report_data` scheme
/// - If `expected_measurement` is provided, the measurement matches
///
/// After the handshake, the full AMD certificate chain is verified
/// (VCEK -> ASK -> ARK, ARK-pinned) and the report signature is checked.
pub async fn attested_request(
    url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
) -> Result<AttestedResponse> {
    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()));
    let client = build_attested_client(&verifier)?;

    let response = client
        .get(url)
        .send()
        .await
        .context("failed to send GET request")?;

    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .context("failed to read response body")?;

    let report = verifier
        .get_report()
        .context("no attestation report extracted from TLS handshake")?;

    let result = verify_sev_snp_report(&report, product)
        .await
        .context("SEV-SNP report verification failed")?;

    Ok(AttestedResponse {
        attestation_valid: result.valid,
        attestation_summary: result.summary,
        measurement: result.measurement,
        status,
        body,
    })
}

/// Layer 3: Request a fresh attestation report with a random nonce.
///
/// This combines TLS-bound verification (Layer 2) with a fresh nonce challenge:
/// 1. TLS handshake verifies key binding and optional measurement, and captures
///    the served TLS public key.
/// 2. A random nonce is sent to the attestation endpoint.
/// 3. The returned report must be bound to BOTH the served key and our nonce
///    (`fresh_report_data`), proving the TEE produced a fresh report for THIS
///    channel (not a relayed report for a different key).
/// 4. The full AMD certificate chain is verified (ARK-pinned).
pub async fn fresh_attestation(
    base_url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
) -> Result<AttestationReport> {
    // Generate a random 32-byte nonce.
    let mut nonce = [0u8; 32];
    rand::rng().fill(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    // Build the attestation URL.
    let base = url::Url::parse(base_url).context("failed to parse base URL")?;
    let attestation_url = base
        .join(&format!(".well-known/attestation?nonce={}", nonce_hex))
        .context("failed to construct attestation URL")?;

    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()));
    let client = build_attested_client(&verifier)?;

    let response = client
        .get(attestation_url.as_str())
        .send()
        .await
        .context("failed to send attestation request")?;

    let body = response
        .text()
        .await
        .context("failed to read attestation response body")?;

    let report: AttestationReport =
        serde_json::from_str(&body).context("failed to parse attestation response as JSON")?;

    // Recover the served TLS public key captured during the handshake. The fresh
    // report must be bound to exactly this key AND our nonce.
    let server_public_key = verifier
        .get_server_public_key()
        .context("no server public key captured from TLS handshake")?;
    verify_fresh_binding(&report, &server_public_key, &nonce)
        .context("fresh attestation channel binding failed")?;

    // Verify the SEV-SNP report against the AMD certificate chain (ARK-pinned).
    let result = verify_sev_snp_report(&report, product)
        .await
        .context("SEV-SNP report verification failed")?;

    if !result.valid {
        bail!(
            "SEV-SNP attestation report is not valid: {}",
            result.summary
        );
    }

    Ok(report)
}

/// Inject secrets into a confidential VM via attested TLS.
///
/// Sends a POST request with a JSON map of key-value secrets to the
/// `confidential/inject-secret` endpoint. The TLS channel is attested
/// (and optionally measurement-pinned), so secrets are only ever sent
/// to a verified TEE.
pub async fn inject_secret(
    base_url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
    secrets: &[(String, String)],
) -> Result<InjectSecretResponse> {
    let base = url::Url::parse(base_url).context("failed to parse base URL")?;
    let inject_url = base
        .join("confidential/inject-secret")
        .context("failed to construct inject-secret URL")?;

    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()));
    let client = build_attested_client(&verifier)?;

    let secrets_map: HashMap<&str, &str> = secrets
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let response = client
        .post(inject_url.as_str())
        .json(&secrets_map)
        .send()
        .await
        .context("failed to send inject-secret request")?;

    // Verify attestation after the TLS handshake (key binding + measurement were
    // already enforced during the handshake; here we run the full KDS chain).
    let report = verifier
        .get_report()
        .context("no attestation report extracted from TLS handshake")?;
    let result = verify_sev_snp_report(&report, product)
        .await
        .context("SEV-SNP report verification failed")?;
    if !result.valid {
        bail!("attestation invalid: {}", result.summary);
    }

    let status = response.status().as_u16();
    if status == 409 {
        bail!("secrets already injected (409 Conflict)");
    }
    if status != 200 {
        let body = response.text().await.unwrap_or_default();
        bail!("inject-secret failed with status {status}: {body}");
    }

    let resp: InjectSecretResponse = response
        .json()
        .await
        .context("failed to parse inject-secret response")?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tee::report_data::key_bound_report_data;
    use aleph_tee::types::TeeType;
    use sha2::{Digest, Sha384};

    fn report_with(report_data: [u8; 64]) -> AttestationReport {
        AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8],
            report_data,
            measurement: vec![0xAB; 48],
        }
    }

    /// A fresh report bound to the served key AND nonce passes.
    #[test]
    fn fresh_binding_accepts_key_and_nonce() {
        let server_key = b"served-tls-public-key";
        let nonce = [0x11u8; 32];
        let report = report_with(fresh_report_data(server_key, &nonce));
        assert!(verify_fresh_binding(&report, server_key, &nonce).is_ok());
    }

    /// A fresh report bound to a DIFFERENT key is rejected (relay defense).
    #[test]
    fn fresh_binding_rejects_wrong_key() {
        let nonce = [0x22u8; 32];
        let report = report_with(fresh_report_data(b"attacker-served-key", &nonce));
        assert!(verify_fresh_binding(&report, b"honest-served-key", &nonce).is_err());
    }

    /// A fresh report bound to a DIFFERENT nonce is rejected (liveness).
    #[test]
    fn fresh_binding_rejects_wrong_nonce() {
        let server_key = b"served-tls-public-key";
        let report = report_with(fresh_report_data(server_key, &[0x33u8; 32]));
        assert!(verify_fresh_binding(&report, server_key, &[0x44u8; 32]).is_err());
    }

    /// Key-confusion attack closed at the fresh path: a report the attacker
    /// obtained under the DONOR's old scheme (raw `SHA-384(attacker_key)` in
    /// report_data) does NOT satisfy the domain-separated key binding for the
    /// attacker key. A verifier holding the attacker key can never accept it.
    #[test]
    fn key_confusion_fresh_report_cannot_forge_key_binding() {
        let attacker_key = b"attacker-public-key";
        // The donor's old key-binding report_data (and equally, a donor-era fresh
        // report requested with nonce = SHA-384(attacker_key)).
        let mut old_scheme = [0u8; 64];
        old_scheme[..48].copy_from_slice(&Sha384::digest(attacker_key));

        // The new domain-separated key binding the verifier now requires.
        let domain_bound = key_bound_report_data(attacker_key);

        assert_ne!(
            old_scheme[..48],
            domain_bound[..48],
            "old raw-SHA-384 binding must never equal the domain-separated binding"
        );
    }
}
