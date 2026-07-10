use std::collections::HashMap;
use std::sync::Arc;

use aleph_tee::report_data::fresh_report_data;
use aleph_tee::sev_snp::verify::verify_sev_snp_report;
use aleph_tee::types::AttestationReport;
use anyhow::{Context, Result, bail};
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
/// `report_data` MUST be the value derived from the AMD-verified blob (i.e.
/// `VerificationResult::report_data`), never an unsigned copy: this function
/// only compares digests and cannot tell a signed value from a forged one.
///
/// Binding the served key (channel binding) is what defeats the relay /
/// attested-key-confusion attack that increment B2a fixed: a fresh report
/// obtained against one TLS channel cannot be replayed against a different key,
/// and the distinct domain tag means it can never collide with a key-binding
/// report. The raw nonce is never compared verbatim; both sides hash it under
/// the domain, so this compares the domain-tagged digests.
fn verify_fresh_binding(
    report_data: &[u8; 64],
    server_public_key: &[u8],
    nonce: &[u8],
) -> Result<()> {
    let expected = fresh_report_data(server_public_key, nonce);
    if report_data[..48] != expected[..48] {
        bail!(
            "fresh attestation binding failed: blob-derived report_data does not \
             match fresh_report_data(server_key, nonce). Expected {}, got {}",
            hex::encode(&expected[..48]),
            hex::encode(&report_data[..48]),
        );
    }
    Ok(())
}

/// Layer 2: Make an API call with TLS-bound attestation verification.
///
/// The custom TLS verifier is the authoritative gate: during the handshake it
/// checks the attestation extension, the blob-derived key binding, the optional
/// measurement pin, AND the full AMD certificate chain (VCEK -> ASK -> ARK,
/// ARK-pinned) plus report signature. The handshake therefore only completes
/// for a fully verified TEE, so `send()` never exchanges application data with
/// an unverified peer.
pub async fn attested_request(
    url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
) -> Result<AttestedResponse> {
    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()), product);
    let client = build_attested_client(&verifier)?;

    let response = client
        .get(url)
        .send()
        .await
        .context("failed to send GET request (attestation gate may have rejected the peer)")?;

    let status = response.status().as_u16();
    let body = response
        .text()
        .await
        .context("failed to read response body")?;

    // The handshake completed, so the peer is fully verified. Reuse the result
    // captured by the gate rather than re-running the chain (and re-hitting KDS).
    let result = verifier
        .get_result()
        .context("no verification result captured from TLS handshake")?;

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
    getrandom::getrandom(&mut nonce).context("failed to generate a random nonce")?;
    let nonce_hex = hex::encode(nonce);

    // Build the attestation URL.
    let base = url::Url::parse(base_url).context("failed to parse base URL")?;
    let attestation_url = base
        .join(&format!(".well-known/attestation?nonce={}", nonce_hex))
        .context("failed to construct attestation URL")?;

    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()), product);
    let client = build_attested_client(&verifier)?;

    // The handshake fully verifies the certificate's key-bound report (chain
    // included). The fresh, nonce-bound report is a SEPARATE report returned in
    // the body, so it must be independently chain-verified below.
    let response = client.get(attestation_url.as_str()).send().await.context(
        "failed to send attestation request (attestation gate may have rejected the peer)",
    )?;

    let body = response
        .text()
        .await
        .context("failed to read attestation response body")?;

    let report: AttestationReport =
        serde_json::from_str(&body).context("failed to parse attestation response as JSON")?;

    // Verify the fresh report's OWN AMD chain first, then bind the nonce to the
    // report_data DERIVED from that verified blob (never an unsigned copy).
    let result = verify_sev_snp_report(&report, product)
        .await
        .context("SEV-SNP report verification failed")?;
    if !result.valid {
        bail!(
            "SEV-SNP attestation report is not valid: {}",
            result.summary
        );
    }

    // Recover the served TLS public key captured during the handshake. The fresh
    // report must be bound to exactly this key AND our nonce.
    let server_public_key = verifier
        .get_server_public_key()
        .context("no server public key captured from TLS handshake")?;
    verify_fresh_binding(&result.report_data, &server_public_key, &nonce)
        .context("fresh attestation channel binding failed")?;

    Ok(report)
}

/// Inject secrets into a confidential VM via attested TLS.
///
/// Sends a POST request with a JSON map of key-value secrets to the
/// `confidential/inject-secret` endpoint.
///
/// # Ordering invariant (increment B2b)
///
/// The custom TLS verifier is the authoritative gate: it runs the FULL AMD
/// certificate chain (plus blob-derived key binding and measurement pin) DURING
/// the TLS handshake and fails the handshake unless everything passes. Because
/// TLS application data (the secret POST body) is only ever sent after the
/// handshake completes, `send()` transmits the secret ONLY to a fully verified
/// TEE. If verification fails, `send()` returns an error and the secret never
/// leaves the client. This diverges from the aleph-cvm donor, which put the
/// secret on the wire before running the chain.
pub async fn inject_secret(
    base_url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
    secrets: &[(String, String)],
) -> Result<InjectSecretResponse> {
    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()), product);
    inject_secret_with_verifier(base_url, &verifier, secrets).await
}

/// Core of [`inject_secret`], parameterised over the verifier so tests can
/// inject a chain check that deterministically passes or fails (proving the
/// secret is gated on the AMD chain without touching hardware or the KDS).
async fn inject_secret_with_verifier(
    base_url: &str,
    verifier: &std::sync::Arc<SnpCertVerifier>,
    secrets: &[(String, String)],
) -> Result<InjectSecretResponse> {
    let base = url::Url::parse(base_url).context("failed to parse base URL")?;
    let inject_url = base
        .join("confidential/inject-secret")
        .context("failed to construct inject-secret URL")?;

    let client = build_attested_client(verifier)?;

    // Reject duplicate secret keys rather than letting the HashMap silently keep
    // only the last value: for a secret-injection tool, dropping a value the
    // caller supplied (e.g. `--secret K=v1 --secret K=v2`) is a footgun.
    let mut secrets_map: HashMap<&str, &str> = HashMap::with_capacity(secrets.len());
    for (key, value) in secrets {
        if secrets_map.insert(key.as_str(), value.as_str()).is_some() {
            bail!("duplicate secret key {key:?}: each key may be given only once");
        }
    }

    // send() drives the handshake (the authoritative gate) and only writes the
    // secret body after it completes. A verification failure fails the handshake
    // here, before any secret byte is transmitted.
    let response = client
        .post(inject_url.as_str())
        .json(&secrets_map)
        .send()
        .await
        .context(
            "failed to send inject-secret request (attestation gate rejected the peer; \
             no secret was transmitted)",
        )?;

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
    use crate::verify::{failing_chain_check, test_attested_identity, valid_chain_check};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A fresh report bound to the served key AND nonce passes.
    #[test]
    fn fresh_binding_accepts_key_and_nonce() {
        let server_key = b"served-tls-public-key";
        let nonce = [0x11u8; 32];
        assert!(
            verify_fresh_binding(&fresh_report_data(server_key, &nonce), server_key, &nonce)
                .is_ok()
        );
    }

    /// A fresh report bound to a DIFFERENT key is rejected (relay defense).
    #[test]
    fn fresh_binding_rejects_wrong_key() {
        let nonce = [0x22u8; 32];
        let rd = fresh_report_data(b"attacker-served-key", &nonce);
        assert!(verify_fresh_binding(&rd, b"honest-served-key", &nonce).is_err());
    }

    /// A fresh report bound to a DIFFERENT nonce is rejected (liveness).
    #[test]
    fn fresh_binding_rejects_wrong_nonce() {
        let server_key = b"served-tls-public-key";
        let rd = fresh_report_data(server_key, &[0x33u8; 32]);
        assert!(verify_fresh_binding(&rd, server_key, &[0x44u8; 32]).is_err());
    }

    /// Key-confusion closed at the fresh path, DRIVEN THROUGH the real check:
    /// a donor-era report_data (raw `SHA-384(attacker_key)`, i.e. a fresh report
    /// requested with `nonce = SHA-384(attacker_key)`) does NOT satisfy the
    /// domain-separated fresh binding for the attacker key. This exercises
    /// `verify_fresh_binding` rather than asserting an inequality of constructors.
    #[test]
    fn key_confusion_donor_report_data_fails_fresh_binding() {
        use aleph_tee::report_data::key_bound_report_data;
        use sha2::{Digest, Sha384};

        let attacker_key = b"attacker-public-key";
        let mut donor_report_data = [0u8; 64];
        donor_report_data[..48].copy_from_slice(&Sha384::digest(attacker_key));

        // Presented as if it were a fresh report for the attacker key + some nonce:
        // the domain-separated binding can never match it.
        assert!(
            verify_fresh_binding(&donor_report_data, attacker_key, b"any-nonce").is_err(),
            "donor raw-SHA-384 report_data must not satisfy the fresh binding"
        );
        // Sanity: the value it WOULD need is different from a key-bound value too.
        assert_ne!(
            donor_report_data[..48],
            key_bound_report_data(attacker_key)[..48]
        );
    }

    /// Spawn a local TLS server presenting `cert_der`/`key_der` that records
    /// whether it ever received the secret marker in a request body, and always
    /// answers 200 with an InjectSecretResponse. Returns (base_url, received_flag).
    async fn spawn_recording_tls_server(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (String, Arc<AtomicBool>) {
        use rustls::ServerConfig;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let received = Arc::new(AtomicBool::new(false));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let config =
            ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![CertificateDer::from(cert_der)],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
                )
                .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));

        let flag = received.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let flag = flag.clone();
                tokio::spawn(async move {
                    // If the client's attestation gate rejected our cert, the TLS
                    // handshake fails here and we never read a request body.
                    let mut tls = match acceptor.accept(stream).await {
                        Ok(t) => t,
                        Err(_) => return,
                    };
                    let mut acc: Vec<u8> = Vec::new();
                    loop {
                        let mut buf = vec![0u8; 4096];
                        match tokio::time::timeout(Duration::from_millis(1000), tls.read(&mut buf))
                            .await
                        {
                            Ok(Ok(0)) => break,
                            Ok(Ok(n)) => {
                                acc.extend_from_slice(&buf[..n]);
                                if String::from_utf8_lossy(&acc).contains("SUPER_SECRET_VALUE") {
                                    flag.store(true, Ordering::SeqCst);
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    let body = r#"{"injected":["MY_SECRET"]}"#;
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = tls.write_all(resp.as_bytes()).await;
                    let _ = tls.flush().await;
                });
            }
        });

        (format!("https://{addr}/"), received)
    }

    /// ORDERING (task test #3 + M7 mutation kill): when the AMD chain check
    /// FAILS, inject_secret must NOT transmit the secret. The local server
    /// records that it received zero secret bytes, and the call errors. Mutating
    /// the gate's `if !result.valid` to `if false` would let the handshake
    /// complete and the secret reach the server, flipping this assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_does_not_send_when_chain_fails() {
        let (cert_der, key_der) = test_attested_identity([0xAB; 48]);
        let (base_url, received) = spawn_recording_tls_server(cert_der, key_der).await;

        // Key binding + measurement are fine; only the chain check fails.
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", failing_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let result = inject_secret_with_verifier(&base_url, &verifier, &secrets).await;

        assert!(
            result.is_err(),
            "inject_secret must fail when the chain check fails"
        );
        // Give any late server-side read a moment; it must still see nothing.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !received.load(Ordering::SeqCst),
            "the secret must NOT be transmitted when the AMD chain verification fails"
        );
    }

    /// Positive control: with a passing chain check the handshake completes, the
    /// secret IS delivered, and the response is parsed. This proves the ordering
    /// test above fails for the right reason (chain gate), not because the
    /// transport is simply broken.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_sends_when_chain_passes() {
        let (cert_der, key_der) = test_attested_identity([0xAB; 48]);
        let (base_url, received) = spawn_recording_tls_server(cert_der, key_der).await;

        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let resp = inject_secret_with_verifier(&base_url, &verifier, &secrets)
            .await
            .expect("inject_secret should succeed when fully verified");

        assert_eq!(resp.injected, vec!["MY_SECRET".to_string()]);
        assert!(
            received.load(Ordering::SeqCst),
            "the secret should be delivered once the peer is fully verified"
        );
    }

    /// A duplicate secret key must fail closed rather than silently keep only the
    /// last value. The check runs before any network I/O, so no server is needed;
    /// the bail happens regardless of the (never-reached) peer.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_rejects_duplicate_keys() {
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        let secrets = vec![
            ("K".to_string(), "v1".to_string()),
            ("K".to_string(), "v2".to_string()),
        ];
        let result = inject_secret_with_verifier("https://127.0.0.1:1/", &verifier, &secrets).await;
        let err = match result {
            Ok(_) => panic!("duplicate secret keys must be rejected"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("duplicate secret key"),
            "error should name the duplicate-key cause, got: {err}"
        );
    }
}
