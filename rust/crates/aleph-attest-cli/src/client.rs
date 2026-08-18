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

#[derive(Debug, Deserialize)]
pub struct InjectSecretResponse {
    pub injected: Vec<String>,
}

/// The owner-authenticated inject-secret body, byte-for-byte the envelope the
/// agent's `InjectSecretEnvelope` deserializes when it runs with `--owner`.
///
/// `signature` is an EIP-191 personal-sign signature over
/// `owner_auth::inject_secret_payload(server_public_key_raw, canonical_secrets_json(secrets))`.
/// The agent re-canonicalizes the received `secrets` map through a `BTreeMap`
/// before recomputing the payload, so the JSON key order on the wire does not
/// matter; only the key/value pairs do.
#[derive(serde::Serialize)]
pub struct OwnerEnvelope {
    pub secrets: HashMap<String, String>,
    pub signature: String,
}

/// Build the owner-signed injection envelope for `secrets`, bound to
/// `server_public_key_raw`.
///
/// # Safety-critical precondition
///
/// `server_public_key_raw` MUST be a key that attestation verification already
/// accepted (i.e. `SnpCertVerifier::get_server_public_key()` after a completed
/// handshake). Signing over an unverified key would hand an attacker a valid
/// owner signature bound to a key they control.
pub fn build_owner_envelope(
    signing_key: &k256::ecdsa::SigningKey,
    server_public_key_raw: &[u8],
    secrets: &[(String, String)],
) -> OwnerEnvelope {
    let map: std::collections::BTreeMap<String, String> = secrets.iter().cloned().collect();
    let canonical = aleph_tee::owner_auth::canonical_secrets_json(&map);
    let payload = aleph_tee::owner_auth::inject_secret_payload(server_public_key_raw, &canonical);
    let signature = aleph_tee::owner_auth::sign_payload(signing_key, &payload);
    OwnerEnvelope {
        secrets: map.into_iter().collect(),
        signature,
    }
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
///
/// # Owner authentication
///
/// With `owner_key = Some(..)` the request is sent as the owner-signed envelope
/// that a confidential-instance agent (started with `--owner`) requires; with
/// `None` it is the legacy flat body that v-program agents accept.
pub async fn inject_secret(
    base_url: &str,
    product: &str,
    expected_measurement: Option<&[u8]>,
    secrets: &[(String, String)],
    owner_key: Option<&k256::ecdsa::SigningKey>,
) -> Result<InjectSecretResponse> {
    let verifier = SnpCertVerifier::new(expected_measurement.map(|m| m.to_vec()), product);
    inject_secret_with_verifier(base_url, &verifier, secrets, owner_key).await
}

/// Drive a verified TLS handshake against the agent and return the served public
/// key that verification accepted.
///
/// The GET is only a vehicle for the handshake: the custom verifier is the gate,
/// so an `Ok` return means the blob-derived key binding, the measurement pin and
/// the full AMD chain all passed for the returned key. The HTTP status is
/// deliberately ignored (any answer means the handshake completed); an empty
/// capture slot is a hard error, never a fallback.
async fn fetch_verified_server_key(
    client: &reqwest::Client,
    base_url: &url::Url,
    verifier: &Arc<SnpCertVerifier>,
) -> Result<Vec<u8>> {
    let attestation_url = base_url
        .join(".well-known/attestation")
        .context("failed to construct attestation URL")?;

    client.get(attestation_url.as_str()).send().await.context(
        "failed to fetch attestation before signing (the attestation gate rejected the \
             peer; nothing was signed and no secret was transmitted)",
    )?;

    verifier.get_server_public_key().context(
        "no verified server public key was captured from the TLS handshake; refusing to sign \
         an owner envelope over an unverified key",
    )
}

/// Core of [`inject_secret`], parameterised over the verifier so tests can
/// inject a chain check that deterministically passes or fails (proving the
/// secret is gated on the AMD chain without touching hardware or the KDS).
async fn inject_secret_with_verifier(
    base_url: &str,
    verifier: &std::sync::Arc<SnpCertVerifier>,
    secrets: &[(String, String)],
    owner_key: Option<&k256::ecdsa::SigningKey>,
) -> Result<InjectSecretResponse> {
    let base = url::Url::parse(base_url).context("failed to parse base URL")?;
    let inject_url = base
        .join("confidential/inject-secret")
        .context("failed to construct inject-secret URL")?;

    let client = build_attested_client(verifier)?;

    // Reject duplicate secret keys rather than letting the map silently keep only
    // the last value: for a secret-injection tool, dropping a value the caller
    // supplied (e.g. `--secret K=v1 --secret K=v2`) is a footgun. This runs
    // before any network I/O and covers both body shapes (the owner envelope
    // collects through a BTreeMap, which would deduplicate just as silently).
    let mut secrets_map: HashMap<&str, &str> = HashMap::with_capacity(secrets.len());
    for (key, value) in secrets {
        if secrets_map.insert(key.as_str(), value.as_str()).is_some() {
            bail!("duplicate secret key {key:?}: each key may be given only once");
        }
    }

    // send() drives the handshake (the authoritative gate) and only writes the
    // secret body after it completes. A verification failure fails the handshake
    // here, before any secret byte is transmitted.
    let request = match owner_key {
        // Owner-authenticated: sign over the server key that verification
        // accepted. The GET both verifies the peer and fills the capture slot,
        // so no signature is ever produced over an unverified key. The agent's
        // key is per-boot stable, so the POST's handshake pins the same key; if
        // the agent rebooted in between, the agent's own signature check fails
        // closed and a retry surfaces it.
        Some(signing_key) => {
            let server_public_key = fetch_verified_server_key(&client, &base, verifier).await?;
            let envelope = build_owner_envelope(signing_key, &server_public_key, secrets);
            client.post(inject_url.as_str()).json(&envelope)
        }
        // Legacy flat body, for v-program agents started without `--owner`.
        None => client.post(inject_url.as_str()).json(&secrets_map),
    };

    let response = request.send().await.context(
        "failed to send inject-secret request (attestation gate rejected the peer; \
         no secret was transmitted)",
    )?;

    let status = response.status().as_u16();
    if status == 409 {
        bail!("secrets already injected (409 Conflict)");
    }
    if status == 403 {
        bail!(
            "the agent rejected the owner signature (403 Forbidden): the --owner-key does not \
             match the agent's configured owner, or the VM rebooted mid-request and now serves \
             a different TLS key (retry)"
        );
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

    /// Whether `acc` holds a complete HTTP/1.1 request: headers terminated by a
    /// blank line, plus `Content-Length` body bytes (0 when the header is
    /// absent). Only ever used against requests this crate itself sends, so no
    /// chunked-encoding handling is needed.
    fn request_is_complete(acc: &[u8]) -> bool {
        let text = String::from_utf8_lossy(acc);
        let Some(header_end) = text.find("\r\n\r\n") else {
            return false;
        };
        let headers = &text[..header_end];
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        acc.len() >= header_end + 4 + content_length
    }

    /// Spawn a local TLS server presenting `cert_der`/`key_der` that records
    /// whether it ever received the secret marker in a request body, and always
    /// answers 200 with an InjectSecretResponse. Returns
    /// (base_url, received_flag, raw_requests). `raw_requests` accumulates the
    /// bytes each accepted connection sent, so a test can inspect the exact
    /// request body that went over the wire.
    async fn spawn_recording_tls_server(
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    ) -> (String, Arc<AtomicBool>, Arc<std::sync::Mutex<Vec<Vec<u8>>>>) {
        use rustls::ServerConfig;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let received = Arc::new(AtomicBool::new(false));
        let requests: Arc<std::sync::Mutex<Vec<Vec<u8>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
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
        let recorder = requests.clone();
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => break,
                };
                let acceptor = acceptor.clone();
                let flag = flag.clone();
                let recorder = recorder.clone();
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
                                }
                                // Stop as soon as the request is complete rather
                                // than waiting out the read timeout, so a test can
                                // inspect the WHOLE body (and the bodiless
                                // key-capture GET is answered immediately).
                                if request_is_complete(&acc) {
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                    recorder.lock().unwrap().push(acc);
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

        (format!("https://{addr}/"), received, requests)
    }

    /// ORDERING (task test #3 + M7 mutation kill): when the AMD chain check
    /// FAILS, inject_secret must NOT transmit the secret. The local server
    /// records that it received zero secret bytes, and the call errors. Mutating
    /// the gate's `if !result.valid` to `if false` would let the handshake
    /// complete and the secret reach the server, flipping this assertion.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_does_not_send_when_chain_fails() {
        let (cert_der, key_der) = test_attested_identity([0xAB; 48]);
        let (base_url, received, _bodies) = spawn_recording_tls_server(cert_der, key_der).await;

        // Key binding + measurement are fine; only the chain check fails.
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", failing_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let result = inject_secret_with_verifier(&base_url, &verifier, &secrets, None).await;

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
        let (base_url, received, _bodies) = spawn_recording_tls_server(cert_der, key_der).await;

        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let resp = inject_secret_with_verifier(&base_url, &verifier, &secrets, None)
            .await
            .expect("inject_secret should succeed when fully verified");

        assert_eq!(resp.injected, vec!["MY_SECRET".to_string()]);
        assert!(
            received.load(Ordering::SeqCst),
            "the secret should be delivered once the peer is fully verified"
        );
    }

    /// The envelope this client builds must be exactly what the agent-side
    /// verifier accepts: same canonical secrets JSON, same key-bound payload,
    /// same EIP-191 signature scheme.
    #[test]
    fn owner_envelope_matches_agent_contract() {
        use std::collections::BTreeMap;
        let key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let secrets = vec![("luks_passphrase".to_string(), "hunter2".to_string())];
        let envelope = build_owner_envelope(&key, b"server-key-raw", &secrets);
        // The agent-side verifier must accept exactly this envelope.
        let map: BTreeMap<String, String> = secrets.into_iter().collect();
        let canonical = aleph_tee::owner_auth::canonical_secrets_json(&map);
        let payload = aleph_tee::owner_auth::inject_secret_payload(b"server-key-raw", &canonical);
        let owner = aleph_tee::owner_auth::address_from_verifying_key(key.verifying_key());
        assert!(aleph_tee::owner_auth::verify_owner(
            &payload,
            &envelope.signature,
            &owner
        ));
        assert_eq!(envelope.secrets.get("luks_passphrase").unwrap(), "hunter2");
    }

    /// The signature is bound to the SERVER key, so an envelope built for one
    /// key must not verify against a payload derived from another. This is the
    /// property that makes signing only a VERIFIED key matter.
    #[test]
    fn owner_envelope_is_bound_to_the_server_key() {
        use std::collections::BTreeMap;
        let key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let secrets = vec![("k".to_string(), "v".to_string())];
        let envelope = build_owner_envelope(&key, b"honest-server-key", &secrets);

        let map: BTreeMap<String, String> = secrets.into_iter().collect();
        let canonical = aleph_tee::owner_auth::canonical_secrets_json(&map);
        let other_payload =
            aleph_tee::owner_auth::inject_secret_payload(b"attacker-server-key", &canonical);
        let owner = aleph_tee::owner_auth::address_from_verifying_key(key.verifying_key());
        assert!(
            !aleph_tee::owner_auth::verify_owner(&other_payload, &envelope.signature, &owner),
            "a signature over the honest server key must not verify for another key"
        );
    }

    /// End to end over attested TLS: with `--owner-key` the client drives a
    /// verified handshake first, then POSTs the envelope body (never the flat
    /// legacy body). The signature must verify against the key the server
    /// actually served.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_sends_owner_envelope_signed_over_the_served_key() {
        let (cert_der, key_der) = test_attested_identity([0xAB; 48]);
        let served_public_key = crate::verify::server_public_key_from_cert(&cert_der).unwrap();
        let (base_url, _received, bodies) = spawn_recording_tls_server(cert_der, key_der).await;

        let owner_key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let resp =
            inject_secret_with_verifier(&base_url, &verifier, &secrets, Some(&owner_key)).await;
        assert!(
            resp.is_ok(),
            "owner-mode injection should succeed: {resp:?}"
        );

        // Find the POSTed envelope among the recorded requests.
        let requests = bodies.lock().unwrap().clone();
        let posted = requests
            .iter()
            .map(|r| String::from_utf8_lossy(r).to_string())
            .find(|r| r.starts_with("POST "))
            .expect("a POST request must have been recorded");
        let body = posted
            .split_once("\r\n\r\n")
            .expect("POST must carry a body")
            .1;
        let envelope: serde_json::Value =
            serde_json::from_str(body).expect("the POST body must be JSON");
        let signature = envelope["signature"]
            .as_str()
            .expect("owner mode must send a `signature` field, not the flat legacy body");

        // Reproduce the agent's check verbatim against the SERVED key.
        let map: std::collections::BTreeMap<String, String> = secrets.into_iter().collect();
        let canonical = aleph_tee::owner_auth::canonical_secrets_json(&map);
        let payload = aleph_tee::owner_auth::inject_secret_payload(&served_public_key, &canonical);
        let owner = aleph_tee::owner_auth::address_from_verifying_key(owner_key.verifying_key());
        assert!(
            aleph_tee::owner_auth::verify_owner(&payload, signature, &owner),
            "the agent must accept the envelope: signature must be over the served TLS key"
        );
        assert_eq!(envelope["secrets"]["MY_SECRET"], "SUPER_SECRET_VALUE");
    }

    /// Owner mode must not weaken the ordering guarantee: when the AMD chain
    /// check fails, no handshake completes, so no key is captured, nothing is
    /// signed and no secret is transmitted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn inject_secret_owner_mode_does_not_send_when_chain_fails() {
        let (cert_der, key_der) = test_attested_identity([0xAB; 48]);
        let (base_url, received, _bodies) = spawn_recording_tls_server(cert_der, key_der).await;

        let owner_key = k256::ecdsa::SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", failing_chain_check());
        let secrets = vec![("MY_SECRET".to_string(), "SUPER_SECRET_VALUE".to_string())];
        let result =
            inject_secret_with_verifier(&base_url, &verifier, &secrets, Some(&owner_key)).await;

        assert!(
            result.is_err(),
            "owner-mode inject_secret must fail when the chain check fails"
        );
        assert!(
            verifier.get_server_public_key().is_none(),
            "no server key may be captured (hence signed over) when verification fails"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !received.load(Ordering::SeqCst),
            "the secret must NOT be transmitted when the AMD chain verification fails"
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
        let result =
            inject_secret_with_verifier("https://127.0.0.1:1/", &verifier, &secrets, None).await;
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
