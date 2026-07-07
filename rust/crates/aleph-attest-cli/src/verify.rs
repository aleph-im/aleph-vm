use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use aleph_tee::report_data::key_bound_report_data;
use aleph_tee::sev_snp::report::{extract_measurement, extract_report_data, parse_sev_snp_report};
use aleph_tee::sev_snp::verify::verify_sev_snp_report;
use aleph_tee::types::{AttestationReport, VerificationResult};
use aleph_tee::x509::extract_attestation_from_cert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// An async closure that runs the full AMD certificate-chain verification over
/// a report's signed blob. In production this is `verify_sev_snp_report`; tests
/// inject a deterministic stub so the ordering/gate behaviour can be exercised
/// without hardware or the AMD KDS network.
pub(crate) type ChainCheck = Arc<
    dyn Fn(
            AttestationReport,
            String,
        ) -> Pin<Box<dyn Future<Output = anyhow::Result<VerificationResult>>>>
        + Send
        + Sync,
>;

/// A custom TLS certificate verifier that extracts a SEV-SNP attestation report
/// from the server's X.509 certificate extension and FULLY verifies it during
/// the TLS handshake.
///
/// # Authoritative gate (increment B2b)
///
/// `verify_server_cert` performs the COMPLETE verification before it returns
/// `Ok`, so the TLS handshake only completes for a genuinely attested TEE. This
/// is what makes it safe for the client to send application data (including
/// injected secrets) immediately after the handshake: an unverified peer never
/// gets a completed connection, so it never receives a request body.
///
/// Verification performed, all against the AMD-signed blob (`report.data`):
/// 1. The certificate must contain an attestation extension carrying a
///    parseable SEV-SNP report blob.
/// 2. **Key binding, blob-derived**: the report_data DERIVED from the parsed
///    blob (not any unsigned copy) must equal the canonical, domain-separated
///    `key_bound_report_data(server_public_key)`, proving the report is bound to
///    this specific TLS key.
/// 3. **Measurement pinning, blob-derived**: if an expected measurement is
///    configured, the measurement DERIVED from the parsed blob must match.
/// 4. **Full AMD chain**: the VCEK -> ASK -> ARK chain (ARK-pinned) and the
///    report signature are verified via `verify_sev_snp_report`. This is async
///    and this callback is sync, so it is driven on the current multi-threaded
///    tokio worker via `block_in_place` + `Handle::block_on`.
///
/// # Trust model
///
/// The report only ever carries `data` (the AMD-signed blob). `report_data` and
/// `measurement` are DERIVED from it here; there are no standalone unsigned
/// copies to be tricked by. This diverges from the aleph-cvm donor, which
/// trusted unsigned JSON copies and verified the chain only AFTER sending
/// secrets. See the rust-port-divergences ledger.
pub struct SnpCertVerifier {
    server_public_key: Mutex<Option<Vec<u8>>>,
    verification_result: Mutex<Option<VerificationResult>>,
    expected_measurement: Option<Vec<u8>>,
    product: String,
    chain_check: ChainCheck,
    provider: Arc<CryptoProvider>,
}

impl std::fmt::Debug for SnpCertVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnpCertVerifier")
            .field("expected_measurement", &self.expected_measurement)
            .field("product", &self.product)
            .field("chain_check", &"<async chain verifier>")
            .finish()
    }
}

impl SnpCertVerifier {
    /// Create a `SnpCertVerifier` that runs the real AMD chain verification.
    ///
    /// If `expected_measurement` is `Some`, the handshake is rejected unless the
    /// blob-derived measurement matches, so the client never completes a TLS
    /// connection to a VM running unexpected code. `product` is the AMD product
    /// line (e.g. "Milan", "Genoa", "Turin") used to pin the ARK and fetch the
    /// VCEK.
    pub fn new(expected_measurement: Option<Vec<u8>>, product: impl Into<String>) -> Arc<Self> {
        Self::with_chain_check(
            expected_measurement,
            product,
            Arc::new(|report, product| {
                Box::pin(async move { verify_sev_snp_report(&report, &product).await })
            }),
        )
    }

    /// Create a `SnpCertVerifier` with an injected chain-verification closure.
    /// Production code uses [`SnpCertVerifier::new`]; tests inject a stub.
    pub(crate) fn with_chain_check(
        expected_measurement: Option<Vec<u8>>,
        product: impl Into<String>,
        chain_check: ChainCheck,
    ) -> Arc<Self> {
        Arc::new(Self {
            server_public_key: Mutex::new(None),
            verification_result: Mutex::new(None),
            expected_measurement,
            product: product.into(),
            chain_check,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }

    /// Retrieve the raw server TLS public key captured during the handshake.
    ///
    /// This is the exact `public_key_raw` the agent bound its key-binding report
    /// to. The fresh-attestation flow needs it to reconstruct and check the
    /// channel-bound `fresh_report_data(server_public_key, nonce)`.
    pub fn get_server_public_key(&self) -> Option<Vec<u8>> {
        self.server_public_key.lock().unwrap().clone()
    }

    /// Retrieve the `VerificationResult` produced by the full AMD chain check
    /// during the handshake. `Some` implies the peer is a fully verified TEE.
    pub fn get_result(&self) -> Option<VerificationResult> {
        self.verification_result.lock().unwrap().clone()
    }
}

/// Extract the raw server public key (the SubjectPublicKeyInfo BIT STRING
/// content, i.e. the uncompressed EC point for a P-384 key) from a DER cert.
///
/// This is the identical byte string the agent obtains from
/// `rcgen::KeyPair::public_key_raw()` and binds its attestation report to.
fn server_public_key_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| Error::General(format!("failed to parse certificate for key binding: {e}")))?;
    Ok(cert
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .to_vec())
}

impl ServerCertVerifier for SnpCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Extract the attestation report from the certificate extension.
        let report = extract_attestation_from_cert(end_entity.as_ref())
            .map_err(|e| {
                Error::General(format!(
                    "failed to extract attestation from certificate: {e}"
                ))
            })?
            .ok_or_else(|| {
                Error::General("certificate does not contain an attestation extension".to_string())
            })?;

        // 2. Parse the AMD-signed blob. report_data AND measurement are DERIVED
        //    from it: that blob is the only thing AMD signs, so it is the single
        //    source of truth. Any unsigned copy that might travel alongside is
        //    ignored (the report type no longer even carries one).
        let parsed = parse_sev_snp_report(&report.data)
            .map_err(|e| Error::General(format!("failed to parse attestation report blob: {e}")))?;
        let blob_report_data = extract_report_data(&parsed);
        let blob_measurement = extract_measurement(&parsed).to_vec();

        // 3. Key binding against the BLOB-DERIVED report_data:
        //    report_data[..48] must equal key_bound_report_data(server_pubkey)[..48].
        //    Proves the report was generated for this specific TLS key AND, thanks
        //    to the domain tag, cannot be confused with a fresh/nonce report.
        let public_key_bytes = server_public_key_from_cert(end_entity.as_ref())?;
        let expected = key_bound_report_data(&public_key_bytes);
        if blob_report_data[..48] != expected[..48] {
            return Err(Error::General(format!(
                "key binding verification failed: blob-derived report_data does not \
                 match the domain-separated key binding. Expected {}, got {}",
                hex::encode(&expected[..48]),
                hex::encode(&blob_report_data[..48]),
            )));
        }

        // 4. Measurement pinning against the BLOB-DERIVED measurement.
        if let Some(ref expected_measurement) = self.expected_measurement
            && blob_measurement != *expected_measurement
        {
            return Err(Error::General(format!(
                "measurement mismatch: expected {}, got {} (blob-derived)",
                hex::encode(expected_measurement),
                hex::encode(&blob_measurement),
            )));
        }

        // 5. FULL AMD chain (VCEK -> ASK -> ARK, ARK-pinned) + report signature.
        //    This is the authoritative gate: only a genuinely AMD-signed,
        //    chain-valid report lets the handshake complete, so secrets are sent
        //    ONLY to a fully verified TEE. The chain check is async and this
        //    callback is sync, so drive it on the current multi-threaded tokio
        //    worker with block_in_place (main.rs uses #[tokio::main], i.e. the
        //    multi-thread runtime).
        let result = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on((self.chain_check)(report.clone(), self.product.clone()))
        })
        .map_err(|e| Error::General(format!("AMD chain verification failed: {e:#}")))?;
        if !result.valid {
            return Err(Error::General(format!(
                "attestation report failed AMD chain verification: {}",
                result.summary
            )));
        }

        *self.server_public_key.lock().unwrap() = Some(public_key_bytes);
        *self.verification_result.lock().unwrap() = Some(result);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ---- test-only chain-check stubs, shared with the client module's tests ----

/// A chain check that always reports a valid report (the AMD chain "passed").
#[cfg(test)]
pub(crate) fn valid_chain_check() -> ChainCheck {
    Arc::new(|_report, _product| {
        Box::pin(async move {
            Ok(VerificationResult {
                valid: true,
                tee_type: aleph_tee::types::TeeType::SevSnp,
                summary: "stub: chain verified".to_string(),
                measurement: vec![0u8; 48],
                report_data: [0u8; 64],
                details: serde_json::Value::Null,
            })
        })
    })
}

/// A chain check that returns `Ok(valid: false)` (chain ran but rejected the
/// report). Exercises the `if !result.valid` gate.
#[cfg(test)]
pub(crate) fn invalid_chain_check() -> ChainCheck {
    Arc::new(|_report, _product| {
        Box::pin(async move {
            Ok(VerificationResult {
                valid: false,
                tee_type: aleph_tee::types::TeeType::SevSnp,
                summary: "stub: chain rejected the report".to_string(),
                measurement: vec![0u8; 48],
                report_data: [0u8; 64],
                details: serde_json::Value::Null,
            })
        })
    })
}

/// A chain check that errors (e.g. an unsigned/forged blob the real chain would
/// reject, or a KDS failure).
#[cfg(test)]
pub(crate) fn failing_chain_check() -> ChainCheck {
    Arc::new(|_report, _product| Box::pin(async move { anyhow::bail!("stub: chain check failed") }))
}

/// Build an attested-TLS identity whose signed blob correctly key-binds the
/// generated key and carries `measurement`. Returns (cert_der, pkcs8_key_der).
/// Shared by the verify and client test modules.
#[cfg(test)]
pub(crate) fn test_attested_identity(measurement: [u8; 48]) -> (Vec<u8>, Vec<u8>) {
    use aleph_tee::x509::{ATTESTATION_OID, encode_attestation_extension};
    use rcgen::{CertificateParams, CustomExtension, KeyPair};
    use sev::firmware::guest::AttestationReport as SevAR;
    use sev::parser::Encoder;

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let public_key_raw = key_pair.public_key_raw().to_vec();

    let mut rep = SevAR {
        version: 3,
        report_data: key_bound_report_data(&public_key_raw),
        measurement,
        cpuid_fam_id: Some(0x19),
        cpuid_mod_id: Some(0x01),
        cpuid_step: Some(0x00),
        ..Default::default()
    };
    rep.chip_id[0] = 1;
    let mut blob = Vec::new();
    rep.encode(&mut blob, ()).unwrap();

    let report = AttestationReport {
        tee_type: aleph_tee::types::TeeType::SevSnp,
        data: blob,
    };
    let ext_value = encode_attestation_extension(&report).unwrap();
    let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.custom_extensions.push(custom_ext);
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.der().to_vec(), key_pair.serialize_der())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tee::types::TeeType;
    use aleph_tee::x509::{ATTESTATION_OID, encode_attestation_extension};
    use rcgen::{CertificateParams, CustomExtension, KeyPair};
    use rustls::pki_types::{ServerName, UnixTime};
    use sha2::{Digest, Sha384};

    /// Build a real 1184-byte SEV-SNP report blob carrying the given internal
    /// report_data and measurement (AMD signature is irrelevant here; the chain
    /// check is injected in tests).
    fn encoded_blob(report_data: [u8; 64], measurement: [u8; 48]) -> Vec<u8> {
        use sev::firmware::guest::AttestationReport as SevAR;
        use sev::parser::Encoder;

        let mut rep = SevAR {
            version: 3,
            report_data,
            measurement,
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0x00),
            ..Default::default()
        };
        rep.chip_id[0] = 1;
        let mut buf = Vec::new();
        rep.encode(&mut buf, ()).unwrap();
        buf
    }

    /// Build a self-signed P-384 cert whose embedded blob has `blob_report_data`
    /// and `blob_measurement` as its INTERNAL (signed) fields. Returns
    /// (cert_der, public_key_raw).
    fn cert_with_blob(
        blob_report_data: [u8; 64],
        blob_measurement: [u8; 48],
    ) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: encoded_blob(blob_report_data, blob_measurement),
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
        (cert_der, public_key_raw)
    }

    /// Build a self-signed cert whose blob correctly key-binds its OWN key.
    /// Returns (cert_der, public_key_raw).
    fn cert_bound_to_own_key(blob_measurement: [u8; 48]) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let blob = encoded_blob(key_bound_report_data(&public_key_raw), blob_measurement);
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: blob,
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
        (cert_der, public_key_raw)
    }

    /// Self-sign a cert with `key_pair` whose attestation extension carries the
    /// RAW `json` payload (so a test can smuggle extra, unsigned fields).
    fn cert_with_raw_extension_json(key_pair: &KeyPair, json: &str) -> Vec<u8> {
        use der::Encode;
        use der::asn1::OctetStringRef;
        let der_bytes = OctetStringRef::new(json.as_bytes())
            .unwrap()
            .to_der()
            .unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, der_bytes);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        params.self_signed(key_pair).unwrap().der().to_vec()
    }

    fn run_verify(
        verifier: &SnpCertVerifier,
        cert_der: &[u8],
    ) -> Result<ServerCertVerified, Error> {
        let cert = CertificateDer::from(cert_der.to_vec());
        verifier.verify_server_cert(
            &cert,
            &[],
            &ServerName::try_from("localhost").unwrap(),
            &[],
            UnixTime::now(),
        )
    }

    /// Happy path: blob correctly key-binds the served key AND the (stubbed) AMD
    /// chain passes -> handshake accepted; served key + result are captured.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepts_correct_binding_and_valid_chain() {
        let (cert_der, public_key_raw) = cert_bound_to_own_key([0xAB; 48]);
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_ok());
        assert_eq!(verifier.get_server_public_key().unwrap(), public_key_raw);
        assert!(verifier.get_result().unwrap().valid);
    }

    /// BLOCKER #1 (key binding is blob-derived): the blob binds a DIFFERENT key
    /// than the cert's key -> rejected, even though the chain would pass.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_blob_bound_to_other_key() {
        let (cert_der, _pk) = cert_with_blob(key_bound_report_data(b"some-other-key"), [0xAB; 48]);
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// BLOCKER #1, sharpest form (task test #1): an attacker smuggles an extra
    /// unsigned `report_data` field equal to key_bound(cert_key) into the cert
    /// JSON, but the blob's INTERNAL report_data binds a DIFFERENT key. The
    /// verifier must REJECT: it uses the blob, never the smuggled JSON copy.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_only_smuggled_json_binds_key() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        // Signed blob binds an UNRELATED key; the smuggled JSON report_data binds
        // the cert's real key (what an attacker would try to fake trust with).
        let blob = encoded_blob(key_bound_report_data(b"unrelated-key"), [0xAB; 48]);
        let json = format!(
            r#"{{"tee_type":"sev-snp","data":"{}","report_data":"{}","measurement":"{}"}}"#,
            hex::encode(&blob),
            hex::encode(key_bound_report_data(&public_key_raw)),
            hex::encode([0xAB; 48]),
        );
        let cert_der = cert_with_raw_extension_json(&key_pair, &json);

        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(
            run_verify(&verifier, &cert_der).is_err(),
            "must reject: only the smuggled JSON binds the key, the signed blob does not"
        );
    }

    /// BLOCKER #1 symmetric: the blob correctly binds the cert key; a smuggled
    /// JSON report_data binding a DIFFERENT key is present but ignored -> accepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn accepts_when_blob_binds_key_despite_smuggled_json() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        // Signed blob binds the cert's real key; smuggled JSON binds an attacker
        // key and carries a bogus measurement. Both smuggled values are ignored.
        let blob = encoded_blob(key_bound_report_data(&public_key_raw), [0xAB; 48]);
        let json = format!(
            r#"{{"tee_type":"sev-snp","data":"{}","report_data":"{}","measurement":"{}"}}"#,
            hex::encode(&blob),
            hex::encode(key_bound_report_data(b"attacker-key")),
            hex::encode([0xEE; 48]),
        );
        let cert_der = cert_with_raw_extension_json(&key_pair, &json);

        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(
            run_verify(&verifier, &cert_der).is_ok(),
            "must accept: the signed blob binds the served key; smuggled JSON is ignored"
        );
    }

    /// BLOCKER #1 (measurement is blob-derived) + task test #2: the blob's
    /// measurement differs from the pin, but a smuggled JSON `measurement` equals
    /// the pin. Must REJECT -> the pin is checked against the blob, not the JSON.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_only_smuggled_json_measurement_matches_pin() {
        let expected = vec![0xCD; 48];
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        // Blob measurement is WRONG (0xEE); smuggled JSON measurement is the pin.
        let blob = encoded_blob(key_bound_report_data(&public_key_raw), [0xEE; 48]);
        let json = format!(
            r#"{{"tee_type":"sev-snp","data":"{}","report_data":"{}","measurement":"{}"}}"#,
            hex::encode(&blob),
            hex::encode([0u8; 64]),
            hex::encode(&expected),
        );
        let cert_der = cert_with_raw_extension_json(&key_pair, &json);

        let verifier =
            SnpCertVerifier::with_chain_check(Some(expected), "Milan", valid_chain_check());
        assert!(
            run_verify(&verifier, &cert_der).is_err(),
            "must reject: blob measurement != pin, smuggled JSON must not rescue it"
        );
    }

    /// Measurement pinning accepts the expected (blob-derived) measurement.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn measurement_pinning_accepts_expected() {
        let (cert_der, _pk) = cert_bound_to_own_key([0xCD; 48]);
        let verifier =
            SnpCertVerifier::with_chain_check(Some(vec![0xCD; 48]), "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_ok());
    }

    /// Measurement pinning rejects a wrong (blob-derived) measurement.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn measurement_pinning_rejects_wrong() {
        let (cert_der, _pk) = cert_bound_to_own_key([0xCD; 48]);
        let verifier =
            SnpCertVerifier::with_chain_check(Some(vec![0xEE; 48]), "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// A cert without any attestation extension is rejected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_cert_without_extension() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// A blob that is not a valid 1184-byte SEV-SNP report is rejected before any
    /// chain work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_unparseable_blob() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8], // too short to be a report
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// Old donor scheme (report_data = raw SHA-384(pubkey), no domain tag) in the
    /// blob is rejected by the domain-separated key binding.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_scheme_key_binding_is_rejected() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let mut old_scheme = [0u8; 64];
        old_scheme[..48].copy_from_slice(&Sha384::digest(&public_key_raw));
        let blob = encoded_blob(old_scheme, [0xAB; 48]);
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: blob,
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", valid_chain_check());
        assert!(
            run_verify(&verifier, &cert_der).is_err(),
            "old-scheme (non-domain-separated) key binding must be rejected"
        );
    }

    /// BLOCKER #2 gate + M7 mutation kill: with a correct key binding and
    /// measurement, but a chain check that reports the report INVALID, the
    /// handshake MUST be rejected. Mutating the `if !result.valid` gate to
    /// `if false` would make this return Ok, so this test kills that mutation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_chain_reports_invalid() {
        let (cert_der, _pk) = cert_bound_to_own_key([0xAB; 48]);
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", invalid_chain_check());
        assert!(
            run_verify(&verifier, &cert_der).is_err(),
            "chain returned valid:false; the gate must reject"
        );
        assert!(
            verifier.get_result().is_none(),
            "no result should be stashed on rejection"
        );
    }

    /// BLOCKER #2 gate: a chain check that ERRORS (as the real chain would for an
    /// unsigned/forged blob or a KDS failure) must reject the handshake.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rejects_when_chain_errors() {
        let (cert_der, _pk) = cert_bound_to_own_key([0xAB; 48]);
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", failing_chain_check());
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// block_in_place reliability: the chain check performs genuinely-pending
    /// async work (a timer that only fires if the runtime keeps progressing while
    /// the sync verify callback blocks on it) plus a real TCP connect (exercising
    /// the IO driver, as the KDS fetch would). It completes without deadlock, so
    /// block_in_place + Handle::block_on is safe inside the handshake callback.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn block_in_place_drives_pending_async_work() {
        // A local listener the inner async work connects to (proves the IO driver
        // still services sockets while the verify callback blocks on block_on).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            // Accept a few connections so the inner connect always succeeds.
            for _ in 0..4 {
                let _ = listener.accept().await;
            }
        });

        let chain: ChainCheck = Arc::new(move |_report, _product| {
            Box::pin(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                tokio::net::TcpStream::connect(addr)
                    .await
                    .map_err(|e| anyhow::anyhow!("inner connect failed: {e}"))?;
                Ok(VerificationResult {
                    valid: true,
                    tee_type: aleph_tee::types::TeeType::SevSnp,
                    summary: "stub: async work completed".to_string(),
                    measurement: vec![0u8; 48],
                    report_data: [0u8; 64],
                    details: serde_json::Value::Null,
                })
            })
        });

        let (cert_der, _pk) = cert_bound_to_own_key([0xAB; 48]);
        let verifier = SnpCertVerifier::with_chain_check(None, "Milan", chain);
        assert!(
            run_verify(&verifier, &cert_der).is_ok(),
            "block_in_place must drive pending async work (timer + connect) to completion"
        );
    }
}
