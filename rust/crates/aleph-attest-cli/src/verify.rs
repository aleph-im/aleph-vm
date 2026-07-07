use std::sync::{Arc, Mutex};

use aleph_tee::report_data::key_bound_report_data;
use aleph_tee::types::AttestationReport;
use aleph_tee::x509::extract_attestation_from_cert;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};

/// A custom TLS certificate verifier that extracts SEV-SNP attestation reports
/// from the server's X.509 certificate extension and verifies them during the
/// TLS handshake.
///
/// Verification performed at handshake time:
/// 1. The certificate must contain an attestation extension.
/// 2. The `report_data` must equal the canonical, domain-separated key binding
///    `aleph_tee::report_data::key_bound_report_data(server_public_key)`, proving
///    the attestation report is bound to this specific TLS key.
/// 3. If an expected measurement is configured, the report's measurement must match.
///
/// # Scheme match with the agent (increment B2a)
///
/// The in-guest `aleph-attest-agent` fills `report_data` with
/// `key_bound_report_data(public_key_raw)` where `public_key_raw` are the raw
/// bytes of its served ECDSA P-384 public key (`rcgen::KeyPair::public_key_raw()`,
/// the uncompressed EC point). This verifier extracts the same raw bytes from the
/// presented certificate (`subject_public_key.data`, the SubjectPublicKeyInfo BIT
/// STRING content) and applies the same canonical constructor, so the two sides
/// cannot drift. This is the NEW domain-separated scheme, which diverges from the
/// aleph-cvm donor's old `report_data == SHA-384(public_key)` binding.
///
/// The full AMD certificate chain verification (VCEK -> ASK -> ARK, ARK-pinned)
/// is performed after the handshake by the caller, since it requires async
/// network access.
#[derive(Debug)]
pub struct SnpCertVerifier {
    extracted_report: Mutex<Option<AttestationReport>>,
    server_public_key: Mutex<Option<Vec<u8>>>,
    expected_measurement: Option<Vec<u8>>,
    provider: Arc<CryptoProvider>,
}

impl SnpCertVerifier {
    /// Create a new `SnpCertVerifier` wrapped in an `Arc` for use with rustls.
    ///
    /// If `expected_measurement` is `Some`, the handshake will be rejected if the
    /// attestation report's measurement doesn't match. This prevents the client
    /// from even completing a TLS connection to a VM running unexpected code.
    pub fn new(expected_measurement: Option<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            extracted_report: Mutex::new(None),
            server_public_key: Mutex::new(None),
            expected_measurement,
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        })
    }

    /// Retrieve the attestation report extracted during the TLS handshake.
    ///
    /// Returns `None` if no report was extracted (i.e., the handshake has not
    /// completed or the certificate did not contain an attestation extension).
    pub fn get_report(&self) -> Option<AttestationReport> {
        self.extracted_report.lock().unwrap().clone()
    }

    /// Retrieve the raw server TLS public key captured during the handshake.
    ///
    /// This is the exact `public_key_raw` the agent bound its key-binding report
    /// to. The fresh-attestation flow needs it to reconstruct and check the
    /// channel-bound `fresh_report_data(server_public_key, nonce)`.
    pub fn get_server_public_key(&self) -> Option<Vec<u8>> {
        self.server_public_key.lock().unwrap().clone()
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
        // 1. Extract attestation report from the certificate extension.
        let report = extract_attestation_from_cert(end_entity.as_ref())
            .map_err(|e| {
                Error::General(format!(
                    "failed to extract attestation from certificate: {e}"
                ))
            })?
            .ok_or_else(|| {
                Error::General("certificate does not contain an attestation extension".to_string())
            })?;

        // 2. Verify key binding against the NEW domain-separated scheme:
        //    report_data[..48] must equal key_bound_report_data(server_pubkey)[..48]
        //    where server_pubkey are the raw bytes of the presented TLS key.
        //    This proves the report was generated for this specific TLS key AND,
        //    thanks to the domain tag, cannot be confused with a fresh/nonce
        //    report (the attested-key-confusion hole B2a closed).
        let public_key_bytes = server_public_key_from_cert(end_entity.as_ref())?;
        let expected = key_bound_report_data(&public_key_bytes);

        if report.report_data[..48] != expected[..48] {
            return Err(Error::General(format!(
                "key binding verification failed: report_data does not match the \
                 domain-separated key binding. Expected {}, got {}",
                hex::encode(&expected[..48]),
                hex::encode(&report.report_data[..48]),
            )));
        }

        // 3. If an expected measurement is configured, verify it matches.
        if let Some(ref expected_measurement) = self.expected_measurement
            && report.measurement != *expected_measurement
        {
            return Err(Error::General(format!(
                "measurement mismatch: expected {}, got {}",
                hex::encode(expected_measurement),
                hex::encode(&report.measurement),
            )));
        }

        *self.server_public_key.lock().unwrap() = Some(public_key_bytes);
        *self.extracted_report.lock().unwrap() = Some(report);
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

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tee::types::TeeType;
    use aleph_tee::x509::{ATTESTATION_OID, encode_attestation_extension};
    use rcgen::{CertificateParams, CustomExtension, KeyPair};
    use rustls::pki_types::{ServerName, UnixTime};
    use sha2::{Digest, Sha384};

    /// Build a self-signed cert (P-384) carrying an attestation report with the
    /// given `report_data` and `measurement`, mirroring what the agent serves.
    /// Returns (cert_der, public_key_raw).
    fn cert_with_report(report_data: [u8; 64], measurement: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();

        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8], // handshake check never parses `data`
            report_data,
            measurement,
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);

        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert = params.self_signed(&key_pair).unwrap();

        (cert.der().to_vec(), public_key_raw)
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

    /// A report bound with the canonical key-binding scheme for the served key
    /// passes the handshake, and the served key is captured for the fresh flow.
    #[test]
    fn key_binding_accepts_correct_scheme() {
        // We do not know the pubkey until the cert is generated, so generate the
        // key first, build report_data from it, then build the cert.
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8],
            report_data: key_bound_report_data(&public_key_raw),
            measurement: vec![0xAB; 48],
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();

        let verifier = SnpCertVerifier::new(None);
        assert!(run_verify(&verifier, &cert_der).is_ok());
        // The captured server key equals the raw key the agent would have bound.
        assert_eq!(verifier.get_server_public_key().unwrap(), public_key_raw);
    }

    /// A report whose report_data does not match the key binding is rejected.
    #[test]
    fn key_binding_rejects_wrong_binding() {
        // report_data bound to a DIFFERENT key than the cert's key.
        let (cert_der, _pk) =
            cert_with_report(key_bound_report_data(b"some-other-key"), vec![0xAB; 48]);
        let verifier = SnpCertVerifier::new(None);
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// Measurement pinning accepts the expected measurement.
    #[test]
    fn measurement_pinning_accepts_expected() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let measurement = vec![0xCD; 48];
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8],
            report_data: key_bound_report_data(&public_key_raw),
            measurement: measurement.clone(),
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();

        let verifier = SnpCertVerifier::new(Some(measurement));
        assert!(run_verify(&verifier, &cert_der).is_ok());
    }

    /// Measurement pinning rejects a wrong measurement (handshake aborts before
    /// any application data is exchanged).
    #[test]
    fn measurement_pinning_rejects_wrong() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8],
            report_data: key_bound_report_data(&public_key_raw),
            measurement: vec![0xCD; 48],
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();

        // Pin a DIFFERENT measurement.
        let verifier = SnpCertVerifier::new(Some(vec![0xEE; 48]));
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// A cert without any attestation extension is rejected.
    #[test]
    fn rejects_cert_without_extension() {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();

        let verifier = SnpCertVerifier::new(None);
        assert!(run_verify(&verifier, &cert_der).is_err());
    }

    /// Key-confusion attack closed end-to-end at the verifier: a report whose
    /// report_data is the DONOR's old-scheme raw `SHA-384(attacker_key)` (which
    /// is also exactly what a donor-era fresh endpoint would emit for
    /// `nonce = SHA-384(attacker_key)`) does NOT satisfy this verifier's
    /// domain-separated key binding for the attacker key. The domain tag makes
    /// `SHA-384(attacker_key)` != `SHA-384(DOMAIN_KEY || attacker_key)`, so the
    /// handshake is rejected. This closes the loop with B2a's fix.
    #[test]
    fn key_confusion_old_scheme_is_rejected() {
        // Build a cert whose embedded report uses the OLD scheme
        // (report_data = SHA-384(pubkey) with no domain tag).
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
        let public_key_raw = key_pair.public_key_raw().to_vec();
        let mut old_scheme = [0u8; 64];
        old_scheme[..48].copy_from_slice(&Sha384::digest(&public_key_raw));
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0u8; 8],
            report_data: old_scheme,
            measurement: vec![0xAB; 48],
        };
        let ext_value = encode_attestation_extension(&report).unwrap();
        let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, ext_value);
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.custom_extensions.push(custom_ext);
        let cert_der = params.self_signed(&key_pair).unwrap().der().to_vec();

        let verifier = SnpCertVerifier::new(None);
        assert!(
            run_verify(&verifier, &cert_der).is_err(),
            "old-scheme (non-domain-separated) key binding must be rejected"
        );
    }
}
