use std::sync::Arc;

use aleph_tee::traits::TeeBackend;
use aleph_tee::types::AttestationReport;
use aleph_tee::x509::{ATTESTATION_OID, encode_attestation_extension};
use anyhow::{Context, Result};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zeroize::Zeroizing;

use crate::attestation::get_key_bound_report;

/// An attested TLS identity: a self-signed certificate with an embedded
/// attestation report, plus the corresponding private key material.
pub struct AttestedTlsIdentity {
    /// DER-encoded self-signed certificate containing the attestation extension.
    pub cert_der: Vec<u8>,
    /// DER-encoded PKCS#8 private key (zeroized on drop).
    pub key_der: Zeroizing<Vec<u8>>,
    /// Raw bytes of the served public key. This is the exact key the key-bound
    /// report commits to, and the key the fresh-attestation endpoint must bind
    /// its nonce to (channel binding). Public material, not secret.
    pub public_key_raw: Vec<u8>,
    /// The attestation report that was embedded in the certificate.
    /// Retained for programmatic access (e.g. logging, diagnostics).
    #[allow(dead_code)]
    pub report: AttestationReport,
}

/// Generate a self-signed TLS certificate with an embedded attestation extension.
///
/// Steps:
/// 1. Generate an ECDSA P-384 key pair.
/// 2. Request an SEV-SNP attestation report bound to the public key.
/// 3. Encode the report as a custom X.509 extension.
/// 4. Create a self-signed certificate containing that extension.
pub fn generate_attested_tls_identity(backend: &dyn TeeBackend) -> Result<AttestedTlsIdentity> {
    // 1. Generate ECDSA P-384 key pair.
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
        .context("failed to generate ECDSA P-384 key pair")?;

    // 2. Get key-bound attestation report using the raw public key bytes.
    let public_key_raw = key_pair.public_key_raw().to_vec();
    let report = get_key_bound_report(backend, &public_key_raw)
        .context("failed to get attestation report bound to TLS key")?;

    // 3. Encode the attestation report as a DER-encoded X.509 extension value.
    let extension_value =
        encode_attestation_extension(&report).context("failed to encode attestation extension")?;
    let custom_ext = CustomExtension::from_oid_content(ATTESTATION_OID, extension_value);

    // 4. Create self-signed certificate.
    let mut params = CertificateParams::new(vec!["localhost".to_string()])
        .context("failed to create certificate params")?;
    params.custom_extensions.push(custom_ext);

    let cert = params
        .self_signed(&key_pair)
        .context("failed to create self-signed certificate")?;

    let cert_der = cert.der().to_vec();
    let key_der = Zeroizing::new(key_pair.serialize_der());

    Ok(AttestedTlsIdentity {
        cert_der,
        key_der,
        public_key_raw,
        report,
    })
}

/// Build a `rustls::ServerConfig` from an `AttestedTlsIdentity`.
///
/// The resulting config can be used with actix-web's `bind_rustls_0_23()`.
/// Uses the `ring` crypto provider explicitly rather than relying on a
/// process-default provider (the workspace pins rustls to ring only, so no
/// aws-lc-rs is in the tree, but naming the provider keeps this correct even
/// if that ever changes).
pub fn build_rustls_config(identity: &AttestedTlsIdentity) -> Result<rustls::ServerConfig> {
    let cert_chain = vec![CertificateDer::from(identity.cert_der.clone())];
    // rustls takes ownership of a plain Vec of the key bytes and does not wipe
    // it: this copy lives, un-zeroized, for the lifetime of the ServerConfig.
    // We cannot change that (rustls owns it), so we make exactly one copy here
    // and rely on SEV-SNP memory encryption to keep it confidential at rest.
    // The persistent secret of record stays under Zeroizing in `identity.key_der`.
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from((*identity.key_der).clone()));

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to set protocol versions")?
    .with_no_client_auth()
    .with_single_cert(cert_chain, private_key)
    .context("failed to build rustls ServerConfig")?;

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tee::types::{AttestationReport, TeeType, VerificationResult, VmConfig};
    use aleph_tee::x509::extract_attestation_from_cert;

    /// Mock backend that returns a report with the given report_data.
    struct MockBackend;

    impl TeeBackend for MockBackend {
        fn tee_type(&self) -> TeeType {
            TeeType::SevSnp
        }

        fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
            Ok(AttestationReport {
                tee_type: TeeType::SevSnp,
                data: vec![0xDE, 0xAD],
                report_data: *report_data,
                measurement: vec![0xBE, 0xEF],
            })
        }

        fn verify_report(&self, _report: &AttestationReport) -> Result<VerificationResult> {
            unimplemented!()
        }

        fn qemu_args(&self, _config: &VmConfig) -> Vec<String> {
            unimplemented!()
        }

        fn parse_report(&self, _raw: &[u8]) -> Result<AttestationReport> {
            unimplemented!()
        }
    }

    #[test]
    fn test_generate_attested_tls_identity() {
        let backend = MockBackend;
        let identity = generate_attested_tls_identity(&backend).unwrap();

        // cert_der and key_der should be non-empty.
        assert!(!identity.cert_der.is_empty());
        assert!(!identity.key_der.is_empty());

        // The report should be embedded in the cert.
        let extracted = extract_attestation_from_cert(&identity.cert_der)
            .unwrap()
            .expect("cert should contain attestation extension");

        assert_eq!(extracted.tee_type, TeeType::SevSnp);
        assert_eq!(extracted.data, vec![0xDE, 0xAD]);
        assert_eq!(extracted.measurement, vec![0xBE, 0xEF]);
    }

    #[test]
    fn test_build_rustls_config() {
        let backend = MockBackend;
        let identity = generate_attested_tls_identity(&backend).unwrap();

        // Building rustls config should succeed.
        let config = build_rustls_config(&identity);
        assert!(config.is_ok());
    }
}
