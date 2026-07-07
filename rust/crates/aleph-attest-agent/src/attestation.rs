use aleph_tee::traits::TeeBackend;
use aleph_tee::types::AttestationReport;
use anyhow::{Context, Result};
use sha2::{Digest, Sha384};

/// Request an attestation report with REPORT_DATA = SHA-384(public_key_bytes),
/// zero-padded to 64 bytes.
///
/// This binds the attestation report to a specific public key, proving that the
/// holder of the corresponding private key is running inside this specific TEE.
pub fn get_key_bound_report(
    backend: &dyn TeeBackend,
    public_key_bytes: &[u8],
) -> Result<AttestationReport> {
    // SHA-384 produces 48 bytes; we pad to 64 bytes (the report_data size).
    let hash = Sha384::digest(public_key_bytes);

    let mut report_data = [0u8; 64];
    report_data[..48].copy_from_slice(&hash);

    backend
        .get_report(&report_data)
        .context("failed to get key-bound attestation report")
}

/// Request an attestation report with the caller's nonce in REPORT_DATA (for Layer 3).
///
/// If the nonce is longer than 64 bytes, it is hashed with SHA-384 and the result
/// is zero-padded to 64 bytes. Otherwise, the nonce is placed directly into
/// report_data and zero-padded.
pub fn get_nonce_bound_report(backend: &dyn TeeBackend, nonce: &[u8]) -> Result<AttestationReport> {
    let mut report_data = [0u8; 64];

    if nonce.len() > 64 {
        // Hash the nonce if it exceeds 64 bytes.
        let hash = Sha384::digest(nonce);
        report_data[..48].copy_from_slice(&hash);
    } else {
        report_data[..nonce.len()].copy_from_slice(nonce);
    }

    backend
        .get_report(&report_data)
        .context("failed to get nonce-bound attestation report")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aleph_tee::types::{AttestationReport, TeeType, VerificationResult, VmConfig};

    /// A mock TEE backend for testing that captures the report_data passed in.
    struct MockBackend;

    impl TeeBackend for MockBackend {
        fn tee_type(&self) -> TeeType {
            TeeType::SevSnp
        }

        fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
            Ok(AttestationReport {
                tee_type: TeeType::SevSnp,
                data: vec![0xAA; 16],
                report_data: *report_data,
                measurement: vec![0xBB; 48],
            })
        }

        fn verify_report(&self, _report: &AttestationReport) -> Result<VerificationResult> {
            unimplemented!("not needed for these tests")
        }

        fn qemu_args(&self, _config: &VmConfig) -> Vec<String> {
            unimplemented!("not needed for these tests")
        }

        fn parse_report(&self, _raw: &[u8]) -> Result<AttestationReport> {
            unimplemented!("not needed for these tests")
        }
    }

    #[test]
    fn test_key_bound_report_uses_sha384_hash() {
        let backend = MockBackend;
        let pubkey = b"test-public-key-bytes";

        let report = get_key_bound_report(&backend, pubkey).unwrap();

        // Verify that report_data contains SHA-384(pubkey) padded to 64 bytes.
        let expected_hash = Sha384::digest(pubkey);
        assert_eq!(&report.report_data[..48], expected_hash.as_slice());
        assert_eq!(&report.report_data[48..], &[0u8; 16]);
    }

    #[test]
    fn test_nonce_bound_report_short_nonce() {
        let backend = MockBackend;
        let nonce = b"short-nonce";

        let report = get_nonce_bound_report(&backend, nonce).unwrap();

        // Short nonce should be placed directly, then zero-padded.
        assert_eq!(&report.report_data[..nonce.len()], nonce.as_slice());
        assert_eq!(
            &report.report_data[nonce.len()..],
            &vec![0u8; 64 - nonce.len()]
        );
    }

    #[test]
    fn test_nonce_bound_report_exact_64_bytes() {
        let backend = MockBackend;
        let nonce = [0x42u8; 64];

        let report = get_nonce_bound_report(&backend, &nonce).unwrap();

        // Exactly 64 bytes should be placed directly without hashing.
        assert_eq!(report.report_data, nonce);
    }

    #[test]
    fn test_nonce_bound_report_long_nonce_is_hashed() {
        let backend = MockBackend;
        let nonce = [0xFF_u8; 100]; // > 64 bytes

        let report = get_nonce_bound_report(&backend, &nonce).unwrap();

        // Long nonce should be hashed with SHA-384, then zero-padded.
        let expected_hash = Sha384::digest(nonce);
        assert_eq!(&report.report_data[..48], expected_hash.as_slice());
        assert_eq!(&report.report_data[48..], &[0u8; 16]);
    }
}
