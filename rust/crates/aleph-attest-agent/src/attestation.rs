use aleph_tee::report_data::{fresh_report_data, key_bound_report_data};
use aleph_tee::traits::TeeBackend;
use aleph_tee::types::AttestationReport;
use anyhow::{Context, Result};

/// Request a key-bound attestation report for the served TLS public key.
///
/// REPORT_DATA is the canonical `key_bound_report_data` scheme (domain-separated
/// SHA-384 of the raw public key), defined once in `aleph_tee::report_data` so
/// the constructing agent and the verifying CLI cannot drift. This binds the
/// report to a specific public key, proving that the holder of the corresponding
/// private key is running inside this specific TEE.
pub fn get_key_bound_report(
    backend: &dyn TeeBackend,
    public_key_bytes: &[u8],
) -> Result<AttestationReport> {
    let report_data = key_bound_report_data(public_key_bytes);

    backend
        .get_report(&report_data)
        .context("failed to get key-bound attestation report")
}

/// Request a fresh (liveness) attestation report bound to BOTH the agent's
/// served TLS public key AND the caller's nonce.
///
/// REPORT_DATA is the canonical `fresh_report_data` scheme (domain-separated
/// SHA-384 of the served public key concatenated with the nonce). Because the
/// served key is mixed in, a relayed fresh report cannot be reused for a
/// different TLS channel; because of the distinct domain tag, it can never
/// collide with a key-bound report. The raw nonce is never placed into
/// REPORT_DATA verbatim, closing the donor's attested-key-confusion / MITM hole.
pub fn get_fresh_report(
    backend: &dyn TeeBackend,
    served_public_key_raw: &[u8],
    nonce: &[u8],
) -> Result<AttestationReport> {
    let report_data = fresh_report_data(served_public_key_raw, nonce);

    backend
        .get_report(&report_data)
        .context("failed to get fresh attestation report")
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
            // On real hardware `report_data` is embedded INSIDE the signed blob
            // (`data`). The mock echoes it into `data` so tests can assert which
            // report_data the agent committed to, mirroring that single-source-of
            // -truth layout (the standalone field no longer exists).
            Ok(AttestationReport {
                tee_type: TeeType::SevSnp,
                data: report_data.to_vec(),
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
    fn test_key_bound_report_uses_canonical_scheme() {
        let backend = MockBackend;
        let pubkey = b"test-public-key-bytes";

        let report = get_key_bound_report(&backend, pubkey).unwrap();

        // report_data (committed into the blob, echoed into `data` by the mock)
        // must be exactly the canonical key-bound scheme.
        assert_eq!(
            report.data,
            aleph_tee::report_data::key_bound_report_data(pubkey).to_vec()
        );
    }

    #[test]
    fn test_fresh_report_binds_key_and_nonce() {
        let backend = MockBackend;
        let served_key = b"agent-served-public-key";
        let nonce = b"caller-nonce";

        let report = get_fresh_report(&backend, served_key, nonce).unwrap();

        // report_data must be exactly the canonical fresh scheme (key + nonce).
        assert_eq!(
            report.data,
            aleph_tee::report_data::fresh_report_data(served_key, nonce).to_vec()
        );
    }

    #[test]
    fn test_fresh_report_is_channel_bound() {
        let backend = MockBackend;
        let nonce = b"same-nonce";

        // Changing the served key changes the report_data (channel binding).
        let a = get_fresh_report(&backend, b"key-A", nonce).unwrap().data;
        let b = get_fresh_report(&backend, b"key-B", nonce).unwrap().data;
        assert_ne!(a, b);
    }

    /// The donor's attested-key-confusion attack is impossible even through the
    /// agent: a fresh report requested with nonce = SHA-384(attacker_key) against
    /// the honest served key never matches the attacker's key-bound report.
    #[test]
    fn test_fresh_report_cannot_forge_key_binding() {
        use sha2::{Digest, Sha384};
        let backend = MockBackend;
        let served_key = b"honest-served-key";
        let attacker_key = b"attacker-key";

        let malicious_nonce = Sha384::digest(attacker_key);
        let fresh = get_fresh_report(&backend, served_key, &malicious_nonce)
            .unwrap()
            .data;
        let attacker_key_bound = get_key_bound_report(&backend, attacker_key).unwrap().data;
        assert_ne!(fresh, attacker_key_bound);
    }
}
