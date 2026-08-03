use crate::types::{AttestationReport, TeeType, VerificationResult};
use anyhow::Result;

/// Attestation interface of a TEE backend.
///
/// This trait deliberately carries NO launch concern: QEMU argument
/// generation needs host-launcher inputs (e.g. the SEV-SNP C-bit parameters
/// read from the host CPUID at launch) that an attestation user, such as the
/// in-guest agent, does not have. Launchers use the explicit per-TEE argv
/// APIs instead (e.g. [`crate::sev_snp::qemu::sev_snp_qemu_args`]).
pub trait TeeBackend: Send + Sync {
    /// Returns the TEE type this backend handles.
    fn tee_type(&self) -> TeeType;

    /// Retrieves an attestation report with the given 64-byte report data.
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport>;

    /// Verifies an attestation report and returns the verification result.
    fn verify_report(&self, report: &AttestationReport) -> Result<VerificationResult>;

    /// Parses a raw byte slice into a structured attestation report.
    fn parse_report(&self, raw: &[u8]) -> Result<AttestationReport>;
}
