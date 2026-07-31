use crate::types::{AttestationReport, TeeType, VerificationResult, VmConfig};
use anyhow::Result;

pub trait TeeBackend: Send + Sync {
    /// Returns the TEE type this backend handles.
    fn tee_type(&self) -> TeeType;

    /// Retrieves an attestation report with the given 64-byte report data.
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport>;

    /// Verifies an attestation report and returns the verification result.
    fn verify_report(&self, report: &AttestationReport) -> Result<VerificationResult>;

    /// Returns the QEMU command-line arguments needed to launch a VM with this TEE backend.
    ///
    /// Fails when the backend is missing launch parameters that must come from
    /// the host at launch time (e.g. the SEV-SNP C-bit parameters read from
    /// CPUID), so a launcher can never fall back to stale hardcoded values.
    fn qemu_args(&self, config: &VmConfig) -> Result<Vec<String>>;

    /// Parses a raw byte slice into a structured attestation report.
    fn parse_report(&self, raw: &[u8]) -> Result<AttestationReport>;
}
