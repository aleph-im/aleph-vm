use crate::types::{AttestationReport, TeeType};
use anyhow::Result;

/// Report-producing interface of a TEE backend: what the attested party
/// (e.g. the in-guest agent) does — retrieve and parse attestation reports.
///
/// This trait deliberately carries neither of the other TEE concerns:
/// - NO launch: QEMU argument generation needs host-launcher inputs (e.g.
///   the SEV-SNP C-bit parameters read from the host CPUID at launch) that
///   the attested party does not have. Launchers use the explicit per-TEE
///   argv APIs instead (e.g. [`crate::sev_snp::qemu::sev_snp_qemu_args`]).
/// - NO verification: a verdict produced by the attested party is worthless
///   (a compromised guest would claim validity), and real verification is
///   async (it fetches the AMD certificate chain over the network). The
///   verifying CLIENT uses the explicit per-TEE verify APIs instead (e.g.
///   [`crate::sev_snp::verify::verify_sev_snp_report`]).
pub trait TeeBackend: Send + Sync {
    /// Returns the TEE type this backend handles.
    fn tee_type(&self) -> TeeType;

    /// Retrieves an attestation report with the given 64-byte report data.
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport>;

    /// Parses a raw byte slice into a structured attestation report.
    fn parse_report(&self, raw: &[u8]) -> Result<AttestationReport>;
}
