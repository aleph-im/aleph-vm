use anyhow::Result;

use crate::traits::TeeBackend;
use crate::types::{AttestationReport, TeeType};

/// No-TEE backend implementing the `TeeBackend` trait for non-confidential VMs.
///
/// This backend is used for plain KVM virtual machines that do not run inside
/// a Trusted Execution Environment. Attestation operations are not available
/// and will return errors.
pub struct NoTeeBackend;

impl NoTeeBackend {
    pub fn new() -> Self {
        Self
    }
}

impl Default for NoTeeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeBackend for NoTeeBackend {
    fn tee_type(&self) -> TeeType {
        TeeType::None
    }

    fn get_report(&self, _report_data: &[u8; 64]) -> Result<AttestationReport> {
        anyhow::bail!("attestation not available: VM is not running in a TEE")
    }

    fn parse_report(&self, _raw: &[u8]) -> Result<AttestationReport> {
        anyhow::bail!("attestation not available: VM is not running in a TEE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TeeType;

    #[test]
    fn test_no_tee_backend_type() {
        let backend = NoTeeBackend::new();
        assert_eq!(backend.tee_type(), TeeType::None);
    }

    #[test]
    fn test_no_tee_attestation_fails() {
        let backend = NoTeeBackend::new();

        let report_data = [0u8; 64];
        let err = backend.get_report(&report_data).unwrap_err();
        assert!(
            err.to_string()
                .contains("attestation not available: VM is not running in a TEE"),
            "get_report error: {err}"
        );

        let err = backend.parse_report(&[0u8; 128]).unwrap_err();
        assert!(
            err.to_string()
                .contains("attestation not available: VM is not running in a TEE"),
            "parse_report error: {err}"
        );
    }
}
