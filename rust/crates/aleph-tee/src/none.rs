use anyhow::Result;

use crate::traits::TeeBackend;
use crate::types::{AttestationReport, TeeType, VerificationResult, VmConfig};

/// No-TEE backend implementing the `TeeBackend` trait for non-confidential VMs.
///
/// This backend is used for plain KVM virtual machines that do not run inside
/// a Trusted Execution Environment. Attestation operations are not available
/// and will return errors. QEMU is launched with `-cpu host` only.
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

    fn verify_report(&self, _report: &AttestationReport) -> Result<VerificationResult> {
        anyhow::bail!("attestation not available: VM is not running in a TEE")
    }

    fn qemu_args(&self, _config: &VmConfig) -> Vec<String> {
        vec!["-cpu".to_string(), "host".to_string()]
    }

    fn parse_report(&self, _raw: &[u8]) -> Result<AttestationReport> {
        anyhow::bail!("attestation not available: VM is not running in a TEE")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TeeConfig, TeeType};

    fn test_vm_config() -> VmConfig {
        VmConfig {
            vm_id: "test-no-tee".to_string(),
            kernel: None,
            initrd: None,
            disks: vec![],
            vcpus: 2,
            memory_mb: 2048,
            tee: TeeConfig {
                backend: TeeType::None,
                policy: None,
            },
            encrypted: false,
            numa_node: None,
            hugepage_size: None,
        }
    }

    #[test]
    fn test_no_tee_backend_type() {
        let backend = NoTeeBackend::new();
        assert_eq!(backend.tee_type(), TeeType::None);
    }

    #[test]
    fn test_no_tee_qemu_args() {
        let backend = NoTeeBackend::new();
        let args = backend.qemu_args(&test_vm_config());
        assert_eq!(args, vec!["-cpu", "host"]);
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

        let dummy_report = AttestationReport {
            tee_type: TeeType::None,
            data: vec![0u8; 64],
            report_data: [0u8; 64],
            measurement: vec![0u8; 48],
        };
        let err = backend.verify_report(&dummy_report).unwrap_err();
        assert!(
            err.to_string()
                .contains("attestation not available: VM is not running in a TEE"),
            "verify_report error: {err}"
        );
    }
}
