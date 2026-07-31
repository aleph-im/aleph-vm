use anyhow::{Context, Result};

use crate::traits::TeeBackend;
use crate::types::{AttestationReport, TeeType, VerificationResult, VmConfig};

use super::qemu::{DEFAULT_OVMF_PATH, sev_snp_qemu_args};
use super::report::{extract_measurement, extract_report_data, parse_sev_snp_report};

/// SEV-SNP backend implementing the `TeeBackend` trait.
///
/// This backend handles attestation report retrieval, parsing,
/// verification (stubbed for now), and QEMU argument generation
/// for AMD SEV-SNP confidential VMs.
pub struct SevSnpBackend {
    /// The AMD product name (e.g., "Milan", "Genoa", "Turin").
    pub product: String,
    /// Path to the OVMF firmware binary used by QEMU.
    pub ovmf_path: String,
    /// Host C-bit parameters read from CPUID leaf `0x8000001F` at launch.
    /// There is deliberately NO default: `None` makes [`Self::qemu_args`] fail
    /// closed, so a launcher can never start a VM with a stale hardcoded pair
    /// from a different EPYC generation. Attestation-only users (e.g. the
    /// in-guest agent) never set this.
    pub cbit_params: Option<CbitParams>,
}

/// Memory-encryption C-bit position and guest physical-address-space
/// reduction, HOST hardware properties read from CPUID leaf `0x8000001F`
/// (not measurement inputs). A launcher must read them from the host at
/// launch and inject them via [`SevSnpBackend::with_cbit_params`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CbitParams {
    pub cbitpos: u32,
    pub reduced_phys_bits: u32,
}

impl SevSnpBackend {
    /// Create a new SEV-SNP backend for the given product line.
    ///
    /// Uses the default OVMF firmware path and NO C-bit parameters: this form
    /// supports attestation (report retrieval, parsing, verification) only.
    /// To generate QEMU launch arguments, inject the host CPUID values via
    /// [`Self::with_cbit_params`] first.
    pub fn new(product: impl Into<String>) -> Self {
        Self {
            product: product.into(),
            ovmf_path: DEFAULT_OVMF_PATH.to_string(),
            cbit_params: None,
        }
    }

    /// Override the OVMF firmware path (builder pattern).
    pub fn with_ovmf_path(mut self, ovmf_path: impl Into<String>) -> Self {
        self.ovmf_path = ovmf_path.into();
        self
    }

    /// Inject the host C-bit parameters read from the host CPUID at launch
    /// (builder pattern). Required before [`Self::qemu_args`].
    pub fn with_cbit_params(mut self, cbitpos: u32, reduced_phys_bits: u32) -> Self {
        self.cbit_params = Some(CbitParams {
            cbitpos,
            reduced_phys_bits,
        });
        self
    }
}

impl TeeBackend for SevSnpBackend {
    fn tee_type(&self) -> TeeType {
        TeeType::SevSnp
    }

    /// Retrieve an attestation report from the AMD Secure Processor.
    ///
    /// This opens `/dev/sev-guest` and issues a GET_REPORT ioctl with the
    /// provided report_data. Only works on Linux hosts with SEV-SNP hardware.
    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
        #[cfg(target_os = "linux")]
        {
            let mut fw =
                sev::firmware::guest::Firmware::open().context("failed to open /dev/sev-guest")?;

            let raw = fw
                .get_report(None, Some(*report_data), None)
                .map_err(|e| anyhow::anyhow!("SEV-SNP get_report failed: {e:?}"))?;

            self.parse_report(&raw)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = report_data;
            anyhow::bail!("SEV-SNP get_report is only supported on Linux")
        }
    }

    /// Verify an attestation report (synchronous, NOT cryptographically verified).
    ///
    /// This method only performs structural validation. It intentionally returns
    /// `valid: false` because real cryptographic verification requires async
    /// network calls to fetch AMD certificates. Use `verify_sev_snp_report()`
    /// from the `verify` module for full verification.
    fn verify_report(&self, report: &AttestationReport) -> Result<VerificationResult> {
        // Parse the raw report to confirm structural validity
        let parsed = parse_sev_snp_report(&report.data)
            .context("report data failed structural validation")?;

        let measurement = extract_measurement(&parsed).to_vec();
        let report_data = extract_report_data(&parsed);

        Ok(VerificationResult {
            valid: false,
            tee_type: TeeType::SevSnp,
            summary: format!(
                "SEV-SNP report parsed but NOT cryptographically verified (product: {}). \
                 Use verify_sev_snp_report() for full async verification.",
                self.product
            ),
            measurement,
            report_data,
            details: serde_json::json!({
                "product": self.product,
                "guest_svn": parsed.inner.guest_svn,
                "vmpl": parsed.inner.vmpl,
                "verified": false,
                "note": "structural validation only, use verify_sev_snp_report() for cryptographic verification"
            }),
        })
    }

    /// Generate QEMU command-line arguments for launching an SEV-SNP VM.
    ///
    /// Fails closed when no host C-bit parameters were injected: the values
    /// vary by EPYC generation, so silently launching with a built-in pair
    /// could break memory encryption on a different host.
    fn qemu_args(&self, config: &VmConfig) -> Result<Vec<String>> {
        let CbitParams {
            cbitpos,
            reduced_phys_bits,
        } = self.cbit_params.ok_or_else(|| {
            anyhow::anyhow!(
                "SEV-SNP host C-bit parameters not set: read cbitpos/reduced-phys-bits \
                 from the host CPUID (leaf 0x8000001F) at launch and inject them via \
                 with_cbit_params()"
            )
        })?;

        Ok(sev_snp_qemu_args(
            config,
            &self.ovmf_path,
            cbitpos,
            reduced_phys_bits,
        ))
    }

    /// Parse raw bytes into a structured attestation report.
    fn parse_report(&self, raw: &[u8]) -> Result<AttestationReport> {
        // Structural validation only; `data` is the single source of truth and
        // the verifier re-parses it to derive report_data / measurement.
        parse_sev_snp_report(raw)?;

        Ok(AttestationReport {
            tee_type: TeeType::SevSnp,
            data: raw.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TeeConfig, TeeType};
    use std::path::PathBuf;

    #[test]
    fn test_sev_snp_backend_tee_type() {
        let backend = SevSnpBackend::new("Milan");
        assert_eq!(backend.tee_type(), TeeType::SevSnp);
    }

    #[test]
    fn test_sev_snp_backend_product() {
        let backend = SevSnpBackend::new("Genoa");
        assert_eq!(backend.product, "Genoa");
    }

    fn make_config() -> VmConfig {
        VmConfig {
            vm_id: "test".to_string(),
            kernel: Some(PathBuf::from("/boot/vmlinuz")),
            initrd: Some(PathBuf::from("/boot/initrd.img")),
            disks: vec![],
            vcpus: 2,
            memory_mb: 2048,
            tee: TeeConfig {
                backend: TeeType::SevSnp,
                policy: Some("0x30000".to_string()),
            },
            encrypted: false,
            numa_node: None,
            hugepage_size: None,
        }
    }

    #[test]
    fn test_sev_snp_backend_qemu_args() {
        let backend = SevSnpBackend::new("Milan").with_cbit_params(51, 1);

        let args = backend.qemu_args(&make_config()).unwrap();
        assert!(!args.is_empty());
        assert!(args.iter().any(|a| a.contains("sev-snp-guest")));
        assert!(args.iter().any(|a| a.contains("2048M")));
        assert!(
            args.iter()
                .any(|a| a.contains("cbitpos=51,reduced-phys-bits=1")),
            "emitted args must reflect the injected C-bit parameters: {args:?}"
        );
    }

    #[test]
    fn test_qemu_args_reflect_injected_cbit_params() {
        // A non-EPYC-default pair must flow through verbatim, proving the
        // backend no longer carries a hardcoded 51/1.
        let backend = SevSnpBackend::new("Genoa").with_cbit_params(47, 2);

        let args = backend.qemu_args(&make_config()).unwrap();
        assert!(
            args.iter()
                .any(|a| a.contains("cbitpos=47,reduced-phys-bits=2")),
            "emitted args must reflect the injected C-bit parameters: {args:?}"
        );
    }

    #[test]
    fn test_qemu_args_fail_closed_without_cbit_params() {
        let backend = SevSnpBackend::new("Milan");

        let err = backend.qemu_args(&make_config()).unwrap_err();
        assert!(
            err.to_string().contains("C-bit parameters not set"),
            "qemu_args error: {err}"
        );
    }

    #[test]
    fn test_parse_report_roundtrip() {
        use sev::firmware::guest::AttestationReport as SevAR;
        use sev::parser::Encoder;

        let backend = SevSnpBackend::new("Milan");

        // Create a valid report using the sev crate encoder
        let mut sev_report = SevAR {
            version: 3,
            report_data: [0x42; 64],
            measurement: [0xAB; 48],
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0x00),
            ..Default::default()
        };
        sev_report.chip_id[0] = 1;

        let mut buf = Vec::new();
        sev_report
            .encode(&mut buf, ())
            .expect("encode should succeed");

        let parsed = backend.parse_report(&buf).expect("parse should succeed");

        assert_eq!(parsed.tee_type, TeeType::SevSnp);
        // `data` is the single source of truth; report_data / measurement are
        // derived by re-parsing it, not stored as standalone (unsigned) fields.
        assert_eq!(parsed.data, buf);
        let reparsed = parse_sev_snp_report(&parsed.data).unwrap();
        assert_eq!(extract_report_data(&reparsed), [0x42; 64]);
        assert_eq!(extract_measurement(&reparsed), [0xAB; 48]);
    }

    #[test]
    fn test_parse_report_invalid_data() {
        let backend = SevSnpBackend::new("Milan");
        let result = backend.parse_report(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_report_returns_not_valid() {
        use sev::firmware::guest::AttestationReport as SevAR;
        use sev::parser::Encoder;

        let backend = SevSnpBackend::new("Milan");

        // Create a structurally valid report
        let mut sev_report = SevAR {
            version: 3,
            report_data: [0x42; 64],
            measurement: [0xAB; 48],
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0x00),
            ..Default::default()
        };
        sev_report.chip_id[0] = 1;

        let mut buf = Vec::new();
        sev_report
            .encode(&mut buf, ())
            .expect("encode should succeed");

        let report = backend.parse_report(&buf).unwrap();
        let result = backend.verify_report(&report).unwrap();

        // Synchronous verify_report intentionally returns valid=false;
        // callers must use verify_sev_snp_report() for real verification.
        assert!(!result.valid);
        assert_eq!(result.tee_type, TeeType::SevSnp);
        assert_eq!(result.measurement, vec![0xAB; 48]);
        assert!(result.summary.contains("NOT cryptographically verified"));
    }
}
