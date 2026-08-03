use anyhow::{Context, Result};

use crate::traits::TeeBackend;
use crate::types::{AttestationReport, TeeType, VerificationResult};

use super::report::{extract_measurement, extract_report_data, parse_sev_snp_report};

/// SEV-SNP attestation backend implementing the `TeeBackend` trait.
///
/// This backend handles attestation report retrieval, parsing, and
/// verification (stubbed for now) for AMD SEV-SNP confidential VMs. It
/// carries NO launch state: QEMU argument generation is a launcher concern
/// with its own explicit API ([`super::qemu::sev_snp_qemu_args`]), which
/// takes the host-CPUID-derived C-bit parameters as arguments.
pub struct SevSnpBackend {
    /// The AMD product name (e.g., "Milan", "Genoa", "Turin").
    pub product: String,
}

impl SevSnpBackend {
    /// Create a new SEV-SNP attestation backend for the given product line.
    pub fn new(product: impl Into<String>) -> Self {
        Self {
            product: product.into(),
        }
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
    use crate::types::TeeType;

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
