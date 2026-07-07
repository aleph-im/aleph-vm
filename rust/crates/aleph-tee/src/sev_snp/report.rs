use anyhow::{Context, Result, bail};
use sev::firmware::guest::AttestationReport as SevAttestationReport;
use sev::parser::ByteParser;

/// Wrapper around the sev crate's AttestationReport that provides
/// convenient accessor methods.
#[derive(Debug)]
pub struct SevReport {
    pub inner: SevAttestationReport,
}

/// Expected size of a raw SEV-SNP attestation report in bytes.
pub const REPORT_SIZE: usize = 1184;

/// Parse raw bytes into a SevReport.
///
/// The raw bytes must be exactly 1184 bytes (the size of an SEV-SNP
/// attestation report as defined by the AMD specification).
pub fn parse_sev_snp_report(raw: &[u8]) -> Result<SevReport> {
    if raw.len() != REPORT_SIZE {
        bail!(
            "invalid SEV-SNP report size: expected {} bytes, got {}",
            REPORT_SIZE,
            raw.len()
        );
    }

    let inner = SevAttestationReport::from_bytes(raw)
        .context("failed to parse SEV-SNP attestation report")?;

    Ok(SevReport { inner })
}

/// Extract the 64-byte report_data field from a parsed report.
pub fn extract_report_data(report: &SevReport) -> [u8; 64] {
    report.inner.report_data
}

/// Extract the 48-byte measurement field from a parsed report.
pub fn extract_measurement(report: &SevReport) -> [u8; 48] {
    report.inner.measurement
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_input_rejected() {
        let short = vec![0u8; 100];
        let result = parse_sev_snp_report(&short);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("expected 1184"),
            "error message should mention expected size, got: {err_msg}"
        );
    }

    #[test]
    fn test_empty_input_rejected() {
        let result = parse_sev_snp_report(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_oversized_input_rejected() {
        let oversized = vec![0u8; 2000];
        let result = parse_sev_snp_report(&oversized);
        assert!(result.is_err());
    }

    #[test]
    fn test_report_data_extraction() {
        // Build a minimal valid-sized buffer with a known report_data pattern.
        // Report version 2 is the simplest; version field is at offset 0 (u32 LE).
        // report_data starts at offset 0x50 + 4 (skip bytes) = 0x50 in the decoded stream,
        // but the binary layout puts it after: version(4) + guest_svn(4) + policy(8) +
        // family_id(16) + image_id(16) + vmpl(4) + sig_algo(4) + current_tcb(8) +
        // plat_info(8) + key_info(4) + skip(4) = 100 bytes = 0x64.
        // Let's just try: create a buffer of REPORT_SIZE with version = 2 and see
        // if we can roundtrip at least the report_data and measurement.
        //
        // The Decoder for AttestationReport uses chip_id to determine the Generation,
        // and for V2, if chip_id is all zeros it returns MaskedChipId error.
        // We need a non-zero chip_id. The chip_id range in the binary is 0x1A0..0x1E0
        // but for V2 there are 24 skip bytes before chip_id, so chip_id is at offset
        // after reported_tcb.
        //
        // This is complex to manually construct. Instead, we use the Encoder to create
        // a valid report and then parse it back.
        use sev::firmware::guest::AttestationReport as SevAR;
        use sev::parser::Encoder;

        let mut report = SevAR {
            version: 3,
            report_data: [0x42; 64],
            measurement: [0xAB; 48],
            // Family 0x19, Model 0x01 => Milan
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0x00),
            ..Default::default()
        };
        // chip_id must be non-zero for the encoder
        report.chip_id[0] = 1;

        // Encode to bytes
        let mut buf = Vec::new();
        report.encode(&mut buf, ()).expect("encode should succeed");

        // Verify we got the right size
        assert_eq!(buf.len(), REPORT_SIZE);

        // Parse it back
        let parsed = parse_sev_snp_report(&buf).expect("parse should succeed");

        assert_eq!(extract_report_data(&parsed), [0x42; 64]);
        assert_eq!(extract_measurement(&parsed), [0xAB; 48]);
    }
}
