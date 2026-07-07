use anyhow::{Context, Result};
use der::Decode;
use der::Encode;
use der::asn1::OctetStringRef;

use crate::types::AttestationReport;

/// OID for the custom attestation report extension.
///
/// This is a private-use OID: 1.3.6.1.4.1.60000.1.1
pub const ATTESTATION_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 60000, 1, 1];

/// OID string for display/comparison purposes.
pub const ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.60000.1.1";

/// Encode an AttestationReport as a DER-encoded OctetString.
///
/// The report is first serialized to JSON, then the JSON bytes are wrapped
/// in a DER OctetString. This produces the extension value suitable for
/// embedding in an X.509 certificate extension.
pub fn encode_attestation_extension(report: &AttestationReport) -> Result<Vec<u8>> {
    let json_bytes =
        serde_json::to_vec(report).context("failed to serialize AttestationReport to JSON")?;

    let octet_string = OctetStringRef::new(&json_bytes)
        .map_err(|e| anyhow::anyhow!("failed to create OctetString: {e}"))?;

    let der_bytes = octet_string
        .to_der()
        .map_err(|e| anyhow::anyhow!("failed to encode OctetString to DER: {e}"))?;

    Ok(der_bytes)
}

/// Decode an AttestationReport from a DER-encoded OctetString.
///
/// This reverses the encoding done by `encode_attestation_extension`:
/// parse the DER OctetString, then deserialize the JSON payload.
pub fn decode_attestation_extension(der_bytes: &[u8]) -> Result<AttestationReport> {
    let octet_string = OctetStringRef::from_der(der_bytes)
        .map_err(|e| anyhow::anyhow!("failed to parse DER OctetString: {e}"))?;

    let json_bytes = octet_string.as_bytes();

    let report: AttestationReport = serde_json::from_slice(json_bytes)
        .context("failed to deserialize AttestationReport from JSON")?;

    Ok(report)
}

/// Extract an AttestationReport from an X.509 certificate (DER-encoded).
///
/// Parses the certificate, searches for an extension with our custom OID,
/// and decodes the attestation report from the extension value.
///
/// Returns `Ok(None)` if the certificate does not contain the extension.
/// Returns `Ok(Some(report))` if the extension is found and decoded.
/// Returns `Err(...)` if parsing fails.
pub fn extract_attestation_from_cert(cert_der: &[u8]) -> Result<Option<AttestationReport>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|e| anyhow::anyhow!("failed to parse X.509 certificate: {e}"))?;

    // Build our OID for comparison
    let target_oid = x509_parser::der_parser::oid::Oid::from(ATTESTATION_OID)
        .map_err(|e| anyhow::anyhow!("failed to construct OID: {e:?}"))?;

    // Search for our extension in the certificate
    for ext in cert.tbs_certificate.extensions() {
        if ext.oid == target_oid {
            // The extension value is the raw content.
            // In X.509, extension values are OCTET STRING wrapped,
            // but x509-parser already gives us the inner OCTET STRING content.
            // However, since we encoded with DER OctetString, the value
            // stored in the extension IS our DER-encoded OctetString.
            let report = decode_attestation_extension(ext.value)
                .context("failed to decode attestation extension")?;
            return Ok(Some(report));
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TeeType;

    /// Helper to create a test AttestationReport.
    fn make_test_report() -> AttestationReport {
        AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04],
            report_data: [0x42; 64],
            measurement: vec![0xAB; 48],
        }
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let original = make_test_report();

        // Encode
        let encoded = encode_attestation_extension(&original).expect("encoding should succeed");

        // Verify it looks like DER (starts with OCTET STRING tag 0x04)
        assert!(!encoded.is_empty());
        assert_eq!(encoded[0], 0x04, "DER should start with OCTET STRING tag");

        // Decode
        let decoded = decode_attestation_extension(&encoded).expect("decoding should succeed");

        // Verify fields match
        assert_eq!(decoded.tee_type, original.tee_type);
        assert_eq!(decoded.data, original.data);
        assert_eq!(decoded.report_data, original.report_data);
        assert_eq!(decoded.measurement, original.measurement);
    }

    #[test]
    fn test_encode_decode_different_tee_types() {
        for tee_type in [TeeType::SevSnp, TeeType::Tdx, TeeType::NvidiaCc] {
            let report = AttestationReport {
                tee_type,
                data: vec![0x01],
                report_data: [0x00; 64],
                measurement: vec![0xFF; 32],
            };

            let encoded = encode_attestation_extension(&report).expect("encoding should succeed");
            let decoded = decode_attestation_extension(&encoded).expect("decoding should succeed");

            assert_eq!(decoded.tee_type, tee_type);
        }
    }

    #[test]
    fn test_decode_invalid_der() {
        let result = decode_attestation_extension(&[0xFF, 0xFF]);
        assert!(result.is_err(), "invalid DER should fail");
    }

    #[test]
    fn test_decode_invalid_json_in_octet_string() {
        // Valid DER OctetString but containing invalid JSON
        let invalid_json = b"not json";
        let octet_string = OctetStringRef::new(invalid_json).unwrap();
        let der_bytes = octet_string.to_der().unwrap();

        let result = decode_attestation_extension(&der_bytes);
        assert!(result.is_err(), "invalid JSON should fail");
    }

    #[test]
    fn test_extract_from_cert_with_extension() {
        let report = make_test_report();

        // Encode the attestation extension
        let extension_value =
            encode_attestation_extension(&report).expect("encoding should succeed");

        // Create a self-signed certificate with our custom extension
        let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("CertificateParams should be valid");

        let custom_ext = rcgen::CustomExtension::from_oid_content(ATTESTATION_OID, extension_value);
        params.custom_extensions.push(custom_ext);

        let key_pair = rcgen::KeyPair::generate().expect("key generation should succeed");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signing should succeed");

        let cert_der = cert.der().to_vec();

        // Extract the attestation report from the certificate
        let extracted =
            extract_attestation_from_cert(&cert_der).expect("extraction should succeed");

        assert!(extracted.is_some(), "extension should be found");
        let extracted = extracted.unwrap();
        assert_eq!(extracted.tee_type, report.tee_type);
        assert_eq!(extracted.data, report.data);
        assert_eq!(extracted.report_data, report.report_data);
        assert_eq!(extracted.measurement, report.measurement);
    }

    #[test]
    fn test_extract_from_cert_without_extension() {
        // Create a self-signed certificate WITHOUT our custom extension
        let params = rcgen::CertificateParams::new(vec!["localhost".to_string()])
            .expect("CertificateParams should be valid");

        let key_pair = rcgen::KeyPair::generate().expect("key generation should succeed");
        let cert = params
            .self_signed(&key_pair)
            .expect("self-signing should succeed");

        let cert_der = cert.der().to_vec();

        // Extract should return None
        let extracted =
            extract_attestation_from_cert(&cert_der).expect("extraction should succeed");

        assert!(extracted.is_none(), "no extension should be found");
    }

    #[test]
    fn test_extract_from_invalid_cert() {
        let result = extract_attestation_from_cert(&[0x30, 0x00]);
        assert!(result.is_err(), "invalid cert should fail");
    }
}
