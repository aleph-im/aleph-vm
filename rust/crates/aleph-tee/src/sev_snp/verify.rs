use anyhow::{Context, Result, bail};
use openssl::asn1::Asn1Time;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use serde_json::json;
use sev::certs::snp::builtin;

use crate::types::{AttestationReport, TeeType, VerificationResult};

use super::certs::{CertChain, TcbParams, fetch_ca_chain, fetch_vcek};
use super::report::{extract_measurement, extract_report_data, parse_sev_snp_report};

/// The signed portion of an SEV-SNP attestation report is bytes 0x000..0x2A0.
const SIGNED_REPORT_SIZE: usize = 0x2A0;

/// Highest VMPL accepted for an attestation report.
///
/// VMPL 0 = firmware (OVMF), VMPL 1 = kernel/attestation agent. Both are part
/// of the measured platform stack and trusted. VMPL 2-3 are less privileged
/// and could be driven by untrusted guest code, so reports from them are
/// rejected.
const MAX_ACCEPTED_VMPL: u32 = 1;

/// Enforce the privileged-VMPL gate: reject reports from unprivileged levels.
fn check_vmpl(vmpl: u32) -> Result<()> {
    if vmpl > MAX_ACCEPTED_VMPL {
        bail!("attestation report from VMPL {vmpl}: only VMPL 0-1 are accepted");
    }
    Ok(())
}

/// Return AMD's genuine, pinned ARK certificate (DER-encoded) for the given
/// product.
///
/// The root of trust is sourced from the `sev` crate's vendored AMD root
/// certificates (`sev::certs::snp::builtin`). These are AMD's real published
/// ARKs: the sev crate's own test suite asserts each ARK is self-signed and
/// signs its ASK. Pinning against these (rather than trusting whatever ARK the
/// KDS or a poisoned cache hands us) is what makes a fabricated self-signed
/// "ARK" unusable, even one carrying the right CN/O strings.
///
/// A wrong pinned key fails CLOSED (it would reject a genuine report), which is
/// the safe direction: the goal is to reject a forged ARK.
fn pinned_amd_ark_der(product: &str) -> Result<Vec<u8>> {
    let cert = match product {
        "Milan" => builtin::milan::ark(),
        "Genoa" => builtin::genoa::ark(),
        "Turin" => builtin::turin::ark(),
        other => bail!("no pinned AMD ARK available for product '{other}'"),
    }
    .map_err(|e| anyhow::anyhow!("failed to load builtin AMD ARK for {product}: {e}"))?;

    cert.to_der()
        .map_err(|e| anyhow::anyhow!("failed to DER-encode builtin AMD ARK for {product}: {e}"))
}

/// Verify an SEV-SNP attestation report by checking the full AMD certificate
/// chain and report signature.
///
/// # What this function DOES verify
///
/// - **Authenticity**: the report is a genuine AMD-signed report for the
///   configured `product`. The VCEK/ASK/ARK chain is validated and, crucially,
///   the chain's ARK is pinned to AMD's genuine root (see [`verify_cert_chain`]),
///   so a fabricated self-signed "ARK" cannot be substituted. The report
///   signature is then checked against the VCEK public key.
/// - **VMPL gate**: the report was produced at a privileged VMPL (0 or 1).
///
/// # What this function does NOT verify (caller responsibilities)
///
/// A `valid: true` result is NOT by itself sufficient to trust a guest. It
/// says only "this is a genuine AMD report from some SEV-SNP machine of this
/// product". A verifying client (the aleph-rs SDK's `attest` module is the
/// reference one) MUST additionally:
///
/// - **Pin the measurement**: compare `VerificationResult.measurement` against
///   the expected launch measurement for the guest image. This function does
///   NOT know or check the expected value.
/// - **Bind freshness / a nonce**: this function does NOT bind `report_data` to
///   a caller-supplied nonce. The caller must supply a fresh nonce in
///   `report_data` at report-generation time and verify it here, otherwise a
///   valid old report can be replayed.
///
/// # Steps
/// 1. Parse the raw report to extract chip_id and TCB version
/// 2. Enforce the privileged-VMPL gate
/// 3. Fetch the VCEK certificate from AMD KDS
/// 4. Fetch the ASK/ARK CA chain from AMD KDS
/// 5. Verify the certificate chain against AMD's pinned root
/// 6. Verify the report signature using the VCEK public key
pub async fn verify_sev_snp_report(
    report: &AttestationReport,
    product: &str,
) -> Result<VerificationResult> {
    let raw = &report.data;

    // 1. Parse the report
    let parsed = parse_sev_snp_report(raw).context("failed to parse SEV-SNP attestation report")?;

    // 2. Enforce the privileged-VMPL gate before doing any network work.
    check_vmpl(parsed.inner.vmpl)?;

    // Derive report_data AND measurement from the parsed, about-to-be-AMD-verified
    // blob. These are the ONLY trustworthy values (once the chain below passes):
    // callers bind key/nonce commitments against these, never against any
    // unsigned copy that travelled alongside the blob.
    let measurement = extract_measurement(&parsed).to_vec();
    let report_data = extract_report_data(&parsed);

    // Extract chip_id and TCB version from the parsed report (input to the
    // VCEK fetch below, not a numbered verification stage of its own).
    let chip_id = parsed.inner.chip_id;
    let reported_tcb = &parsed.inner.reported_tcb;
    let tcb = TcbParams {
        bl_spl: reported_tcb.bootloader,
        tee_spl: reported_tcb.tee,
        snp_spl: reported_tcb.snp,
        ucode_spl: reported_tcb.microcode,
    };

    // 3. Fetch VCEK from AMD KDS
    let vcek_der = fetch_vcek(product, &chip_id, &tcb)
        .await
        .context("failed to fetch VCEK certificate from AMD KDS")?;

    // 4. Fetch ASK/ARK CA chain
    let (ask_der, ark_der) = fetch_ca_chain(product)
        .await
        .context("failed to fetch CA chain from AMD KDS")?;

    let chain = CertChain {
        vcek_der,
        ask_der,
        ark_der,
    };

    // 5. Resolve AMD's genuine, pinned ARK for this product and verify the
    // certificate chain against it (this is what defeats a forged ARK).
    let pinned_ark_der =
        pinned_amd_ark_der(product).context("failed to resolve pinned AMD ARK for product")?;
    verify_cert_chain(&chain, &pinned_ark_der).context("certificate chain verification failed")?;

    // 6. Verify report signature
    verify_report_signature(raw, &chain.vcek_der)
        .context("report signature verification failed")?;

    Ok(VerificationResult {
        valid: true,
        tee_type: TeeType::SevSnp,
        summary: format!("SEV-SNP report verified successfully (product: {product})"),
        measurement,
        report_data,
        details: json!({
            "product": product,
            "guest_svn": parsed.inner.guest_svn,
            "vmpl": parsed.inner.vmpl,
            "verified": true,
            "tcb": {
                "bootloader": tcb.bl_spl,
                "tee": tcb.tee_spl,
                "snp": tcb.snp_spl,
                "microcode": tcb.ucode_spl,
            },
        }),
    })
}

/// Known AMD ARK issuer/subject Common Name patterns.
///
/// AMD's Root Key certificates use CN = "ARK-{product}" (e.g., "ARK-Milan", "ARK-Genoa").
/// The Organization is always "Advanced Micro Devices".
const AMD_ARK_CN_PREFIX: &str = "ARK-";
const AMD_ORG_NAME: &str = "Advanced Micro Devices";

/// Verify the AMD certificate chain against a pinned AMD root.
///
/// `pinned_ark_der` is AMD's genuine ARK certificate for the product (in
/// production, sourced from [`pinned_amd_ark_der`]; in tests, injected so the
/// happy path and each reject reason can be exercised).
///
/// Checks, in order:
/// - ARK has AMD's expected subject metadata (CN = "ARK-{product}",
///   O = "Advanced Micro Devices"). This is SECONDARY, non-security metadata.
/// - ARK is self-signed.
/// - **ARK is pinned to AMD's genuine root**: the chain ARK's public key
///   (SubjectPublicKeyInfo) must equal the pinned AMD ARK's public key. This is
///   the real defense: without it, a fabricated self-signed cert carrying the
///   right CN/O strings plus an attacker ASK/VCEK would pass. Combined with the
///   self-signed check above, a forged ARK is rejected either way (a forger's
///   key fails the pin; AMD's key cannot be self-signed without AMD's private
///   key).
/// - ASK is signed by ARK.
/// - VCEK is signed by ASK.
/// - ARK, ASK, and VCEK are all within their validity period (notBefore/notAfter).
pub fn verify_cert_chain(chain: &CertChain, pinned_ark_der: &[u8]) -> Result<()> {
    let ark = X509::from_der(&chain.ark_der).context("failed to parse ARK certificate")?;
    let ask = X509::from_der(&chain.ask_der).context("failed to parse ASK certificate")?;
    let vcek = X509::from_der(&chain.vcek_der).context("failed to parse VCEK certificate")?;

    // Secondary, non-security metadata check (CN/O). Not a trust decision on
    // its own: the pinning below is what actually ties the chain to AMD.
    verify_ark_identity(&ark).context("ARK identity verification failed")?;

    // Verify ARK is self-signed
    let ark_pubkey = ark
        .public_key()
        .context("failed to extract ARK public key")?;
    if !ark
        .verify(&ark_pubkey)
        .context("failed to verify ARK self-signature")?
    {
        bail!("ARK certificate is not validly self-signed");
    }

    // SECURITY-CRITICAL: pin the chain's ARK to AMD's genuine root.
    verify_ark_matches_pinned_root(&ark, pinned_ark_der)
        .context("ARK does not match the pinned AMD root")?;

    // Verify ASK is signed by ARK
    if !ask
        .verify(&ark_pubkey)
        .context("failed to verify ASK signature")?
    {
        bail!("ASK certificate is not signed by ARK");
    }

    // Verify VCEK is signed by ASK
    let ask_pubkey = ask
        .public_key()
        .context("failed to extract ASK public key")?;
    if !vcek
        .verify(&ask_pubkey)
        .context("failed to verify VCEK signature")?
    {
        bail!("VCEK certificate is not signed by ASK");
    }

    // Reject expired or not-yet-valid certificates.
    check_cert_validity(&ark, "ARK")?;
    check_cert_validity(&ask, "ASK")?;
    check_cert_validity(&vcek, "VCEK")?;

    Ok(())
}

/// Verify that the chain's ARK carries the same public key
/// (SubjectPublicKeyInfo) as AMD's pinned genuine ARK.
///
/// A mismatch means the ARK is not AMD's (forged or cache-poisoned) and the
/// chain is rejected.
fn verify_ark_matches_pinned_root(ark: &X509, pinned_ark_der: &[u8]) -> Result<()> {
    let pinned = X509::from_der(pinned_ark_der).context("failed to parse pinned AMD ARK")?;

    let ark_spki = ark
        .public_key()
        .context("failed to extract chain ARK public key")?
        .public_key_to_der()
        .context("failed to encode chain ARK public key")?;
    let pinned_spki = pinned
        .public_key()
        .context("failed to extract pinned ARK public key")?
        .public_key_to_der()
        .context("failed to encode pinned ARK public key")?;

    if ark_spki != pinned_spki {
        bail!(
            "chain ARK public key does not match the pinned AMD root \
             (possible forged or cache-poisoned ARK)"
        );
    }
    Ok(())
}

/// Reject a certificate whose validity period does not include the current
/// time (expired, or not yet valid).
fn check_cert_validity(cert: &X509, label: &str) -> Result<()> {
    let now = Asn1Time::days_from_now(0).context("failed to obtain current time")?;

    if cert
        .not_before()
        .compare(&now)
        .context("failed to compare notBefore")?
        == std::cmp::Ordering::Greater
    {
        bail!("{label} certificate is not yet valid (notBefore is in the future)");
    }
    if cert
        .not_after()
        .compare(&now)
        .context("failed to compare notAfter")?
        == std::cmp::Ordering::Less
    {
        bail!("{label} certificate has expired");
    }
    Ok(())
}

/// Check an ARK certificate's subject metadata against AMD's expected values.
///
/// This is SECONDARY, non-security validation: the CN/O strings are forgeable,
/// so passing this check proves nothing on its own. The actual tie to AMD is
/// [`verify_ark_matches_pinned_root`], which pins the ARK public key to AMD's
/// genuine root. This check exists only to give a clearer error when a cert
/// that is not even shaped like an AMD ARK is supplied.
///
/// Checks:
/// - Subject CN starts with "ARK-" (e.g., "ARK-Milan", "ARK-Genoa", "ARK-Turin")
/// - Subject O is "Advanced Micro Devices"
/// - Issuer matches subject (self-issued)
fn verify_ark_identity(ark: &X509) -> Result<()> {
    let subject = ark.subject_name();
    let issuer = ark.issuer_name();

    // Extract CN from subject
    let cn_nid = openssl::nid::Nid::COMMONNAME;
    let cn = subject
        .entries_by_nid(cn_nid)
        .next()
        .context("ARK certificate has no Common Name in subject")?;
    let cn_str =
        String::from_utf8(cn.data().as_slice().to_vec()).context("ARK CN is not valid UTF-8")?;

    let cn_str: &str = &cn_str;
    if !cn_str.starts_with(AMD_ARK_CN_PREFIX) {
        bail!(
            "ARK certificate CN '{}' does not start with expected prefix '{}'",
            cn_str,
            AMD_ARK_CN_PREFIX,
        );
    }

    // Extract O (Organization) from subject
    let org_nid = openssl::nid::Nid::ORGANIZATIONNAME;
    let org = subject
        .entries_by_nid(org_nid)
        .next()
        .context("ARK certificate has no Organization in subject")?;
    let org_str = String::from_utf8(org.data().as_slice().to_vec())
        .context("ARK Organization is not valid UTF-8")?;

    let org_str: &str = &org_str;
    if org_str != AMD_ORG_NAME {
        bail!(
            "ARK certificate Organization '{}' does not match expected '{}'",
            org_str,
            AMD_ORG_NAME,
        );
    }

    // Verify issuer == subject (ARK must be self-issued)
    // Compare the DER encoding of issuer and subject names.
    let subject_der = subject
        .to_der()
        .context("failed to encode subject to DER")?;
    let issuer_der = issuer.to_der().context("failed to encode issuer to DER")?;
    if subject_der != issuer_der {
        bail!("ARK certificate issuer does not match subject (not self-issued)");
    }

    Ok(())
}

/// Verify the SEV-SNP report signature using the VCEK public key.
///
/// The signed portion of the report is bytes 0x000..0x2A0, hashed with SHA-384.
/// The signature is an ECDSA P-384 signature with r and s components of 72 bytes each
/// (little-endian, zero-padded), starting at offset 0x2A0 in the raw report.
pub fn verify_report_signature(report_raw: &[u8], vcek_der: &[u8]) -> Result<()> {
    if report_raw.len() < SIGNED_REPORT_SIZE + 144 {
        bail!(
            "report too short for signature verification: need at least {} bytes, got {}",
            SIGNED_REPORT_SIZE + 144,
            report_raw.len()
        );
    }

    // Extract the signed portion (bytes 0..0x2A0)
    let signed_data = &report_raw[..SIGNED_REPORT_SIZE];

    // Extract signature components (r and s, each 72 bytes, little-endian)
    let sig_offset = SIGNED_REPORT_SIZE;
    let r_bytes_le = &report_raw[sig_offset..sig_offset + 72];
    let s_bytes_le = &report_raw[sig_offset + 72..sig_offset + 144];

    // Convert from little-endian to big-endian (openssl expects big-endian)
    let r_bytes_be: Vec<u8> = r_bytes_le
        .iter()
        .rev()
        .collect::<Vec<_>>()
        .into_iter()
        .copied()
        .collect();
    let s_bytes_be: Vec<u8> = s_bytes_le
        .iter()
        .rev()
        .collect::<Vec<_>>()
        .into_iter()
        .copied()
        .collect();

    // Strip leading zeros but keep at least 1 byte
    let r_trimmed = strip_leading_zeros(&r_bytes_be);
    let s_trimmed = strip_leading_zeros(&s_bytes_be);

    // Build ECDSA signature from r and s components
    let r_bn = openssl::bn::BigNum::from_slice(r_trimmed)
        .context("failed to create BigNum from r component")?;
    let s_bn = openssl::bn::BigNum::from_slice(s_trimmed)
        .context("failed to create BigNum from s component")?;

    let ecdsa_sig = EcdsaSig::from_private_components(r_bn, s_bn)
        .context("failed to create ECDSA signature")?;

    // Hash the signed portion with SHA-384
    let digest = openssl::hash::hash(MessageDigest::sha384(), signed_data)
        .context("failed to compute SHA-384 digest")?;

    // Extract VCEK public key
    let vcek = X509::from_der(vcek_der)
        .context("failed to parse VCEK certificate for signature verification")?;
    let vcek_pkey = vcek
        .public_key()
        .context("failed to extract VCEK public key")?;
    let ec_key = vcek_pkey
        .ec_key()
        .context("VCEK public key is not an EC key")?;

    // Verify the ECDSA signature
    let valid = ecdsa_sig
        .verify(&digest, &ec_key)
        .context("ECDSA signature verification failed")?;

    if !valid {
        bail!("SEV-SNP report signature is invalid");
    }

    Ok(())
}

/// Strip leading zero bytes from a big-endian byte slice, keeping at least one byte.
fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let first_nonzero = bytes.iter().position(|&b| b != 0);
    match first_nonzero {
        Some(pos) => &bytes[pos..],
        None => &bytes[bytes.len().saturating_sub(1)..], // all zeros, keep last byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::hash;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::x509::{X509Builder, X509NameBuilder};

    // ---- test helpers: synthetic P-384 keys and certificates (no hardware) ----

    /// Generate a fresh P-384 (secp384r1) key pair.
    fn gen_p384() -> PKey<Private> {
        let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
        let ec = EcKey::generate(&group).unwrap();
        PKey::from_ec_key(ec).unwrap()
    }

    /// Absolute Asn1Time at `offset_secs` from now (negative = in the past).
    fn asn1_time(offset_secs: i64) -> openssl::asn1::Asn1Time {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        openssl::asn1::Asn1Time::from_unix(now + offset_secs).unwrap()
    }

    /// Build an X.509 certificate whose subject public key is `subject_key`,
    /// signed by `signer_key`, with the given subject/issuer CN and O and a
    /// validity window (in seconds relative to now).
    #[allow(clippy::too_many_arguments)]
    fn build_cert(
        subject_key: &PKey<Private>,
        signer_key: &PKey<Private>,
        subject_cn: &str,
        subject_org: &str,
        issuer_cn: &str,
        issuer_org: &str,
        not_before_secs: i64,
        not_after_secs: i64,
    ) -> X509 {
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        b.set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();

        let mut sub = X509NameBuilder::new().unwrap();
        sub.append_entry_by_nid(Nid::COMMONNAME, subject_cn)
            .unwrap();
        sub.append_entry_by_nid(Nid::ORGANIZATIONNAME, subject_org)
            .unwrap();
        b.set_subject_name(&sub.build()).unwrap();

        let mut iss = X509NameBuilder::new().unwrap();
        iss.append_entry_by_nid(Nid::COMMONNAME, issuer_cn).unwrap();
        iss.append_entry_by_nid(Nid::ORGANIZATIONNAME, issuer_org)
            .unwrap();
        b.set_issuer_name(&iss.build()).unwrap();

        b.set_pubkey(subject_key).unwrap();
        b.set_not_before(&asn1_time(not_before_secs)).unwrap();
        b.set_not_after(&asn1_time(not_after_secs)).unwrap();
        b.sign(signer_key, MessageDigest::sha384()).unwrap();
        b.build()
    }

    const AMD_CN: &str = "ARK-Milan";
    const ASK_CN: &str = "SEV-Milan";
    const VCEK_CN: &str = "SEV-VCEK-Milan";

    /// Build a valid synthetic ARK/ASK/VCEK chain and return the chain plus the
    /// three keys (so tests can re-sign individual certs to break links).
    fn valid_chain() -> (CertChain, PKey<Private>, PKey<Private>, PKey<Private>, X509) {
        let ark_key = gen_p384();
        let ask_key = gen_p384();
        let vcek_key = gen_p384();

        let ark = build_cert(
            &ark_key,
            &ark_key,
            AMD_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let ask = build_cert(
            &ask_key,
            &ark_key,
            ASK_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let vcek = build_cert(
            &vcek_key,
            &ask_key,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );

        let chain = CertChain {
            vcek_der: vcek.to_der().unwrap(),
            ask_der: ask.to_der().unwrap(),
            ark_der: ark.to_der().unwrap(),
        };
        (chain, ark_key, ask_key, vcek_key, ark)
    }

    // ---- strip_leading_zeros ----

    #[test]
    fn test_strip_leading_zeros() {
        assert_eq!(strip_leading_zeros(&[0, 0, 1, 2, 3]), &[1, 2, 3]);
        assert_eq!(strip_leading_zeros(&[1, 2, 3]), &[1, 2, 3]);
        assert_eq!(strip_leading_zeros(&[0, 0, 0]), &[0]);
        assert_eq!(strip_leading_zeros(&[0]), &[0]);
        assert_eq!(strip_leading_zeros(&[5]), &[5]);
    }

    #[test]
    fn test_verify_report_signature_too_short() {
        let short = vec![0u8; 100];
        let result = verify_report_signature(&short, &[]);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("too short"), "unexpected error: {err}");
    }

    // ---- VMPL gate (kills `> 1` -> `> 100`) ----

    #[test]
    fn test_vmpl_gate() {
        use sev::firmware::guest::AttestationReport as SevAR;
        use sev::parser::Encoder;

        // A report constructed at VMPL 2 (unprivileged) must be rejected.
        let mut rep = SevAR {
            version: 3,
            vmpl: 2,
            cpuid_fam_id: Some(0x19),
            cpuid_mod_id: Some(0x01),
            cpuid_step: Some(0x00),
            ..Default::default()
        };
        rep.chip_id[0] = 1;
        let mut buf = Vec::new();
        rep.encode(&mut buf, ()).unwrap();

        let parsed = parse_sev_snp_report(&buf).expect("parse should succeed");
        assert_eq!(parsed.inner.vmpl, 2);
        assert!(
            check_vmpl(parsed.inner.vmpl).is_err(),
            "VMPL 2 report must be rejected"
        );

        // Privileged levels are accepted.
        assert!(check_vmpl(0).is_ok());
        assert!(check_vmpl(1).is_ok());
        // Higher unprivileged levels are rejected.
        assert!(check_vmpl(3).is_err());
    }

    // ---- report signature (kills `if !valid` -> `if false`) ----

    /// Write a big-endian integer into a 72-byte little-endian field.
    fn write_le72(dst: &mut [u8], be: &[u8]) {
        for (i, byte) in be.iter().rev().enumerate() {
            dst[i] = *byte;
        }
    }

    #[test]
    fn test_verify_report_signature_good_and_tampered() {
        use super::super::report::REPORT_SIZE;

        let vcek_key = gen_p384();
        // VCEK cert only needs to carry the P-384 public key; verify_report_signature
        // extracts the key and does not re-check the cert chain.
        let vcek = build_cert(
            &vcek_key,
            &vcek_key,
            VCEK_CN,
            AMD_ORG_NAME,
            VCEK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let vcek_der = vcek.to_der().unwrap();

        // Build a raw report and sign its signed range [0..0x2A0].
        let mut raw = vec![0u8; REPORT_SIZE];
        for (i, byte) in raw[..SIGNED_REPORT_SIZE].iter_mut().enumerate() {
            *byte = (i % 251) as u8;
        }
        let digest = hash(MessageDigest::sha384(), &raw[..SIGNED_REPORT_SIZE]).unwrap();
        let ec = vcek_key.ec_key().unwrap();
        let sig = EcdsaSig::sign(&digest, &ec).unwrap();

        write_le72(
            &mut raw[SIGNED_REPORT_SIZE..SIGNED_REPORT_SIZE + 72],
            &sig.r().to_vec(),
        );
        write_le72(
            &mut raw[SIGNED_REPORT_SIZE + 72..SIGNED_REPORT_SIZE + 144],
            &sig.s().to_vec(),
        );

        // Good signature verifies.
        assert!(
            verify_report_signature(&raw, &vcek_der).is_ok(),
            "genuine signature must verify"
        );

        // Tampering the signed body invalidates the signature.
        let mut tampered_body = raw.clone();
        tampered_body[10] ^= 0xFF;
        assert!(
            verify_report_signature(&tampered_body, &vcek_der).is_err(),
            "tampered report body must be rejected"
        );

        // Tampering the signature itself is rejected.
        let mut tampered_sig = raw.clone();
        tampered_sig[SIGNED_REPORT_SIZE] ^= 0xFF;
        assert!(
            verify_report_signature(&tampered_sig, &vcek_der).is_err(),
            "tampered signature must be rejected"
        );
    }

    // ---- certificate chain (kills the AMD_ORG identity mutation, etc.) ----

    #[test]
    fn test_verify_cert_chain_happy_path() {
        let (chain, _ark_key, _ask_key, _vcek_key, ark) = valid_chain();
        let pinned = ark.to_der().unwrap();
        verify_cert_chain(&chain, &pinned).expect("valid chain should verify");
    }

    #[test]
    fn test_verify_cert_chain_wrong_ark_identity() {
        // ARK with a non-AMD Organization: identity check must fire.
        let ark_key = gen_p384();
        let ask_key = gen_p384();
        let vcek_key = gen_p384();

        let ark = build_cert(
            &ark_key,
            &ark_key,
            AMD_CN,
            "Evil Corp",
            AMD_CN,
            "Evil Corp",
            -3600,
            3600,
        );
        let ask = build_cert(
            &ask_key,
            &ark_key,
            ASK_CN,
            AMD_ORG_NAME,
            AMD_CN,
            "Evil Corp",
            -3600,
            3600,
        );
        let vcek = build_cert(
            &vcek_key,
            &ask_key,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let chain = CertChain {
            vcek_der: vcek.to_der().unwrap(),
            ask_der: ask.to_der().unwrap(),
            ark_der: ark.to_der().unwrap(),
        };
        let pinned = ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("identity") || err.contains("Organization"),
            "expected ARK identity failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_ark_not_self_signed() {
        // ARK carries the pinned public key but is signed by a DIFFERENT key,
        // so the self-signature check must fire (pinning still matches).
        let ark_key = gen_p384();
        let other_key = gen_p384();
        let ask_key = gen_p384();
        let vcek_key = gen_p384();

        // Pinned ARK: genuine self-signed cert with ark_key.
        let pinned_ark = build_cert(
            &ark_key,
            &ark_key,
            AMD_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        // Chain ARK: same subject key (ark_key) but signed by other_key.
        let ark = build_cert(
            &ark_key,
            &other_key,
            AMD_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let ask = build_cert(
            &ask_key,
            &ark_key,
            ASK_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let vcek = build_cert(
            &vcek_key,
            &ask_key,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let chain = CertChain {
            vcek_der: vcek.to_der().unwrap(),
            ask_der: ask.to_der().unwrap(),
            ark_der: ark.to_der().unwrap(),
        };
        let pinned = pinned_ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("self-signed"),
            "expected self-signed failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_ark_not_matching_pinned_root() {
        // Genuine, self-consistent chain, but pinned to a DIFFERENT AMD root.
        let (chain, _ark_key, _ask_key, _vcek_key, _ark) = valid_chain();
        let other_ark_key = gen_p384();
        let other_ark = build_cert(
            &other_ark_key,
            &other_ark_key,
            AMD_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let pinned = other_ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("pinned"),
            "expected pinned-root mismatch, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_broken_ask_link() {
        // ASK signed by a rogue key, not the ARK.
        let (mut chain, _ark_key, _ask_key, vcek_key, ark) = valid_chain();
        let rogue = gen_p384();
        let ask_key = gen_p384();
        let bad_ask = build_cert(
            &ask_key,
            &rogue,
            ASK_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        // VCEK must chain to the (bad) ASK so the failure is the ASK<-ARK link.
        let vcek = build_cert(
            &vcek_key,
            &ask_key,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        chain.ask_der = bad_ask.to_der().unwrap();
        chain.vcek_der = vcek.to_der().unwrap();
        let pinned = ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("ASK certificate is not signed by ARK"),
            "expected ASK<-ARK link failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_broken_vcek_link() {
        // VCEK signed by a rogue key, not the ASK.
        let (mut chain, _ark_key, _ask_key, vcek_key, ark) = valid_chain();
        let rogue = gen_p384();
        let bad_vcek = build_cert(
            &vcek_key,
            &rogue,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        chain.vcek_der = bad_vcek.to_der().unwrap();
        let pinned = ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("VCEK certificate is not signed by ASK"),
            "expected VCEK<-ASK link failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_expired_ark() {
        // ARK already expired (notAfter in the past); everything else valid.
        let ark_key = gen_p384();
        let ask_key = gen_p384();
        let vcek_key = gen_p384();

        let ark = build_cert(
            &ark_key,
            &ark_key,
            AMD_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -7200,
            -3600,
        );
        let ask = build_cert(
            &ask_key,
            &ark_key,
            ASK_CN,
            AMD_ORG_NAME,
            AMD_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let vcek = build_cert(
            &vcek_key,
            &ask_key,
            VCEK_CN,
            AMD_ORG_NAME,
            ASK_CN,
            AMD_ORG_NAME,
            -3600,
            3600,
        );
        let chain = CertChain {
            vcek_der: vcek.to_der().unwrap(),
            ask_der: ask.to_der().unwrap(),
            ark_der: ark.to_der().unwrap(),
        };
        let pinned = ark.to_der().unwrap();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("expired"),
            "expected expiry failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_invalid_certs() {
        // Non-parseable DER: fails before reaching crypto.
        let chain = CertChain {
            vcek_der: vec![0x30, 0x00],
            ask_der: vec![0x30, 0x00],
            ark_der: vec![0x30, 0x00],
        };
        let result = verify_cert_chain(&chain, &[0x30, 0x00]);
        assert!(result.is_err(), "invalid certs should fail verification");
    }

    #[test]
    fn test_pinned_amd_ark_der_known_products() {
        // The sev crate ships genuine AMD ARKs for these products.
        for product in ["Milan", "Genoa", "Turin"] {
            let der = pinned_amd_ark_der(product).expect("pinned ARK should resolve");
            assert!(!der.is_empty());
            // Must parse as an X.509 cert.
            X509::from_der(&der).expect("pinned ARK must be a valid certificate");
        }
        assert!(pinned_amd_ark_der("Bogus").is_err());
    }

    /// A freshly generated self-signed cert carrying AMD's CN/O strings (plus an
    /// attacker ASK/VCEK) must be REJECTED: the CN/O check alone is not enough,
    /// the ARK must match AMD's pinned root. This is the FIX 1 blocker scenario.
    #[test]
    fn test_forged_amd_ark_is_rejected_against_real_pin() {
        let (chain, _ark_key, _ask_key, _vcek_key, _ark) = valid_chain();
        // Pin against AMD's genuine Milan ARK: our synthetic (forged) ARK cannot match.
        let pinned = pinned_amd_ark_der("Milan").unwrap();
        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("pinned"),
            "forged ARK must be rejected by the pin, got: {err}"
        );
    }

    /// Assert the pinned AMD ARK (vendored via the sev crate) still matches what
    /// AMD's KDS currently serves for each product. Ignored by default because
    /// it hits the network; run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "network: hits AMD KDS; run explicitly with --ignored"]
    async fn test_pinned_ark_matches_live_kds() {
        use crate::sev_snp::certs::fetch_ca_chain;

        for product in ["Milan", "Genoa", "Turin"] {
            let (_ask_der, ark_der) = fetch_ca_chain(product)
                .await
                .unwrap_or_else(|e| panic!("KDS fetch for {product} failed: {e}"));
            let kds_ark = X509::from_der(&ark_der).unwrap();
            let pinned = X509::from_der(&pinned_amd_ark_der(product).unwrap()).unwrap();
            assert_eq!(
                kds_ark.public_key().unwrap().public_key_to_der().unwrap(),
                pinned.public_key().unwrap().public_key_to_der().unwrap(),
                "pinned ARK for {product} diverged from live KDS"
            );
        }
    }
}
