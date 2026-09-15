use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sev::certs::snp::builtin;
use x509_parser::certificate::X509Certificate;

use crate::pki::{
    Curve, check_cert_window, check_pinned_root_key, check_signed_by, ec_public_key,
    p384_signature_from_le, parse_cert, unix_seconds, verify_raw_ecdsa,
};
use crate::types::{AttestationReport, SevSnpRegisters, TeeType, VerificationResult};

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
/// - **Pin the registers**: compare `VerificationResult.registers` against
///   the launch measurement pinned for the guest image. This function does
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
        registers: SevSnpRegisters {
            launch: measurement,
        },
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
/// production, sourced from `pinned_amd_ark_der`; in tests, injected so the
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
/// - ARK, ASK, and VCEK are all within their validity period at the current
///   wall-clock time, which this entry point reads.
pub fn verify_cert_chain(chain: &CertChain, pinned_ark_der: &[u8]) -> Result<()> {
    verify_cert_chain_at(chain, pinned_ark_der, SystemTime::now())
}

/// [`verify_cert_chain`] against an injected verification time, so a test can
/// drive an expired or not-yet-valid chain. Crate-private: injecting the
/// clock is a testing affordance.
pub(crate) fn verify_cert_chain_at(
    chain: &CertChain,
    pinned_ark_der: &[u8],
    now: SystemTime,
) -> Result<()> {
    let ark = parse_cert("ARK certificate", &chain.ark_der)?;
    let ask = parse_cert("ASK certificate", &chain.ask_der)?;
    let vcek = parse_cert("VCEK certificate", &chain.vcek_der)?;

    // Secondary, non-security metadata check (CN/O). Not a trust decision on
    // its own: the pinning below is what actually ties the chain to AMD.
    verify_ark_identity(&ark).context("ARK identity verification failed")?;

    check_signed_by("ARK certificate", &ark, "its own key", &ark)?;

    // SECURITY-CRITICAL: pin the chain's ARK to AMD's genuine root.
    let pinned = parse_cert("pinned AMD ARK", pinned_ark_der)?;
    check_pinned_root_key("the chain ARK", &ark, "the pinned AMD root", &pinned)
        .context("ARK does not match the pinned AMD root")?;

    check_signed_by("ASK certificate", &ask, "ARK", &ark)?;
    check_signed_by("VCEK certificate", &vcek, "ASK", &ask)?;

    // Reject expired or not-yet-valid certificates.
    let now = unix_seconds(now)?;
    check_cert_window("the ARK certificate", &ark, now)?;
    check_cert_window("the ASK certificate", &ask, now)?;
    check_cert_window("the VCEK certificate", &vcek, now)?;

    Ok(())
}

/// Check an ARK certificate's subject metadata against AMD's expected values.
///
/// This is SECONDARY, non-security validation: the CN/O strings are forgeable,
/// so passing this check proves nothing on its own. The actual tie to AMD is
/// the pin against AMD's genuine root in [`verify_cert_chain_at`], which pins
/// the ARK public key. This check exists only to give a clearer error when a
/// cert that is not even shaped like an AMD ARK is supplied.
///
/// Checks:
/// - Subject CN starts with "ARK-" (e.g., "ARK-Milan", "ARK-Genoa", "ARK-Turin")
/// - Subject O is "Advanced Micro Devices"
/// - Issuer matches subject (self-issued)
fn verify_ark_identity(ark: &X509Certificate<'_>) -> Result<()> {
    let subject = ark.subject();

    let cn = subject
        .iter_common_name()
        .next()
        .context("ARK certificate has no Common Name in subject")?
        .as_str()
        .context("ARK CN is not valid UTF-8")?;
    if !cn.starts_with(AMD_ARK_CN_PREFIX) {
        bail!(
            "ARK certificate CN '{cn}' does not start with expected prefix '{AMD_ARK_CN_PREFIX}'"
        );
    }

    let org = subject
        .iter_organization()
        .next()
        .context("ARK certificate has no Organization in subject")?
        .as_str()
        .context("ARK Organization is not valid UTF-8")?;
    if org != AMD_ORG_NAME {
        bail!("ARK certificate Organization '{org}' does not match expected '{AMD_ORG_NAME}'");
    }

    // The ARK must be self-issued: same DER for issuer and subject.
    if subject.as_raw() != ark.issuer().as_raw() {
        bail!("ARK certificate issuer does not match subject (not self-issued)");
    }

    Ok(())
}

/// Verify the SEV-SNP report signature using the VCEK public key.
///
/// The signed portion of the report is bytes 0x000..0x2A0, hashed with
/// SHA-384. The signature is ECDSA P-384 with r and s of 72 bytes each
/// (little-endian, zero-padded), starting at offset 0x2A0 in the raw report.
pub fn verify_report_signature(report_raw: &[u8], vcek_der: &[u8]) -> Result<()> {
    if report_raw.len() < SIGNED_REPORT_SIZE + 144 {
        bail!(
            "report too short for signature verification: need at least {} bytes, got {}",
            SIGNED_REPORT_SIZE + 144,
            report_raw.len()
        );
    }

    let signed_data = &report_raw[..SIGNED_REPORT_SIZE];
    let r_le = &report_raw[SIGNED_REPORT_SIZE..SIGNED_REPORT_SIZE + 72];
    let s_le = &report_raw[SIGNED_REPORT_SIZE + 72..SIGNED_REPORT_SIZE + 144];
    let signature = p384_signature_from_le(r_le, s_le)?;

    let vcek = parse_cert("VCEK certificate", vcek_der)
        .context("failed to parse VCEK certificate for signature verification")?;
    let key = ec_public_key("VCEK public", vcek.public_key(), Curve::P384)?;

    verify_raw_ecdsa(
        "the SEV-SNP report",
        Curve::P384,
        key,
        signed_data,
        &signature,
    )
    .context("SEV-SNP report signature is invalid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::testing::{Name, cert, p384_key};
    use rcgen::KeyPair;
    use std::time::{Duration, UNIX_EPOCH};

    const MILAN_REPORT_HEX: &[u8] = include_bytes!("../../tests/fixtures/sev_snp/report_milan.hex");
    const MILAN_VCEK_DER: &[u8] = include_bytes!("../../tests/fixtures/sev_snp/vcek_milan.der");

    /// 2026-08-18T00:00:00Z: inside the fixture VCEK window (2023 to 2030)
    /// and the ARK/ASK windows (through 2045).
    fn milan_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_787_011_200)
    }

    fn milan_report() -> Vec<u8> {
        let hex_text = std::str::from_utf8(MILAN_REPORT_HEX).unwrap().trim();
        hex::decode(hex_text).unwrap()
    }

    /// AMD's genuine Milan chain: the fixture VCEK under the crate's builtin
    /// ASK and ARK. Every certificate is RSASSA-PSS signed, as AMD ships them.
    fn milan_chain() -> CertChain {
        CertChain {
            vcek_der: MILAN_VCEK_DER.to_vec(),
            ask_der: builtin::milan::ask().unwrap().to_der().unwrap(),
            ark_der: builtin::milan::ark().unwrap().to_der().unwrap(),
        }
    }

    // ---- synthetic P-384 chains (no hardware, no AMD key) ----

    const AMD_CN: &str = "ARK-Milan";
    const ASK_CN: &str = "SEV-Milan";
    const VCEK_CN: &str = "SEV-VCEK-Milan";

    /// A window containing the wall clock for the `verify_cert_chain` entry
    /// point (which reads the clock): 2020-01-01 to 2099-01-01.
    const NOT_BEFORE: i64 = 1_577_836_800;
    const NOT_AFTER: i64 = 4_070_908_800;

    fn amd_name(common_name: &str) -> Name<'_> {
        Name {
            common_names: vec![common_name],
            organization: Some(AMD_ORG_NAME),
        }
    }

    /// Build a synthetic ARK/ASK/VCEK chain with the given windows and
    /// return it with its three keys, so tests can re-sign individual certs
    /// to break links.
    fn synthetic_chain(not_before: i64, not_after: i64) -> (CertChain, KeyPair, KeyPair, KeyPair) {
        let ark_key = p384_key();
        let ask_key = p384_key();
        let vcek_key = p384_key();
        let ark_name = amd_name(AMD_CN);
        let ask_name = amd_name(ASK_CN);
        let ark = cert(&ark_name, &ark_key, None, not_before, not_after);
        let ask = cert(
            &ask_name,
            &ask_key,
            Some((&ark_name, &ark_key)),
            not_before,
            not_after,
        );
        let vcek = cert(
            &amd_name(VCEK_CN),
            &vcek_key,
            Some((&ask_name, &ask_key)),
            not_before,
            not_after,
        );
        let chain = CertChain {
            vcek_der: vcek.der().to_vec(),
            ask_der: ask.der().to_vec(),
            ark_der: ark.der().to_vec(),
        };
        (chain, ark_key, ask_key, vcek_key)
    }

    fn valid_chain() -> (CertChain, KeyPair, KeyPair, KeyPair) {
        synthetic_chain(NOT_BEFORE, NOT_AFTER)
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

    // ---- report signature: genuine Milan fixtures ----

    #[test]
    fn genuine_milan_report_signature_verifies() {
        verify_report_signature(&milan_report(), MILAN_VCEK_DER)
            .expect("AMD's P-384 report signature verifies under the fixture VCEK");
    }

    #[test]
    fn tampered_milan_report_is_rejected() {
        // One bit in the measurement (inside the signed region).
        let mut report = milan_report();
        report[0x90] ^= 0x01;
        let err = verify_report_signature(&report, MILAN_VCEK_DER)
            .unwrap_err()
            .to_string();
        assert!(err.contains("signature is invalid"), "got: {err}");

        // One bit in the signature itself.
        let mut report = milan_report();
        report[SIGNED_REPORT_SIZE] ^= 0x01;
        assert!(verify_report_signature(&report, MILAN_VCEK_DER).is_err());
    }

    #[test]
    fn report_signature_needs_a_p384_vcek() {
        // A P-256 certificate where the VCEK belongs: refused on the curve,
        // not on a failed signature.
        use crate::pki::testing::{cert as make_cert, p256_key};
        let wrong = make_cert(&amd_name(VCEK_CN), &p256_key(), None, NOT_BEFORE, NOT_AFTER);
        let err = verify_report_signature(&milan_report(), wrong.der())
            .unwrap_err()
            .to_string();
        assert!(err.contains("not on P-384"), "got: {err}");
    }

    // ---- certificate chain (kills the AMD_ORG identity mutation, etc.) ----

    #[test]
    fn test_verify_cert_chain_happy_path() {
        let (chain, _ark_key, _ask_key, _vcek_key) = valid_chain();
        verify_cert_chain(&chain, &chain.ark_der).expect("valid chain should verify");
    }

    #[test]
    fn test_verify_cert_chain_wrong_ark_identity() {
        // ARK with a non-AMD Organization: identity check must fire.
        let ark_key = p384_key();
        let ask_key = p384_key();
        let vcek_key = p384_key();
        let evil_ark = Name {
            common_names: vec![AMD_CN],
            organization: Some("Evil Corp"),
        };
        let ark = cert(&evil_ark, &ark_key, None, NOT_BEFORE, NOT_AFTER);
        let ask = cert(
            &amd_name(ASK_CN),
            &ask_key,
            Some((&evil_ark, &ark_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let vcek = cert(
            &amd_name(VCEK_CN),
            &vcek_key,
            Some((&amd_name(ASK_CN), &ask_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let chain = CertChain {
            vcek_der: vcek.der().to_vec(),
            ask_der: ask.der().to_vec(),
            ark_der: ark.der().to_vec(),
        };

        let err = verify_cert_chain(&chain, &chain.ark_der)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("identity") || err.contains("Organization"),
            "expected ARK identity failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_ark_not_self_signed() {
        // ARK carries the pinned public key but is signed by a DIFFERENT key,
        // so the self-signature check must fire (pinning still matches).
        let ark_key = p384_key();
        let other_key = p384_key();
        let ask_key = p384_key();
        let vcek_key = p384_key();
        let ark_name = amd_name(AMD_CN);

        // Pinned ARK: genuine self-signed cert with ark_key.
        let pinned_ark = cert(&ark_name, &ark_key, None, NOT_BEFORE, NOT_AFTER);
        // Chain ARK: same subject key (ark_key), same issuer name, but
        // signed by other_key.
        let ark = cert(
            &ark_name,
            &ark_key,
            Some((&ark_name, &other_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let ask = cert(
            &amd_name(ASK_CN),
            &ask_key,
            Some((&ark_name, &ark_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let vcek = cert(
            &amd_name(VCEK_CN),
            &vcek_key,
            Some((&amd_name(ASK_CN), &ask_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        let chain = CertChain {
            vcek_der: vcek.der().to_vec(),
            ask_der: ask.der().to_vec(),
            ark_der: ark.der().to_vec(),
        };

        let err = verify_cert_chain(&chain, pinned_ark.der())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("ARK certificate is not signed by its own key"),
            "expected self-signature failure, got: {err}"
        );
    }

    /// The pin is on the key: a chain carrying an AMD re-issue of the same key
    /// must keep verifying against the vendored copy.
    #[test]
    fn test_verify_cert_chain_accepts_a_same_key_reissued_ark() {
        let (chain, ark_key, _ask_key, _vcek_key) = valid_chain();
        // Same key, different envelope: a wider window and a fresh serial.
        let reissued = cert(
            &amd_name(AMD_CN),
            &ark_key,
            None,
            NOT_BEFORE - 3600,
            NOT_AFTER + 3600,
        );
        assert_ne!(
            reissued.der().as_ref(),
            chain.ark_der.as_slice(),
            "the re-issued certificate must differ from the chain's"
        );

        verify_cert_chain(&chain, reissued.der())
            .expect("a re-issue carrying the pinned key must still verify");
    }

    #[test]
    fn test_verify_cert_chain_broken_ask_link() {
        // ASK signed by a rogue key, not the ARK.
        let (mut chain, _ark_key, _ask_key, vcek_key) = valid_chain();
        let rogue = p384_key();
        let ask_key = p384_key();
        let bad_ask = cert(
            &amd_name(ASK_CN),
            &ask_key,
            Some((&amd_name(AMD_CN), &rogue)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        // VCEK must chain to the (bad) ASK so the failure is the ASK<-ARK link.
        let vcek = cert(
            &amd_name(VCEK_CN),
            &vcek_key,
            Some((&amd_name(ASK_CN), &ask_key)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        chain.ask_der = bad_ask.der().to_vec();
        chain.vcek_der = vcek.der().to_vec();
        let pinned = chain.ark_der.clone();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("ASK certificate is not signed by ARK"),
            "expected ASK<-ARK link failure, got: {err}"
        );
    }

    #[test]
    fn test_verify_cert_chain_broken_vcek_link() {
        // VCEK signed by a rogue key, not the ASK.
        let (mut chain, _ark_key, _ask_key, vcek_key) = valid_chain();
        let rogue = p384_key();
        let bad_vcek = cert(
            &amd_name(VCEK_CN),
            &vcek_key,
            Some((&amd_name(ASK_CN), &rogue)),
            NOT_BEFORE,
            NOT_AFTER,
        );
        chain.vcek_der = bad_vcek.der().to_vec();
        let pinned = chain.ark_der.clone();

        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("VCEK certificate is not signed by ASK"),
            "expected VCEK<-ASK link failure, got: {err}"
        );
    }

    /// The window check follows the injected instant, not the wall clock.
    #[test]
    fn test_cert_windows_follow_the_injected_clock() {
        // Certificates valid from 2023-11-14 to 2027-01-15.
        let (chain, _ark_key, _ask_key, _vcek_key) = synthetic_chain(1_700_000_000, 1_800_000_000);
        let pinned = chain.ark_der.clone();

        let inside = UNIX_EPOCH + Duration::from_secs(1_750_000_000);
        verify_cert_chain_at(&chain, &pinned, inside).expect("valid inside the window");

        let later = UNIX_EPOCH + Duration::from_secs(1_900_000_000);
        let err = verify_cert_chain_at(&chain, &pinned, later)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("expired"),
            "expected an expiry failure, got: {err}"
        );

        let earlier = UNIX_EPOCH + Duration::from_secs(1_600_000_000);
        let err = verify_cert_chain_at(&chain, &pinned, earlier)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("not yet valid"),
            "expected a not-yet-valid failure, got: {err}"
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
            parse_cert("pinned ARK", &der).expect("pinned ARK must be a valid certificate");
        }
        assert!(pinned_amd_ark_der("Bogus").is_err());
    }

    /// A freshly generated self-signed cert carrying AMD's CN/O strings (plus an
    /// attacker ASK/VCEK) must be REJECTED: the CN/O check alone is not enough,
    /// the ARK must match AMD's pinned root.
    #[test]
    fn test_forged_amd_ark_is_rejected_against_real_pin() {
        let (chain, _ark_key, _ask_key, _vcek_key) = valid_chain();
        // Pin against AMD's genuine Milan ARK: our synthetic (forged) ARK cannot match.
        let pinned = pinned_amd_ark_der("Milan").unwrap();
        let err = verify_cert_chain(&chain, &pinned).unwrap_err().to_string();
        assert!(
            err.contains("pinned"),
            "forged ARK must be rejected by the pin, got: {err}"
        );
    }

    #[test]
    fn genuine_milan_chain_verifies_under_the_pin() {
        let pinned = pinned_amd_ark_der("Milan").unwrap();
        verify_cert_chain_at(&milan_chain(), &pinned, milan_now())
            .expect("AMD's RSASSA-PSS chain verifies to the pinned ARK");
    }

    #[test]
    fn genuine_milan_chain_expires() {
        let pinned = pinned_amd_ark_der("Milan").unwrap();
        // 2200-01-01: every certificate is long expired.
        let later = UNIX_EPOCH + Duration::from_secs(7_258_118_400);
        let err = verify_cert_chain_at(&milan_chain(), &pinned, later)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "got: {err}");
    }

    #[test]
    fn genuine_milan_vcek_under_the_wrong_ask_is_rejected() {
        // Genoa's ASK did not sign a Milan VCEK: the ASK -> VCEK link fails,
        // before that the pin fails because Genoa's ARK is not Milan's.
        let chain = CertChain {
            vcek_der: MILAN_VCEK_DER.to_vec(),
            ask_der: builtin::genoa::ask().unwrap().to_der().unwrap(),
            ark_der: builtin::genoa::ark().unwrap().to_der().unwrap(),
        };
        let pinned = pinned_amd_ark_der("Milan").unwrap();
        assert!(verify_cert_chain_at(&chain, &pinned, milan_now()).is_err());
        let pinned = pinned_amd_ark_der("Genoa").unwrap();
        let err = verify_cert_chain_at(&chain, &pinned, milan_now())
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("VCEK certificate is not signed by ASK"),
            "got: {err}"
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
            let kds_ark = parse_cert("KDS ARK", &ark_der).unwrap();
            let pinned_der = pinned_amd_ark_der(product).unwrap();
            let pinned = parse_cert("pinned ARK", &pinned_der).unwrap();
            // The key, because that is what the pin compares: AMD may
            // re-issue the certificate around it.
            assert_eq!(
                kds_ark.public_key().raw,
                pinned.public_key().raw,
                "pinned ARK for {product} diverged from live KDS"
            );
        }
    }
}
