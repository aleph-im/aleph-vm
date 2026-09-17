//! TDX quote verification: the certificate-chain and signature half.
//!
//! `verify_tdx_quote_chain` establishes that a parsed quote is genuinely
//! Intel-attested: the PCK chain roots in the pinned Intel SGX Root CA,
//! nothing in it is revoked, the QE report is signed by the PCK key, the
//! attestation key is bound to the QE report, and the quote body is signed
//! by that attestation key. What it does NOT establish is that the
//! platform's TCB is acceptable (the TCB Info / QE Identity walk) or that
//! the TD is the one a message pinned (register comparison, report_data
//! freshness) - those remain the caller's responsibility.
//!
//! The verifier takes the current time as a parameter and never reads the
//! clock: CRLs and collateral carry validity windows, and a verifier that
//! calls the clock internally cannot be tested against archived collateral
//! (which expires). Production callers pass the real time; tests pass a
//! timestamp inside their fixture's window. Freshness stays enforced in
//! production.

use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::pki::{Curve, ec_public_key, parse_cert, verify_raw_ecdsa};

use super::certs::verify_pck_chain;
use super::collateral::TdxCollateral;
use super::quote::{INTEL_QE_VENDOR_ID, TdxQuote, TdxRegisters, extract_registers};
use super::tcb::{TdxTcbOutcome, TdxTcbPolicy, evaluate_tcb};

/// Offset of `report_data` inside an SGX enclave report (the QE report).
const QE_REPORT_DATA_OFFSET: usize = 320;

/// Verify the QE report signature under the PCK leaf key.
fn verify_qe_report_signature(quote: &TdxQuote, pck_leaf_der: &[u8]) -> Result<()> {
    let pck_leaf = parse_cert("the PCK leaf certificate", pck_leaf_der)?;
    let key = ec_public_key("PCK leaf", pck_leaf.public_key(), Curve::P256)?;
    verify_raw_ecdsa(
        "the QE report",
        Curve::P256,
        key,
        &quote.signature.qe_report,
        &quote.signature.qe_report_signature,
    )
    .context("the QE report signature does not verify under the PCK key")
}

/// Verify that the QE report binds the attestation key: its `report_data`
/// must open with `SHA-256(attestation_key || qe_auth_data)`. Skipping this
/// check is a total break: without it, any key could sign the quote body.
fn check_attestation_key_binding(quote: &TdxQuote) -> Result<()> {
    let mut hasher = Sha256::new();
    hasher.update(quote.signature.attestation_key);
    hasher.update(&quote.signature.qe_auth_data);
    let bound: [u8; 32] = hasher.finalize().into();
    let report_data = &quote.signature.qe_report[QE_REPORT_DATA_OFFSET..QE_REPORT_DATA_OFFSET + 32];
    if report_data != bound {
        bail!("the QE report does not bind the quote's attestation key");
    }
    Ok(())
}

/// Verify the quote signature over the signed region under the attestation
/// key (a P-256 point given as `x || y`, which is the SEC1 uncompressed
/// form without its leading 0x04).
fn verify_quote_signature(quote: &TdxQuote) -> Result<()> {
    let mut key = Vec::with_capacity(65);
    key.push(0x04);
    key.extend_from_slice(&quote.signature.attestation_key);
    verify_raw_ecdsa(
        "the quote",
        Curve::P256,
        &key,
        &quote.signed_region,
        &quote.signature.quote_signature,
    )
    .context("the quote signature does not verify under the attestation key")
}

/// Verify a parsed TDX quote's certificate chain and signatures.
///
/// On success the quote is genuinely Intel-attested, and the returned PCK
/// leaf certificate (DER) carries the platform identity (FMSPC, SVNs) the
/// TCB walk consumes. See the module docs for what this does NOT establish.
pub(crate) fn verify_tdx_quote_chain(
    quote: &TdxQuote,
    collateral: &TdxCollateral,
    now: SystemTime,
) -> Result<Vec<u8>> {
    if quote.header.qe_vendor_id != INTEL_QE_VENDOR_ID {
        bail!(
            "unknown QE vendor id {}: only Intel's quoting enclave is supported",
            hex::encode(quote.header.qe_vendor_id)
        );
    }

    let pck_leaf = verify_pck_chain(&quote.signature.pck_chain_pem, collateral, now)
        .context("PCK chain verification failed")?;
    verify_qe_report_signature(quote, &pck_leaf)?;
    check_attestation_key_binding(quote)?;
    verify_quote_signature(quote)?;

    Ok(pck_leaf)
}

/// A fully verified TDX quote: genuine, at an accepted TCB level, with the
/// registers and `report_data` a caller pins and binds freshness against.
///
/// A `TdxVerification` is NOT on its own a decision to trust a guest. It
/// says the TD is a genuine Intel-attested platform at an acceptable TCB.
/// The caller must still compare `registers` against the message's declared
/// `LaunchMeasurement`, bind freshness through `report_data`, and (once the
/// guest-side extend ships) check the derived `rtmr3` commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxVerification {
    pub tcb: TdxTcbOutcome,
    pub registers: TdxRegisters,
    pub report_data: [u8; 64],
}

/// Fully verify a parsed TDX quote: chain and signatures, then TCB
/// appraisal and the platform gates under `policy`.
pub fn verify_tdx_quote(
    quote: &TdxQuote,
    collateral: &TdxCollateral,
    now: SystemTime,
    policy: &TdxTcbPolicy,
) -> Result<TdxVerification> {
    let pck_leaf = verify_tdx_quote_chain(quote, collateral, now)?;
    let tcb =
        evaluate_tcb(quote, collateral, &pck_leaf, now, policy).context("TCB appraisal failed")?;
    Ok(TdxVerification {
        tcb,
        registers: extract_registers(&quote.body),
        report_data: quote.body.report_data,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::tdx::quote::parse_tdx_quote;

    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");
    const COLLATERAL_V4: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_collateral.json");
    const QUOTE_OUTDATED: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_outdated.bin");
    const COLLATERAL_OUTDATED: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_outdated_collateral.json");

    /// Inside the v4 collateral's windows: 2025-06-20T00:00:00Z.
    fn now_v4() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_750_377_600)
    }

    /// Inside the outdated collateral's windows: 2026-02-19T00:00:00Z.
    fn now_outdated() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_771_459_200)
    }

    #[test]
    fn verifies_genuine_v4_quote() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let leaf = verify_tdx_quote_chain(&quote, &collateral, now_v4()).expect("chain verifies");
        let leaf = parse_cert("leaf", &leaf).unwrap();
        let subject = leaf.subject().to_string();
        assert!(
            subject.contains("PCK"),
            "leaf must be a PCK cert, got {subject}"
        );
    }

    #[test]
    fn verifies_outdated_tcb_quote_chain() {
        // "Outdated" is a TCB status, not a chain defect: the certificate
        // and signature half must pass; the TCB walk is what flags it.
        let quote = parse_tdx_quote(QUOTE_OUTDATED).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).expect("collateral parses");
        verify_tdx_quote_chain(&quote, &collateral, now_outdated()).expect("chain verifies");
    }

    #[test]
    fn rejects_expired_collateral() {
        // The injected clock is the enforcement point: the same collateral
        // fails once `now` passes the PCK CRL's nextUpdate.
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let later = now_v4() + Duration::from_secs(90 * 24 * 3600);
        let err = verify_tdx_quote_chain(&quote, &collateral, later)
            .unwrap_err()
            .to_string();
        assert!(err.contains("PCK chain verification failed"), "got: {err}");
    }

    #[test]
    fn rejects_time_before_validity() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        // 2015: before every certificate in the chain existed.
        let early = UNIX_EPOCH + Duration::from_secs(1_420_070_400);
        assert!(verify_tdx_quote_chain(&quote, &collateral, early).is_err());
    }

    #[test]
    fn rejects_swapped_crls() {
        // The v4 collateral with its PCK CRL replaced by the root CA CRL:
        // the signature check against the intermediate must fail.
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let mut collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        collateral.pck_crl = collateral.root_ca_crl.clone();
        assert!(verify_tdx_quote_chain(&quote, &collateral, now_v4()).is_err());
    }

    #[test]
    fn rejects_garbage_crl() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let mut collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        collateral.pck_crl = "deadbeef".into();
        assert!(verify_tdx_quote_chain(&quote, &collateral, now_v4()).is_err());
    }

    #[test]
    fn rejects_non_intel_vendor() {
        let mut raw = QUOTE_V4.to_vec();
        raw[12] ^= 0xff;
        let quote = parse_tdx_quote(&raw).expect("vendor id is not a parse-time gate");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let err = verify_tdx_quote_chain(&quote, &collateral, now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("unknown QE vendor id"), "got: {err}");
    }

    #[test]
    fn rejects_tampered_qe_report() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let mut tampered = quote.clone();
        // Flip a byte outside report_data so the binding hash still holds
        // and the failure is unambiguously the PCK signature check.
        tampered.signature.qe_report[0] ^= 0x01;
        let err = verify_tdx_quote_chain(&tampered, &collateral, now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("QE report signature"), "got: {err}");
    }

    #[test]
    fn rejects_unbound_attestation_key() {
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let mut tampered = quote.clone();
        // Flip a bit in the QE report's report_data: the PCK-signed report
        // no longer vouches for the attestation key. (Flipping the key
        // itself would fail here too, but through the same hash.)
        tampered.signature.qe_report[QE_REPORT_DATA_OFFSET] ^= 0x01;
        let err = verify_tdx_quote_chain(&tampered, &collateral, now_v4())
            .unwrap_err()
            .to_string();
        // The QE report signature breaks first (the report changed); both
        // failures are correct rejections of the same tamper.
        assert!(
            err.contains("QE report signature") || err.contains("does not bind"),
            "got: {err}"
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let mut raw = QUOTE_V4.to_vec();
        // Flip one bit in mrtd (body offset 136 + header 48).
        raw[48 + 136] ^= 0x01;
        let quote = parse_tdx_quote(&raw).expect("still parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let err = verify_tdx_quote_chain(&quote, &collateral, now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("quote signature"), "got: {err}");
    }

    #[test]
    fn full_verify_accepts_genuine_quote() {
        use crate::tdx::tcb::{TcbStatus, TdxTcbPolicy};
        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        let verified = verify_tdx_quote(&quote, &collateral, now_v4(), &TdxTcbPolicy::default())
            .expect("full verification succeeds");
        assert_eq!(verified.tcb.status, TcbStatus::UpToDate);
        assert_eq!(verified.registers, extract_registers(&quote.body));
        assert_eq!(verified.report_data, quote.body.report_data);
    }

    #[test]
    fn full_verify_rejects_bad_tcb_before_returning_registers() {
        use crate::tdx::tcb::TdxTcbPolicy;
        // Genuine chain, but a debuggable TD: the composed verify must fail
        // rather than hand back registers for a rejected quote.
        let mut raw = QUOTE_V4.to_vec();
        raw[48 + 120] |= 0x01;
        let quote = parse_tdx_quote(&raw).expect("parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");
        assert!(verify_tdx_quote(&quote, &collateral, now_v4(), &TdxTcbPolicy::default()).is_err());
    }

    #[test]
    fn rejects_foreign_root() {
        // Replace the embedded chain's root with a same-subject self-signed
        // impostor: the byte-level pin must reject it before any signature
        // logic runs.
        use crate::pki::testing::{Name, cert, p256_key, pem_blocks};

        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");

        let impostor = cert(
            &Name {
                common_names: vec!["Intel SGX Root CA"],
                organization: None,
            },
            &p256_key(),
            None,
            1_700_000_000,
            1_900_000_000,
        );

        let chain = pem_blocks(&String::from_utf8_lossy(&quote.signature.pck_chain_pem));
        let pem = format!("{}{}{}", chain[0], chain[1], impostor.pem());
        let mut tampered = quote.clone();
        tampered.signature.pck_chain_pem = pem.into_bytes();

        // {:#} prints the whole context chain; the pin rejection is the
        // inner cause under the "PCK chain verification failed" wrapper.
        let err = format!(
            "{:#}",
            verify_tdx_quote_chain(&tampered, &collateral, now_v4()).unwrap_err()
        );
        assert!(err.contains("pinned Intel SGX Root CA"), "got: {err}");
    }
}
