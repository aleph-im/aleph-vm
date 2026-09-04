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
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::x509::X509;
use sha2::{Digest, Sha256};

use super::certs::verify_pck_chain;
use super::collateral::TdxCollateral;
use super::quote::{INTEL_QE_VENDOR_ID, TdxQuote};

/// Offset of `report_data` inside an SGX enclave report (the QE report).
const QE_REPORT_DATA_OFFSET: usize = 320;

/// Build an ECDSA signature object from a raw `r || s` pair.
fn ecdsa_from_raw(sig: &[u8; 64]) -> Result<EcdsaSig> {
    let r = BigNum::from_slice(&sig[..32]).context("failed to load the signature r component")?;
    let s = BigNum::from_slice(&sig[32..]).context("failed to load the signature s component")?;
    EcdsaSig::from_private_components(r, s).context("failed to assemble the ECDSA signature")
}

/// Verify the QE report signature under the PCK leaf key.
fn verify_qe_report_signature(quote: &TdxQuote, pck_leaf: &X509) -> Result<()> {
    let key = pck_leaf
        .public_key()
        .context("failed to extract the PCK leaf public key")?;
    let ec = key.ec_key().context("the PCK leaf key is not an EC key")?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &quote.signature.qe_report)
        .context("failed to hash the QE report")?;
    let sig = ecdsa_from_raw(&quote.signature.qe_report_signature)?;
    if !sig
        .verify(&digest, &ec)
        .context("failed to check the QE report signature")?
    {
        bail!("the QE report signature does not verify under the PCK key");
    }
    Ok(())
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
/// key (an uncompressed P-256 point, x || y).
fn verify_quote_signature(quote: &TdxQuote) -> Result<()> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .context("failed to load the P-256 group")?;
    let x = BigNum::from_slice(&quote.signature.attestation_key[..32])
        .context("failed to load the attestation key x coordinate")?;
    let y = BigNum::from_slice(&quote.signature.attestation_key[32..])
        .context("failed to load the attestation key y coordinate")?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .context("the attestation key is not a valid P-256 point")?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), &quote.signed_region)
        .context("failed to hash the signed region")?;
    let sig = ecdsa_from_raw(&quote.signature.quote_signature)?;
    if !sig
        .verify(&digest, &key)
        .context("failed to check the quote signature")?
    {
        bail!("the quote signature does not verify under the attestation key");
    }
    Ok(())
}

/// Verify a parsed TDX quote's certificate chain and signatures.
///
/// On success the quote is genuinely Intel-attested, and the returned PCK
/// leaf certificate carries the platform identity (FMSPC, SVNs) the TCB
/// walk consumes. See the module docs for what this does NOT establish.
pub fn verify_tdx_quote_chain(
    quote: &TdxQuote,
    collateral: &TdxCollateral,
    now: SystemTime,
) -> Result<X509> {
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
        let subject = format!("{:?}", leaf.subject_name());
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
    fn rejects_foreign_root() {
        // Replace the embedded chain's root with a same-subject self-signed
        // impostor: the byte-level pin must reject it before any signature
        // logic runs.
        use openssl::asn1::Asn1Time;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::x509::X509Builder;
        use openssl::x509::X509NameBuilder;

        let quote = parse_tdx_quote(QUOTE_V4).expect("quote parses");
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses");

        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Intel SGX Root CA")
            .unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        let impostor = builder.build();

        let chain = X509::stack_from_pem(&quote.signature.pck_chain_pem).unwrap();
        let mut pem = Vec::new();
        pem.extend_from_slice(&chain[0].to_pem().unwrap());
        pem.extend_from_slice(&chain[1].to_pem().unwrap());
        pem.extend_from_slice(&impostor.to_pem().unwrap());
        let mut tampered = quote.clone();
        tampered.signature.pck_chain_pem = pem;

        // {:#} prints the whole context chain; the pin rejection is the
        // inner cause under the "PCK chain verification failed" wrapper.
        let err = format!(
            "{:#}",
            verify_tdx_quote_chain(&tampered, &collateral, now_v4()).unwrap_err()
        );
        assert!(err.contains("pinned Intel SGX Root CA"), "got: {err}");
    }
}
