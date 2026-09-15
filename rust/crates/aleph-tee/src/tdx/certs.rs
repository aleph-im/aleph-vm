//! The Intel certificate side of TDX quote verification: the pinned SGX
//! Root CA, PCK chain verification, and CRL checks.

use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use x509_parser::certificate::X509Certificate;

use crate::pki::{
    check_cert_window, check_crl_signed_by, check_pinned_root, check_signed_by,
    check_validity_window, parse_cert, parse_crl, pem_certs_to_der, single_common_name,
    unix_seconds,
};

use super::collateral::TdxCollateral;

/// Intel's published SGX Provisioning Certification Root CA.
///
/// SHA-256 fingerprint
/// `44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3`,
/// serial `22650CD65A9D3489F383B49552BF501B392706AC`, valid to 2049. Every
/// genuine PCK chain terminates in this certificate; pinning it (rather
/// than trusting whatever root a quote or collateral carries) is what makes
/// a fabricated self-signed "root" unusable, even one carrying the right
/// subject strings. A wrong pin fails CLOSED: it rejects genuine quotes
/// rather than accepting forged ones. The ignored network test below
/// compares this pin against the copy Intel currently serves.
const INTEL_SGX_ROOT_CA_PEM: &[u8] = include_bytes!("intel_sgx_root_ca.pem");

/// Number of certificates in a PCK chain: leaf, intermediate CA, root CA.
const PCK_CHAIN_LEN: usize = 3;

/// Number of certificates in a collateral issuer chain: signer, root CA.
const SIGNER_CHAIN_LEN: usize = 2;

/// How the pinned Intel root is named in rejection messages.
const PINNED_ROOT_LABEL: &str = "the pinned Intel SGX Root CA";

/// The pinned Intel SGX Root CA as DER.
pub(crate) fn pinned_intel_root_der() -> Result<Vec<u8>> {
    let mut certs = pem_certs_to_der(PINNED_ROOT_LABEL, INTEL_SGX_ROOT_CA_PEM)?;
    if certs.len() != 1 {
        bail!(
            "{PINNED_ROOT_LABEL} file carries {} certificates, expected 1",
            certs.len()
        );
    }
    Ok(certs.remove(0))
}

/// Verify one CRL: signature by its issuer, validity window against the
/// injected clock, and that *cert* is not on it.
fn check_crl(
    what: &str,
    crl_der: &[u8],
    issuer: &X509Certificate<'_>,
    cert: &X509Certificate<'_>,
    now: i64,
) -> Result<()> {
    let crl = parse_crl(what, crl_der)?;

    check_crl_signed_by(what, &crl, "its issuer", issuer)?;

    // A CRL without nextUpdate never expires; Intel's always carry one, so
    // treat its absence as an error rather than an open-ended pass.
    let list = &crl.tbs_cert_list;
    let next_update = list
        .next_update
        .as_ref()
        .with_context(|| format!("{what} carries no nextUpdate"))?;
    check_validity_window(what, &list.this_update, next_update, now)?;

    if crl
        .iter_revoked_certificates()
        .any(|revoked| revoked.raw_serial() == cert.raw_serial())
    {
        bail!("certificate is revoked by the {what}");
    }
    Ok(())
}

/// Verify the quote's embedded PCK chain to the pinned Intel root and check
/// both CRLs from the collateral. Returns the PCK leaf certificate (DER),
/// whose key signs the QE report and whose SGX extension carries the
/// platform's FMSPC and SVNs.
///
/// The CRL signatures are checked against certificates taken from the
/// verified chain itself (root CA CRL under the pinned root, PCK CRL under
/// the chain's intermediate), so the collateral's own issuer-chain fields
/// are never trusted here.
pub(crate) fn verify_pck_chain(
    pck_chain_pem: &[u8],
    collateral: &TdxCollateral,
    now: SystemTime,
) -> Result<Vec<u8>> {
    let now = unix_seconds(now)?;

    let chain = pem_certs_to_der("the PCK chain PEM", pck_chain_pem)?;
    if chain.len() != PCK_CHAIN_LEN {
        bail!(
            "expected {PCK_CHAIN_LEN} certificates in the PCK chain (leaf, intermediate, root), got {}",
            chain.len()
        );
    }

    // The embedded root must BE the pinned root, not merely resemble it: Intel
    // publishes one fixed SGX Root CA and every genuine chain carries it
    // verbatim, so the whole certificate is compared.
    let pinned_der = pinned_intel_root_der()?;
    check_pinned_root(
        "the quote's root certificate",
        &chain[2],
        PINNED_ROOT_LABEL,
        &pinned_der,
    )?;

    let leaf = parse_cert("the PCK leaf certificate", &chain[0])?;
    let intermediate = parse_cert("the intermediate CA certificate", &chain[1])?;
    let root = parse_cert("the root certificate", &chain[2])?;

    // Signatures down the chain, and validity windows for all three.
    check_signed_by(
        "the intermediate CA certificate",
        &intermediate,
        "the Intel root",
        &root,
    )?;
    check_signed_by(
        "the PCK leaf certificate",
        &leaf,
        "the intermediate CA",
        &intermediate,
    )?;
    check_cert_window("the root certificate", &root, now)?;
    check_cert_window("the intermediate certificate", &intermediate, now)?;
    check_cert_window("the PCK leaf certificate", &leaf, now)?;

    // Revocation: the root's CRL covers intermediates, the intermediate's
    // covers PCK leaves. The root here is the pinned one, byte for byte.
    check_crl(
        "root CA CRL",
        &collateral.root_ca_crl_der()?,
        &root,
        &intermediate,
        now,
    )?;
    check_crl(
        "PCK CRL",
        &collateral.pck_crl_der()?,
        &intermediate,
        &leaf,
        now,
    )?;

    Ok(chain[0].clone())
}

/// Common Name Intel gives the certificate that signs its TCB Info and QE
/// Identity documents.
const TCB_SIGNING_CN: &str = "Intel SGX TCB Signing";

/// Verify an Intel collateral issuer chain (the signer certificate, then the
/// root that issued it) and return the signer (DER).
///
/// The root is pinned as in a PCK chain, and Intel publishes no CRL for these
/// signers. The signer's Common Name is checked too: without it any
/// certificate the Intel root issued for another purpose would pass as a TCB
/// Info signer.
pub(crate) fn verify_signer_chain(chain_pem: &[u8], now: SystemTime) -> Result<Vec<u8>> {
    let now = unix_seconds(now)?;
    let chain = pem_certs_to_der("the issuer chain PEM", chain_pem)?;
    if chain.len() != SIGNER_CHAIN_LEN {
        bail!(
            "expected {SIGNER_CHAIN_LEN} certificates in the issuer chain (signer, root), got {}",
            chain.len()
        );
    }

    let pinned_der = pinned_intel_root_der()?;
    check_pinned_root(
        "the collateral issuer chain's root",
        &chain[1],
        PINNED_ROOT_LABEL,
        &pinned_der,
    )?;

    let signer = parse_cert("the collateral signer certificate", &chain[0])?;
    let pinned = parse_cert(PINNED_ROOT_LABEL, &pinned_der)?;
    check_signed_by(
        "the collateral signer certificate",
        &signer,
        "the Intel root",
        &pinned,
    )?;
    check_signer_identity(&signer)?;

    // The pinned copy's window rather than the presented root's, which is the
    // same check: the two were just established to be the same bytes.
    check_cert_window(PINNED_ROOT_LABEL, &pinned, now)?;
    check_cert_window("the signer certificate", &signer, now)?;
    Ok(chain[0].clone())
}

/// Reject a collateral signer that is not Intel's TCB signing certificate.
fn check_signer_identity(signer: &X509Certificate<'_>) -> Result<()> {
    let common_name = single_common_name("the collateral signer certificate", signer.subject())?;
    if common_name != TCB_SIGNING_CN {
        bail!("the collateral signer Common Name {common_name:?} is not {TCB_SIGNING_CN:?}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;
    use crate::pki::testing::{Name, cert, cert_for_public_key, p256_key, pem_blocks};

    const COLLATERAL_V4: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_collateral.json");

    /// Inside the v4 collateral's certificate windows: 2025-06-20T00:00:00Z.
    fn now_v4() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_750_377_600)
    }

    fn collateral() -> TdxCollateral {
        TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses")
    }

    fn intel_root_name() -> Name<'static> {
        Name {
            common_names: vec!["Intel SGX Root CA"],
            organization: None,
        }
    }

    #[test]
    fn genuine_collateral_chain_verifies() {
        let signer_der =
            verify_signer_chain(collateral().tcb_info_issuer_chain.as_bytes(), now_v4())
                .expect("the fixture's TCB Info chain verifies");
        let signer = parse_cert("signer", &signer_der).unwrap();
        assert_eq!(
            single_common_name("signer", signer.subject()).unwrap(),
            TCB_SIGNING_CN
        );
    }

    /// A collateral chain ending in some other genuine Intel certificate is
    /// refused: the second position must hold the pinned root.
    #[test]
    fn collateral_chain_must_end_in_the_pinned_root() {
        let collateral = collateral();
        let signer = &pem_blocks(&collateral.tcb_info_issuer_chain)[0];
        let platform_ca = &pem_blocks(&collateral.pck_crl_issuer_chain)[0];
        let chain = format!("{signer}{platform_ca}");
        let err = verify_signer_chain(chain.as_bytes(), now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("pinned Intel SGX Root CA"), "got: {err}");
    }

    /// A root carrying the pinned public key in a different envelope is a
    /// maintenance task rather than an attack, and the message has to say so.
    #[test]
    fn a_root_reissued_with_the_pinned_key_asks_for_a_refresh() {
        let pinned_der = pinned_intel_root_der().expect("pin parses");
        let pinned = parse_cert("pin", &pinned_der).unwrap();
        let reissued = cert_for_public_key(
            &intel_root_name(),
            pinned.public_key().raw,
            (&intel_root_name(), &p256_key()),
            1_700_000_000,
            1_900_000_000,
        );
        assert_ne!(
            reissued.der().as_ref(),
            pinned_der.as_slice(),
            "the re-issued envelope must differ from the pin"
        );

        let signer = &pem_blocks(&collateral().tcb_info_issuer_chain)[0];
        let chain = format!("{signer}{}", reissued.pem());
        let err = verify_signer_chain(chain.as_bytes(), now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("same public key"), "got: {err}");
        assert!(err.contains("pin needs refreshing"), "got: {err}");
        // And it is not confused with the forged-root case.
        assert!(!err.contains("forged"), "got: {err}");
    }

    /// The PCK Platform CA has the same root but is not the TCB signing key,
    /// so as a collateral signer it must be refused on its subject.
    #[test]
    fn collateral_signer_must_be_the_tcb_signing_certificate() {
        let err = verify_signer_chain(collateral().pck_crl_issuer_chain.as_bytes(), now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Intel SGX TCB Signing"), "got: {err}");
    }

    /// The subject gate is an equality on a single Common Name: one that only
    /// embeds the name, or hides a second name behind it, is refused.
    #[test]
    fn signer_common_name_must_match_exactly_and_stand_alone() {
        fn identity_check(common_names: &[&str]) -> Result<()> {
            let fabricated = cert(
                &Name {
                    common_names: common_names.to_vec(),
                    organization: None,
                },
                &p256_key(),
                None,
                1_700_000_000,
                1_900_000_000,
            );
            let parsed = parse_cert("fabricated", fabricated.der()).unwrap();
            check_signer_identity(&parsed)
        }

        identity_check(&[TCB_SIGNING_CN]).expect("the exact Common Name is accepted");

        let err = identity_check(&["Not the Intel SGX TCB Signing CA"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not"), "got: {err}");

        let err = identity_check(&[TCB_SIGNING_CN, "Something Else"])
            .unwrap_err()
            .to_string();
        assert!(err.contains("more than one Common Name"), "got: {err}");
    }

    #[test]
    fn pinned_root_parses_and_is_self_signed() {
        let der = pinned_intel_root_der().expect("pin parses");
        let root = parse_cert("pin", &der).unwrap();
        check_signed_by("the pin", &root, "itself", &root).expect("pin must be self-signed");
        let now = unix_seconds(SystemTime::now()).expect("clock converts");
        check_cert_window(PINNED_ROOT_LABEL, &root, now).expect("pin must still be in its window");
    }

    /// Compares the pin against the root CA Intel currently serves.
    #[tokio::test]
    #[ignore = "network: hits Intel trusted services; run explicitly with --ignored"]
    async fn pinned_root_matches_live_intel_root() {
        let url = "https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem";
        let live = reqwest::get(url)
            .await
            .expect("fetch Intel root")
            .bytes()
            .await
            .expect("read Intel root body");
        let live = pem_certs_to_der("live root", &live).expect("live root parses");
        assert_eq!(
            live[0],
            pinned_intel_root_der().unwrap(),
            "Intel now serves a different root CA than the pin"
        );
    }
}
