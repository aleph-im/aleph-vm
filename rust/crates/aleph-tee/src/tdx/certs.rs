//! The Intel certificate side of TDX quote verification: the pinned SGX
//! Root CA, PCK chain verification, and CRL checks.

use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use openssl::asn1::Asn1TimeRef;
use openssl::x509::{CrlStatus, X509, X509Crl};

use crate::pki::{asn1_now, check_cert_window, check_pinned_root, check_validity_window};

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

/// Parse the pinned Intel SGX Root CA.
pub(crate) fn pinned_intel_root() -> Result<X509> {
    X509::from_pem(INTEL_SGX_ROOT_CA_PEM).context("failed to parse the pinned Intel SGX Root CA")
}

/// Verify one CRL: signature by its issuer, validity window against the
/// injected clock, and that *cert* is not on it.
fn check_crl(
    what: &str,
    crl_der: &[u8],
    issuer: &X509,
    cert: &X509,
    now: &Asn1TimeRef,
) -> Result<()> {
    let crl = X509Crl::from_der(crl_der).with_context(|| format!("failed to parse {what}"))?;

    let issuer_key = issuer
        .public_key()
        .with_context(|| format!("failed to extract the {what} issuer public key"))?;
    if !crl
        .verify(&issuer_key)
        .with_context(|| format!("failed to check the {what} signature"))?
    {
        bail!("{what} signature does not verify under its issuer");
    }

    // A CRL without nextUpdate never expires; Intel's always carry one, so
    // treat its absence as an error rather than an open-ended pass.
    let last_update = crl.last_update();
    let next_update = crl
        .next_update()
        .with_context(|| format!("{what} carries no nextUpdate"))?;
    check_validity_window(what, last_update, next_update, now)?;

    match crl.get_by_cert(cert) {
        CrlStatus::NotRevoked => Ok(()),
        CrlStatus::Revoked(_) | CrlStatus::RemoveFromCrl(_) => {
            bail!("certificate is revoked by the {what}")
        }
    }
}

/// Verify the quote's embedded PCK chain to the pinned Intel root and check
/// both CRLs from the collateral. Returns the PCK leaf certificate, whose
/// key signs the QE report and whose SGX extension carries the platform's
/// FMSPC and SVNs.
///
/// The CRL signatures are checked against certificates taken from the
/// verified chain itself (root CA CRL under the pinned root, PCK CRL under
/// the chain's intermediate), so the collateral's own issuer-chain fields
/// are never trusted here.
pub(crate) fn verify_pck_chain(
    pck_chain_pem: &[u8],
    collateral: &TdxCollateral,
    now: SystemTime,
) -> Result<X509> {
    let now = asn1_now(now)?;

    let chain = X509::stack_from_pem(pck_chain_pem).context("failed to parse the PCK chain PEM")?;
    if chain.len() != PCK_CHAIN_LEN {
        bail!(
            "expected {PCK_CHAIN_LEN} certificates in the PCK chain (leaf, intermediate, root), got {}",
            chain.len()
        );
    }
    let (leaf, intermediate, root) = (&chain[0], &chain[1], &chain[2]);

    // The embedded root must BE the pinned root, not merely resemble it.
    let pinned = pinned_intel_root()?;
    check_pinned_root(
        "the quote's root certificate",
        root,
        PINNED_ROOT_LABEL,
        &pinned,
    )?;

    // Signatures down the chain, and validity windows for all three.
    let root_key = root
        .public_key()
        .context("failed to extract the root public key")?;
    if !intermediate
        .verify(&root_key)
        .context("failed to check the intermediate signature")?
    {
        bail!("the intermediate CA certificate is not signed by the Intel root");
    }
    let intermediate_key = intermediate
        .public_key()
        .context("failed to extract the intermediate public key")?;
    if !leaf
        .verify(&intermediate_key)
        .context("failed to check the PCK leaf signature")?
    {
        bail!("the PCK leaf certificate is not signed by the intermediate CA");
    }
    check_cert_window("the root certificate", root, &now)?;
    check_cert_window("the intermediate certificate", intermediate, &now)?;
    check_cert_window("the PCK leaf certificate", leaf, &now)?;

    // Revocation: the root's CRL covers intermediates, the intermediate's
    // covers PCK leaves.
    check_crl(
        "root CA CRL",
        &collateral.root_ca_crl_der()?,
        &pinned,
        intermediate,
        &now,
    )?;
    check_crl(
        "PCK CRL",
        &collateral.pck_crl_der()?,
        intermediate,
        leaf,
        &now,
    )?;

    Ok(leaf.to_owned())
}

/// Common Name Intel gives the certificate that signs its TCB Info and QE
/// Identity documents.
const TCB_SIGNING_CN: &str = "Intel SGX TCB Signing";

/// Verify an Intel collateral issuer chain (the signer certificate, then
/// the root that issued it) and return the signer.
///
/// Used for the TCB Info and QE Identity signatures. Intel issues the TCB
/// signing certificate directly off the root and ships the root itself as
/// the second element, so this chain is two certificates long and the root
/// is pinned in place exactly as it is in a PCK chain. Intel publishes no
/// CRL for these signers, matching the DCAP reference, so none is applied
/// here.
///
/// The signer's Common Name is checked as well. Without it any certificate
/// the Intel root issued for another purpose (the PCK Platform CA, for one)
/// would be accepted as a TCB Info signer, which is a certificate-purpose
/// confusion the chain arithmetic alone does not catch.
pub(crate) fn verify_signer_chain(chain_pem: &[u8], now: SystemTime) -> Result<X509> {
    let now = asn1_now(now)?;
    let chain = X509::stack_from_pem(chain_pem).context("failed to parse the issuer chain PEM")?;
    if chain.len() != SIGNER_CHAIN_LEN {
        bail!(
            "expected {SIGNER_CHAIN_LEN} certificates in the issuer chain (signer, root), got {}",
            chain.len()
        );
    }
    let (signer, root) = (&chain[0], &chain[1]);

    let pinned = pinned_intel_root()?;
    check_pinned_root(
        "the collateral issuer chain's root",
        root,
        PINNED_ROOT_LABEL,
        &pinned,
    )?;

    let pinned_key = pinned
        .public_key()
        .context("failed to extract the pinned root public key")?;
    if !signer
        .verify(&pinned_key)
        .context("failed to check the signer signature")?
    {
        bail!("the collateral signer certificate is not signed by the Intel root");
    }
    check_signer_identity(signer)?;

    check_cert_window("the pinned root certificate", &pinned, &now)?;
    check_cert_window("the signer certificate", signer, &now)?;
    Ok(signer.to_owned())
}

/// Reject a collateral signer that is not Intel's TCB signing certificate.
fn check_signer_identity(signer: &X509) -> Result<()> {
    let cn = signer
        .subject_name()
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .context("the collateral signer certificate has no Common Name")?;
    let cn = String::from_utf8(cn.data().as_slice().to_vec())
        .context("the collateral signer Common Name is not valid UTF-8")?;
    if !cn.contains(TCB_SIGNING_CN) {
        bail!("the collateral signer Common Name {cn:?} is not a {TCB_SIGNING_CN} certificate");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    const COLLATERAL_V4: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_collateral.json");

    /// Inside the v4 collateral's certificate windows: 2025-06-20T00:00:00Z.
    fn now_v4() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_750_377_600)
    }

    fn collateral() -> TdxCollateral {
        TdxCollateral::from_json(COLLATERAL_V4).expect("collateral parses")
    }

    fn cert_at(chain_pem: &str, index: usize) -> X509 {
        X509::stack_from_pem(chain_pem.as_bytes())
            .expect("chain parses")
            .swap_remove(index)
    }

    fn pem_chain(certs: &[&X509]) -> Vec<u8> {
        certs
            .iter()
            .flat_map(|cert| cert.to_pem().expect("cert re-encodes"))
            .collect()
    }

    #[test]
    fn genuine_collateral_chain_verifies() {
        let signer = verify_signer_chain(collateral().tcb_info_issuer_chain.as_bytes(), now_v4())
            .expect("the fixture's TCB Info chain verifies");
        let subject = format!("{:?}", signer.subject_name());
        assert!(subject.contains("TCB Signing"), "got {subject}");
    }

    /// Intel's collateral chains carry the root itself in second position,
    /// so the root must be pinned there exactly as it is in a PCK chain. A
    /// chain ending in some other genuine Intel certificate is refused.
    #[test]
    fn collateral_chain_must_end_in_the_pinned_root() {
        let collateral = collateral();
        let signer = cert_at(&collateral.tcb_info_issuer_chain, 0);
        let platform_ca = cert_at(&collateral.pck_crl_issuer_chain, 0);
        let err = verify_signer_chain(&pem_chain(&[&signer, &platform_ca]), now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("pinned Intel SGX Root CA"), "got: {err}");
    }

    /// The PCK Platform CA is a genuine Intel certificate issued by the same
    /// root, but it is not the TCB signing key: presented as a collateral
    /// signer it must be refused on its subject.
    #[test]
    fn collateral_signer_must_be_the_tcb_signing_certificate() {
        let err = verify_signer_chain(collateral().pck_crl_issuer_chain.as_bytes(), now_v4())
            .unwrap_err()
            .to_string();
        assert!(err.contains("Intel SGX TCB Signing"), "got: {err}");
    }

    #[test]
    fn pinned_root_parses_and_is_self_signed() {
        let root = pinned_intel_root().expect("pin parses");
        let key = root.public_key().expect("key extracts");
        assert!(
            root.verify(&key).expect("verify runs"),
            "pin must be self-signed"
        );
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
        let live = X509::from_pem(&live).expect("live root parses");
        let pinned = pinned_intel_root().expect("pin parses");
        assert_eq!(
            live.to_der().unwrap(),
            pinned.to_der().unwrap(),
            "Intel now serves a different root CA than the pin"
        );
    }
}
