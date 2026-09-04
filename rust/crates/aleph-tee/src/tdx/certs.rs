//! The Intel certificate side of TDX quote verification: the pinned SGX
//! Root CA, PCK chain verification, and CRL checks.

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::{CrlStatus, X509, X509Crl};

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

/// Parse the pinned Intel SGX Root CA.
pub fn pinned_intel_root() -> Result<X509> {
    X509::from_pem(INTEL_SGX_ROOT_CA_PEM).context("failed to parse the pinned Intel SGX Root CA")
}

/// Convert an injected clock into an ASN.1 time for certificate checks.
fn asn1_now(now: SystemTime) -> Result<Asn1Time> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .context("verification time predates the unix epoch")?
        .as_secs();
    let secs: i64 = secs
        .try_into()
        .context("verification time does not fit in an i64")?;
    Asn1Time::from_unix(secs).context("failed to convert verification time to ASN.1")
}

fn check_window(
    what: &str,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
    now: &Asn1TimeRef,
) -> Result<()> {
    if not_before.compare(now)? == Ordering::Greater {
        bail!("{what} is not yet valid (notBefore {not_before})");
    }
    if not_after.compare(now)? == Ordering::Less {
        bail!("{what} expired (notAfter {not_after})");
    }
    Ok(())
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
    check_window(what, last_update, next_update, now)?;

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
pub fn verify_pck_chain(
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
    if root.to_der().context("failed to encode the chain root")?
        != pinned
            .to_der()
            .context("failed to encode the pinned root")?
    {
        bail!("the quote's root certificate is not the pinned Intel SGX Root CA");
    }

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
    check_window(
        "the root certificate",
        root.not_before(),
        root.not_after(),
        &now,
    )?;
    check_window(
        "the intermediate certificate",
        intermediate.not_before(),
        intermediate.not_after(),
        &now,
    )?;
    check_window(
        "the PCK leaf certificate",
        leaf.not_before(),
        leaf.not_after(),
        &now,
    )?;

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

/// Verify an Intel collateral issuer chain (signer certificate, then its
/// issuing intermediate) up to the pinned root, and return the signer.
///
/// Used for the TCB Info and QE Identity signatures. Unlike the PCK chain
/// the root is not embedded, so the intermediate is checked directly
/// against the pin. Intel publishes no CRL for these signers, matching the
/// DCAP reference, so none is applied here.
pub fn verify_signer_chain(chain_pem: &[u8], now: SystemTime) -> Result<X509> {
    let now = asn1_now(now)?;
    let chain = X509::stack_from_pem(chain_pem).context("failed to parse the issuer chain PEM")?;
    if chain.len() != 2 {
        bail!(
            "expected 2 certificates in the issuer chain (signer, intermediate), got {}",
            chain.len()
        );
    }
    let (signer, intermediate) = (&chain[0], &chain[1]);

    let pinned = pinned_intel_root()?;
    let pinned_key = pinned
        .public_key()
        .context("failed to extract the pinned root public key")?;
    if !intermediate
        .verify(&pinned_key)
        .context("failed to check the intermediate signature")?
    {
        bail!("the issuer chain intermediate is not signed by the pinned Intel root");
    }
    let intermediate_key = intermediate
        .public_key()
        .context("failed to extract the intermediate public key")?;
    if !signer
        .verify(&intermediate_key)
        .context("failed to check the signer signature")?
    {
        bail!("the collateral signer certificate is not signed by the intermediate CA");
    }
    check_window(
        "the intermediate certificate",
        intermediate.not_before(),
        intermediate.not_after(),
        &now,
    )?;
    check_window(
        "the signer certificate",
        signer.not_before(),
        signer.not_after(),
        &now,
    )?;
    Ok(signer.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

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
