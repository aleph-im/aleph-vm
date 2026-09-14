//! Primitives shared by the SEV-SNP and TDX verifiers.
//!
//! Both stacks parse raw `r || s` ECDSA signatures out of binary evidence and
//! both walk certificate validity windows, so the two implementations live
//! here once instead of drifting apart in each backend.

use std::cmp::Ordering;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::x509::{X509, X509Crl};

/// Reject a certificate that does not carry a valid signature by its issuer.
pub(crate) fn check_signed_by(
    child_label: &str,
    child: &X509,
    issuer_label: &str,
    issuer: &X509,
) -> Result<()> {
    let key = issuer
        .public_key()
        .with_context(|| format!("failed to extract the public key of {issuer_label}"))?;
    if !child
        .verify(&key)
        .with_context(|| format!("failed to check the signature of {child_label}"))?
    {
        bail!("{child_label} is not signed by {issuer_label}");
    }
    Ok(())
}

/// [`check_signed_by`] for a CRL, which openssl types separately from a
/// certificate.
pub(crate) fn check_crl_signed_by(
    crl_label: &str,
    crl: &X509Crl,
    issuer_label: &str,
    issuer: &X509,
) -> Result<()> {
    let key = issuer
        .public_key()
        .with_context(|| format!("failed to extract the public key of {issuer_label}"))?;
    if !crl
        .verify(&key)
        .with_context(|| format!("failed to check the signature of {crl_label}"))?
    {
        bail!("{crl_label} is not signed by {issuer_label}");
    }
    Ok(())
}

/// Assemble an ECDSA signature from its raw big-endian `r` and `s`
/// components, since attestation evidence carries them as fixed-width
/// integers rather than as a DER `SEQUENCE`.
pub(crate) fn ecdsa_from_components(r: &[u8], s: &[u8]) -> Result<EcdsaSig> {
    let r = BigNum::from_slice(r).context("failed to load the signature r component")?;
    let s = BigNum::from_slice(s).context("failed to load the signature s component")?;
    EcdsaSig::from_private_components(r, s).context("failed to assemble the ECDSA signature")
}

/// Assemble an ECDSA signature from a raw `r || s` pair, `r` in the first
/// half of `raw` and `s` in the second.
pub(crate) fn ecdsa_from_raw(raw: &[u8]) -> Result<EcdsaSig> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        bail!(
            "a raw ECDSA signature must be a non-empty even number of bytes (r || s), got {}",
            raw.len()
        );
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    ecdsa_from_components(r, s)
}

/// Reject a root certificate that is not, byte for byte, the pinned one.
///
/// For Intel, which publishes one fixed SGX Root CA. AMD re-issues its ARK
/// with the same key, so the SEV-SNP side pins the key through
/// [`check_pinned_root_key`] instead.
pub(crate) fn check_pinned_root(
    presented_label: &str,
    presented: &X509,
    pin_label: &str,
    pinned: &X509,
) -> Result<()> {
    let presented_der = presented
        .to_der()
        .with_context(|| format!("failed to encode {presented_label}"))?;
    let pinned_der = pinned
        .to_der()
        .with_context(|| format!("failed to encode {pin_label}"))?;
    if presented_der == pinned_der {
        return Ok(());
    }

    let presented_key = presented
        .public_key()
        .and_then(|key| key.public_key_to_der());
    let pinned_key = pinned.public_key().and_then(|key| key.public_key_to_der());
    let same_key = matches!((presented_key, pinned_key), (Ok(a), Ok(b)) if a == b);
    if same_key {
        bail!(
            "{presented_label} is not {pin_label}: it carries the same public key \
             but a different certificate, so the pin needs refreshing"
        );
    }
    bail!("{presented_label} is not {pin_label} (possible forged or cache-poisoned root)");
}

/// Reject a root certificate that does not carry the pinned public key.
///
/// The counterpart of [`check_pinned_root`] for a vendor that re-issues its
/// root: the key is the trust anchor and the envelope may change, so subject
/// strings alone never satisfy it.
pub(crate) fn check_pinned_root_key(
    presented_label: &str,
    presented: &X509,
    pin_label: &str,
    pinned: &X509,
) -> Result<()> {
    let presented_key = presented
        .public_key()
        .with_context(|| format!("failed to extract the public key of {presented_label}"))?
        .public_key_to_der()
        .with_context(|| format!("failed to encode the public key of {presented_label}"))?;
    let pinned_key = pinned
        .public_key()
        .with_context(|| format!("failed to extract the public key of {pin_label}"))?
        .public_key_to_der()
        .with_context(|| format!("failed to encode the public key of {pin_label}"))?;
    if presented_key != pinned_key {
        bail!(
            "the public key of {presented_label} does not match {pin_label} \
             (possible forged or cache-poisoned root)"
        );
    }
    Ok(())
}

/// Convert an injected clock into an ASN.1 time, at second granularity.
///
/// Verification time is a parameter everywhere in this crate: a verifier that
/// read the clock itself could not be tested against archived evidence.
pub(crate) fn asn1_now(now: SystemTime) -> Result<Asn1Time> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .context("verification time predates the unix epoch")?
        .as_secs();
    let secs: i64 = secs
        .try_into()
        .context("verification time does not fit in an i64")?;
    Asn1Time::from_unix(secs).context("failed to convert verification time to ASN.1")
}

/// Reject a validity window that does not contain `now`.
pub(crate) fn check_validity_window(
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

/// Reject a certificate whose validity window does not contain `now`.
pub(crate) fn check_cert_window(what: &str, cert: &X509, now: &Asn1TimeRef) -> Result<()> {
    check_validity_window(what, cert.not_before(), cert.not_after(), now)
}

/// A fresh P-256 key for the certificates tests fabricate.
#[cfg(test)]
pub(crate) fn test_p256_key() -> openssl::pkey::PKey<openssl::pkey::Private> {
    let group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
    openssl::pkey::PKey::from_ec_key(openssl::ec::EcKey::generate(&group).unwrap()).unwrap()
}

/// A certificate carrying the Common Names given, self-signed unless an
/// issuer name and signing key are supplied. For the tests that present an
/// impostor where a pinned certificate belongs.
#[cfg(test)]
pub(crate) fn test_cert(
    common_names: &[&str],
    key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    issuer: Option<(&str, &openssl::pkey::PKeyRef<openssl::pkey::Private>)>,
    not_before: &Asn1TimeRef,
    not_after: &Asn1TimeRef,
) -> X509 {
    fn name(common_names: &[&str]) -> openssl::x509::X509Name {
        let mut builder = openssl::x509::X509NameBuilder::new().unwrap();
        for common_name in common_names {
            builder.append_entry_by_text("CN", common_name).unwrap();
        }
        builder.build()
    }

    let (issuer_name, signer) = match issuer {
        Some((issuer_cn, signer)) => (name(&[issuer_cn]), signer),
        None => (name(common_names), key),
    };
    let mut builder = openssl::x509::X509Builder::new().unwrap();
    builder.set_subject_name(&name(common_names)).unwrap();
    builder.set_issuer_name(&issuer_name).unwrap();
    builder.set_pubkey(key).unwrap();
    builder.set_not_before(not_before).unwrap();
    builder.set_not_after(not_after).unwrap();
    builder
        .sign(signer, openssl::hash::MessageDigest::sha256())
        .unwrap();
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;

    /// Round trip a real P-256 signature through the raw form: sign, split
    /// into fixed-width `r || s`, rebuild, verify.
    #[test]
    fn raw_round_trip_verifies() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = EcKey::generate(&group).unwrap();
        let digest = openssl::hash::hash(MessageDigest::sha256(), b"evidence").unwrap();
        let sig = EcdsaSig::sign(&digest, &key).unwrap();

        let mut raw = [0u8; 64];
        let (r, s) = (sig.r().to_vec(), sig.s().to_vec());
        raw[32 - r.len()..32].copy_from_slice(&r);
        raw[64 - s.len()..].copy_from_slice(&s);

        let rebuilt = ecdsa_from_raw(&raw).expect("raw signature rebuilds");
        assert!(rebuilt.verify(&digest, &key).unwrap());

        // Swapping the halves must not verify: the split is at the middle,
        // r first.
        let mut swapped = [0u8; 64];
        swapped[..32].copy_from_slice(&raw[32..]);
        swapped[32..].copy_from_slice(&raw[..32]);
        let swapped = ecdsa_from_raw(&swapped).expect("swapped signature rebuilds");
        assert!(!swapped.verify(&digest, &key).unwrap());
    }

    #[test]
    fn odd_length_raw_signatures_are_refused() {
        let err = ecdsa_from_raw(&[0u8; 63]).unwrap_err().to_string();
        assert!(err.contains("even number of bytes"), "got: {err}");
        let err = ecdsa_from_raw(&[]).unwrap_err().to_string();
        assert!(err.contains("non-empty"), "got: {err}");
    }
}
