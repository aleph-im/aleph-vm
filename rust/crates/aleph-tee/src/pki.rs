//! Primitives shared by the SEV-SNP and TDX verifiers.
//!
//! Both stacks parse raw `r || s` ECDSA signatures out of binary evidence and
//! both walk certificate validity windows, so the two implementations live
//! here once instead of drifting apart in each backend.

use anyhow::{Context, Result, bail};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;

/// Assemble an ECDSA signature from its raw big-endian `r` and `s`
/// components.
///
/// Attestation evidence carries signatures as two fixed-width integers
/// rather than as a DER `SEQUENCE`, so every verification path has to
/// rebuild the signature object before openssl will check it. The
/// components may be any length openssl accepts: TDX quotes and Intel's
/// signed collateral use 32 bytes each (P-256), an SEV-SNP report uses up
/// to 48 (P-384, after the little-endian fields have been reversed and
/// trimmed).
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
