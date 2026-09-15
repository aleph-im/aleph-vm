//! Primitives shared by the SEV-SNP and TDX verifiers.
//!
//! Both stacks parse raw `r || s` ECDSA signatures out of binary evidence,
//! walk certificate chains to a pinned root and check validity windows, so
//! the implementations live here once. Structure comes from x509-parser
//! and signature math from ring: no native crypto library, because this
//! code is compiled into the measured guest agent and into client SDKs
//! that cross-compile, and both must stay free of openssl.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::oid::Oid;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_NIST_EC_P384, OID_PKCS1_RSASSAPSS,
    OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
};
use x509_parser::pem::Pem;
use x509_parser::revocation_list::CertificateRevocationList;
use x509_parser::time::ASN1Time;
use x509_parser::x509::{AlgorithmIdentifier, SubjectPublicKeyInfo, X509Name};

/// Parse one DER certificate, rejecting trailing bytes.
pub(crate) fn parse_cert<'a>(what: &str, der: &'a [u8]) -> Result<X509Certificate<'a>> {
    let (rest, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| anyhow::anyhow!("failed to parse {what}: {e}"))?;
    if !rest.is_empty() {
        bail!(
            "{what} carries {} trailing bytes after the certificate",
            rest.len()
        );
    }
    Ok(cert)
}

/// Parse one DER CRL, rejecting trailing bytes.
pub(crate) fn parse_crl<'a>(what: &str, der: &'a [u8]) -> Result<CertificateRevocationList<'a>> {
    let (rest, crl) = x509_parser::parse_x509_crl(der)
        .map_err(|e| anyhow::anyhow!("failed to parse {what}: {e}"))?;
    if !rest.is_empty() {
        bail!("{what} carries {} trailing bytes after the CRL", rest.len());
    }
    Ok(crl)
}

/// Split a PEM stack into DER certificates, in order.
///
/// Every block must be a CERTIFICATE. Bytes outside the blocks are ignored:
/// Intel terminates the chain embedded in a quote with a NUL, and AMD's
/// KDS answers with plain concatenated PEM.
pub(crate) fn pem_certs_to_der(what: &str, pem: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut certs = Vec::new();
    for block in Pem::iter_from_buffer(pem) {
        let block = block.map_err(|e| anyhow::anyhow!("failed to parse {what}: {e}"))?;
        if block.label != "CERTIFICATE" {
            bail!(
                "{what} carries a {} block where a CERTIFICATE was expected",
                block.label
            );
        }
        certs.push(block.contents);
    }
    if certs.is_empty() {
        bail!("{what} carries no certificate");
    }
    Ok(certs)
}

/// The injected verification clock as seconds since the Unix epoch.
///
/// Verification time is a parameter everywhere in this crate: a verifier
/// that read the clock itself could not be tested against archived
/// evidence.
pub(crate) fn unix_seconds(now: SystemTime) -> Result<i64> {
    let secs = now
        .duration_since(UNIX_EPOCH)
        .context("verification time predates the unix epoch")?
        .as_secs();
    secs.try_into()
        .context("verification time does not fit in an i64")
}

/// The curve an ECDSA key or signature lives on, with the digest each
/// vendor pairs it with: SHA-256 on P-256 (Intel), SHA-384 on P-384 (AMD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Curve {
    P256,
    P384,
}

impl Curve {
    fn named_curve(self) -> Oid<'static> {
        match self {
            Curve::P256 => OID_EC_P256.clone(),
            Curve::P384 => OID_NIST_EC_P384.clone(),
        }
    }

    /// ring's algorithm for a raw fixed-width `r || s` signature.
    fn fixed(self) -> &'static signature::EcdsaVerificationAlgorithm {
        match self {
            Curve::P256 => &signature::ECDSA_P256_SHA256_FIXED,
            Curve::P384 => &signature::ECDSA_P384_SHA384_FIXED,
        }
    }

    /// ring's algorithm for a DER `SEQUENCE { r, s }` signature, the form
    /// certificates and CRLs carry.
    fn asn1(self) -> &'static signature::EcdsaVerificationAlgorithm {
        match self {
            Curve::P256 => &signature::ECDSA_P256_SHA256_ASN1,
            Curve::P384 => &signature::ECDSA_P384_SHA384_ASN1,
        }
    }

    fn raw_signature_len(self) -> usize {
        match self {
            Curve::P256 => 64,
            Curve::P384 => 96,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Curve::P256 => "P-256",
            Curve::P384 => "P-384",
        }
    }
}

/// The SEC1 point of an EC public key, after checking the key is on `curve`.
pub(crate) fn ec_public_key<'s>(
    what: &str,
    spki: &'s SubjectPublicKeyInfo<'_>,
    curve: Curve,
) -> Result<&'s [u8]> {
    if spki.algorithm.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
        bail!("the {what} key is not an EC key");
    }
    let named_curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|params| params.as_oid().ok());
    match named_curve {
        Some(oid) if oid == curve.named_curve() => {}
        _ => bail!("the {what} key is not on {}", curve.name()),
    }
    Ok(spki.subject_public_key.data.as_ref())
}

/// Verify an ECDSA signature given as raw `r || s` (fixed-width big-endian
/// scalars) over `message`, hashed with the curve's companion digest.
pub(crate) fn verify_raw_ecdsa(
    what: &str,
    curve: Curve,
    public_key_sec1: &[u8],
    message: &[u8],
    raw_signature: &[u8],
) -> Result<()> {
    let expected = curve.raw_signature_len();
    if raw_signature.len() != expected {
        bail!(
            "{what} signature is {} bytes, expected {expected} (r || s on {})",
            raw_signature.len(),
            curve.name()
        );
    }
    UnparsedPublicKey::new(curve.fixed(), public_key_sec1)
        .verify(message, raw_signature)
        .map_err(|_| anyhow::anyhow!("{what} signature does not verify"))
}

/// Rebuild a fixed-width big-endian `r || s` from the two little-endian,
/// zero-padded 72-byte scalars an SEV-SNP report carries.
pub(crate) fn p384_signature_from_le(r_le: &[u8], s_le: &[u8]) -> Result<[u8; 96]> {
    fn scalar(what: &str, le: &[u8]) -> Result<[u8; 48]> {
        if le.len() != 72 {
            bail!("signature {what} is {} bytes, expected 72", le.len());
        }
        // Little-endian: bytes 48..72 are the high-order padding, and a
        // non-zero byte there means a value no P-384 scalar can take.
        if le[48..].iter().any(|&b| b != 0) {
            bail!("signature {what} exceeds the P-384 scalar width");
        }
        let mut be = [0u8; 48];
        for (i, b) in le[..48].iter().enumerate() {
            be[47 - i] = *b;
        }
        Ok(be)
    }
    let mut out = [0u8; 96];
    out[..48].copy_from_slice(&scalar("r", r_le)?);
    out[48..].copy_from_slice(&scalar("s", s_le)?);
    Ok(out)
}

/// Pick ring's algorithm for a certificate or CRL signature from the
/// algorithm the signed object declares and the key its signer carries.
///
/// Only what the attestation vendors use is accepted: RSASSA-PSS with
/// SHA-384 (AMD's chain and CRLs) and ECDSA with SHA-256 on P-256 or
/// SHA-384 on P-384 (Intel's chain and CRLs). Anything else fails closed.
/// ring's PSS profile fixes SHA-384, MGF1-SHA-384 and a 48-byte salt, which
/// is AMD's profile; a PSS signature under other parameters fails to
/// verify rather than being accepted.
fn chain_signature_algorithm(
    what: &str,
    signed_with: &AlgorithmIdentifier<'_>,
    signer: &SubjectPublicKeyInfo<'_>,
) -> Result<&'static dyn VerificationAlgorithm> {
    let algorithm = &signed_with.algorithm;
    if *algorithm == OID_PKCS1_RSASSAPSS {
        return Ok(&signature::RSA_PSS_2048_8192_SHA384);
    }
    let curve = if *algorithm == OID_SIG_ECDSA_WITH_SHA256 {
        Curve::P256
    } else if *algorithm == OID_SIG_ECDSA_WITH_SHA384 {
        Curve::P384
    } else {
        bail!("{what} uses the unsupported signature algorithm {algorithm}");
    };
    ec_public_key(what, signer, curve).with_context(|| format!("{what} signer key"))?;
    Ok(curve.asn1())
}

fn verify_chain_signature(
    child_label: &str,
    issuer_label: &str,
    signer: &SubjectPublicKeyInfo<'_>,
    signed_with: &AlgorithmIdentifier<'_>,
    to_be_signed: &[u8],
    signature_value: &[u8],
) -> Result<()> {
    let algorithm = chain_signature_algorithm(child_label, signed_with, signer)?;
    // For an RSA key the SPKI bit string is the PKCS#1 RSAPublicKey DER,
    // for an EC key the SEC1 point: both are what ring expects.
    UnparsedPublicKey::new(algorithm, signer.subject_public_key.data.as_ref())
        .verify(to_be_signed, signature_value)
        .map_err(|_| anyhow::anyhow!("{child_label} is not signed by {issuer_label}"))
}

/// Reject a certificate that does not carry a valid signature by its issuer.
pub(crate) fn check_signed_by(
    child_label: &str,
    child: &X509Certificate<'_>,
    issuer_label: &str,
    issuer: &X509Certificate<'_>,
) -> Result<()> {
    // RFC 5280 4.1.1.2 requires the outer AlgorithmIdentifier to equal the
    // one inside the signed TBSCertificate. The outer copy is not itself
    // signed, so without this check an attacker could leave the signed
    // inner algorithm alone and swap the outer one for a weaker or
    // different algorithm to change how the signature below gets verified.
    if child.signature_algorithm != child.tbs_certificate.signature {
        bail!(
            "{child_label} declares different signature algorithms inside and outside the signed bytes"
        );
    }
    verify_chain_signature(
        child_label,
        issuer_label,
        issuer.public_key(),
        &child.signature_algorithm,
        child.tbs_certificate.as_ref(),
        child.signature_value.data.as_ref(),
    )
}

/// [`check_signed_by`] for a CRL.
pub(crate) fn check_crl_signed_by(
    crl_label: &str,
    crl: &CertificateRevocationList<'_>,
    issuer_label: &str,
    issuer: &X509Certificate<'_>,
) -> Result<()> {
    // Same binding as in check_signed_by, and for the same reason: the
    // outer AlgorithmIdentifier is unsigned, so it must be checked against
    // the signed copy inside the TBSCertList rather than trusted on its own.
    if crl.signature_algorithm != crl.tbs_cert_list.signature {
        bail!(
            "{crl_label} declares different signature algorithms inside and outside the signed bytes"
        );
    }
    verify_chain_signature(
        crl_label,
        issuer_label,
        issuer.public_key(),
        &crl.signature_algorithm,
        crl.tbs_cert_list.as_ref(),
        crl.signature_value.data.as_ref(),
    )
}

/// Reject a root certificate that is not, byte for byte, the pinned one.
///
/// For Intel, which publishes one fixed SGX Root CA. AMD re-issues its ARK
/// with the same key, so the SEV-SNP side pins the key through
/// [`check_pinned_root_key`] instead.
pub(crate) fn check_pinned_root(
    presented_label: &str,
    presented_der: &[u8],
    pin_label: &str,
    pinned_der: &[u8],
) -> Result<()> {
    if presented_der == pinned_der {
        return Ok(());
    }
    let presented = parse_cert(presented_label, presented_der)?;
    let pinned = parse_cert(pin_label, pinned_der)?;
    if presented.public_key().raw == pinned.public_key().raw {
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
    presented: &X509Certificate<'_>,
    pin_label: &str,
    pinned: &X509Certificate<'_>,
) -> Result<()> {
    if presented.public_key().raw != pinned.public_key().raw {
        bail!(
            "the public key of {presented_label} does not match {pin_label} \
             (possible forged or cache-poisoned root)"
        );
    }
    Ok(())
}

/// Reject a validity window that does not contain `now`.
pub(crate) fn check_validity_window(
    what: &str,
    not_before: &ASN1Time,
    not_after: &ASN1Time,
    now: i64,
) -> Result<()> {
    if now < not_before.timestamp() {
        bail!("{what} is not yet valid (notBefore {not_before})");
    }
    if now > not_after.timestamp() {
        bail!("{what} expired (notAfter {not_after})");
    }
    Ok(())
}

/// Reject a certificate whose validity window does not contain `now`.
pub(crate) fn check_cert_window(what: &str, cert: &X509Certificate<'_>, now: i64) -> Result<()> {
    let validity = cert.validity();
    check_validity_window(what, &validity.not_before, &validity.not_after, now)
}

/// The one Common Name of a subject, refusing a subject that carries none
/// or several: a substring test, or the first of several, would let the
/// rest of the subject say something else.
pub(crate) fn single_common_name<'a>(what: &str, name: &X509Name<'a>) -> Result<&'a str> {
    let mut common_names = name.iter_common_name();
    let common_name = common_names
        .next()
        .with_context(|| format!("{what} has no Common Name"))?;
    if common_names.next().is_some() {
        bail!("{what} carries more than one Common Name");
    }
    common_name
        .as_str()
        .with_context(|| format!("the {what} Common Name is not a string"))
}

/// Certificate fabrication for the tests that present an impostor where a
/// pinned certificate belongs, or a synthetic chain in place of a vendor's.
#[cfg(test)]
pub(crate) mod testing {
    use rcgen::{
        CertificateParams, DistinguishedName, DnType, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
        PKCS_ECDSA_P384_SHA384,
    };
    use time::OffsetDateTime;

    /// A fresh P-256 key.
    pub(crate) fn p256_key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("P-256 key generation")
    }

    /// A fresh P-384 key.
    pub(crate) fn p384_key() -> KeyPair {
        KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 key generation")
    }

    /// A subject or issuer name: Common Names in order, optional Organization.
    pub(crate) struct Name<'a> {
        pub(crate) common_names: Vec<&'a str>,
        pub(crate) organization: Option<&'a str>,
    }

    impl Name<'_> {
        fn distinguished(&self) -> DistinguishedName {
            let mut dn = DistinguishedName::new();
            for (i, common_name) in self.common_names.iter().enumerate() {
                // rcgen keys entries by DnType, so a second Common Name goes
                // in under the same OID (2.5.4.3) spelled as a custom type.
                let ty = if i == 0 {
                    DnType::CommonName
                } else {
                    DnType::CustomDnType(vec![2, 5, 4, 3])
                };
                dn.push(ty, *common_name);
            }
            if let Some(organization) = self.organization {
                dn.push(DnType::OrganizationName, organization);
            }
            dn
        }
    }

    fn params(subject: &Name<'_>, not_before: i64, not_after: i64) -> CertificateParams {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
        params.distinguished_name = subject.distinguished();
        params.not_before = OffsetDateTime::from_unix_timestamp(not_before).expect("not_before");
        params.not_after = OffsetDateTime::from_unix_timestamp(not_after).expect("not_after");
        params
    }

    /// A certificate for `key`, self-signed unless an issuer is given.
    /// Validity bounds are unix seconds.
    pub(crate) fn cert(
        subject: &Name<'_>,
        key: &KeyPair,
        issuer: Option<(&Name<'_>, &KeyPair)>,
        not_before: i64,
        not_after: i64,
    ) -> rcgen::Certificate {
        let subject_params = params(subject, not_before, not_after);
        match issuer {
            None => subject_params
                .self_signed(key)
                .expect("self-signed certificate"),
            Some((issuer_name, issuer_key)) => {
                let issuer_params = params(issuer_name, not_before, not_after);
                let issuer = Issuer::from_params(&issuer_params, issuer_key);
                subject_params
                    .signed_by(key, &issuer)
                    .expect("signed certificate")
            }
        }
    }

    /// A certificate carrying someone else's public key (an SPKI DER),
    /// signed by `issuer`: the "same key, different envelope" case.
    pub(crate) fn cert_for_public_key(
        subject: &Name<'_>,
        spki_der: &[u8],
        issuer: (&Name<'_>, &KeyPair),
        not_before: i64,
        not_after: i64,
    ) -> rcgen::Certificate {
        let subject_params = params(subject, not_before, not_after);
        let issuer_params = params(issuer.0, not_before, not_after);
        let issuer = Issuer::from_params(&issuer_params, issuer.1);
        let spki = rcgen::SubjectPublicKeyInfo::from_der(spki_der).expect("SPKI parses");
        subject_params
            .signed_by(&spki, &issuer)
            .expect("signed certificate")
    }

    /// The PEM blocks of a stack, each its own string ending in a newline,
    /// for tests that reorder or recombine real chains.
    pub(crate) fn pem_blocks(stack: &str) -> Vec<String> {
        stack
            .split_inclusive("-----END CERTIFICATE-----")
            .filter(|block| block.contains("-----BEGIN CERTIFICATE-----"))
            .map(|block| format!("{}\n", block.trim()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _};

    /// Round trip a real P-256 signature through the raw form: sign into
    /// fixed-width `r || s`, verify, and check the halves are not
    /// interchangeable.
    #[test]
    fn raw_ecdsa_round_trip_verifies() {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        let raw = key.sign(&rng, b"evidence").unwrap();
        let public = key.public_key().as_ref();

        verify_raw_ecdsa("test", Curve::P256, public, b"evidence", raw.as_ref())
            .expect("the raw signature verifies");

        let mut swapped = [0u8; 64];
        swapped[..32].copy_from_slice(&raw.as_ref()[32..]);
        swapped[32..].copy_from_slice(&raw.as_ref()[..32]);
        assert!(verify_raw_ecdsa("test", Curve::P256, public, b"evidence", &swapped).is_err());
        assert!(verify_raw_ecdsa("test", Curve::P256, public, b"evidenc", raw.as_ref()).is_err());
    }

    #[test]
    fn wrong_length_raw_signatures_are_refused() {
        let err = verify_raw_ecdsa("test", Curve::P256, &[], b"", &[0u8; 63])
            .unwrap_err()
            .to_string();
        assert!(err.contains("63 bytes, expected 64"), "got: {err}");
        let err = verify_raw_ecdsa("test", Curve::P384, &[], b"", &[0u8; 64])
            .unwrap_err()
            .to_string();
        assert!(err.contains("64 bytes, expected 96"), "got: {err}");
    }

    #[test]
    fn p384_le_scalars_rebuild_big_endian() {
        let mut r = [0u8; 72];
        r[0] = 0x01; // least-significant byte first
        let mut s = [0u8; 72];
        s[47] = 0xff; // most-significant in-range byte
        let sig = p384_signature_from_le(&r, &s).unwrap();
        assert_eq!(sig[47], 0x01);
        assert_eq!(sig[48], 0xff);
        let mut oversized = [0u8; 72];
        oversized[48] = 1;
        let err = p384_signature_from_le(&oversized, &s)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds the P-384 scalar width"), "got: {err}");
        assert!(p384_signature_from_le(&r[..71], &s).is_err());
    }

    #[test]
    fn fabricated_chain_signatures_and_pins_behave() {
        use testing::{Name, cert, p384_key};
        let root_key = p384_key();
        let root_name = Name {
            common_names: vec!["Test Root"],
            organization: Some("Tests"),
        };
        let root = cert(&root_name, &root_key, None, 1_700_000_000, 1_900_000_000);
        // Same curve as the root so the reversed check below fails on the
        // signature itself, not on the curve gate.
        let leaf_key = p384_key();
        let leaf = cert(
            &Name {
                common_names: vec!["Test Leaf"],
                organization: None,
            },
            &leaf_key,
            Some((&root_name, &root_key)),
            1_700_000_000,
            1_900_000_000,
        );
        let root_parsed = parse_cert("root", root.der()).unwrap();
        let leaf_parsed = parse_cert("leaf", leaf.der()).unwrap();

        check_signed_by("root", &root_parsed, "itself", &root_parsed).unwrap();
        check_signed_by("leaf", &leaf_parsed, "root", &root_parsed).unwrap();
        let err = check_signed_by("root", &root_parsed, "leaf", &leaf_parsed)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not signed by"), "got: {err}");

        check_pinned_root("root", root.der(), "pin", root.der()).unwrap();
        let err = check_pinned_root("leaf", leaf.der(), "pin", root.der())
            .unwrap_err()
            .to_string();
        assert!(err.contains("forged or cache-poisoned root"), "got: {err}");

        check_cert_window("leaf", &leaf_parsed, 1_800_000_000).unwrap();
        let err = check_cert_window("leaf", &leaf_parsed, 1_600_000_000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not yet valid"), "got: {err}");
        let err = check_cert_window("leaf", &leaf_parsed, 2_000_000_000)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "got: {err}");

        assert_eq!(
            single_common_name("root", root_parsed.subject()).unwrap(),
            "Test Root"
        );
    }

    #[test]
    fn pem_stack_splits_and_tolerates_trailing_bytes() {
        use testing::{Name, cert, p256_key};
        let a = cert(
            &Name {
                common_names: vec!["A"],
                organization: None,
            },
            &p256_key(),
            None,
            1_700_000_000,
            1_900_000_000,
        );
        let b = cert(
            &Name {
                common_names: vec!["B"],
                organization: None,
            },
            &p256_key(),
            None,
            1_700_000_000,
            1_900_000_000,
        );
        let mut stack = format!("{}{}", a.pem(), b.pem()).into_bytes();
        stack.push(0);
        let certs = pem_certs_to_der("stack", &stack).unwrap();
        assert_eq!(certs.len(), 2);
        assert_eq!(certs[0], a.der().as_ref());
        assert_eq!(certs[1], b.der().as_ref());
        assert!(pem_certs_to_der("empty", b"nothing here").is_err());
        let key_block = p256_key().serialize_pem();
        assert!(pem_certs_to_der("key", key_block.as_bytes()).is_err());
    }

    #[test]
    fn signature_algorithm_binding_is_enforced() {
        use testing::{Name, cert, p256_key, p384_key};
        let name = Name {
            common_names: vec!["Self Signed"],
            organization: None,
        };
        let p256 = cert(&name, &p256_key(), None, 1_700_000_000, 1_900_000_000);
        let p256_parsed = parse_cert("p256", p256.der()).unwrap();
        check_signed_by("p256", &p256_parsed, "itself", &p256_parsed)
            .expect("a self-signed certificate verifies against itself");

        // A P-384 cert to steal a mismatched (but validly encoded)
        // AlgorithmIdentifier from, for the outer field.
        let p384 = cert(&name, &p384_key(), None, 1_700_000_000, 1_900_000_000);
        let p384_parsed = parse_cert("p384", p384.der()).unwrap();

        let mut mismatched = p256_parsed.clone();
        mismatched.signature_algorithm = p384_parsed.signature_algorithm.clone();
        let err = check_signed_by("mismatched", &mismatched, "itself", &p256_parsed)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains(
                "declares different signature algorithms inside and outside the signed bytes"
            ),
            "got: {err}"
        );
    }
}
