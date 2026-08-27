//! Canonical `report_data` construction for attested TLS.
//!
//! An SEV-SNP attestation report carries 64 free bytes (`report_data`) that the
//! guest chooses and AMD signs verbatim. This module defines the ONE canonical
//! way those 64 bytes are filled, so the constructing side (aleph-attest-agent)
//! and the verifying side (the `attest` module of the aleph-rs SDK, which
//! mirrors these constructors) cannot drift. Both MUST use this scheme: an
//! ad-hoc variant on either side reopens the attack described below.
//!
//! # Why domain separation and channel binding
//!
//! There are two distinct report shapes:
//!   * key binding: proves "the holder of this TLS key runs in this TEE".
//!   * fresh/nonce binding: proves liveness against a caller-chosen nonce.
//!
//! The aleph-cvm donor placed the caller's raw nonce DIRECTLY into
//! `report_data`, sharing the same 64-byte namespace as the key-binding report
//! (which stored `SHA-384(public_key)`). An attacker could request a fresh
//! report with `nonce = SHA-384(attacker_key)` and receive a genuine,
//! AMD-signed report whose `report_data` is byte-identical to a legitimate
//! key-bound report for the attacker's key: an attested-key confusion that
//! enables a full MITM. See the rust-port-divergences ledger.
//!
//! The fix, encoded here:
//!   * Each scheme is prefixed with a distinct domain constant (with a trailing
//!     separator byte), so the two namespaces can never collide.
//!   * The fresh scheme hashes the SERVED public key together with the nonce, so
//!     a fresh report is bound to the exact TLS channel it was produced for and
//!     cannot be relayed against a different key.
//!   * The raw nonce is never placed into `report_data`; it is always hashed
//!     under a domain, so no caller-controlled bytes land in the report verbatim.
//!
//! Both schemes write `SHA-384(...)` (48 bytes) into the first 48 bytes of the
//! 64-byte field and leave the remaining 16 bytes zero.

use sha2::{Digest, Sha384};

/// Domain tag for the key-binding report (`SHA-384(DOMAIN_KEY || public_key)`).
/// The trailing `0x00` is a separator byte, so the domain can never be a prefix
/// of the data that follows it.
pub const DOMAIN_KEY: &[u8] = b"aleph-attest-tls-key-v1\x00";

/// Domain tag for the fresh/nonce-binding report
/// (`SHA-384(DOMAIN_FRESH || public_key || nonce)`). The trailing `0x00` is a
/// separator byte.
pub const DOMAIN_FRESH: &[u8] = b"aleph-attest-fresh-v1\x00";

/// Write a SHA-384 digest into a fresh 64-byte `report_data` buffer (first 48
/// bytes = digest, remaining 16 bytes = zero).
fn digest_into_report_data(hasher: Sha384) -> [u8; 64] {
    let hash = hasher.finalize();
    let mut report_data = [0u8; 64];
    report_data[..48].copy_from_slice(&hash);
    report_data
}

/// Canonical key-binding `report_data`: `SHA-384(DOMAIN_KEY || public_key_raw)`
/// in the first 48 bytes, rest zero.
///
/// Binds an attestation report to the raw bytes of a public key, proving the
/// holder of the corresponding private key runs inside the attested TEE.
pub fn key_bound_report_data(public_key_raw: &[u8]) -> [u8; 64] {
    let mut hasher = Sha384::new();
    hasher.update(DOMAIN_KEY);
    hasher.update(public_key_raw);
    digest_into_report_data(hasher)
}

/// Canonical fresh/nonce-binding `report_data`:
/// `SHA-384(DOMAIN_FRESH || public_key_raw || nonce)` in the first 48 bytes,
/// rest zero.
///
/// Binds BOTH the served TLS public key AND the caller's nonce. Because the key
/// is mixed in, a fresh report cannot be relayed and reused for a different TLS
/// channel; because of the domain tag, it can never collide with a key-bound
/// report. The raw nonce is never placed into `report_data` verbatim.
pub fn fresh_report_data(public_key_raw: &[u8], nonce: &[u8]) -> [u8; 64] {
    let mut hasher = Sha384::new();
    hasher.update(DOMAIN_FRESH);
    hasher.update(public_key_raw);
    hasher.update(nonce);
    digest_into_report_data(hasher)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (a) Domain separation: the two schemes produce DIFFERENT outputs even
    /// when fed the same underlying bytes.
    #[test]
    fn schemes_are_domain_separated() {
        let bytes = b"same-input-bytes";
        // key_bound hashes DOMAIN_KEY || bytes; fresh hashes
        // DOMAIN_FRESH || bytes || (empty nonce). Different domains -> different.
        let key = key_bound_report_data(bytes);
        let fresh = fresh_report_data(bytes, b"");
        assert_ne!(key, fresh, "domains must not collide");
    }

    /// (b) Channel binding: the fresh scheme changes when the served pubkey
    /// changes, even for a fixed nonce.
    #[test]
    fn fresh_is_channel_bound_to_pubkey() {
        let nonce = b"caller-nonce";
        let a = fresh_report_data(b"server-key-A", nonce);
        let b = fresh_report_data(b"server-key-B", nonce);
        assert_ne!(a, b, "fresh report_data must bind the served pubkey");
    }

    /// The fresh scheme also changes with the nonce (liveness), for a fixed key.
    #[test]
    fn fresh_changes_with_nonce() {
        let key = b"server-key";
        let a = fresh_report_data(key, b"nonce-1");
        let b = fresh_report_data(key, b"nonce-2");
        assert_ne!(a, b, "fresh report_data must bind the nonce");
    }

    /// (c) The specific attested-key-confusion attack is impossible: for any
    /// attacker key `K`, a fresh report requested with `nonce = SHA-384(K)`
    /// against the honest server key can never equal the key-bound report for
    /// `K`. This is exactly the donor collision, now closed by domain separation.
    #[test]
    fn attack_key_confusion_is_impossible() {
        let server_key = b"honest-server-public-key";
        for attacker_key in [
            b"attacker-key-0".as_slice(),
            b"attacker-key-1".as_slice(),
            b"\x00\x01\x02\x03".as_slice(),
            &[0xFFu8; 97],
        ] {
            // The attacker's chosen nonce is the raw SHA-384 of their own key,
            // which is precisely what the donor's key-bound scheme stored.
            let malicious_nonce = Sha384::digest(attacker_key);
            let fresh = fresh_report_data(server_key, &malicious_nonce);
            let key_bound = key_bound_report_data(attacker_key);
            assert_ne!(
                fresh, key_bound,
                "fresh report must never collide with a key-bound report"
            );
        }
    }

    /// The tail 16 bytes are always zero and the first 48 hold the digest.
    #[test]
    fn layout_is_48_byte_digest_then_zero() {
        let out = key_bound_report_data(b"k");
        let expected = {
            let mut h = Sha384::new();
            h.update(DOMAIN_KEY);
            h.update(b"k");
            h.finalize()
        };
        assert_eq!(&out[..48], expected.as_slice());
        assert_eq!(&out[48..], &[0u8; 16]);
    }
}
