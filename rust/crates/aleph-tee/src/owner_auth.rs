//! Owner authentication for secret injection.
//!
//! An EIP-191 personal-sign signature over a payload bound to the guest's
//! per-boot TLS key: `aleph-snp-inject-secret-v1|sha384(server public key)|
//! sha256(canonical secrets JSON)`, all hex lowercase. Binding to the per-boot
//! key gives channel binding and replay protection in one: a captured signed
//! request is only valid for that key, i.e. that boot of that VM. See
//! docs/plans/2026-08-18-snp-confidential-instances-design.md section 4.2.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256, Sha384};
use sha3::Keccak256;

pub const INJECT_SECRET_DOMAIN: &str = "aleph-snp-inject-secret-v1";

pub fn canonical_secrets_json(secrets: &BTreeMap<String, String>) -> String {
    serde_json::to_string(secrets).expect("a BTreeMap<String, String> always serializes")
}

pub fn inject_secret_payload(server_public_key_raw: &[u8], canonical_secrets_json: &str) -> String {
    let key_hash = hex::encode(Sha384::digest(server_public_key_raw));
    let body_hash = hex::encode(Sha256::digest(canonical_secrets_json.as_bytes()));
    format!("{INJECT_SECRET_DOMAIN}|{key_hash}|{body_hash}")
}

fn eip191_digest(payload: &str) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(format!("\x19Ethereum Signed Message:\n{}", payload.len()));
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}

pub fn address_from_verifying_key(key: &VerifyingKey) -> String {
    let uncompressed = key.to_encoded_point(false);
    let digest = Keccak256::digest(&uncompressed.as_bytes()[1..]);
    format!("0x{}", hex::encode(&digest[12..]))
}

pub fn sign_payload(signing_key: &SigningKey, payload: &str) -> String {
    let digest = eip191_digest(payload);
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(&digest)
        .expect("signing a 32-byte prehash cannot fail");
    let mut bytes = signature.to_bytes().to_vec();
    bytes.push(27 + recovery_id.to_byte());
    format!("0x{}", hex::encode(bytes))
}

pub fn recover_address(payload: &str, signature_hex: &str) -> anyhow::Result<String> {
    let stripped = signature_hex
        .strip_prefix("0x")
        .context("signature must be 0x-prefixed")?;
    let bytes = hex::decode(stripped).context("signature is not hex")?;
    if bytes.len() != 65 {
        bail!("signature must be 65 bytes, got {}", bytes.len());
    }
    let v = bytes[64];
    let recovery = match v {
        0 | 1 => v,
        27 | 28 => v - 27,
        other => bail!("invalid recovery byte {other}"),
    };
    let recovery_id = RecoveryId::try_from(recovery).context("invalid recovery id")?;
    let signature = Signature::from_slice(&bytes[..64]).context("invalid r||s")?;
    let digest = eip191_digest(payload);
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id)
        .context("public key recovery failed")?;
    Ok(address_from_verifying_key(&key))
}

pub fn verify_owner(payload: &str, signature_hex: &str, owner: &str) -> bool {
    match recover_address(payload, signature_hex) {
        Ok(address) => address.eq_ignore_ascii_case(owner),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use std::collections::BTreeMap;

    fn test_key() -> SigningKey {
        // Fixed key so the test is deterministic.
        SigningKey::from_slice(&[0x42u8; 32]).expect("valid scalar")
    }

    fn secrets() -> BTreeMap<String, String> {
        BTreeMap::from([("luks_passphrase".to_string(), "hunter2".to_string())])
    }

    #[test]
    fn canonical_json_is_sorted_and_compact() {
        let mut map = BTreeMap::new();
        map.insert("b".to_string(), "2".to_string());
        map.insert("a".to_string(), "1".to_string());
        assert_eq!(canonical_secrets_json(&map), r#"{"a":"1","b":"2"}"#);
    }

    #[test]
    fn sign_then_recover_roundtrips() {
        let key = test_key();
        let owner = address_from_verifying_key(key.verifying_key());
        let payload =
            inject_secret_payload(b"server-pubkey-raw", &canonical_secrets_json(&secrets()));
        let sig = sign_payload(&key, &payload);
        assert_eq!(recover_address(&payload, &sig).unwrap(), owner);
        assert!(verify_owner(&payload, &sig, &owner));
        assert!(verify_owner(
            &payload,
            &sig,
            &owner.to_uppercase().replace("0X", "0x")
        ));
    }

    #[test]
    fn tampered_payload_or_wrong_key_fails() {
        let key = test_key();
        let owner = address_from_verifying_key(key.verifying_key());
        let payload =
            inject_secret_payload(b"server-pubkey-raw", &canonical_secrets_json(&secrets()));
        let sig = sign_payload(&key, &payload);
        // Different server key = different payload = signature invalid for it.
        let other_payload =
            inject_secret_payload(b"OTHER-server-key", &canonical_secrets_json(&secrets()));
        assert!(!verify_owner(&other_payload, &sig, &owner));
        // Signature by a different key recovers a different address.
        let other = SigningKey::from_slice(&[0x43u8; 32]).unwrap();
        let sig2 = sign_payload(&other, &payload);
        assert!(!verify_owner(&payload, &sig2, &owner));
    }

    #[test]
    fn malformed_signature_is_rejected_not_panicking() {
        for bad in [
            "",
            "0x",
            "0xzz",
            "0x1234",
            &format!("0x{}", "00".repeat(65)),
        ] {
            assert!(!verify_owner(
                "payload",
                bad,
                "0x0000000000000000000000000000000000000000"
            ));
        }
    }

    #[test]
    fn payload_shape_is_stable() {
        // The payload format is a wire contract shared with attest-cli and the
        // Python harness; lock its shape.
        let payload = inject_secret_payload(b"k", "{}");
        let parts: Vec<&str> = payload.split('|').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[0], INJECT_SECRET_DOMAIN);
        assert_eq!(parts[1].len(), 96); // sha384 hex
        assert_eq!(parts[2].len(), 64); // sha256 hex
    }
}
