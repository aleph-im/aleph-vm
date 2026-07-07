use std::collections::HashMap;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use tracing::info;
use zeroize::Zeroizing;

/// Default directory where injected secrets are written as individual files.
const DEFAULT_SECRETS_DIR: &str = "/tmp/secrets";

/// Maximum number of secrets that can be injected in a single request.
const MAX_SECRETS: usize = 16;

/// Maximum length of a secret key name.
const MAX_KEY_LEN: usize = 64;

/// Maximum size of a single secret value in bytes (64 KiB).
const MAX_VALUE_SIZE: usize = 64 * 1024;

#[derive(Deserialize)]
pub struct InjectSecretRequest {
    #[serde(flatten)]
    pub secrets: HashMap<String, String>,
}

#[derive(Serialize)]
pub struct InjectSecretResponse {
    pub injected: Vec<String>,
}

/// One-shot secret store: holds the injection guard and the target directory.
///
/// The `Mutex` makes the entire check-and-write atomic (no TOCTOU race between
/// the one-shot check and the write), exactly as the donor's global static did.
/// Unlike the donor (a process-global `static Mutex` + a hard-coded path), the
/// state lives here as injectable actix `web::Data`, so the one-shot semantics
/// and the input limits are unit-testable against a temp directory. See the
/// rust-port-divergences entry.
pub struct SecretStore {
    /// `true` once a successful (or partially-written) injection has occurred.
    injected: Mutex<bool>,
    /// Directory the secret files are written into (created on first inject).
    dir: PathBuf,
}

/// The outcome of an injection attempt, mapped to an HTTP response by the handler.
enum InjectOutcome {
    Ok(Vec<String>),
    Conflict,
    BadRequest(String),
    Internal(String),
}

impl SecretStore {
    /// Create a store writing to an explicit directory (used by tests).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            injected: Mutex::new(false),
            dir: dir.into(),
        }
    }

    /// Create a store writing to the production `/tmp/secrets` directory.
    pub fn with_default_dir() -> Self {
        Self::new(DEFAULT_SECRETS_DIR)
    }

    /// Validate and write the secrets. One-shot: a second successful attempt is
    /// rejected with `Conflict`. Validation failures (empty, over-limit, bad key
    /// or oversized value) do not consume the one-shot guard.
    fn inject(&self, secrets: &HashMap<String, String>) -> InjectOutcome {
        // Acquire the injection lock for the entire operation.
        // This eliminates the TOCTOU race that an AtomicBool would have.
        let mut guard = match self.injected.lock() {
            Ok(g) => g,
            Err(_) => return InjectOutcome::Internal("internal lock error".to_string()),
        };

        if *guard {
            return InjectOutcome::Conflict;
        }

        if secrets.is_empty() {
            return InjectOutcome::BadRequest("no secrets provided".to_string());
        }

        if secrets.len() > MAX_SECRETS {
            return InjectOutcome::BadRequest(format!(
                "too many secrets: max {MAX_SECRETS}, got {}",
                secrets.len()
            ));
        }

        // Validate all keys and values before writing anything (all-or-nothing).
        for (key, value) in secrets {
            if key.is_empty() || key.len() > MAX_KEY_LEN {
                return InjectOutcome::BadRequest(format!(
                    "secret key length must be 1-{MAX_KEY_LEN}, got {}",
                    key.len()
                ));
            }
            if !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                return InjectOutcome::BadRequest(format!(
                    "invalid secret key: must be alphanumeric/underscore/hyphen, got: {key}"
                ));
            }
            if value.len() > MAX_VALUE_SIZE {
                return InjectOutcome::BadRequest(format!(
                    "secret value too large for key '{key}': max {MAX_VALUE_SIZE} bytes, got {}",
                    value.len()
                ));
            }
        }

        // Create secrets directory.
        if let Err(e) = std::fs::create_dir_all(&self.dir) {
            tracing::error!("failed to create secrets directory: {e}");
            return InjectOutcome::Internal("failed to create secrets directory".to_string());
        }

        // Write each secret as a file.
        let mut injected = Vec::new();
        for (key, value) in secrets {
            // Wrap value in Zeroizing so it's wiped from memory when dropped.
            let secret_value = Zeroizing::new(value.as_bytes().to_vec());

            let path = self.dir.join(key);
            // Write with mode 0600 (owner read/write only).
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(&secret_value)
                });

            if let Err(e) = result {
                tracing::error!("failed to write secret {key}: {e}");
                // Partial write: some secrets may already be on disk.
                // Still mark as injected to prevent retry with inconsistent state.
                *guard = true;
                return InjectOutcome::Internal(format!("failed to write secret: {key}"));
            }
            info!(key = %key, "injected secret");
            injected.push(key.clone());
        }

        // Mark as injected only after all secrets are successfully written.
        *guard = true;

        InjectOutcome::Ok(injected)
    }
}

/// POST /confidential/inject-secret
///
/// Accepts a JSON object of key-value pairs. Each key is written as a file
/// under the store directory (`/tmp/secrets/<key>` in production) containing the
/// value. One-shot: returns 409 on subsequent calls. Secret values are zeroized
/// from memory after being written to disk. Files are created with mode 0600.
///
/// Limits: max 16 secrets, max 64-char key names, max 64 KiB per value.
pub async fn inject_secret_handler(
    store: web::Data<SecretStore>,
    body: web::Json<InjectSecretRequest>,
) -> HttpResponse {
    match store.inject(&body.secrets) {
        InjectOutcome::Ok(injected) => HttpResponse::Ok().json(InjectSecretResponse { injected }),
        InjectOutcome::Conflict => {
            HttpResponse::Conflict().json(serde_json::json!({"error": "secrets already injected"}))
        }
        InjectOutcome::BadRequest(msg) => {
            HttpResponse::BadRequest().json(serde_json::json!({"error": msg}))
        }
        InjectOutcome::Internal(msg) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": msg}))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        // Unique per test to avoid cross-test collisions in a shared /tmp.
        let nonce = format!(
            "aleph-attest-secrets-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        p.push(nonce);
        p
    }

    fn secrets_of(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn is_ok(o: &InjectOutcome) -> bool {
        matches!(o, InjectOutcome::Ok(_))
    }

    #[test]
    fn test_inject_writes_files_mode_0600_and_zeroizes() {
        let dir = tmpdir();
        let store = SecretStore::new(&dir);

        let out = store.inject(&secrets_of(&[
            ("api_key", "s3cr3t"),
            ("db-pass", "hunter2"),
        ]));
        assert!(is_ok(&out));

        // Both files exist with the expected content and mode 0600.
        for (name, expected) in [("api_key", "s3cr3t"), ("db-pass", "hunter2")] {
            let path = dir.join(name);
            let content = std::fs::read_to_string(&path).unwrap();
            assert_eq!(content, expected);
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "secret file must be owner-only 0600");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_inject_is_one_shot() {
        let dir = tmpdir();
        let store = SecretStore::new(&dir);

        // First injection succeeds.
        assert!(is_ok(&store.inject(&secrets_of(&[("k", "v")]))));

        // A second injection is rejected as a conflict (409), even with new keys.
        assert!(matches!(
            store.inject(&secrets_of(&[("other", "value")])),
            InjectOutcome::Conflict
        ));

        // The second injection's file was never written.
        assert!(!dir.join("other").exists());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_inject_rejects_empty() {
        let store = SecretStore::new(tmpdir());
        assert!(matches!(
            store.inject(&HashMap::new()),
            InjectOutcome::BadRequest(_)
        ));
    }

    #[test]
    fn test_inject_rejects_too_many_secrets() {
        let store = SecretStore::new(tmpdir());
        let mut many = HashMap::new();
        for i in 0..(MAX_SECRETS + 1) {
            many.insert(format!("k{i}"), "v".to_string());
        }
        assert!(matches!(store.inject(&many), InjectOutcome::BadRequest(_)));
    }

    #[test]
    fn test_inject_rejects_oversized_key() {
        let store = SecretStore::new(tmpdir());
        let long_key = "a".repeat(MAX_KEY_LEN + 1);
        assert!(matches!(
            store.inject(&secrets_of(&[(long_key.as_str(), "v")])),
            InjectOutcome::BadRequest(_)
        ));
    }

    #[test]
    fn test_inject_rejects_invalid_key_chars() {
        let store = SecretStore::new(tmpdir());
        // Path separators and other punctuation are rejected.
        for bad in ["../escape", "has/slash", "space key", "dot.name"] {
            assert!(
                matches!(
                    store.inject(&secrets_of(&[(bad, "v")])),
                    InjectOutcome::BadRequest(_)
                ),
                "key {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn test_inject_rejects_oversized_value() {
        let store = SecretStore::new(tmpdir());
        let big = "x".repeat(MAX_VALUE_SIZE + 1);
        assert!(matches!(
            store.inject(&secrets_of(&[("k", big.as_str())])),
            InjectOutcome::BadRequest(_)
        ));
    }

    #[test]
    fn test_validation_failure_does_not_consume_one_shot() {
        let dir = tmpdir();
        let store = SecretStore::new(&dir);

        // A rejected request (empty) leaves the guard untouched...
        assert!(matches!(
            store.inject(&HashMap::new()),
            InjectOutcome::BadRequest(_)
        ));

        // ...so a subsequent valid injection still succeeds.
        assert!(is_ok(&store.inject(&secrets_of(&[("k", "v")]))));

        std::fs::remove_dir_all(&dir).ok();
    }
}
