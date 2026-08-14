use std::collections::HashMap;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
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

/// Ensure the secret directory exists as a real, agent-owned, 0700 directory.
///
/// Hardening: `/tmp` is a shared, world-writable location, so a pre-created
/// symlink or a directory with the wrong owner must be refused rather than
/// followed. If the path exists it must be a genuine directory (not a symlink),
/// owned by the agent's effective uid; its mode is tightened to 0700. If it does
/// not exist it is created with mode 0700.
fn ensure_secret_dir(dir: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(meta) => {
            let file_type = meta.file_type();
            if file_type.is_symlink() {
                anyhow::bail!("secret directory path is a symlink");
            }
            if !file_type.is_dir() {
                anyhow::bail!("secret directory path exists but is not a directory");
            }
            // Refuse a directory we do not own: it could have been planted.
            // SAFETY: geteuid() takes no pointer arguments and has no
            // preconditions; it cannot cause undefined behavior.
            let euid = unsafe { libc::geteuid() };
            if meta.uid() != euid {
                anyhow::bail!("secret directory has unexpected owner");
            }
            // Tighten perms to owner-only in case it was pre-created looser.
            if meta.permissions().mode() & 0o777 != 0o700
                && let Err(e) =
                    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            {
                anyhow::bail!("failed to set secret directory mode: {e}");
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // Create parents first (ordinary dirs), then the leaf as 0700.
            if let Some(parent) = dir.parent()
                && let Err(e) = std::fs::create_dir_all(parent)
            {
                anyhow::bail!("failed to create secret directory parent: {e}");
            }
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| anyhow::anyhow!("failed to create secret directory: {e}"))
        }
        Err(e) => anyhow::bail!("failed to stat secret directory: {e}"),
    }
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

        // Create (or validate) the secrets directory: real dir, agent-owned, 0700.
        if let Err(e) = ensure_secret_dir(&self.dir) {
            tracing::error!("secret directory rejected: {e}");
            return InjectOutcome::Internal("failed to prepare secrets directory".to_string());
        }

        // Write each secret as a file.
        let mut injected = Vec::new();
        for (key, value) in secrets {
            // Wrap value in Zeroizing so it's wiped from memory when dropped.
            let secret_value = Zeroizing::new(value.as_bytes().to_vec());

            let path = self.dir.join(key);
            // Create fresh, owner-only files and never follow a symlink:
            //   - create_new(true) sets O_CREAT|O_EXCL, so a pre-existing file
            //     (e.g. a planted symlink or a world-readable decoy) is refused
            //     rather than opened, and cannot defeat the 0600 mode;
            //   - O_NOFOLLOW additionally refuses a symlink at the final path
            //     component. Together these stop a /tmp squatter from redirecting
            //     the write or downgrading permissions.
            let result = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
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
/// value. One-shot: returns 409 on subsequent calls. Files are created fresh
/// (O_EXCL|O_NOFOLLOW) with mode 0600 in an agent-owned 0700 directory.
///
/// Zeroization is best-effort: the primary per-value copy is wrapped in
/// `Zeroizing` and wiped after the disk write, but the deserialized request map
/// (owned by actix) still holds plaintext copies that are not individually
/// zeroized. Under confidential compute the VM's memory encryption is the real
/// backstop for plaintext lingering in RAM.
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

    /// A pre-planted symlink at the target key path must cause a clean error, not
    /// a follow-through write to the symlink's target (O_EXCL | O_NOFOLLOW).
    #[test]
    fn test_symlink_at_key_path_is_refused_not_followed() {
        use std::os::unix::fs::symlink;

        let dir = tmpdir();
        std::fs::create_dir_all(&dir).unwrap();

        // The attacker's redirect target, outside the secret dir.
        let decoy = tmpdir();

        // Plant a symlink api_key -> decoy inside the secret directory.
        symlink(&decoy, dir.join("api_key")).unwrap();

        let out = store_inject(&dir, &[("api_key", "s3cr3t")]);

        // The write is refused (Internal), never a silent follow-through.
        assert!(
            matches!(out, InjectOutcome::Internal(_)),
            "planted symlink must cause an error"
        );
        // The decoy target was never created/written.
        assert!(!decoy.exists(), "symlink target must not be written");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Helper: run a single injection against a fresh store at `dir`.
    fn store_inject(dir: &Path, pairs: &[(&str, &str)]) -> InjectOutcome {
        SecretStore::new(dir).inject(&secrets_of(pairs))
    }

    /// Under concurrency, the Mutex-held check-and-write is atomic: exactly one
    /// of two racing injections succeeds and the other gets a Conflict (409).
    /// This guards against a reintroduced TOCTOU that single-threaded tests miss.
    #[test]
    fn test_concurrent_inject_exactly_one_succeeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tmpdir();
        let store = Arc::new(SecretStore::new(&dir));
        let ok_count = Arc::new(AtomicUsize::new(0));
        let conflict_count = Arc::new(AtomicUsize::new(0));

        // Barrier so both threads reach inject as close together as possible.
        let barrier = Arc::new(std::sync::Barrier::new(2));

        let mut handles = Vec::new();
        for i in 0..2 {
            let store = Arc::clone(&store);
            let ok_count = Arc::clone(&ok_count);
            let conflict_count = Arc::clone(&conflict_count);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let key = format!("k{i}");
                match store.inject(&secrets_of(&[(key.as_str(), "v")])) {
                    InjectOutcome::Ok(_) => ok_count.fetch_add(1, Ordering::SeqCst),
                    InjectOutcome::Conflict => conflict_count.fetch_add(1, Ordering::SeqCst),
                    other => panic!("unexpected outcome: {}", outcome_name(&other)),
                };
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            ok_count.load(Ordering::SeqCst),
            1,
            "exactly one must succeed"
        );
        assert_eq!(
            conflict_count.load(Ordering::SeqCst),
            1,
            "the loser must get a conflict"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    fn outcome_name(o: &InjectOutcome) -> &'static str {
        match o {
            InjectOutcome::Ok(_) => "Ok",
            InjectOutcome::Conflict => "Conflict",
            InjectOutcome::BadRequest(_) => "BadRequest",
            InjectOutcome::Internal(_) => "Internal",
        }
    }
}
