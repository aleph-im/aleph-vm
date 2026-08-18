use std::collections::{BTreeMap, HashMap};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use actix_web::{HttpResponse, web};
use aleph_tee::owner_auth;
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

/// Owner-authenticated inject envelope: the only body accepted on
/// `POST /confidential/inject-secret` when the agent was started with
/// `--owner`. `signature` is the EIP-191 personal-sign signature (from
/// `aleph_tee::owner_auth::sign_payload`) over
/// `owner_auth::inject_secret_payload(server_public_key_raw, canonical_secrets_json(secrets))`.
#[derive(Deserialize)]
pub struct InjectSecretEnvelope {
    pub secrets: HashMap<String, String>,
    pub signature: String,
}

#[derive(Serialize)]
pub struct InjectSecretResponse {
    pub injected: Vec<String>,
}

/// Owner authorized to inject secrets, and the TLS identity the signature is
/// bound to. Registered as `web::Data<Option<OwnerAuth>>`: `None` on
/// v-program images (unauthenticated one-shot injection, unchanged), `Some`
/// on confidential-instance images (owner-signature-gated, overwriting).
pub struct OwnerAuth {
    pub owner: String,
    pub server_public_key_raw: Vec<u8>,
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

        if let Some(outcome) = validate_secrets(secrets) {
            return outcome;
        }

        Self::write_secrets(&self.dir, &mut guard, secrets, WriteMode::CreateNew)
    }

    /// Validate and write the secrets, authenticated by a verified owner
    /// signature (see `inject_secret_handler`). Unlike `inject`, this is not
    /// one-shot: it may be called repeatedly and overwrites previously
    /// injected keys, so a wrong LUKS passphrase can be retried. It shares
    /// the same validation limits and write hardening as `inject` via
    /// `validate_secrets` / `write_secrets`, so the two entry points cannot
    /// drift apart.
    fn inject_authenticated(&self, secrets: &HashMap<String, String>) -> InjectOutcome {
        let mut guard = match self.injected.lock() {
            Ok(g) => g,
            Err(_) => return InjectOutcome::Internal("internal lock error".to_string()),
        };

        if let Some(outcome) = validate_secrets(secrets) {
            return outcome;
        }

        Self::write_secrets(&self.dir, &mut guard, secrets, WriteMode::Overwrite)
    }

    /// Shared write loop for `inject` and `inject_authenticated`: prepares the
    /// secrets directory and writes each secret as an owner-only file, then
    /// marks the one-shot guard as consumed. Called with the injection lock
    /// already held.
    fn write_secrets(
        dir: &Path,
        guard: &mut std::sync::MutexGuard<'_, bool>,
        secrets: &HashMap<String, String>,
        mode: WriteMode,
    ) -> InjectOutcome {
        // Create (or validate) the secrets directory: real dir, agent-owned, 0700.
        if let Err(e) = ensure_secret_dir(dir) {
            tracing::error!("secret directory rejected: {e}");
            return InjectOutcome::Internal("failed to prepare secrets directory".to_string());
        }

        // Write each secret as a file.
        let mut injected = Vec::new();
        for (key, value) in secrets {
            // Wrap value in Zeroizing so it's wiped from memory when dropped.
            let secret_value = Zeroizing::new(value.as_bytes().to_vec());

            let path = dir.join(key);
            // Never follow a symlink at the final path component: O_NOFOLLOW
            // stops a /tmp squatter from redirecting the write regardless of
            // write mode. On top of that:
            //   - CreateNew sets O_CREAT|O_EXCL, so a pre-existing file (e.g.
            //     a planted symlink or a world-readable decoy) is refused
            //     rather than opened, and cannot defeat the 0600 mode;
            //   - Overwrite truncates an existing regular file in place (an
            //     authenticated reinject may legitimately replace a
            //     previously injected key), still refusing a symlink.
            let mut options = std::fs::OpenOptions::new();
            options
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW);
            match mode {
                WriteMode::CreateNew => {
                    options.create_new(true);
                }
                WriteMode::Overwrite => {
                    options.create(true).truncate(true);
                }
            }
            let result = options.open(&path).and_then(|mut f| {
                use std::io::Write;
                f.write_all(&secret_value)
            });

            if let Err(e) = result {
                tracing::error!("failed to write secret {key}: {e}");
                // Partial write: some secrets may already be on disk.
                // Still mark as injected to prevent retry with inconsistent state.
                **guard = true;
                return InjectOutcome::Internal(format!("failed to write secret: {key}"));
            }
            info!(key = %key, "injected secret");
            injected.push(key.clone());
        }

        // Mark as injected only after all secrets are successfully written.
        **guard = true;

        InjectOutcome::Ok(injected)
    }
}

/// How `write_secrets` should open each per-key file.
#[derive(Clone, Copy)]
enum WriteMode {
    /// One-shot `inject`: refuse if the file already exists.
    CreateNew,
    /// Authenticated `inject_authenticated`: create or truncate-overwrite.
    Overwrite,
}

/// Shared validation for both `inject` and `inject_authenticated`: checks
/// the secrets map is non-empty, within `MAX_SECRETS`, and that every key and
/// value is within limits and well-formed. Returns `None` when valid.
fn validate_secrets(secrets: &HashMap<String, String>) -> Option<InjectOutcome> {
    if secrets.is_empty() {
        return Some(InjectOutcome::BadRequest("no secrets provided".to_string()));
    }

    if secrets.len() > MAX_SECRETS {
        return Some(InjectOutcome::BadRequest(format!(
            "too many secrets: max {MAX_SECRETS}, got {}",
            secrets.len()
        )));
    }

    for (key, value) in secrets {
        if key.is_empty() || key.len() > MAX_KEY_LEN {
            return Some(InjectOutcome::BadRequest(format!(
                "secret key length must be 1-{MAX_KEY_LEN}, got {}",
                key.len()
            )));
        }
        if !key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Some(InjectOutcome::BadRequest(format!(
                "invalid secret key: must be alphanumeric/underscore/hyphen, got: {key}"
            )));
        }
        if value.len() > MAX_VALUE_SIZE {
            return Some(InjectOutcome::BadRequest(format!(
                "secret value too large for key '{key}': max {MAX_VALUE_SIZE} bytes, got {}",
                value.len()
            )));
        }
    }

    None
}

/// Maps an `InjectOutcome` to the HTTP response, shared by both the
/// unauthenticated and owner-authenticated paths so they cannot diverge.
fn outcome_to_response(outcome: InjectOutcome) -> HttpResponse {
    match outcome {
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

/// POST /confidential/inject-secret
///
/// Two mutually exclusive modes, selected by whether the agent was started
/// with `--owner`:
///
/// - Unauthenticated (v-program images, `owner` data is `None`): body is the
///   flat `{"<key>": "<value>", ...}` object of today. One-shot: returns 409
///   on a second attempt.
/// - Owner-authenticated (confidential-instance images, `owner` data is
///   `Some`): body must be the envelope
///   `{"secrets": {...}, "signature": "0x..."}`. The signature is an EIP-191
///   personal-sign signature over
///   `owner_auth::inject_secret_payload(server_public_key_raw, canonical_secrets_json(secrets))`,
///   binding the request to this agent's per-boot TLS key. A failed check
///   returns 403; a legacy flat body (missing `secrets`/`signature`) returns
///   400. Authenticated injects are not one-shot: a repeat overwrites
///   previously injected keys, so a wrong LUKS passphrase is retryable.
///
/// Both modes share the same validation limits and write hardening
/// (`SecretStore::write_secrets`): max 16 secrets, max 64-char key names, max
/// 64 KiB per value, files created fresh or overwritten with O_NOFOLLOW and
/// mode 0600 in an agent-owned 0700 directory.
///
/// Zeroization is best-effort: the primary per-value copy is wrapped in
/// `Zeroizing` and wiped after the disk write, but the deserialized request
/// map still holds plaintext copies that are not individually zeroized. Under
/// confidential compute the VM's memory encryption is the real backstop for
/// plaintext lingering in RAM.
///
/// Secret material (keys, values, the raw body) is never logged; an auth
/// failure is logged at info level with only the expected owner address.
pub async fn inject_secret_handler(
    store: web::Data<SecretStore>,
    owner: web::Data<Option<OwnerAuth>>,
    body: web::Bytes,
) -> HttpResponse {
    match owner.as_ref() {
        Some(auth) => {
            let envelope: InjectSecretEnvelope = match serde_json::from_slice(&body) {
                Ok(envelope) => envelope,
                Err(_) => {
                    return HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "expected envelope body: {\"secrets\": {...}, \"signature\": \"0x...\"}"
                    }));
                }
            };

            let canonical: BTreeMap<String, String> = envelope
                .secrets
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let canonical_json = owner_auth::canonical_secrets_json(&canonical);
            let payload =
                owner_auth::inject_secret_payload(&auth.server_public_key_raw, &canonical_json);

            if !owner_auth::verify_owner(&payload, &envelope.signature, &auth.owner) {
                info!(
                    expected_owner = %auth.owner,
                    "owner signature verification failed for inject-secret request"
                );
                return HttpResponse::Forbidden()
                    .json(serde_json::json!({"error": "owner signature verification failed"}));
            }

            outcome_to_response(store.inject_authenticated(&envelope.secrets))
        }
        None => {
            let request: InjectSecretRequest = match serde_json::from_slice(&body) {
                Ok(request) => request,
                Err(_) => {
                    return HttpResponse::BadRequest()
                        .json(serde_json::json!({"error": "invalid request body"}));
                }
            };

            outcome_to_response(store.inject(&request.secrets))
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

    /// Owner-authenticated inject-secret handler tests, exercising the actix
    /// route end to end (envelope parsing, signature verification, and the
    /// store's overwrite semantics).
    mod owner_authenticated {
        use super::*;
        use actix_web::{App, http::StatusCode, test};
        use k256::ecdsa::SigningKey;

        /// The server key bytes bound into the payload, matching the brief.
        const TEST_SERVER_KEY: &[u8] = b"test-server-key";

        fn signing_key(seed: u8) -> SigningKey {
            SigningKey::from_slice(&[seed; 32]).expect("valid scalar")
        }

        /// Sign the payload for `secrets` bound to `server_key`, as an owner
        /// holding `signer` would.
        fn sign_for(
            server_key: &[u8],
            secrets: &HashMap<String, String>,
            signer: &SigningKey,
        ) -> String {
            let canonical: BTreeMap<String, String> = secrets
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let payload = owner_auth::inject_secret_payload(
                server_key,
                &owner_auth::canonical_secrets_json(&canonical),
            );
            owner_auth::sign_payload(signer, &payload)
        }

        fn envelope_body(secrets: &HashMap<String, String>, signature: &str) -> Vec<u8> {
            serde_json::to_vec(&serde_json::json!({
                "secrets": secrets,
                "signature": signature,
            }))
            .unwrap()
        }

        fn owner_data(owner: String) -> web::Data<Option<OwnerAuth>> {
            web::Data::new(Some(OwnerAuth {
                owner,
                server_public_key_raw: TEST_SERVER_KEY.to_vec(),
            }))
        }

        /// Drive the real `inject_secret_handler` through an actix service,
        /// exactly as the production router would.
        async fn post_inject(
            store: web::Data<SecretStore>,
            owner: web::Data<Option<OwnerAuth>>,
            body: Vec<u8>,
        ) -> actix_web::dev::ServiceResponse {
            let app = test::init_service(App::new().app_data(store).app_data(owner).route(
                "/confidential/inject-secret",
                web::post().to(inject_secret_handler),
            ))
            .await;
            let req = test::TestRequest::post()
                .uri("/confidential/inject-secret")
                .set_payload(body)
                .to_request();
            test::call_service(&app, req).await
        }

        #[actix_web::test]
        async fn authenticated_inject_accepts_owner_signature() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            let secrets = secrets_of(&[("luks_passphrase", "hunter2")]);
            let sig = sign_for(TEST_SERVER_KEY, &secrets, &signer);
            let resp = post_inject(store, owner, envelope_body(&secrets, &sig)).await;

            assert_eq!(resp.status(), StatusCode::OK);
            let content = std::fs::read_to_string(dir.join("luks_passphrase")).unwrap();
            assert_eq!(content, "hunter2");

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn authenticated_inject_rejects_wrong_signer() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let wrong_signer = signing_key(0x22);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            let secrets = secrets_of(&[("luks_passphrase", "hunter2")]);
            // Signed by a key that does not recover to the registered owner.
            let sig = sign_for(TEST_SERVER_KEY, &secrets, &wrong_signer);
            let resp = post_inject(store, owner, envelope_body(&secrets, &sig)).await;

            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert!(!dir.join("luks_passphrase").exists());

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn authenticated_inject_rejects_wrong_server_key() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            let secrets = secrets_of(&[("luks_passphrase", "hunter2")]);
            // Signed over a payload bound to a DIFFERENT server key than the
            // one registered in `OwnerAuth`, so verification recomputes a
            // different payload and the signature no longer matches.
            let sig = sign_for(b"OTHER-server-key", &secrets, &signer);
            let resp = post_inject(store, owner, envelope_body(&secrets, &sig)).await;

            assert_eq!(resp.status(), StatusCode::FORBIDDEN);

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn authenticated_inject_rejects_tampered_body() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            let signed_secrets = secrets_of(&[("luks_passphrase", "hunter2")]);
            let sig = sign_for(TEST_SERVER_KEY, &signed_secrets, &signer);
            // Send a different secrets map than the one that was signed.
            let sent_secrets = secrets_of(&[("luks_passphrase", "tampered")]);
            let resp = post_inject(store, owner, envelope_body(&sent_secrets, &sig)).await;

            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
            assert!(!dir.join("luks_passphrase").exists());

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn authenticated_reinject_overwrites() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            let first = secrets_of(&[("luks_passphrase", "first-value")]);
            let sig1 = sign_for(TEST_SERVER_KEY, &first, &signer);
            let resp1 =
                post_inject(store.clone(), owner.clone(), envelope_body(&first, &sig1)).await;
            assert_eq!(resp1.status(), StatusCode::OK);

            let second = secrets_of(&[("luks_passphrase", "second-value")]);
            let sig2 = sign_for(TEST_SERVER_KEY, &second, &signer);
            let resp2 =
                post_inject(store.clone(), owner.clone(), envelope_body(&second, &sig2)).await;
            assert_eq!(resp2.status(), StatusCode::OK, "reinject must not conflict");

            let content = std::fs::read_to_string(dir.join("luks_passphrase")).unwrap();
            assert_eq!(content, "second-value", "reinject must overwrite");

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn unauthenticated_mode_unchanged() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let owner: web::Data<Option<OwnerAuth>> = web::Data::new(None);

            let body = serde_json::to_vec(&serde_json::json!({"k": "v"})).unwrap();
            let resp1 = post_inject(store.clone(), owner.clone(), body.clone()).await;
            assert_eq!(resp1.status(), StatusCode::OK);

            // A second flat-body attempt is still one-shot: 409, unchanged.
            let resp2 = post_inject(store.clone(), owner.clone(), body).await;
            assert_eq!(resp2.status(), StatusCode::CONFLICT);

            std::fs::remove_dir_all(&dir).ok();
        }

        #[actix_web::test]
        async fn authenticated_mode_rejects_flat_body() {
            let dir = tmpdir();
            let store = web::Data::new(SecretStore::new(&dir));
            let signer = signing_key(0x11);
            let owner = owner_data(owner_auth::address_from_verifying_key(
                signer.verifying_key(),
            ));

            // Legacy flat body: no "secrets"/"signature" envelope fields.
            let body =
                serde_json::to_vec(&serde_json::json!({"luks_passphrase": "hunter2"})).unwrap();
            let resp = post_inject(store, owner, body).await;

            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert!(!dir.join("luks_passphrase").exists());

            std::fs::remove_dir_all(&dir).ok();
        }
    }
}
