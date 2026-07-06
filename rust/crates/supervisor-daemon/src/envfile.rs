//! `--env-file` support for dev runs.
//!
//! Under systemd the unit's `EnvironmentFile=` sources
//! /etc/aleph-vm/supervisor.env before the process starts; this module gives
//! `aleph-vm-supervisor --env-file ...` the same behavior for manual runs.
//! Variables already present in the process environment win over the file,
//! matching both systemd (Environment= after EnvironmentFile=) and
//! pydantic-settings (env beats dotenv) precedence.

use std::path::Path;

use crate::error::DaemonError;

/// Parse KEY=VALUE lines. Blank lines and `#` comments are skipped, an
/// optional `export ` prefix is tolerated, and surrounding single or double
/// quotes are stripped from values.
pub fn parse_env_file(content: &str) -> Vec<(String, String)> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (key, value) = line.split_once('=')?;
            let key = key.trim();
            if key.is_empty() {
                return None;
            }
            let value = value.trim();
            let value = strip_quotes(value);
            Some((key.to_string(), value.to_string()))
        })
        .collect()
}

fn strip_quotes(value: &str) -> &str {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// Source `path` into the process environment. Existing variables are not
/// overridden. Must be called before the tokio runtime spawns threads:
/// mutating the environment is only sound while the process is
/// single-threaded.
///
/// "Existing" is checked case-insensitively: config.rs reads ALEPH_VM_* keys
/// case-insensitively (pydantic-settings parity), so a lowercase-spelled
/// process variable already wins at read time and the file must not
/// introduce a competing spelling.
pub fn apply_env_file(path: &Path) -> Result<(), DaemonError> {
    let content = std::fs::read_to_string(path).map_err(|source| DaemonError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    for (key, value) in parse_env_file(&content) {
        if !env_key_exists_case_insensitive(&key) {
            // SAFETY: called from main() before the async runtime (and any
            // other thread) exists; see the function doc.
            unsafe { std::env::set_var(&key, &value) };
        }
    }
    Ok(())
}

/// Whether any spelling of `key` exists in the process environment,
/// compared uppercase-normalized like the config.rs EnvSlice.
fn env_key_exists_case_insensitive(key: &str) -> bool {
    let wanted = key.to_ascii_uppercase();
    std::env::vars_os().any(|(existing, _)| {
        existing
            .to_str()
            .is_some_and(|existing| existing.to_ascii_uppercase() == wanted)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_pairs_comments_and_blanks() {
        let parsed = parse_env_file(
            "# supervisor env\n\
             ALEPH_VM_EXECUTION_ROOT=/var/lib/aleph/vm\n\
             \n\
             ALEPH_VM_SUPERVISOR_IMPL=rust\n",
        );
        assert_eq!(
            parsed,
            vec![
                (
                    "ALEPH_VM_EXECUTION_ROOT".to_string(),
                    "/var/lib/aleph/vm".to_string()
                ),
                ("ALEPH_VM_SUPERVISOR_IMPL".to_string(), "rust".to_string()),
            ]
        );
    }

    #[test]
    fn strips_quotes_and_export_prefix() {
        let parsed = parse_env_file(
            "export ALEPH_VM_DOMAIN_NAME=\"example.org\"\n\
             ALEPH_VM_OWNER_ADDRESS='0xabc'\n",
        );
        assert_eq!(
            parsed,
            vec![
                (
                    "ALEPH_VM_DOMAIN_NAME".to_string(),
                    "example.org".to_string()
                ),
                ("ALEPH_VM_OWNER_ADDRESS".to_string(), "0xabc".to_string()),
            ]
        );
    }

    #[test]
    fn keeps_equals_signs_in_values_and_skips_malformed_lines() {
        let parsed = parse_env_file("KEY=a=b\nnot a pair\n=novalue\n");
        assert_eq!(parsed, vec![("KEY".to_string(), "a=b".to_string())]);
    }

    // The apply_env_file tests mutate the process environment, which is
    // shared between test threads: each test uses variable names unique to
    // itself so they cannot race one another.

    fn write_env_file(content: &str) -> tempfile::TempPath {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.into_temp_path()
    }

    #[test]
    fn existing_exact_case_variable_wins_over_the_file() {
        // SAFETY (all set_var calls below): test-only, with names no other
        // test or library code reads.
        unsafe { std::env::set_var("ALEPH_TEST_ENVFILE_EXACT", "from-env") };
        let path = write_env_file("ALEPH_TEST_ENVFILE_EXACT=from-file\n");
        apply_env_file(path.as_ref()).unwrap();
        assert_eq!(
            std::env::var("ALEPH_TEST_ENVFILE_EXACT").unwrap(),
            "from-env"
        );
    }

    #[test]
    fn existing_variable_with_a_different_case_wins_over_the_file() {
        // config.rs reads ALEPH_VM_* keys case-insensitively, so the
        // lowercase spelling already wins at read time; the file must not
        // introduce an uppercase competitor.
        unsafe { std::env::set_var("aleph_test_envfile_lower", "from-env") };
        let path = write_env_file("ALEPH_TEST_ENVFILE_LOWER=from-file\n");
        apply_env_file(path.as_ref()).unwrap();
        assert_eq!(std::env::var_os("ALEPH_TEST_ENVFILE_LOWER"), None);
        assert_eq!(
            std::env::var("aleph_test_envfile_lower").unwrap(),
            "from-env"
        );
    }

    #[test]
    fn absent_variable_is_set_from_the_file() {
        assert_eq!(std::env::var_os("ALEPH_TEST_ENVFILE_ABSENT"), None);
        let path = write_env_file("ALEPH_TEST_ENVFILE_ABSENT=from-file\n");
        apply_env_file(path.as_ref()).unwrap();
        assert_eq!(
            std::env::var("ALEPH_TEST_ENVFILE_ABSENT").unwrap(),
            "from-file"
        );
    }
}
