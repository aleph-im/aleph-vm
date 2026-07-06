//! Journald history for VM controllers, the engine behind GetLogs.
//!
//! Python parity: `LocalSupervisor._history_chunks` reads the journal
//! through the sd-journal binding with two `SYSLOG_IDENTIFIER` matches
//! (`vm-{hash}-stdout` and `vm-{hash}-stderr`), from the head, in journal
//! order; each entry becomes a LogChunk with a microsecond-precision
//! timestamp (`whole seconds * 1e9 + microseconds * 1000`, i.e. the entry's
//! `__REALTIME_TIMESTAMP` in microseconds times 1000).
//!
//! Implementation choice (design doc section 11 left it open): a
//! `journalctl -o json` subprocess rather than a native sd-journal binding.
//! Rationale: no C library dependency in the daemon (the binary stays
//! self-contained and buildable in minimal containers), and the daemon sees
//! exactly what operators see when they debug with journalctl, so any
//! filtering discrepancy is reproducible with the standard tool. Matches on
//! the same field are OR-ed by journalctl, exactly like consecutive
//! `add_match` calls on one sd-journal reader. Recorded in
//! docs/plans/rust-port-divergences.md.
//!
//! Memory bound: the caller passes `last_lines` (journalctl `-n`) whenever
//! it only needs the tail, so the subprocess output is bounded at the
//! source instead of buffering the full history; the GetLogs handler adds a
//! Rust-only server cap for "unlimited" requests (ledger entry 16 in
//! docs/plans/rust-port-divergences.md).
//!
//! The trait seam keeps cargo tests hermetic: production uses
//! [`JournalctlLogSource`], tests use [`StaticLogSource`].

use std::process::Command;

/// Which stream a journal entry came from (by SYSLOG_IDENTIFIER match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// One journal entry mapped to the boundary vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// `__REALTIME_TIMESTAMP`, microseconds since the epoch.
    pub timestamp_us: u64,
    pub message: String,
    pub source: LogStream,
}

/// Where GetLogs reads VM history from. Blocking (subprocess or file I/O);
/// handlers call it through `spawn_blocking`.
pub trait LogSource: Send + Sync {
    /// Journal entries matching either identifier, oldest first. When
    /// `last_lines` is set, only the LAST n matching entries are read
    /// (journalctl `-n`), which bounds the subprocess output; `None` reads
    /// everything, for head slices where `-n` would keep the wrong end.
    fn read_history(
        &self,
        stdout_id: &str,
        stderr_id: &str,
        last_lines: Option<u32>,
    ) -> Result<Vec<LogEntry>, String>;
}

/// Production implementation: one `journalctl -o json` run per call.
pub struct JournalctlLogSource;

impl LogSource for JournalctlLogSource {
    fn read_history(
        &self,
        stdout_id: &str,
        stderr_id: &str,
        last_lines: Option<u32>,
    ) -> Result<Vec<LogEntry>, String> {
        // --all: emit MESSAGE for unprintable/binary payloads too (as byte
        // arrays), which the sd-journal reader also yields (as bytes that
        // Python decodes with errors="replace").
        let mut command = Command::new("journalctl");
        command
            .arg("--output=json")
            .arg("--all")
            .arg("--no-pager")
            .arg("--quiet");
        if let Some(lines) = last_lines {
            // Bound the buffered output at the source: -n keeps the last n
            // entries in normal journal order, exactly the tail slice.
            command.arg(format!("--lines={lines}"));
        }
        let output = command
            .arg(format!("SYSLOG_IDENTIFIER={stdout_id}"))
            .arg(format!("SYSLOG_IDENTIFIER={stderr_id}"))
            .output()
            .map_err(|error| format!("failed to run journalctl: {error}"))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "journalctl failed ({}): {}",
                output.status,
                stderr.trim()
            ));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_journal_json(&stdout, stdout_id))
    }
}

/// Parse `journalctl -o json` output (one JSON object per line) into
/// entries. Lines that are not valid entries are skipped with a warning:
/// one corrupt journal line must not take the whole history down.
pub fn parse_journal_json(output: &str, stdout_id: &str) -> Vec<LogEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_journal_line(line, stdout_id) {
            Some(entry) => entries.push(entry),
            None => tracing::warn!(line, "skipping unparseable journal entry"),
        }
    }
    entries
}

fn parse_journal_line(line: &str, stdout_id: &str) -> Option<LogEntry> {
    let value: serde_json::Value = serde_json::from_str(line).ok()?;
    let timestamp_us: u64 = match value.get("__REALTIME_TIMESTAMP")? {
        serde_json::Value::String(text) => text.parse().ok()?,
        serde_json::Value::Number(number) => number.as_u64()?,
        _ => return None,
    };
    let message = journal_field_string(value.get("MESSAGE")?)?;
    // Python: STDOUT when the identifier equals the stdout id, STDERR
    // otherwise (the reader only matches the two identifiers).
    let source = if value.get("SYSLOG_IDENTIFIER").and_then(|id| id.as_str()) == Some(stdout_id) {
        LogStream::Stdout
    } else {
        LogStream::Stderr
    };
    Some(LogEntry {
        timestamp_us,
        message,
        source,
    })
}

/// A journal field is a string, or an array of bytes for non-UTF8 payloads
/// (decoded lossily, like the Python `message.decode("utf-8",
/// errors="replace")`).
fn journal_field_string(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Array(bytes) => {
            let raw: Vec<u8> = bytes
                .iter()
                .map(|byte| byte.as_u64().map(|value| value as u8))
                .collect::<Option<_>>()?;
            Some(String::from_utf8_lossy(&raw).into_owned())
        }
        _ => None,
    }
}

/// In-memory fake for tests: a fixed entry list, whatever the identifiers.
#[derive(Debug, Default, Clone)]
pub struct StaticLogSource {
    pub entries: Vec<LogEntry>,
}

impl StaticLogSource {
    pub fn new(entries: Vec<LogEntry>) -> Self {
        Self { entries }
    }
}

impl LogSource for StaticLogSource {
    fn read_history(
        &self,
        _stdout_id: &str,
        _stderr_id: &str,
        last_lines: Option<u32>,
    ) -> Result<Vec<LogEntry>, String> {
        let mut entries = self.entries.clone();
        // Emulate journalctl -n: keep the LAST n entries, journal order.
        if let Some(lines) = last_lines {
            let lines = lines as usize;
            if entries.len() > lines {
                entries.drain(..entries.len() - lines);
            }
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STDOUT_ID: &str = "vm-aa-stdout";

    #[test]
    fn parses_string_messages_and_identifiers() {
        let output = concat!(
            r#"{"__REALTIME_TIMESTAMP": "1751790000123456", "MESSAGE": "booted", "SYSLOG_IDENTIFIER": "vm-aa-stdout"}"#,
            "\n",
            r#"{"__REALTIME_TIMESTAMP": "1751790001000000", "MESSAGE": "oops", "SYSLOG_IDENTIFIER": "vm-aa-stderr"}"#,
            "\n",
        );
        let entries = parse_journal_json(output, STDOUT_ID);
        assert_eq!(
            entries,
            vec![
                LogEntry {
                    timestamp_us: 1_751_790_000_123_456,
                    message: "booted".to_string(),
                    source: LogStream::Stdout,
                },
                LogEntry {
                    timestamp_us: 1_751_790_001_000_000,
                    message: "oops".to_string(),
                    source: LogStream::Stderr,
                },
            ]
        );
    }

    #[test]
    fn byte_array_messages_are_decoded_lossily() {
        // journalctl --all emits non-UTF8 MESSAGE payloads as byte arrays;
        // 0xFF is invalid UTF-8 and becomes U+FFFD, like Python's
        // errors="replace".
        let output = r#"{"__REALTIME_TIMESTAMP": "1", "MESSAGE": [104, 105, 255], "SYSLOG_IDENTIFIER": "vm-aa-stdout"}"#;
        let entries = parse_journal_json(output, STDOUT_ID);
        assert_eq!(entries[0].message, "hi\u{FFFD}");
    }

    #[test]
    fn corrupt_lines_are_skipped_not_fatal() {
        let output = concat!(
            "not json\n",
            r#"{"MESSAGE": "no timestamp"}"#,
            "\n",
            r#"{"__REALTIME_TIMESTAMP": "2", "MESSAGE": "ok", "SYSLOG_IDENTIFIER": "vm-aa-stdout"}"#,
            "\n",
        );
        let entries = parse_journal_json(output, STDOUT_ID);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "ok");
    }
}
