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

/// A live journal follow behind StreamLogs: a blocking entry pump. `None`
/// means the stream ended (the subprocess exited or was stopped).
pub trait LogFollowReader: Send {
    fn next_entry(&mut self) -> Option<LogEntry>;
}

/// Stops a follow from another thread (kills the subprocess), unblocking a
/// concurrent `next_entry`. Called when the gRPC client drops the stream.
pub trait LogFollowStopper: Send + Sync {
    fn stop(&self);
}

/// A running follow: the blocking reader plus its stop handle.
pub type LogFollow = (
    Box<dyn LogFollowReader>,
    std::sync::Arc<dyn LogFollowStopper>,
);

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

    /// Follow the journal live (StreamLogs): the LAST `last_lines` matching
    /// entries first (0 = only new lines from now), then every new entry as
    /// it lands, until the stopper fires. The single subprocess makes the
    /// history-to-live transition gap-free.
    fn follow(
        &self,
        stdout_id: &str,
        stderr_id: &str,
        last_lines: u32,
    ) -> Result<LogFollow, String>;
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

    fn follow(
        &self,
        stdout_id: &str,
        stderr_id: &str,
        last_lines: u32,
    ) -> Result<LogFollow, String> {
        // Same flags as read_history plus --follow; --lines bounds the
        // history replay at the source (journalctl -f alone would default
        // to the last 10 lines, so the bound is always explicit).
        let child = Command::new("journalctl")
            .arg("--output=json")
            .arg("--all")
            .arg("--no-pager")
            .arg("--quiet")
            .arg("--follow")
            .arg(format!("--lines={last_lines}"))
            .arg(format!("SYSLOG_IDENTIFIER={stdout_id}"))
            .arg(format!("SYSLOG_IDENTIFIER={stderr_id}"))
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|error| format!("failed to run journalctl --follow: {error}"))?;
        follow_child(child, stdout_id)
    }
}

/// Wrap a spawned journalctl-shaped child (stdout piped) into the follow
/// reader/stopper pair. Split out of `follow` so the kill-and-reap contract
/// is testable against a real child process.
fn follow_child(mut child: std::process::Child, stdout_id: &str) -> Result<LogFollow, String> {
    use std::io::BufRead;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "journalctl --follow has no stdout".to_string())?;
    let child = std::sync::Arc::new(std::sync::Mutex::new(child));
    let reader = JournalctlFollowReader {
        child: child.clone(),
        lines: std::io::BufReader::new(stdout).lines(),
        stdout_id: stdout_id.to_string(),
    };
    Ok((Box::new(reader), std::sync::Arc::new(KillChild(child))))
}

struct JournalctlFollowReader {
    child: std::sync::Arc<std::sync::Mutex<std::process::Child>>,
    lines: std::io::Lines<std::io::BufReader<std::process::ChildStdout>>,
    stdout_id: String,
}

impl LogFollowReader for JournalctlFollowReader {
    fn next_entry(&mut self) -> Option<LogEntry> {
        for line in self.lines.by_ref() {
            let Ok(line) = line else { break };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match parse_journal_line(line, &self.stdout_id) {
                Some(entry) => return Some(entry),
                None => tracing::warn!(line, "skipping unparseable journal entry"),
            }
        }
        // EOF (journalctl exited or was stopped): reap the child.
        let _ = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .wait();
        None
    }
}

struct KillChild(std::sync::Arc<std::sync::Mutex<std::process::Child>>);

impl LogFollowStopper for KillChild {
    fn stop(&self) {
        // Kill AND reap: the pump can exit without another next_entry call
        // (the client dropped mid-send), so the EOF-path wait alone would
        // leave a zombie journalctl behind. Both calls tolerate a child
        // already gone; wait after kill returns as soon as the process
        // exits.
        let mut child = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = child.kill();
        let _ = child.wait();
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

    fn follow(
        &self,
        stdout_id: &str,
        stderr_id: &str,
        last_lines: u32,
    ) -> Result<LogFollow, String> {
        // The fake replays the bounded history and then ends the stream
        // (no live phase to wait on in hermetic tests).
        let entries = self.read_history(stdout_id, stderr_id, Some(last_lines))?;
        struct StaticFollow(std::vec::IntoIter<LogEntry>);
        impl LogFollowReader for StaticFollow {
            fn next_entry(&mut self) -> Option<LogEntry> {
                self.0.next()
            }
        }
        struct NoopStopper;
        impl LogFollowStopper for NoopStopper {
            fn stop(&self) {}
        }
        Ok((
            Box::new(StaticFollow(entries.into_iter())),
            std::sync::Arc::new(NoopStopper),
        ))
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
    fn stopping_a_follow_kills_and_reaps_the_child() {
        // A real child standing in for journalctl --follow: `sleep 30`
        // keeps its stdout pipe open and produces nothing, exactly like a
        // follow with no new entries. stop() must kill AND reap it: a
        // zombie keeps the pid alive in state Z.
        let child = std::process::Command::new("sleep")
            .arg("30")
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let (mut reader, stopper) = follow_child(child, STDOUT_ID).unwrap();
        // The pump half: blocked in next_entry until the child dies.
        let pump = std::thread::spawn(move || while reader.next_entry().is_some() {});

        stopper.stop();
        // stop() waits synchronously: by now the child must be fully
        // reaped, not a zombie. (The pid could in principle be recycled,
        // which the state check tolerates.)
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            let state = stat
                .rsplit(')')
                .next()
                .unwrap_or("")
                .split_whitespace()
                .next()
                .unwrap_or("");
            assert_ne!(state, "Z", "the killed follow child was never reaped");
        }
        pump.join().unwrap();
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
