//! systemd journal stdout streams, the Rust counterpart of the Python
//! controller's `journal.stream(name)`.
//!
//! The Python `QemuVM.start()` wires qemu's stdout and stderr to
//! `systemd.journal.stream(identifier)`, which under the hood is libsystemd's
//! `sd_journal_stream_fd`: it connects a stream socket to the journal's
//! `/run/systemd/journal/stdout`, writes a fixed header naming the syslog
//! identifier, and hands back the fd. Everything written to that fd is logged
//! under the identifier (readable with `journalctl -t {identifier}`).
//!
//! This module reproduces that header protocol in pure Rust, so the QEMU
//! output lands under the same `vm-{hash}-stdout` / `vm-{hash}-stderr` tags a
//! rollback to the Python controller would use. If the journal socket is not
//! present (a dev box or container without systemd-journald), it falls back
//! to inheriting the controller's own stdout/stderr and logs a warning; the
//! VM still runs, its console output just goes wherever the controller's
//! streams point.

use std::io::Write;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::Stdio;

/// The well-known journald stdout stream socket.
const JOURNAL_STDOUT_SOCKET: &str = "/run/systemd/journal/stdout";

/// LOG_INFO, the priority `systemd.journal.stream` defaults to.
const LOG_INFO: i32 = 6;

/// Build a `Stdio` that writes to the systemd journal under `identifier`.
/// Falls back to inheriting the parent stream when the journal socket is
/// unavailable, matching the "still run the VM" intent of the Python path.
pub fn stream(identifier: &str) -> Stdio {
    match connect_journal_stream(identifier) {
        Ok(fd) => Stdio::from(fd),
        Err(error) => {
            tracing::warn!(
                identifier,
                %error,
                "cannot open a systemd journal stream, inheriting stdio instead"
            );
            Stdio::inherit()
        }
    }
}

/// Connect to `/run/systemd/journal/stdout` and send the stream header
/// (`sd_journal_stream_fd`), returning the fd qemu should write to.
///
/// The header is seven newline-terminated lines the journald stdout protocol
/// consumes before switching the connection to log-payload mode:
///   1. syslog identifier
///   2. unit id (empty)
///   3. priority
///   4. level-prefix flag
///   5. forward-to-syslog flag
///   6. forward-to-kmsg flag
///   7. forward-to-console flag
fn connect_journal_stream(identifier: &str) -> std::io::Result<OwnedFd> {
    let mut stream = UnixStream::connect(JOURNAL_STDOUT_SOCKET)?;
    let header = format!("{identifier}\n\n{LOG_INFO}\n0\n0\n0\n0\n");
    stream.write_all(header.as_bytes())?;
    stream.flush()?;
    Ok(OwnedFd::from(stream))
}
