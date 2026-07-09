//! A minimal blocking QMP client for the graceful-stop escalation.
//!
//! `QemuVM.stop()` only ever issues two QMP commands, `system_powerdown` and
//! `quit`, via the Python `qmp` library. This client reproduces that: connect
//! (only if the socket exists, like `_get_qmpclient`), negotiate the
//! capabilities handshake, send the command and best-effort read its reply.
//! `quit` makes QEMU exit, so the socket may close before a reply arrives;
//! that is treated as success, not an error.
//!
//! Every command round-trip is bounded three ways so a wedged or chatty
//! monitor cannot hang the shutdown escalation or exhaust memory:
//!   - a TOTAL wall-clock deadline over handshake + command + reply
//!     ([`COMMAND_DEADLINE`]), independent of the per-read inactivity timeout;
//!   - a cap on the bytes of a single reply line ([`MAX_REPLY_LINE_BYTES`]),
//!     so a peer that streams bytes without a newline cannot grow the buffer;
//!   - a cap on the number of skipped async events ([`MAX_SKIPPED_EVENTS`]),
//!     so a monitor that emits POWERDOWN/RTC_CHANGE/BALLOON_CHANGE forever
//!     (never a `return`) cannot spin the event-skipping loop indefinitely.

use std::io::{BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// Total wall-clock budget for one command round-trip (handshake + command +
/// reply). A wedged monitor that keeps the socket open but never answers is
/// cut off here rather than parking the blocking-pool thread. The caller's
/// escalation (GRACEFUL_SHUTDOWN_TIMEOUT) is the outer, much larger, bound.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(5);

/// Per-read inactivity timeout: no single blocking read waits longer than this
/// (and never longer than the remaining wall-clock deadline).
const READ_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(10);

/// Cap on the bytes of a single reply line. A monitor that streams bytes
/// without ever sending a newline cannot grow the read buffer without bound.
const MAX_REPLY_LINE_BYTES: usize = 64 * 1024;

/// Cap on the number of asynchronous events skipped while waiting for the
/// command's `return`/`error`. A monitor that emits events forever is cut off.
const MAX_SKIPPED_EVENTS: usize = 1024;

/// Send one QMP command over the monitor socket. Returns Ok when the command
/// was sent (and, for non-`quit` commands, acknowledged); a missing socket is
/// Ok (the VM is already gone, like Python's `if not socket.exists(): return`).
pub fn send_command(qmp_socket_path: &str, command: &str) -> Result<(), String> {
    send_command_within(qmp_socket_path, command, COMMAND_DEADLINE)
}

/// [`send_command`] with an explicit total wall-clock budget (tests use a
/// short one so the deadline/bounds fire fast).
fn send_command_within(
    qmp_socket_path: &str,
    command: &str,
    budget: Duration,
) -> Result<(), String> {
    let path = Path::new(qmp_socket_path);
    if !path.exists() {
        return Ok(());
    }
    let deadline = Instant::now() + budget;

    let stream =
        UnixStream::connect(path).map_err(|error| format!("cannot connect to QMP: {error}"))?;
    stream
        .set_write_timeout(Some(READ_INACTIVITY_TIMEOUT))
        .map_err(|error| format!("cannot set the QMP write timeout: {error}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("cannot clone the QMP socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    // Greeting, then the qmp_capabilities handshake into command mode.
    read_line(&mut reader, deadline).map_err(|error| format!("no QMP greeting: {error}"))?;
    send(&mut writer, "qmp_capabilities")?;
    read_reply(&mut reader, "qmp_capabilities", deadline)?;

    send(&mut writer, command)?;
    // `quit` tells QEMU to exit; the reply may never arrive because the socket
    // closes first. A closed socket after issuing the command is success.
    match read_reply(&mut reader, command, deadline) {
        Ok(()) => Ok(()),
        Err(_) if command == "quit" => Ok(()),
        Err(error) => Err(error),
    }
}

fn send(writer: &mut UnixStream, command: &str) -> Result<(), String> {
    let request = format!("{{\"execute\": \"{command}\"}}\n");
    writer
        .write_all(request.as_bytes())
        .and_then(|_| writer.flush())
        .map_err(|error| format!("cannot send the QMP command {command}: {error}"))
}

/// Read reply lines until a `return`/`error` for the command, skipping any
/// asynchronous `event` messages (the `qmp` library's command loop). Bounded
/// by the wall-clock `deadline` and by [`MAX_SKIPPED_EVENTS`].
fn read_reply(
    reader: &mut BufReader<UnixStream>,
    command: &str,
    deadline: Instant,
) -> Result<(), String> {
    let mut skipped = 0usize;
    loop {
        let line = read_line(reader, deadline)?;
        let value: serde_json::Value = serde_json::from_str(line.trim())
            .map_err(|error| format!("invalid QMP response: {error}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("QMP error for {command}: {error}"));
        }
        if value.get("return").is_some() {
            return Ok(());
        }
        // An asynchronous event (or the greeting echo): keep reading, but do
        // not let a monitor that never returns spin here forever.
        skipped += 1;
        if skipped > MAX_SKIPPED_EVENTS {
            return Err(format!(
                "QMP monitor sent {skipped} events without a reply to {command}"
            ));
        }
    }
}

/// Read one newline-terminated line, enforcing the wall-clock `deadline` (no
/// single read blocks past the remaining budget) and the [`MAX_REPLY_LINE_BYTES`]
/// byte cap (a never-terminated line returns an Err instead of growing memory).
fn read_line(reader: &mut BufReader<UnixStream>, deadline: Instant) -> Result<String, String> {
    let mut buffer: Vec<u8> = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| "QMP command deadline exceeded".to_string())?;
        // A single read waits no longer than the remaining budget, so the
        // total round-trip cannot exceed the deadline.
        let read_timeout = remaining.min(READ_INACTIVITY_TIMEOUT);
        reader
            .get_ref()
            .set_read_timeout(Some(read_timeout))
            .map_err(|error| format!("cannot set the QMP read timeout: {error}"))?;

        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => return Err("QMP socket closed".to_string()),
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(String::from_utf8_lossy(&buffer).into_owned());
                }
                buffer.push(byte[0]);
                if buffer.len() > MAX_REPLY_LINE_BYTES {
                    return Err(format!(
                        "QMP reply line exceeded {MAX_REPLY_LINE_BYTES} bytes without a newline"
                    ));
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err("QMP read timed out".to_string());
            }
            Err(error) => return Err(format!("cannot read from the QMP socket: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn a_missing_socket_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let absent = dir.path().join("absent.sock");
        assert!(send_command(absent.to_str().unwrap(), "system_powerdown").is_ok());
    }

    #[test]
    fn it_handshakes_then_sends_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = seen.clone();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            // qmp_capabilities, then the command; ACK each.
            for _ in 0..2 {
                let mut line = String::new();
                std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
                recorder.lock().unwrap().push(line.trim().to_string());
                writer.write_all(b"{\"return\": {}}\n").unwrap();
            }
        });
        send_command(socket.to_str().unwrap(), "system_powerdown").unwrap();
        server.join().unwrap();
        let seen = seen.lock().unwrap();
        assert_eq!(seen[0], "{\"execute\": \"qmp_capabilities\"}");
        assert_eq!(seen[1], "{\"execute\": \"system_powerdown\"}");
    }

    #[test]
    fn it_skips_async_events_before_the_return() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            // ACK qmp_capabilities.
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            // Read the command, then emit a few events before the return.
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer
                .write_all(b"{\"event\": \"POWERDOWN\"}\n{\"event\": \"RTC_CHANGE\"}\n")
                .unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
        });
        send_command(socket.to_str().unwrap(), "system_powerdown").unwrap();
        server.join().unwrap();
    }

    #[test]
    fn quit_tolerates_a_closed_socket_after_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            // ACK qmp_capabilities, read `quit`, then drop the socket without
            // replying (QEMU exiting).
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
        });
        send_command(socket.to_str().unwrap(), "quit").unwrap();
        server.join().unwrap();
    }

    /// A monitor that streams async events forever and never a `return` must
    /// not hang the reader: the skipped-event cap cuts it off with an Err,
    /// well within the deadline.
    #[test]
    fn a_never_returning_event_stream_is_bounded_not_hung() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            // Never a `return`: just events until the client disconnects.
            loop {
                if writer.write_all(b"{\"event\": \"RTC_CHANGE\"}\n").is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let result = send_command_within(
            socket.to_str().unwrap(),
            "system_powerdown",
            COMMAND_DEADLINE,
        );
        assert!(result.is_err(), "a never-returning event stream must fail");
        assert!(
            start.elapsed() < COMMAND_DEADLINE + Duration::from_secs(2),
            "the reader must not hang"
        );
        let _ = server.join();
    }

    /// A monitor that streams bytes with no newline must not grow the read
    /// buffer without bound: the byte cap cuts it off with an Err.
    #[test]
    fn a_never_terminated_line_is_bounded_not_oom() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            // A reply that never ends with a newline: spaces forever.
            let chunk = vec![b' '; 4096];
            loop {
                if writer.write_all(&chunk).is_err() {
                    break;
                }
            }
        });
        let start = Instant::now();
        let result = send_command_within(
            socket.to_str().unwrap(),
            "system_powerdown",
            COMMAND_DEADLINE,
        );
        assert!(result.is_err(), "a never-terminated line must fail");
        assert!(
            start.elapsed() < COMMAND_DEADLINE + Duration::from_secs(2),
            "the reader must not hang"
        );
        let _ = server.join();
    }

    /// A monitor that goes silent after the handshake (no bytes at all) is cut
    /// off by the wall-clock deadline, not left to park forever.
    #[test]
    fn a_silent_monitor_hits_the_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            let mut line = String::new();
            std::io::BufRead::read_line(&mut reader, &mut line).unwrap();
            // Go silent: never answer the command. Hold the socket open until
            // the client gives up.
            let mut sink = [0u8; 1];
            let _ = reader.read(&mut sink);
        });
        let budget = Duration::from_millis(400);
        let start = Instant::now();
        let result = send_command_within(socket.to_str().unwrap(), "system_powerdown", budget);
        assert!(result.is_err(), "a silent monitor must hit the deadline");
        assert!(
            start.elapsed() < budget + Duration::from_secs(2),
            "the deadline must fire promptly"
        );
        let _ = server.join();
    }
}
