//! A minimal blocking QMP client for the graceful-stop escalation.
//!
//! `QemuVM.stop()` only ever issues two QMP commands, `system_powerdown` and
//! `quit`, via the Python `qmp` library. This client reproduces that: connect
//! (only if the socket exists, like `_get_qmpclient`), negotiate the
//! capabilities handshake, send the command and best-effort read its reply.
//! `quit` makes QEMU exit, so the socket may close before a reply arrives;
//! that is treated as success, not an error.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Bound the wait on the monitor so a wedged QEMU cannot hang the shutdown
/// escalation (the escalation itself is time-boxed by the caller, but the
/// blocking-pool thread should not park indefinitely).
const QMP_TIMEOUT: Duration = Duration::from_secs(10);

/// Send one QMP command over the monitor socket. Returns Ok when the command
/// was sent (and, for non-`quit` commands, acknowledged); a missing socket is
/// Ok (the VM is already gone, like Python's `if not socket.exists(): return`).
pub fn send_command(qmp_socket_path: &str, command: &str) -> Result<(), String> {
    let path = Path::new(qmp_socket_path);
    if !path.exists() {
        return Ok(());
    }
    let stream =
        UnixStream::connect(path).map_err(|error| format!("cannot connect to QMP: {error}"))?;
    stream
        .set_read_timeout(Some(QMP_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(QMP_TIMEOUT)))
        .map_err(|error| format!("cannot set the QMP timeouts: {error}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("cannot clone the QMP socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    // Greeting, then the qmp_capabilities handshake into command mode.
    read_line(&mut reader).map_err(|error| format!("no QMP greeting: {error}"))?;
    send(&mut writer, "qmp_capabilities")?;
    read_reply(&mut reader, "qmp_capabilities")?;

    send(&mut writer, command)?;
    // `quit` tells QEMU to exit; the reply may never arrive because the socket
    // closes first. A closed socket after issuing the command is success.
    match read_reply(&mut reader, command) {
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
/// asynchronous `event` messages (the `qmp` library's command loop).
fn read_reply(reader: &mut BufReader<UnixStream>, command: &str) -> Result<(), String> {
    loop {
        let line = read_line(reader)?;
        let value: serde_json::Value = serde_json::from_str(line.trim())
            .map_err(|error| format!("invalid QMP response: {error}"))?;
        if let Some(error) = value.get("error") {
            return Err(format!("QMP error for {command}: {error}"));
        }
        if value.get("return").is_some() {
            return Ok(());
        }
        // An asynchronous event (or the greeting echo): keep reading.
    }
}

fn read_line(reader: &mut BufReader<UnixStream>) -> Result<String, String> {
    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| format!("cannot read from the QMP socket: {error}"))?;
    if read == 0 {
        return Err("QMP socket closed".to_string());
    }
    Ok(line)
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
                reader.read_line(&mut line).unwrap();
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
            reader.read_line(&mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
        });
        send_command(socket.to_str().unwrap(), "quit").unwrap();
        server.join().unwrap();
    }
}
