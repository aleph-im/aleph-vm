//! Blocking QMP and QGA clients (increments 5-6), a 1:1 port of the Python
//! `QemuVmClient` / `QemuGuestAgentClient`
//! (src/aleph/vm/supervisor/controllers/qemu/client.py).
//!
//! Both speak line-delimited JSON over a Unix socket. QGA (the guest agent,
//! used by the backup fs-freeze) is plain request/response with no
//! negotiation. QMP (the QEMU monitor, used by the confidential measurement
//! and secret injection) opens with a greeting and a `qmp_capabilities`
//! handshake, and interleaves asynchronous `event` messages that a command
//! read must skip.
//!
//! HARDWARE-GATED: the SEV commands (`query-sev`, `query-sev-launch-measure`,
//! `sev-inject-launch-secret`) only return meaningful data from a running
//! confidential VM on an SEV host. Without SEV hardware the connection itself
//! fails ("VM is not running"), exactly as in Python. The protocol handshake
//! is exercised by the unit tests against a fake QMP/QGA server socket.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

/// The read timeout Python's QGA client applies (`asyncio.wait_for(..., 30)`).
const QGA_TIMEOUT: Duration = Duration::from_secs(30);
/// A conservative bound on QMP reads so a wedged monitor cannot hang a
/// lifecycle RPC forever (Rust-only robustness, ledger entry 44 family).
const QMP_TIMEOUT: Duration = Duration::from_secs(30);

/// A ceiling on a single QMP/QGA response line so a monitor that streams
/// bytes without ever emitting a newline cannot grow the read buffer without
/// bound (a memory DoS on the blocking pool thread). QMP replies are small
/// JSON objects; 8 MiB is far above any legitimate line (Rust-only bound,
/// ledger entry 50 family).
const MAX_LINE_BYTES: usize = 8 * 1024 * 1024;

// ── QGA (guest agent) ────────────────────────────────────────────────────

/// `QemuGuestAgentClient.fsfreeze_freeze`: freeze all freezable guest
/// filesystems, returning the count.
pub fn qga_fsfreeze_freeze(socket_path: &Path) -> Result<i64, String> {
    qga_command(socket_path, "guest-fsfreeze-freeze")?
        .as_i64()
        .ok_or_else(|| "guest-fsfreeze-freeze did not return a count".to_string())
}

/// `QemuGuestAgentClient.fsfreeze_thaw`: thaw all frozen guest filesystems.
pub fn qga_fsfreeze_thaw(socket_path: &Path) -> Result<i64, String> {
    qga_command(socket_path, "guest-fsfreeze-thaw")?
        .as_i64()
        .ok_or_else(|| "guest-fsfreeze-thaw did not return a count".to_string())
}

/// `QemuGuestAgentClient.command`: one QGA request/response. QGA emits no
/// greeting and no events, so exactly one response line follows the request.
fn qga_command(socket_path: &Path, command: &str) -> Result<Value, String> {
    if !socket_path.exists() {
        return Err("QEMU Guest Agent socket not available".to_string());
    }
    let stream = UnixStream::connect(socket_path)
        .map_err(|error| format!("cannot connect to QGA: {error}"))?;
    stream
        .set_read_timeout(Some(QGA_TIMEOUT))
        .map_err(|error| format!("cannot set the QGA read timeout: {error}"))?;
    // A write timeout matching the read timeout: a guest agent that never
    // drains its socket must not block write_all forever, parking this
    // blocking-pool thread (Rust-only robustness, ledger entry 50).
    stream
        .set_write_timeout(Some(QGA_TIMEOUT))
        .map_err(|error| format!("cannot set the QGA write timeout: {error}"))?;
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("cannot clone the QGA socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    let request = json!({ "execute": command });
    writer
        .write_all(format!("{request}\n").as_bytes())
        .and_then(|_| writer.flush())
        .map_err(|error| format!("cannot send the QGA command: {error}"))?;

    let line = read_capped_line(&mut reader, MAX_LINE_BYTES)
        .map_err(|error| format!("cannot read the QGA response: {error}"))?;
    if line.is_empty() {
        return Err("QGA socket closed unexpectedly".to_string());
    }
    let response: Value = serde_json::from_str(line.trim())
        .map_err(|error| format!("invalid QGA response: {error}"))?;
    if let Some(error) = response.get("error") {
        return Err(format!("QGA error: {error}"));
    }
    Ok(response.get("return").cloned().unwrap_or(Value::Null))
}

// ── QMP (monitor) ────────────────────────────────────────────────────────

/// The SEV platform state `query-sev` reports (`VmSevInfo`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevInfo {
    pub enabled: bool,
    pub api_major: u32,
    pub api_minor: u32,
    pub build_id: u32,
    pub policy: u32,
    pub state: String,
    pub handle: u32,
}

/// A blocking QMP monitor connection.
#[derive(Debug)]
pub struct QmpClient {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl QmpClient {
    /// `QemuVmClient.__init__`: the QMP socket must exist (the VM must be
    /// running), then connect and negotiate capabilities. The missing-socket
    /// message matches Python's RuntimeError verbatim so the agent surfaces
    /// the same text.
    pub fn connect(socket_path: &Path) -> Result<Self, String> {
        if !socket_path.exists() {
            return Err("VM is not running (QMP socket missing)".to_string());
        }
        let stream = UnixStream::connect(socket_path)
            .map_err(|error| format!("cannot connect to QMP: {error}"))?;
        stream
            .set_read_timeout(Some(QMP_TIMEOUT))
            .map_err(|error| format!("cannot set the QMP read timeout: {error}"))?;
        // A write timeout matching the read timeout: a monitor socket that
        // never drains must not block write_all forever, parking this
        // blocking-pool thread (Rust-only robustness, ledger entry 50).
        stream
            .set_write_timeout(Some(QMP_TIMEOUT))
            .map_err(|error| format!("cannot set the QMP write timeout: {error}"))?;
        let writer = stream
            .try_clone()
            .map_err(|error| format!("cannot clone the QMP socket: {error}"))?;
        let mut client = Self {
            writer,
            reader: BufReader::new(stream),
        };
        // The greeting: `{"QMP": {...}}`.
        client
            .read_line()
            .map_err(|error| format!("no QMP greeting: {error}"))?;
        // qmp_capabilities enters command mode.
        client.command("qmp_capabilities", None)?;
        Ok(client)
    }

    /// `query-sev`.
    pub fn query_sev_info(&mut self) -> Result<SevInfo, String> {
        let caps = self.command("query-sev", None)?;
        Ok(SevInfo {
            enabled: caps
                .get("enabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            api_major: u32_field(&caps, "api-major"),
            api_minor: u32_field(&caps, "api-minor"),
            build_id: u32_field(&caps, "build-id"),
            policy: u32_field(&caps, "policy"),
            state: caps
                .get("state")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            handle: u32_field(&caps, "handle"),
        })
    }

    /// `query-sev-launch-measure`: the base64 launch measurement (`data`).
    pub fn query_launch_measure(&mut self) -> Result<String, String> {
        let measure = self.command("query-sev-launch-measure", None)?;
        Ok(measure
            .get("data")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string())
    }

    /// `sev-inject-launch-secret`: the base64 packet header and secret.
    pub fn inject_secret(&mut self, packet_header: &str, secret: &str) -> Result<(), String> {
        self.command(
            "sev-inject-launch-secret",
            Some(json!({ "packet-header": packet_header, "secret": secret })),
        )?;
        Ok(())
    }

    /// `cont`: resume the VM.
    pub fn continue_execution(&mut self) -> Result<(), String> {
        self.command("cont", None)?;
        Ok(())
    }

    /// One QMP command: send `{"execute": ..., "arguments": ...}` and read
    /// until the matching `return`/`error` reply, skipping asynchronous
    /// `event` messages (the `qmp` library's command loop).
    fn command(&mut self, execute: &str, arguments: Option<Value>) -> Result<Value, String> {
        let mut request = json!({ "execute": execute });
        if let Some(arguments) = arguments {
            request["arguments"] = arguments;
        }
        self.writer
            .write_all(format!("{request}\n").as_bytes())
            .and_then(|_| self.writer.flush())
            .map_err(|error| format!("cannot send the QMP command {execute}: {error}"))?;
        loop {
            let line = self.read_line()?;
            let response: Value = serde_json::from_str(line.trim())
                .map_err(|error| format!("invalid QMP response: {error}"))?;
            if let Some(error) = response.get("error") {
                return Err(format!("QMP error for {execute}: {error}"));
            }
            if let Some(result) = response.get("return") {
                return Ok(result.clone());
            }
            // An asynchronous event (or the greeting echo): keep reading.
        }
    }

    fn read_line(&mut self) -> Result<String, String> {
        let line = read_capped_line(&mut self.reader, MAX_LINE_BYTES)
            .map_err(|error| format!("cannot read from the QMP socket: {error}"))?;
        if line.is_empty() {
            return Err("QMP socket closed".to_string());
        }
        Ok(line)
    }
}

fn u32_field(value: &Value, key: &str) -> u32 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0) as u32
}

/// Read one newline-terminated line, capped at `cap` bytes so a peer that
/// streams without ever sending a newline cannot grow the buffer unbounded.
/// Returns the line (including the trailing newline when present) or an empty
/// string at EOF; errors if the line would exceed `cap`. The underlying read
/// timeout still bounds the wait for each fill.
fn read_capped_line<R: BufRead>(reader: &mut R, cap: usize) -> std::io::Result<String> {
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(newline) = available.iter().position(|byte| *byte == b'\n') {
            line.extend_from_slice(&available[..=newline]);
            reader.consume(newline + 1);
            break;
        }
        let consumed = available.len();
        line.extend_from_slice(available);
        reader.consume(consumed);
        if line.len() > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("response line exceeded {cap} bytes without a newline"),
            ));
        }
    }
    Ok(String::from_utf8_lossy(&line).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::os::unix::net::UnixListener;
    use std::sync::{Arc, Mutex};
    use std::thread;

    /// The exact request lines a [`fake_qmp_server`] received, parsed as JSON,
    /// so a test can pin the exact command name and argument keys the client
    /// sent. A mutation renaming `query-sev`, `packet-header`, or `cont` must
    /// fail an assertion here.
    type RecordedRequests = Arc<Mutex<Vec<Value>>>;

    /// Spawn a fake QMP server that greets, records and validates the
    /// `qmp_capabilities` handshake, then records each command request and
    /// answers it with the scripted reply. Returns the socket path and the
    /// recorded request log (which starts with the qmp_capabilities request).
    fn fake_qmp_server(dir: &Path, replies: Vec<Value>) -> (std::path::PathBuf, RecordedRequests) {
        let socket_path = dir.join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let requests: RecordedRequests = Arc::new(Mutex::new(Vec::new()));
        let recorder = requests.clone();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            // Greeting.
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            // qmp_capabilities: record the exact request the client sent.
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            recorder
                .lock()
                .unwrap()
                .push(serde_json::from_str(line.trim()).unwrap());
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            for reply in replies {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                recorder
                    .lock()
                    .unwrap()
                    .push(serde_json::from_str(line.trim()).unwrap());
                // Emit an interleaved event first: the client must skip it.
                writer
                    .write_all(b"{\"event\": \"NIC_RX_FILTER_CHANGED\"}\n")
                    .unwrap();
                writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
            }
        });
        // The listener binding is synchronous, so the socket exists now.
        (socket_path, requests)
    }

    #[test]
    fn the_handshake_sends_qmp_capabilities_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qmp_server(dir.path(), vec![]);
        let _client = QmpClient::connect(&socket).unwrap();
        assert_eq!(
            requests.lock().unwrap()[0],
            json!({"execute": "qmp_capabilities"})
        );
    }

    #[test]
    fn query_sev_skips_events_and_pins_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qmp_server(
            dir.path(),
            vec![json!({"return": {
                "enabled": true, "api-major": 1, "api-minor": 55, "build-id": 42,
                "policy": 5, "state": "launch-secret", "handle": 7
            }})],
        );
        let mut client = QmpClient::connect(&socket).unwrap();
        let info = client.query_sev_info().unwrap();
        assert_eq!(
            info,
            SevInfo {
                enabled: true,
                api_major: 1,
                api_minor: 55,
                build_id: 42,
                policy: 5,
                state: "launch-secret".to_string(),
                handle: 7,
            }
        );
        // The exact request bytes: query-sev with no arguments.
        assert_eq!(requests.lock().unwrap()[1], json!({"execute": "query-sev"}));
    }

    #[test]
    fn query_launch_measure_pins_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qmp_server(
            dir.path(),
            vec![json!({"return": {"data": "bWVhc3VyZQ=="}})],
        );
        let mut client = QmpClient::connect(&socket).unwrap();
        assert_eq!(client.query_launch_measure().unwrap(), "bWVhc3VyZQ==");
        assert_eq!(
            requests.lock().unwrap()[1],
            json!({"execute": "query-sev-launch-measure"})
        );
    }

    #[test]
    fn inject_secret_pins_the_command_and_argument_keys() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qmp_server(dir.path(), vec![json!({"return": {}})]);
        let mut client = QmpClient::connect(&socket).unwrap();
        client.inject_secret("aGVhZGVy", "c2VjcmV0").unwrap();
        // The exact command name and argument keys, matching the Python
        // QemuVmClient.inject_secret (src/aleph/vm/controllers/qemu/client.py).
        assert_eq!(
            requests.lock().unwrap()[1],
            json!({
                "execute": "sev-inject-launch-secret",
                "arguments": {"packet-header": "aGVhZGVy", "secret": "c2VjcmV0"}
            })
        );
    }

    #[test]
    fn continue_execution_pins_the_cont_command() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qmp_server(dir.path(), vec![json!({"return": {}})]);
        let mut client = QmpClient::connect(&socket).unwrap();
        client.continue_execution().unwrap();
        assert_eq!(requests.lock().unwrap()[1], json!({"execute": "cont"}));
    }

    #[test]
    fn a_missing_socket_reports_the_python_message() {
        let dir = tempfile::tempdir().unwrap();
        let error = QmpClient::connect(&dir.path().join("absent.sock")).unwrap_err();
        assert_eq!(error, "VM is not running (QMP socket missing)");
    }

    #[test]
    fn a_qmp_error_reply_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, _requests) = fake_qmp_server(
            dir.path(),
            vec![json!({"error": {"class": "GenericError", "desc": "sev not enabled"}})],
        );
        let mut client = QmpClient::connect(&socket).unwrap();
        let error = client.query_launch_measure().unwrap_err();
        assert!(error.contains("sev not enabled"), "got: {error}");
    }

    /// A fake QGA server: one plain request/response, no handshake. Records
    /// the request so the test can pin the exact command bytes.
    fn fake_qga_server(dir: &Path, reply: Value) -> (std::path::PathBuf, RecordedRequests) {
        let socket_path = dir.join("qga.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let requests: RecordedRequests = Arc::new(Mutex::new(Vec::new()));
        let recorder = requests.clone();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            recorder
                .lock()
                .unwrap()
                .push(serde_json::from_str(line.trim()).unwrap());
            writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
        });
        (socket_path, requests)
    }

    #[test]
    fn qga_fsfreeze_pins_the_command_names() {
        let dir = tempfile::tempdir().unwrap();
        let (freeze_socket, freeze_requests) = fake_qga_server(dir.path(), json!({"return": 2}));
        assert_eq!(qga_fsfreeze_freeze(&freeze_socket).unwrap(), 2);
        assert_eq!(
            freeze_requests.lock().unwrap()[0],
            json!({"execute": "guest-fsfreeze-freeze"})
        );

        // A separate socket for thaw (the freeze server handled one request).
        let thaw_dir = tempfile::tempdir().unwrap();
        let (thaw_socket, thaw_requests) = fake_qga_server(thaw_dir.path(), json!({"return": 2}));
        assert_eq!(qga_fsfreeze_thaw(&thaw_socket).unwrap(), 2);
        assert_eq!(
            thaw_requests.lock().unwrap()[0],
            json!({"execute": "guest-fsfreeze-thaw"})
        );
    }

    #[test]
    fn read_capped_line_rejects_an_overlong_newlineless_line() {
        // 100 bytes, no newline, cap 10: the read must error, not grow.
        let mut reader = Cursor::new(vec![b'a'; 100]);
        let error = read_capped_line(&mut reader, 10).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        // A line within the cap reads fine (including its newline).
        let mut ok = Cursor::new(b"{\"return\": {}}\n".to_vec());
        assert_eq!(
            read_capped_line(&mut ok, 1024).unwrap(),
            "{\"return\": {}}\n"
        );

        // EOF with no data is an empty string (the closed-socket signal).
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(read_capped_line(&mut empty, 1024).unwrap(), "");
    }
}
