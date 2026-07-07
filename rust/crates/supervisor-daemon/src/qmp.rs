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
    let mut writer = stream
        .try_clone()
        .map_err(|error| format!("cannot clone the QGA socket: {error}"))?;
    let mut reader = BufReader::new(stream);

    let request = json!({ "execute": command });
    writer
        .write_all(format!("{request}\n").as_bytes())
        .and_then(|_| writer.flush())
        .map_err(|error| format!("cannot send the QGA command: {error}"))?;

    let mut line = String::new();
    let read = reader
        .read_line(&mut line)
        .map_err(|error| format!("cannot read the QGA response: {error}"))?;
    if read == 0 {
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
        let mut line = String::new();
        let read = self
            .reader
            .read_line(&mut line)
            .map_err(|error| format!("cannot read from the QMP socket: {error}"))?;
        if read == 0 {
            return Err("QMP socket closed".to_string());
        }
        Ok(line)
    }
}

fn u32_field(value: &Value, key: &str) -> u32 {
    value.get(key).and_then(Value::as_u64).unwrap_or(0) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// Spawn a fake QMP server that greets, accepts qmp_capabilities, then
    /// answers each command with the scripted reply. Returns the socket path.
    fn fake_qmp_server(dir: &Path, replies: Vec<Value>) -> std::path::PathBuf {
        let socket_path = dir.join("qmp.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut writer = stream.try_clone().unwrap();
            let mut reader = BufReader::new(stream);
            // Greeting.
            writer.write_all(b"{\"QMP\": {\"version\": {}}}\n").unwrap();
            // qmp_capabilities.
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            writer.write_all(b"{\"return\": {}}\n").unwrap();
            for reply in replies {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                // Emit an interleaved event first: the client must skip it.
                writer
                    .write_all(b"{\"event\": \"NIC_RX_FILTER_CHANGED\"}\n")
                    .unwrap();
                writer.write_all(format!("{reply}\n").as_bytes()).unwrap();
            }
        });
        // The listener binding is synchronous, so the socket exists now.
        socket_path
    }

    #[test]
    fn query_sev_skips_events_and_parses_the_reply() {
        let dir = tempfile::tempdir().unwrap();
        let socket = fake_qmp_server(
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
        let socket = fake_qmp_server(
            dir.path(),
            vec![json!({"error": {"class": "GenericError", "desc": "sev not enabled"}})],
        );
        let mut client = QmpClient::connect(&socket).unwrap();
        let error = client.query_launch_measure().unwrap_err();
        assert!(error.contains("sev not enabled"), "got: {error}");
    }
}
