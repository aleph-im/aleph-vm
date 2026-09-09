//! GPU evidence for NVIDIA confidential computing.
//!
//! The guest driver holds an SPDM session with the GPU; NVIDIA's
//! `nvattest collect-evidence` reads the signed GET_MEASUREMENTS response
//! and the GPU certificate chain through NVML and prints them as JSON. The
//! agent is a static musl binary inside a content-only measured initrd, so
//! it cannot load NVIDIA's glibc libraries itself; it runs the collector as
//! a child process instead, with the derived SPDM nonce as the last argument,
//! and parses what comes back. The trait keeps the route testable with a
//! fake collector script.

use std::io::Read;
use std::process::Command;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// One GPU's evidence, in the exact JSON shape `nvattest collect-evidence
/// --format json` emits per device, so NVIDIA's verifier and the aleph-rs
/// client read the same document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GpuEvidence {
    pub arch: String,
    /// Hex, 32 bytes: the derived GPU nonce this report answers.
    pub nonce: String,
    /// Base64 of the raw SPDM GET_MEASUREMENTS response.
    pub evidence: String,
    /// Base64 of the PEM certificate chain, leaf first.
    pub certificate: String,
}

pub trait GpuEvidenceSource: Send + Sync {
    fn collect(&self, nonce: &[u8; 32]) -> Result<Vec<GpuEvidence>>;
}

/// An upper bound on one collection: an SPDM exchange takes well under a
/// second, RIM-free collection does no network I/O, so a minute means the
/// driver is wedged and the request should fail rather than pile up.
pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(60);

/// More than any evidence document: eight GPUs with full certificate
/// chains stay well under a megabyte. A collector still writing past this
/// is wedged or not the collector we measured, and the request fails
/// instead of growing the guest's memory until the timeout.
pub const MAX_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
struct CollectorOutput {
    evidences: Vec<GpuEvidence>,
    result_code: i64,
    #[serde(default)]
    result_message: String,
}

/// The collector command, e.g. `/bin/busybox chroot /mnt/root /usr/bin/env
/// LD_LIBRARY_PATH=/opt/nvidia/lib nvattest collect-evidence --device gpu
/// --format json --nonce`; the nonce hex is appended at collect time.
pub struct CollectorProcess {
    pub program: String,
    pub args: Vec<String>,
    /// Bound on one collection, child and pipe drain included; tests lower
    /// it so the kill path runs in milliseconds.
    pub timeout: Duration,
}

impl CollectorProcess {
    pub fn from_command_line(command: &str) -> Result<Self> {
        let mut parts = command.split_whitespace().map(str::to_string);
        let program = parts.next().context("--gpu-collector is empty")?;
        Ok(Self {
            program,
            args: parts.collect(),
            timeout: COLLECT_TIMEOUT,
        })
    }

    /// Parse the collector's stdout, requiring a zero result code, at least
    /// one device, and every device answering exactly the nonce we asked
    /// for: a collector that answered a different nonce (a stale or foreign
    /// report) is a failure, never a substitution.
    pub fn parse_output(stdout: &[u8], expected_nonce_hex: &str) -> Result<Vec<GpuEvidence>> {
        let output: CollectorOutput =
            serde_json::from_slice(stdout).context("collector output is not the expected JSON")?;
        if output.result_code != 0 {
            bail!(
                "collector failed: result_code {} ({})",
                output.result_code,
                output.result_message
            );
        }
        if output.evidences.is_empty() {
            bail!("collector reported no GPU");
        }
        for (index, evidence) in output.evidences.iter().enumerate() {
            if !evidence.nonce.eq_ignore_ascii_case(expected_nonce_hex) {
                bail!(
                    "GPU {index} evidence answers nonce {} instead of {expected_nonce_hex}",
                    evidence.nonce
                );
            }
        }
        Ok(output.evidences)
    }
}

/// Drain one pipe on its own thread, so a collector writing more than the
/// pipe buffer holds (64 KiB) never blocks on a write we are not reading.
/// The buffer comes back over a channel rather than a join handle, so the
/// caller can give up on it at its deadline. Past the cap the pipe is
/// dropped, which ends the writer with EPIPE instead of letting it fill
/// memory.
fn drain(
    mut pipe: impl Read + Send + 'static,
    what: &'static str,
) -> mpsc::Receiver<Result<Vec<u8>>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let read = pipe
            .by_ref()
            .take(MAX_OUTPUT_BYTES + 1)
            .read_to_end(&mut buf)
            .with_context(|| format!("reading the GPU collector's {what}"));
        let result = match read {
            Ok(_) if buf.len() as u64 > MAX_OUTPUT_BYTES => Err(anyhow::anyhow!(
                "GPU collector {what} exceeds {MAX_OUTPUT_BYTES} bytes"
            )),
            Ok(_) => Ok(buf),
            Err(e) => Err(e),
        };
        drop(pipe);
        let _ = tx.send(result);
    });
    rx
}

/// Wait for a drained pipe until the deadline. A pipe still open after the
/// child exited is held by something the child spawned; waiting for that
/// would pin this worker and the caller's mutex for as long as it lives.
/// The reader thread stays behind, detached, and ends when the pipe
/// finally closes.
fn receive_by(
    rx: &mpsc::Receiver<Result<Vec<u8>>>,
    deadline: Instant,
    what: &str,
    timeout: Duration,
) -> Result<Vec<u8>> {
    match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            bail!("GPU collector exited but its {what} stayed open past {timeout:?}")
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => bail!("{what} reader thread panicked"),
    }
}

impl GpuEvidenceSource for CollectorProcess {
    fn collect(&self, nonce: &[u8; 32]) -> Result<Vec<GpuEvidence>> {
        let nonce_hex = hex::encode(nonce);
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .arg(&nonce_hex)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .with_context(|| format!("cannot start GPU collector {}", self.program))?;
        let deadline = Instant::now() + self.timeout;

        let stdout = child.stdout.take().context("expected piped stdout")?;
        let stderr = child.stderr.take().context("expected piped stderr")?;
        let stdout_rx = drain(stdout, "stdout");
        let stderr_rx = drain(stderr, "stderr");

        loop {
            if child
                .try_wait()
                .context("waiting for the GPU collector")?
                .is_some()
            {
                break;
            }
            if Instant::now() >= deadline {
                // The reader threads are left behind on purpose: joining
                // them could block on a pipe a surviving grandchild holds.
                let _ = child.kill();
                let _ = child.wait();
                bail!("GPU collector exceeded {:?}", self.timeout);
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let stdout_buf = receive_by(&stdout_rx, deadline, "stdout", self.timeout)?;
        let stderr_buf = receive_by(&stderr_rx, deadline, "stderr", self.timeout)?;

        let status = child
            .wait()
            .context("waiting for collector after pipes drained")?;
        if !status.success() {
            // stderr stays in the guest log; the caller only learns it failed.
            tracing::error!(
                status = %status,
                stderr = %String::from_utf8_lossy(&stderr_buf),
                "GPU collector failed"
            );
            bail!("GPU collector exit status {}", status);
        }
        Self::parse_output(&stdout_buf, &nonce_hex)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE_GPU: &str = r#"{"evidences":[{"arch":"BLACKWELL","nonce":"NONCE","evidence":"EeAB","certificate":"LS0t"}],"result_code":0,"result_message":"Ok"}"#;

    /// Write a shell script and return a collector running it through
    /// /bin/sh. The file is deliberately not exec'd itself: a fork from
    /// another test thread can still hold the just-written script open, and
    /// exec would then fail ETXTBSY. The nonce still lands last, so the
    /// script reads it as $1.
    fn script_collector(name: &str, body: &str) -> (tempfile::TempDir, CollectorProcess) {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join(name);
        std::fs::write(&script, body).unwrap();
        let collector =
            CollectorProcess::from_command_line(&format!("/bin/sh {}", script.display())).unwrap();
        (dir, collector)
    }

    #[test]
    fn evidence_serializes_in_the_nvattest_shape() {
        let evidence = GpuEvidence {
            arch: "BLACKWELL".into(),
            nonce: "00".repeat(32),
            evidence: "EeAB".into(),
            certificate: "LS0t".into(),
        };
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"arch": "BLACKWELL", "nonce": "00".repeat(32), "evidence": "EeAB", "certificate": "LS0t"})
        );
    }

    #[test]
    fn parse_output_accepts_a_matching_nonce() {
        let nonce = "ab".repeat(32);
        let out =
            CollectorProcess::parse_output(ONE_GPU.replace("NONCE", &nonce).as_bytes(), &nonce)
                .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].arch, "BLACKWELL");
        assert_eq!(out[0].evidence, "EeAB");
    }

    #[test]
    fn parse_output_rejects_a_foreign_nonce() {
        let nonce = "ab".repeat(32);
        let err = CollectorProcess::parse_output(
            ONE_GPU.replace("NONCE", &"cd".repeat(32)).as_bytes(),
            &nonce,
        )
        .unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err}");
    }

    #[test]
    fn parse_output_rejects_a_failed_collection() {
        let nonce = "ab".repeat(32);
        let failed = ONE_GPU
            .replace("NONCE", &nonce)
            .replace("\"result_code\":0", "\"result_code\":7");
        assert!(CollectorProcess::parse_output(failed.as_bytes(), &nonce).is_err());
        let empty = r#"{"evidences":[],"result_code":0,"result_message":"Ok"}"#;
        assert!(
            CollectorProcess::parse_output(empty.as_bytes(), &nonce).is_err(),
            "no GPU is an error"
        );
        assert!(CollectorProcess::parse_output(b"not json", &nonce).is_err());
    }

    #[test]
    fn command_line_splits_program_and_args() {
        let collector = CollectorProcess::from_command_line(
            "/bin/busybox chroot /mnt/root /usr/bin/env LD_LIBRARY_PATH=/opt/nvidia/lib nvattest collect-evidence --device gpu --format json --nonce",
        )
        .unwrap();
        assert_eq!(collector.program, "/bin/busybox");
        assert_eq!(collector.args.last().unwrap(), "--nonce");
        assert_eq!(collector.timeout, COLLECT_TIMEOUT);
        assert!(CollectorProcess::from_command_line("   ").is_err());
    }

    /// End to end against a fake collector script: the nonce hex must arrive
    /// as the last argument and the JSON on stdout must be parsed.
    #[test]
    fn collect_runs_the_program_with_the_nonce_appended() {
        let (_dir, collector) = script_collector(
            "fake-nvattest.sh",
            "nonce=\"$1\"\nprintf '{\"evidences\":[{\"arch\":\"HOPPER\",\"nonce\":\"%s\",\"evidence\":\"ZQ==\",\"certificate\":\"Yw==\"}],\"result_code\":0,\"result_message\":\"Ok\"}' \"$nonce\"\n",
        );
        let nonce = [0x5au8; 32];
        let out = collector.collect(&nonce).unwrap();
        assert_eq!(out[0].nonce, "5a".repeat(32));
        assert_eq!(out[0].arch, "HOPPER");
    }

    #[test]
    fn collect_reports_a_non_zero_exit() {
        let collector = CollectorProcess::from_command_line("/bin/false").unwrap();
        let err = collector.collect(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("exit"), "{err}");
    }

    /// Large output that would overflow pipe buffers (>64 KiB) must not deadlock.
    /// The fix drains stdout and stderr on separate threads while polling try_wait.
    #[test]
    fn collect_handles_large_output_without_deadlock() {
        // Output ~200 KiB JSON: pipe buffer overflow without the drain fix.
        let padding = "x".repeat(200000);
        let (_dir, collector) = script_collector(
            "large-output.sh",
            &format!(
                "nonce=\"$1\"\nprintf '{{\"evidences\":[{{\"arch\":\"HOPPER\",\"nonce\":\"%s\",\"evidence\":\"ZQ==\",\"certificate\":\"Yw==\"}}],\"result_code\":0,\"result_message\":\"{}\"}}' \"$nonce\"\n",
                padding
            ),
        );
        let nonce = [0xabu8; 32];
        // Must complete within COLLECT_TIMEOUT (60 s), not deadlock.
        let out = collector.collect(&nonce).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].arch, "HOPPER");
        assert_eq!(out[0].nonce, "ab".repeat(32));
    }

    /// A collector that never exits is killed at the timeout, and the call
    /// returns then rather than waiting on the child.
    #[test]
    fn collect_kills_a_collector_that_exceeds_the_timeout() {
        let (_dir, mut collector) = script_collector("wedged.sh", "sleep 30\n");
        collector.timeout = Duration::from_millis(200);
        let started = Instant::now();
        let err = collector.collect(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("exceeded"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    /// The deadline also covers the pipe drain: a helper that inherits stdout
    /// and outlives the collector must not turn the call into an unbounded
    /// wait, since the caller holds the GPU mutex for its whole duration.
    #[test]
    fn collect_gives_up_on_a_pipe_a_survivor_keeps_open() {
        let (_dir, mut collector) = script_collector("survivor.sh", "sleep 5 &\nexit 0\n");
        collector.timeout = Duration::from_millis(300);
        let started = Instant::now();
        let err = collector.collect(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("stayed open"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{:?}",
            started.elapsed()
        );
    }

    /// Output past the cap fails the collection instead of being buffered.
    #[test]
    fn collect_rejects_output_beyond_the_cap() {
        let (_dir, collector) = script_collector(
            "flood.sh",
            &format!("head -c {} /dev/zero\n", MAX_OUTPUT_BYTES + 1024),
        );
        let err = collector.collect(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }
}
