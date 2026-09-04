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

#![allow(dead_code)]

use std::io::Read;
use std::process::Command;
use std::time::Duration;

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
}

impl CollectorProcess {
    pub fn from_command_line(command: &str) -> Result<Self> {
        let mut parts = command.split_whitespace().map(str::to_string);
        let program = parts.next().context("--gpu-collector is empty")?;
        Ok(Self {
            program,
            args: parts.collect(),
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

        // Take ownership of pipes and spawn reader threads to avoid deadlock:
        // if collector writes >64 KiB, it blocks on the pipe write; without
        // draining on separate threads, try_wait loops forever and times out.
        let mut stdout = child.stdout.take().context("expected piped stdout")?;
        let mut stderr = child.stderr.take().context("expected piped stderr")?;

        let stdout_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        });

        let stderr_handle = std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stderr.read_to_end(&mut buf);
            buf
        });

        let started = std::time::Instant::now();
        loop {
            if child
                .try_wait()
                .context("waiting for the GPU collector")?
                .is_some()
            {
                break;
            }
            if started.elapsed() > COLLECT_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                bail!("GPU collector exceeded {COLLECT_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Join reader threads
        let stdout_buf = stdout_handle
            .join()
            .map_err(|_| anyhow::anyhow!("stdout reader thread panicked"))?;
        let stderr_buf = stderr_handle
            .join()
            .map_err(|_| anyhow::anyhow!("stderr reader thread panicked"))?;

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
        assert!(CollectorProcess::from_command_line("   ").is_err());
    }

    /// End to end against a fake collector script: the nonce hex must arrive
    /// as the last argument and the JSON on stdout must be parsed.
    #[test]
    fn collect_runs_the_program_with_the_nonce_appended() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("fake-nvattest.sh");
        std::fs::write(
            &script,
            "#!/bin/sh\nnonce=\"$1\"\nprintf '{\"evidences\":[{\"arch\":\"HOPPER\",\"nonce\":\"%s\",\"evidence\":\"ZQ==\",\"certificate\":\"Yw==\"}],\"result_code\":0,\"result_message\":\"Ok\"}' \"$nonce\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let collector = CollectorProcess::from_command_line(script.to_str().unwrap()).unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("large-output.sh");
        // Output ~200 KiB JSON: pipe buffer overflow without the drain fix.
        let padding = "x".repeat(200000);
        let script_content = format!(
            "#!/bin/sh\nnonce=\"$1\"\nprintf '{{\"evidences\":[{{\"arch\":\"HOPPER\",\"nonce\":\"%s\",\"evidence\":\"ZQ==\",\"certificate\":\"Yw==\"}}],\"result_code\":0,\"result_message\":\"{}\"}}' \"$nonce\"\n",
            padding
        );
        std::fs::write(&script, script_content).unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let collector = CollectorProcess::from_command_line(script.to_str().unwrap()).unwrap();
        let nonce = [0xabu8; 32];
        // Must complete within COLLECT_TIMEOUT (60 s), not deadlock.
        let out = collector.collect(&nonce).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].arch, "HOPPER");
        assert_eq!(out[0].nonce, "ab".repeat(32));
    }
}
