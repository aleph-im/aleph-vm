# NVIDIA CC on SEV-SNP (aleph-vm half) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a CRN pass one NVIDIA GPU in confidential-computing mode into a measured SEV-SNP V-PROGRAM guest, verify the GPU in the guest at boot, and serve nonce-bound GPU evidence to clients over the attested TLS channel.

**Architecture:** Five stacked PRs off `origin/dev-2.1`, each independently testable without hardware: (A) the attest-agent grows a GPU evidence route fed by NVIDIA's collector process through a trait with a fake for tests; (B) the daemon probes each NVIDIA card's CC mode from a BAR0 register and advertises it through proto and the agent's capability endpoint; (C) the controller emits the SNP passthrough argv and the daemon's fail-closed gate opens only for CC-mode cards; (D) the Nix flake gains a `gpuImage` flavor carrying the open kernel modules, the raw driver userland, GSP firmware, NVIDIA's libnvat verifier and a fail-closed `init-gpu.sh`; (E) the runtime manifest and bundle gain a `gpu` block and the agent resolves a V-PROGRAM's confidential GPU against CC-mode cards. The aleph-message, aleph-rs and scheduler halves are separate plans.

**Tech Stack:** Rust 2024 (actix-web, serde, libc), Python 3.12+ (pydantic v2, aiohttp, pytest-asyncio), protobuf via `scripts/generate_proto.py`, Nix flakes on nixpkgs `nixos-26.05`, NVIDIA driver 595.71.05 open modules, NVIDIA attestation-sdk 1.2.2 (libnvat, nvattest), busybox init.

**Spec:** `docs/superpowers/specs/2026-09-04-nvidia-cc-design.md`

## Global Constraints

- Every fail-closed gate stays fail-closed: a GPU on an SNP spec is accepted only when its card reports `cc_mode == on` (spec 7.2); a V-PROGRAM with `gpus` whose manifest has no `gpu` block is `VmSetupError` (spec 5.2); init powers off on any GPU verification failure (spec 6.4).
- Non-GPU images and configs stay byte-identical: the base `image`, `composeImage`, `instanceImage` golden measurements in `nix/golden-measurements.json` must not move; the SNP argv with no GPU must equal the existing conformance fixtures; the `GpuDevice` inventory JSON for a card without a probed CC mode must equal today's bytes.
- GPU nonce scheme, verbatim: `SHA-256("aleph-gpu-nonce-v1\0" || served_public_key_raw || client_nonce)`, 32 bytes (spec 4.3). Domain constant `DOMAIN_GPU_NONCE = b"aleph-gpu-nonce-v1\x00"`.
- GPU route path, verbatim: `/.well-known/attestation/gpu?nonce=<hex>`; response `tee_type` is `"nvidia-cc"` (spec 4.4). The existing `/.well-known/attestation` response is untouched.
- BAR0 CC-mode register: offset `0x590` on Blackwell, `0x1182CC` on Hopper; bits `[1:0]`: `0b00` off, `0b01` on, `0b11` devtools (spec 7.1). Only `on` counts as confidential-capable; `devtools` is refused.
- SNP GPU argv, verbatim per card `i` (spec 7.2): `-device pcie-root-port,id=rp{i},bus=pcie.0,chassis={i+1}` then `-device vfio-pci,host={bdf},bus=rp{i},rombar=0`; once: `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string={mmio_mb}`. No `x-vga`, no `-cpu host`.
- Measured cmdline for the GPU runtime (spec 6.2): `console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash} workload_roothash={workload_roothash} swiotlb=262144 {verified_volumes}`; `swiotlb=262144` is fixed text, not a placeholder.
- GPU V-PROGRAM minimum memory: 2048 MiB (`GPU_VPROGRAM_MIN_MEMORY_MIB`), enforced at spec build (spec 6.2).
- Driver userland path inside the guest and the workload chroot: `/opt/nvidia/lib` (spec 6.3, decision 7). Raw (unpatched) driver `.so` files, so the workload's own libc loads them.
- Single GPU per V-PROGRAM (`max_length=1` on the message; the agent also refuses more than one).
- No em-dashes anywhere; no references to design docs or decision numbers inside code comments (inline the rationale).
- Commit messages: conventional prefix (`feat(...)`, `test(...)`, `docs(...)`), no `Co-Authored-By` trailer.
- Rust: `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings` clean in `rust/`; Python: `ruff check` and `mypy` clean per the repo's `pyproject.toml`. Python tests run with the venv described in `.claude` memory (`PYTHONPATH=$PWD/src`).

---

## File map

**PR A, attest-agent GPU route**
- Modify: `rust/crates/aleph-tee/src/report_data.rs` (add `DOMAIN_GPU_NONCE`, `gpu_nonce`)
- Create: `rust/crates/aleph-attest-agent/src/gpu.rs` (evidence types, `GpuEvidenceSource` trait, external collector process)
- Modify: `rust/crates/aleph-attest-agent/src/proxy.rs` (`AppState.gpu`, `gpu_attestation_endpoint`)
- Modify: `rust/crates/aleph-attest-agent/src/main.rs` (`--gpu-claims`, `--gpu-collector`, route)

**PR B, CC-mode probe and advertisement**
- Create: `rust/crates/supervisor-daemon/src/gpu_cc.rs`
- Modify: `rust/crates/supervisor-daemon/src/lspci.rs` (`GpuDevice.cc_mode`)
- Modify: `rust/crates/supervisor-daemon/src/service.rs` (`DaemonState.gpu_cc_modes`, probe in `get_host_info`, proto field)
- Modify: `proto/supervisor.proto` (`GpuDevice.cc_mode = 5`), regenerate Python bindings
- Modify: `src/aleph/vm/resources.py` (`GpuDevice.cc_mode`), `src/aleph/vm/supervisor_interface/wire/proto_convert.py`
- Modify: `src/aleph/vm/agent/resources.py` (`NvidiaCcDevice`, `NvidiaCcProperties`, `TeeProperties.nvidia_cc`, `get_machine_capability`)

**PR C, SNP passthrough argv and gate**
- Create: `rust/crates/supervisor-daemon/src/gpu_bar.rs`
- Modify: `rust/crates/supervisor-controller/src/config.rs` (`pci_mmio64_mb`), `rust/crates/supervisor-controller/src/qemu.rs` (`snp_gpu_args`, `build_snp_argv`)
- Create: `rust/crates/supervisor-controller/tests/conformance/controller_argv_snp/gpu.json`
- Modify: `rust/crates/supervisor-controller/tests/argv_parity_snp.rs`
- Modify: `rust/crates/supervisor-daemon/src/lifecycle.rs` (`snp_config_slice` gate, `SnpSlice.pci_mmio64_mb`), `rust/crates/supervisor-daemon/src/controller_config.rs` (written and parsed `pci_mmio64_mb`)

**PR D, Nix GPU flavor**
- Modify: `nix/kernel.nix` (`extraFragment`), Create: `nix/kernel-config-gpu.fragment`
- Create: `nix/nvidia.nix`, `nix/nvat.nix`, `nix/gpu-rootfs.nix`, `nix/init-gpu.sh`
- Modify: `nix/initrd.nix` (`withNvidia`), `nix/flake.nix` (gpu outputs), `nix/golden-measurements.json`, `nix/check-golden-measurements.sh`, `nix/boot-smoke.sh`, `.github/workflows/golden-measurements.yml`

**PR E, manifest, bundle, agent**
- Modify: `src/aleph/vm/vprogram/manifest.py` (`GpuRuntimeSpec`, `RuntimeManifest.gpu`), `src/aleph/vm/vprogram/bundle.py` (`BundleInfo.gpu`, flavor `gpu`), `scripts/vprogram_bundle.py`
- Modify: `src/aleph/vm/agent/vprogram_launch.py`, `src/aleph/vm/agent/capacity.py` (`resolve_confidential_gpus`), `src/aleph/vm/agent/run.py`
- Create: `docs/operators/nvidia-cc.md`; Modify: `docs/architecture/confidential.md`, `docs/architecture/divergences.md`

---

# PR A: attest-agent GPU evidence route

### Task 1: `gpu_nonce` scheme in aleph-tee

**Files:**
- Modify: `rust/crates/aleph-tee/src/report_data.rs`

**Interfaces:**
- Produces: `pub const DOMAIN_GPU_NONCE: &[u8]`, `pub fn gpu_nonce(served_public_key_raw: &[u8], client_nonce: &[u8]) -> [u8; 32]`. Used by Task 3 (agent) and mirrored in aleph-rs.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module of `rust/crates/aleph-tee/src/report_data.rs`:

```rust
    /// Pinned vector shared with the aleph-rs SDK mirror. Recompute with
    /// python: sha256(b"aleph-gpu-nonce-v1\x00" + b"served-key" + b"client-nonce").
    #[test]
    fn gpu_nonce_matches_pinned_vector() {
        let out = gpu_nonce(b"served-key", b"client-nonce");
        assert_eq!(
            hex::encode(out),
            "20e597c53ba9506fc210a99757a7aef042b6d907c5492fa4b3ae91497d5dc71b"
        );
    }

    #[test]
    fn gpu_nonce_is_bound_to_key_and_nonce() {
        let base = gpu_nonce(b"served-key", b"client-nonce");
        assert_eq!(
            hex::encode(gpu_nonce(b"served-key-B", b"client-nonce")),
            "f32959269c10e809bc5c5a828c61c34b430e51862040c2bb5d7e3bfbba68064f"
        );
        assert_eq!(
            hex::encode(gpu_nonce(b"served-key", b"client-nonce-2")),
            "f99366e40cf9bbed2cdc36dd2e900899f1c62818bef6fdc40ac56a012cdd04e1"
        );
        assert_ne!(base, gpu_nonce(b"served-key-B", b"client-nonce"));
    }

    /// A GPU nonce can never equal the first 32 bytes of either SNP scheme:
    /// different hash function (SHA-256 vs SHA-384) and different domain.
    #[test]
    fn gpu_nonce_never_collides_with_snp_report_data() {
        let key = b"served-key";
        let nonce = b"client-nonce";
        let gpu = gpu_nonce(key, nonce);
        assert_ne!(&gpu[..], &fresh_report_data(key, nonce)[..32]);
        assert_ne!(&gpu[..], &key_bound_report_data(key)[..32]);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd rust && cargo test -p aleph-tee report_data::tests::gpu_nonce`
Expected: compile error, `gpu_nonce` not found.

- [ ] **Step 3: Implement**

Add `use sha2::Sha256;` to the imports (keep `Sha384`), then after `DOMAIN_FRESH`:

```rust
/// Domain tag for the GPU evidence nonce
/// (`SHA-256(DOMAIN_GPU_NONCE || public_key || client_nonce)`). The trailing
/// `0x00` is a separator byte.
pub const DOMAIN_GPU_NONCE: &[u8] = b"aleph-gpu-nonce-v1\x00";

/// The 32-byte SPDM nonce the guest hands the GPU when a client asks for GPU
/// evidence: bound to the served TLS key (so a relayed GPU report cannot be
/// reused against another channel) and to the client's nonce (liveness).
/// The raw client nonce never reaches the GPU verbatim.
///
/// SHA-256 rather than SHA-384: the SPDM nonce field is exactly 32 bytes, and
/// truncating a 48-byte digest would invite a "which 32 bytes" mismatch
/// between guest and client. The verifying side (aleph-rs) mirrors this
/// function byte for byte.
pub fn gpu_nonce(served_public_key_raw: &[u8], client_nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_GPU_NONCE);
    hasher.update(served_public_key_raw);
    hasher.update(client_nonce);
    hasher.finalize().into()
}
```

Update the module doc comment's "two distinct report shapes" list with a third bullet: "gpu nonce: the SPDM nonce for GPU evidence, bound to the same key". Add `hex` as a dev-dependency of aleph-tee if it is not one already (check `Cargo.toml`; it is a regular dependency of the crate because `types.rs` uses `hex_serde`, so nothing to add).

- [ ] **Step 4: Run the tests**

Run: `cd rust && cargo test -p aleph-tee report_data`
Expected: all pass, including the three new ones.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/aleph-tee/src/report_data.rs
git commit -m "feat(tee): gpu_nonce, the key-bound SPDM nonce scheme for GPU evidence"
```

---

### Task 2: external GPU evidence collector in the attest-agent

**Files:**
- Create: `rust/crates/aleph-attest-agent/src/gpu.rs`
- Modify: `rust/crates/aleph-attest-agent/src/main.rs` (add `mod gpu;` only)

**Why an external process:** the attest-agent is a static musl binary and the measured initrd refuses anything dynamically linked, so it cannot dlopen NVIDIA's glibc `libnvidia-ml.so`. NVIDIA's own `nvattest collect-evidence` (in the GPU rootfs, Task 12) already emits the exact per-GPU evidence JSON the route serves, so the agent runs it as a child process and parses its output. No new dependencies, so the agent's `Cargo.lock` and the base image measurement do not move in this PR.

**Interfaces:**
- Produces:
  - `pub struct GpuEvidence { pub arch: String, pub nonce: String, pub evidence: String, pub certificate: String }` (serde Serialize + Deserialize; `nonce` hex, `evidence` and `certificate` base64, exactly the `nvattest collect-evidence --format json` `evidences[]` entry shape)
  - `pub trait GpuEvidenceSource: Send + Sync { fn collect(&self, nonce: &[u8; 32]) -> anyhow::Result<Vec<GpuEvidence>>; }`
  - `pub struct CollectorProcess { pub program: String, pub args: Vec<String> }` with `pub fn from_command_line(command: &str) -> anyhow::Result<Self>` (whitespace-split; the nonce hex is appended as the final argument at collect time) and `pub fn parse_output(stdout: &[u8], expected_nonce_hex: &str) -> anyhow::Result<Vec<GpuEvidence>>`; implements `GpuEvidenceSource`.
  - `pub const COLLECT_TIMEOUT: Duration = Duration::from_secs(60)`.

- [ ] **Step 1: Write the failing tests**

Create `rust/crates/aleph-attest-agent/src/gpu.rs` with only the test module first:

```rust
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
        let out = CollectorProcess::parse_output(ONE_GPU.replace("NONCE", &nonce).as_bytes(), &nonce).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].arch, "BLACKWELL");
        assert_eq!(out[0].evidence, "EeAB");
    }

    #[test]
    fn parse_output_rejects_a_foreign_nonce() {
        let nonce = "ab".repeat(32);
        let err = CollectorProcess::parse_output(ONE_GPU.replace("NONCE", &"cd".repeat(32)).as_bytes(), &nonce).unwrap_err();
        assert!(err.to_string().contains("nonce"), "{err}");
    }

    #[test]
    fn parse_output_rejects_a_failed_collection() {
        let nonce = "ab".repeat(32);
        let failed = ONE_GPU.replace("NONCE", &nonce).replace("\"result_code\":0", "\"result_code\":7");
        assert!(CollectorProcess::parse_output(failed.as_bytes(), &nonce).is_err());
        let empty = r#"{"evidences":[],"result_code":0,"result_message":"Ok"}"#;
        assert!(CollectorProcess::parse_output(empty.as_bytes(), &nonce).is_err(), "no GPU is an error");
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
}
```

Add `tempfile = "3"` under `[dev-dependencies]` in the agent's `Cargo.toml` if it is not already there (dev-dependencies do not enter the measured binary, but they do enter `Cargo.lock`; check `git diff Cargo.lock` and mention it in the report if the lock changed).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd rust/crates/aleph-attest-agent && cargo test gpu::`
Expected: compile errors for every missing item.

- [ ] **Step 3: Implement the module**

Above the test module:

```rust
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
        Ok(Self { program, args: parts.collect() })
    }

    /// Parse the collector's stdout, requiring a zero result code, at least
    /// one device, and every device answering exactly the nonce we asked
    /// for: a collector that answered a different nonce (a stale or foreign
    /// report) is a failure, never a substitution.
    pub fn parse_output(stdout: &[u8], expected_nonce_hex: &str) -> Result<Vec<GpuEvidence>> {
        let output: CollectorOutput = serde_json::from_slice(stdout).context("collector output is not the expected JSON")?;
        if output.result_code != 0 {
            bail!("collector failed: result_code {} ({})", output.result_code, output.result_message);
        }
        if output.evidences.is_empty() {
            bail!("collector reported no GPU");
        }
        for (index, evidence) in output.evidences.iter().enumerate() {
            if !evidence.nonce.eq_ignore_ascii_case(expected_nonce_hex) {
                bail!("GPU {index} evidence answers nonce {} instead of {expected_nonce_hex}", evidence.nonce);
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
        let started = std::time::Instant::now();
        loop {
            if child.try_wait().context("waiting for the GPU collector")?.is_some() {
                break;
            }
            if started.elapsed() > COLLECT_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                bail!("GPU collector exceeded {COLLECT_TIMEOUT:?}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let output = child.wait_with_output().context("reading the GPU collector output")?;
        if !output.status.success() {
            // stderr stays in the guest log; the caller only learns it failed.
            tracing::error!(status = %output.status, stderr = %String::from_utf8_lossy(&output.stderr), "GPU collector failed");
            bail!("GPU collector exit status {}", output.status);
        }
        Self::parse_output(&output.stdout, &nonce_hex)
    }
}
```

Add `mod gpu;` to `main.rs`. `hex`, `serde`, `serde_json`, `anyhow` and `tracing` are already dependencies.

- [ ] **Step 4: Run the tests**

Run: `cd rust/crates/aleph-attest-agent && cargo test gpu::`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/aleph-attest-agent/Cargo.toml rust/crates/aleph-attest-agent/Cargo.lock rust/crates/aleph-attest-agent/src/gpu.rs rust/crates/aleph-attest-agent/src/main.rs
git commit -m "feat(attest-agent): GPU evidence source that runs NVIDIA's collector with the derived nonce"
```

---

### Task 3: GPU attestation route and `--gpu-claims` / `--gpu-collector`

**Files:**
- Modify: `rust/crates/aleph-attest-agent/src/proxy.rs`, `rust/crates/aleph-attest-agent/src/main.rs`

**Interfaces:**
- Consumes: `aleph_tee::report_data::gpu_nonce` (Task 1), `gpu::{GpuEvidence, GpuEvidenceSource, CollectorProcess}` (Task 2).
- Produces: `pub struct GpuState { pub source: Box<dyn GpuEvidenceSource>, pub boot_claims: serde_json::Value, pub lock: tokio::sync::Mutex<()> }`, `AppState.gpu: Option<Arc<GpuState>>`, `pub async fn gpu_attestation_endpoint(...)`, response `GpuAttestationResponse { tee_type, client_nonce, gpus, boot_claims }`. CLI: `--gpu-claims <PATH>` and `--gpu-collector <COMMAND LINE>`, both required together.

- [ ] **Step 1: Write the failing tests**

In `proxy.rs` `tests` module, after the existing `attest` helper, add:

```rust
    struct FakeGpu;
    impl crate::gpu::GpuEvidenceSource for FakeGpu {
        fn collect(&self, nonce: &[u8; 32]) -> anyhow::Result<Vec<crate::gpu::GpuEvidence>> {
            Ok(vec![crate::gpu::GpuEvidence {
                arch: "BLACKWELL".into(),
                nonce: hex::encode(nonce),
                evidence: "ZXZpZGVuY2U=".into(),
                certificate: "Y2VydA==".into(),
            }])
        }
    }

    fn gpu_state(gpu: Option<Arc<GpuState>>) -> web::Data<AppState> {
        web::Data::new(AppState {
            backend: Arc::new(MockBackend),
            served_public_key_raw: b"served-key".to_vec(),
            upstream: "http://127.0.0.1:1".into(),
            http_client: reqwest::Client::new(),
            gpu,
        })
    }

    async fn gpu_attest(state: web::Data<AppState>, nonce: &str) -> (StatusCode, serde_json::Value) {
        let query = web::Query(AttestationQuery { nonce: nonce.to_string() });
        let resp = gpu_attestation_endpoint(state, query).await;
        let status = resp.status();
        let body = to_bytes(resp.into_body()).await.unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[actix_web::test]
    async fn gpu_route_derives_the_nonce_from_key_and_client_nonce() {
        let state = gpu_state(Some(Arc::new(GpuState {
            source: Box::new(FakeGpu),
            boot_claims: serde_json::json!([{"measres": "Success"}]),
            lock: tokio::sync::Mutex::new(()),
        })));
        let client_nonce = hex::encode(b"client-nonce");
        let (status, body) = gpu_attest(state, &client_nonce).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["tee_type"], "nvidia-cc");
        assert_eq!(body["client_nonce"], client_nonce);
        // Pinned in aleph-tee's report_data tests: gpu_nonce(b"served-key", b"client-nonce").
        assert_eq!(
            body["gpus"][0]["nonce"],
            "20e597c53ba9506fc210a99757a7aef042b6d907c5492fa4b3ae91497d5dc71b"
        );
        assert_eq!(body["gpus"][0]["arch"], "BLACKWELL");
        assert_eq!(body["boot_claims"][0]["measres"], "Success");
    }

    #[actix_web::test]
    async fn gpu_route_is_404_on_a_runtime_without_gpu_attestation() {
        let (status, body) = gpu_attest(gpu_state(None), "00").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "no gpu attestation on this runtime");
    }

    #[actix_web::test]
    async fn gpu_route_bounds_and_decodes_the_nonce_like_the_snp_route() {
        let state = gpu_state(Some(Arc::new(GpuState {
            source: Box::new(FakeGpu),
            boot_claims: serde_json::Value::Null,
            lock: tokio::sync::Mutex::new(()),
        })));
        let (status, _) = gpu_attest(state.clone(), &"a".repeat(MAX_NONCE_LEN * 2 + 2)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let (status, _) = gpu_attest(state, "zz").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
```

Also fix the existing test constructor of `AppState` in this module (search for `AppState {` in the tests) to add `gpu: None`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd rust/crates/aleph-attest-agent && cargo test proxy::`
Expected: compile errors, `GpuState` and `gpu_attestation_endpoint` missing.

- [ ] **Step 3: Implement the route**

In `proxy.rs`:

```rust
use aleph_tee::report_data::gpu_nonce;
use serde::Serialize;

use crate::gpu::{GpuEvidence, GpuEvidenceSource};

/// GPU attestation state, present only when init handed the agent the
/// claims its boot-time verification produced (`--gpu-claims`) and the
/// collector command (`--gpu-collector`).
pub struct GpuState {
    pub source: Box<dyn GpuEvidenceSource>,
    /// The per-GPU claims NVIDIA's local verifier produced at boot. Served
    /// as information for the client; nothing in it replaces a client-side
    /// cryptographic check.
    pub boot_claims: serde_json::Value,
    /// One SPDM exchange at a time: concurrent callers queue.
    pub lock: tokio::sync::Mutex<()>,
}

// add to AppState:
    /// GPU evidence source and boot claims; `None` on runtimes without a GPU.
    pub gpu: Option<Arc<GpuState>>,

#[derive(Serialize)]
pub struct GpuAttestationResponse {
    pub tee_type: &'static str,
    pub client_nonce: String,
    pub gpus: Vec<GpuEvidence>,
    pub boot_claims: serde_json::Value,
}

/// Decode and bound the hex nonce shared by both attestation routes.
fn decode_nonce(nonce_hex: &str) -> Result<Vec<u8>, HttpResponse> {
    if nonce_hex.len() > MAX_NONCE_LEN * 2 {
        return Err(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("nonce too long: at most {MAX_NONCE_LEN} bytes ({} hex chars)", MAX_NONCE_LEN * 2)
        })));
    }
    hex::decode(nonce_hex).map_err(|e| {
        HttpResponse::BadRequest().json(serde_json::json!({"error": format!("invalid hex nonce: {e}")}))
    })
}

/// GET `/.well-known/attestation/gpu?nonce=<hex>`
///
/// Returns fresh GPU evidence for every attached GPU, each answering the
/// SPDM nonce `gpu_nonce(served_key, client_nonce)`. The client recomputes
/// that nonce, so a report relayed from another channel or another request
/// cannot match. Served over the same attested TLS channel as the SNP
/// report, which is what makes the document guest-authored.
pub async fn gpu_attestation_endpoint(
    state: web::Data<AppState>,
    query: web::Query<AttestationQuery>,
) -> HttpResponse {
    let Some(gpu) = state.gpu.as_ref() else {
        return HttpResponse::NotFound()
            .json(serde_json::json!({"error": "no gpu attestation on this runtime"}));
    };
    let client_nonce = match decode_nonce(&query.nonce) {
        Ok(n) => n,
        Err(resp) => return resp,
    };
    let nonce = gpu_nonce(&state.served_public_key_raw, &client_nonce);
    let _serialized = gpu.lock.lock().await;
    // The collector is a blocking child process; keep it off the async workers.
    let gpu_for_task = Arc::clone(gpu);
    let collected = web::block(move || gpu_for_task.source.collect(&nonce)).await;
    match collected {
        Ok(Ok(gpus)) => HttpResponse::Ok().json(GpuAttestationResponse {
            tee_type: "nvidia-cc",
            client_nonce: query.nonce.clone(),
            gpus,
            boot_claims: gpu.boot_claims.clone(),
        }),
        Ok(Err(e)) => {
            tracing::error!("gpu evidence collection failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "gpu evidence collection failed"}))
        }
        Err(e) => {
            tracing::error!("gpu evidence task failed: {e:#}");
            HttpResponse::InternalServerError()
                .json(serde_json::json!({"error": "gpu evidence collection failed"}))
        }
    }
}
```

Refactor `attestation_endpoint` to use `decode_nonce` so both routes share the bound (its existing tests keep passing). `web::block` needs a `'static` closure, hence the `Arc` clone; `Box<dyn GpuEvidenceSource>` is `Send + Sync` by the trait bound.

- [ ] **Step 4: Wire the CLI**

In `main.rs`:

```rust
use crate::gpu::CollectorProcess;
use crate::proxy::{GpuState, gpu_attestation_endpoint};

// in Cli:
    /// Path to the per-GPU claims JSON NVIDIA's local verifier wrote at boot.
    /// Enables the GPU attestation route; absent on runtimes without a GPU.
    /// Requires --gpu-collector.
    #[arg(long, requires = "gpu_collector")]
    gpu_claims: Option<std::path::PathBuf>,

    /// Command line that collects GPU evidence and prints nvattest's
    /// collect-evidence JSON; the derived nonce (hex) is appended as the last
    /// argument. Requires --gpu-claims.
    #[arg(long, requires = "gpu_claims")]
    gpu_collector: Option<String>,
```

Before building `app_state`:

```rust
    let gpu = match (&cli.gpu_claims, &cli.gpu_collector) {
        (Some(path), Some(command)) => {
            let raw = std::fs::read(path)
                .with_context(|| format!("cannot read --gpu-claims {}", path.display()))?;
            let boot_claims: serde_json::Value =
                serde_json::from_slice(&raw).context("--gpu-claims is not JSON")?;
            let source = CollectorProcess::from_command_line(command).context("--gpu-collector")?;
            info!(program = %source.program, "GPU attestation route enabled");
            Some(Arc::new(GpuState {
                source: Box::new(source),
                boot_claims,
                lock: tokio::sync::Mutex::new(()),
            }))
        }
        _ => None,
    };
```

Add `gpu` to the `AppState` literal, and the route:

```rust
            .route("/.well-known/attestation/gpu", web::get().to(gpu_attestation_endpoint))
```

A missing or unparsable claims file, or an empty collector, exits non-zero on purpose: init only passes these flags after verification succeeded, so any of those is a broken image, and a broken image must not serve an attested endpoint.

- [ ] **Step 5: Run all agent tests, fmt, clippy**

Run: `cd rust/crates/aleph-attest-agent && cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test`
Expected: clean, all tests pass including the three new route tests.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/aleph-attest-agent/src
git commit -m "feat(attest-agent): /.well-known/attestation/gpu, nonce-bound NVIDIA evidence over the attested channel"
```

---

# PR B: CC-mode probe and capability advertisement

### Task 4: `gpu_cc.rs`, architecture table and BAR0 register read

**Files:**
- Create: `rust/crates/supervisor-daemon/src/gpu_cc.rs`
- Modify: `rust/crates/supervisor-daemon/src/lib.rs` or `main.rs` (wherever modules are declared; add `pub mod gpu_cc;`), `rust/crates/supervisor-daemon/src/error.rs` (`DaemonError::GpuProbe(String)`)

**Interfaces:**
- Produces: `pub enum CcMode { On, Devtools, Off }` (serde `rename_all = "lowercase"`, `Display` gives `on`/`devtools`/`off`), `pub enum GpuArch { Hopper, Blackwell }`, `pub fn arch_from_device_id(device_id: &str) -> Option<GpuArch>`, `pub fn bar0_register_offset(arch: GpuArch) -> u64`, `pub fn cc_mode_from_register(value: u32) -> Option<CcMode>`, `pub fn read_bar0_u32(resource0: &Path, offset: u64) -> Result<u32, DaemonError>`, `pub fn sysfs_device_dir(pci_host: &str) -> PathBuf`, `pub fn probe_cc_mode(pci_host: &str, device_id: &str) -> Result<Option<CcMode>, DaemonError>`.

- [ ] **Step 1: Write the failing tests**

Create `gpu_cc.rs` with the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_ranges_follow_gpu_admin_tools() {
        // gpu/devid_chips.py in NVIDIA/gpu-admin-tools, Blackwell rows.
        assert_eq!(arch_from_device_id("10de:2b85"), Some(GpuArch::Blackwell)); // GB202, RTX PRO 6000
        assert_eq!(arch_from_device_id("10de:2901"), Some(GpuArch::Blackwell)); // GB100
        assert_eq!(arch_from_device_id("10de:2331"), Some(GpuArch::Hopper)); // GH100, H100 PCIe
        assert_eq!(arch_from_device_id("10de:20f1"), None); // GA100, no CC
        assert_eq!(arch_from_device_id("1002:744c"), None); // AMD
        assert_eq!(arch_from_device_id("garbage"), None);
    }

    #[test]
    fn register_bits_decode_the_three_modes() {
        assert_eq!(cc_mode_from_register(0x0000_0000), Some(CcMode::Off));
        assert_eq!(cc_mode_from_register(0x0000_0001), Some(CcMode::On));
        assert_eq!(cc_mode_from_register(0x0000_0003), Some(CcMode::Devtools));
        assert_eq!(cc_mode_from_register(0x0000_0002), None, "reserved encoding");
        // Higher bits (BMSAI, boot status) are ignored.
        assert_eq!(cc_mode_from_register(0xffff_ff01), Some(CcMode::On));
    }

    #[test]
    fn register_offsets_per_architecture() {
        assert_eq!(bar0_register_offset(GpuArch::Blackwell), 0x590);
        assert_eq!(bar0_register_offset(GpuArch::Hopper), 0x1182cc);
    }

    #[test]
    fn sysfs_path_adds_the_pci_domain() {
        assert_eq!(
            sysfs_device_dir("06:00.0"),
            PathBuf::from("/sys/bus/pci/devices/0000:06:00.0")
        );
        assert_eq!(
            sysfs_device_dir("0000:06:00.0"),
            PathBuf::from("/sys/bus/pci/devices/0000:06:00.0")
        );
    }

    #[test]
    fn bar0_read_maps_the_page_and_reads_little_endian() {
        // A regular file stands in for resource0: mmap works the same way.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resource0");
        let mut bytes = vec![0u8; 0x2000];
        bytes[0x590..0x594].copy_from_slice(&0x0000_0101u32.to_le_bytes());
        bytes[0x1182cc % 0x2000..][..4].copy_from_slice(&3u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read_bar0_u32(&path, 0x590).unwrap(), 0x101);
        assert_eq!(cc_mode_from_register(read_bar0_u32(&path, 0x590).unwrap()), Some(CcMode::On));
        // Past the end of the mapping is a clean error, never a fault.
        assert!(read_bar0_u32(&path, 0x4000).is_err());
    }

    #[test]
    fn cc_mode_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&CcMode::On).unwrap(), "\"on\"");
        assert_eq!(CcMode::Devtools.to_string(), "devtools");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-daemon gpu_cc::`
Expected: compile errors.

- [ ] **Step 3: Implement**

```rust
//! NVIDIA confidential-computing mode probe.
//!
//! A GPU in CC mode refuses plaintext DMA and answers SPDM attestation; the
//! CRN must know which cards are in that mode before advertising them as
//! confidential capacity. The mode lives in a BAR0 register that NVIDIA's
//! gpu-admin-tools reads the same way (offset 0x590 on Blackwell, 0x1182CC
//! on Hopper, bits [1:0]). Reading it needs no driver: the card is bound to
//! vfio-pci, and the register is reachable through the sysfs resource file.
//! The read only ever runs on a card no VM owns, so it never races a guest.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::DaemonError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CcMode {
    On,
    Devtools,
    Off,
}

impl fmt::Display for CcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CcMode::On => "on",
            CcMode::Devtools => "devtools",
            CcMode::Off => "off",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuArch {
    Hopper,
    Blackwell,
}

/// (first, last, arch) PCI device-id ranges. Blackwell rows are copied from
/// NVIDIA/gpu-admin-tools `gpu/devid_chips.py`; the Hopper row is the GH100
/// block (H100/H200 PCIe, SXM and NVL ids all fall in 0x2300..0x237f).
const DEVICE_ID_RANGES: &[(u16, u16, GpuArch)] = &[
    (0x2300, 0x237f, GpuArch::Hopper),
    (0x2900, 0x297f, GpuArch::Blackwell), // gb100
    (0x2980, 0x29ff, GpuArch::Blackwell), // gb102
    (0x3180, 0x31ff, GpuArch::Blackwell), // gb110
    (0x3200, 0x327f, GpuArch::Blackwell), // gb112
    (0x2b80, 0x2bff, GpuArch::Blackwell), // gb202 (RTX PRO 6000 Blackwell)
    (0x2c00, 0x2c7f, GpuArch::Blackwell), // gb203
    (0x2f00, 0x2f7f, GpuArch::Blackwell), // gb205
    (0x2d00, 0x2d7f, GpuArch::Blackwell), // gb206
    (0x2d80, 0x2dff, GpuArch::Blackwell), // gb207
];

/// `vendor:device` -> architecture, NVIDIA cards with a CC mode only.
pub fn arch_from_device_id(device_id: &str) -> Option<GpuArch> {
    let (vendor, device) = device_id.split_once(':')?;
    if vendor != "10de" {
        return None;
    }
    let device = u16::from_str_radix(device, 16).ok()?;
    DEVICE_ID_RANGES
        .iter()
        .find(|(first, last, _)| (*first..=*last).contains(&device))
        .map(|(_, _, arch)| *arch)
}

pub fn bar0_register_offset(arch: GpuArch) -> u64 {
    match arch {
        GpuArch::Blackwell => 0x590,
        GpuArch::Hopper => 0x1182cc,
    }
}

/// Bits [1:0] of the CC register. `0b10` is reserved and yields None.
pub fn cc_mode_from_register(value: u32) -> Option<CcMode> {
    match value & 0x3 {
        0b00 => Some(CcMode::Off),
        0b01 => Some(CcMode::On),
        0b11 => Some(CcMode::Devtools),
        _ => None,
    }
}

pub fn sysfs_device_dir(pci_host: &str) -> PathBuf {
    let full = if pci_host.matches(':').count() == 1 {
        format!("0000:{pci_host}")
    } else {
        pci_host.to_string()
    };
    PathBuf::from("/sys/bus/pci/devices").join(full)
}

/// Read one 32-bit register from a BAR0 mapping. sysfs `resourceN` files
/// only support mmap (read() is refused for memory BARs), so map the page
/// holding the offset and do a volatile read.
pub fn read_bar0_u32(resource0: &Path, offset: u64) -> Result<u32, DaemonError> {
    use std::os::fd::AsRawFd as _;
    let file = std::fs::File::open(resource0).map_err(|error| {
        DaemonError::GpuProbe(format!("cannot open {}: {error}", resource0.display()))
    })?;
    let len = file
        .metadata()
        .map_err(|error| DaemonError::GpuProbe(format!("cannot stat {}: {error}", resource0.display())))?
        .len();
    if offset + 4 > len {
        return Err(DaemonError::GpuProbe(format!(
            "register offset {offset:#x} is past the end of {} ({len} bytes)",
            resource0.display()
        )));
    }
    let page = 4096u64;
    let base = offset & !(page - 1);
    let within = (offset - base) as usize;
    // SAFETY: a read-only shared mapping of one page of an open file; the
    // pointer is checked against MAP_FAILED, the read stays inside the page,
    // and the mapping is released before returning.
    unsafe {
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            page as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            base as libc::off_t,
        );
        if mapped == libc::MAP_FAILED {
            return Err(DaemonError::GpuProbe(format!(
                "mmap of {} at {base:#x} failed: {}",
                resource0.display(),
                std::io::Error::last_os_error()
            )));
        }
        let value = std::ptr::read_volatile(mapped.cast::<u8>().add(within).cast::<u32>());
        libc::munmap(mapped, page as usize);
        Ok(u32::from_le(value))
    }
}

/// The CC mode of one vfio-bound NVIDIA card, `None` for cards without a
/// CC mode (other vendors, pre-Hopper) or a reserved register encoding.
pub fn probe_cc_mode(pci_host: &str, device_id: &str) -> Result<Option<CcMode>, DaemonError> {
    let Some(arch) = arch_from_device_id(device_id) else {
        return Ok(None);
    };
    let resource0 = sysfs_device_dir(pci_host).join("resource0");
    let value = read_bar0_u32(&resource0, bar0_register_offset(arch))?;
    Ok(cc_mode_from_register(value))
}
```

Add to `error.rs` `DaemonError`:

```rust
    #[error("GPU probe failed: {0}")]
    GpuProbe(String),
```

(Match the enum's existing derive style; if it is a hand-written `Display`, add the arm there.)

- [ ] **Step 4: Run the tests**

Run: `cd rust && cargo test -p supervisor-daemon gpu_cc::`
Expected: 6 passed.

- [ ] **Step 5: Commit**

```bash
git add rust/crates/supervisor-daemon/src/gpu_cc.rs rust/crates/supervisor-daemon/src/error.rs rust/crates/supervisor-daemon/src/lib.rs
git commit -m "feat(daemon): probe NVIDIA CC mode from the BAR0 register gpu-admin-tools reads"
```

---

### Task 5: `cc_mode` on the inventory, the proto and the Python model

**Files:**
- Modify: `rust/crates/supervisor-daemon/src/lspci.rs`, `rust/crates/supervisor-daemon/src/service.rs`, `proto/supervisor.proto`, `src/aleph/vm/resources.py`, `src/aleph/vm/supervisor_interface/wire/proto_convert.py`, regenerated `src/aleph/vm/supervisor_interface/wire/_pb/*`
- Test: `tests/supervisor/test_proto_convert.py`, `tests/supervisor/test_host_gpu_detail.py`

**Interfaces:**
- Produces: `GpuDevice.cc_mode: Option<CcMode>` (Rust, `skip_serializing_if = "Option::is_none"`, serialized last); proto `GpuDevice.cc_mode = 5` (string, empty = unknown); Python `GpuDevice.cc_mode: Literal["on", "devtools", "off"] | None = None`; `DaemonState.gpu_cc_modes: std::sync::Mutex<HashMap<String, CcMode>>`; `pub fn cc_mode_of(state: &DaemonState, pci_host: &str) -> Option<CcMode>`.

- [ ] **Step 1: Write the failing Rust tests**

In `lspci.rs` tests add:

```rust
    #[test]
    fn a_card_without_a_probed_cc_mode_serializes_exactly_as_before() {
        let device = parse_gpu_device_info(NVIDIA_VGA_LINE, &mut vfio_everywhere).unwrap().unwrap();
        assert_eq!(device.cc_mode, None);
        let json = serde_json::to_string(&device).unwrap();
        assert!(!json.contains("cc_mode"), "absent mode must not change the inventory bytes: {json}");
    }

    #[test]
    fn a_probed_cc_mode_is_appended_last() {
        let mut device = parse_gpu_device_info(NVIDIA_VGA_LINE, &mut vfio_everywhere).unwrap().unwrap();
        device.cc_mode = Some(crate::gpu_cc::CcMode::On);
        let json = serde_json::to_string(&device).unwrap();
        assert!(json.ends_with(r#""device_id":"10de:2b85","cc_mode":"on"}"#), "{json}");
    }
```

In `service.rs` tests (find the existing `get_host_info` tests; there is a harness building a `DaemonState`), add one test that seeds `state.gpu_cc_modes` with `("06:00.0", CcMode::On)` for an inventory card, calls `get_host_info`, and asserts `gpu_inventory_json` contains `"cc_mode":"on"` while a second card without an entry has no `cc_mode` key. Also assert `available_gpus_json` carries the same.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-daemon lspci:: service::`
Expected: `cc_mode` field missing.

- [ ] **Step 3: Implement Rust**

`lspci.rs`, on `GpuDevice`, after `device_id`:

```rust
    /// NVIDIA confidential-computing mode, probed from BAR0 for idle
    /// NVIDIA cards (gpu_cc.rs); `None` when not NVIDIA, not probed yet, or
    /// the probe failed. Skipped when absent so a fleet without CC cards
    /// keeps today's inventory bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cc_mode: Option<crate::gpu_cc::CcMode>,
```

Set `cc_mode: None` in `parse_gpu_device_info`. `Hash`/`Eq` derives keep working (`CcMode` derives both).

`service.rs`: add `pub gpu_cc_modes: std::sync::Mutex<HashMap<String, crate::gpu_cc::CcMode>>` to `DaemonState`, initialized empty wherever the state is constructed (grep `DaemonState {`). Add:

```rust
/// The cached CC mode of one card, if it has been probed.
pub fn cc_mode_of(state: &DaemonState, pci_host: &str) -> Option<crate::gpu_cc::CcMode> {
    state.gpu_cc_modes.lock().expect("gpu_cc_modes poisoned").get(pci_host).copied()
}

/// Probe every NVIDIA card no VM owns and remember the answer. A card that
/// becomes attached keeps its last value (the register is never read under
/// a guest); a probe error is logged and leaves the card unknown, which
/// advertises nothing. Runs on the blocking pool: mmap of a BAR is a
/// syscall against device memory.
fn refresh_cc_modes(state: &DaemonState, attached: &HashSet<String>) {
    for gpu in &state.host.gpus {
        if attached.contains(&gpu.pci_host) || gpu.vendor != "NVIDIA" {
            continue;
        }
        match crate::gpu_cc::probe_cc_mode(&gpu.pci_host, &gpu.device_id) {
            Ok(Some(mode)) => {
                state.gpu_cc_modes.lock().expect("gpu_cc_modes poisoned").insert(gpu.pci_host.clone(), mode);
            }
            Ok(None) => {}
            Err(error) => tracing::warn!(pci_host = %gpu.pci_host, %error, "GPU CC mode probe failed"),
        }
    }
}
```

In `get_host_info`, after computing `attached`: run `refresh_cc_modes` via `tokio::task::spawn_blocking` (clone what it needs: `DaemonState` is behind an `Arc` in the service, so clone the `Arc` and the `attached` set). Then build the inventory JSON from a copy of `state.host.gpus` with `cc_mode` filled from `cc_mode_of`, for both `gpu_inventory_json` and `available_gpus_json` (replace the direct `gpu_json(&self.state.host.gpus)` and the `available` filter with the annotated copies). Keep `gpu_json` as the serializer. In the VmInfo mapping (`pb::GpuDevice` at the `.map(|gpu| pb::GpuDevice {` site) set `cc_mode: cc_mode_of(&self.state, &gpu.pci_host).map(|m| m.to_string()).unwrap_or_default()`.

- [ ] **Step 4: Proto and regeneration**

`proto/supervisor.proto`, in `message GpuDevice` add `string cc_mode = 5;  // NVIDIA confidential-computing mode: "on", "devtools", "off"; empty when unknown`. Run `python scripts/generate_proto.py` and `scripts/check_proto_clean.sh`. The Rust build regenerates from the proto through `build.rs` (verify with `cargo build -p supervisor-daemon`).

- [ ] **Step 5: Write the failing Python tests**

In `tests/supervisor/test_proto_convert.py` add:

```python
def test_gpu_device_cc_mode_round_trips():
    from aleph.vm.supervisor_interface.wire.proto_convert import gpu_device_from_pb, gpu_device_to_pb
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2 as pb

    msg = pb.GpuDevice(pci_host="06:00.0", device_id="10de:2b85", model="", supports_x_vga=False, cc_mode="on")
    device = gpu_device_from_pb(msg)
    assert device.cc_mode == "on"
    assert gpu_device_to_pb(device).cc_mode == "on"
    # Empty on the wire means unknown, never a mode.
    assert gpu_device_from_pb(pb.GpuDevice(pci_host="06:00.0")).cc_mode is None
```

In `tests/supervisor/test_host_gpu_detail.py` (or a new `test_gpu_cc_mode.py`) add:

```python
def test_inventory_gpu_accepts_and_defaults_cc_mode():
    from aleph.vm.resources import GpuDevice

    raw = {"vendor": "NVIDIA", "device_name": "GB202", "device_class": "0300", "pci_host": "06:00.0", "device_id": "10de:2b85"}
    assert GpuDevice.model_validate(raw).cc_mode is None
    assert GpuDevice.model_validate(raw | {"cc_mode": "on"}).cc_mode == "on"
    with pytest.raises(ValidationError):
        GpuDevice.model_validate(raw | {"cc_mode": "maybe"})
```

- [ ] **Step 6: Implement Python**

`src/aleph/vm/resources.py`: on `HostGPU` and `GpuDevice` add
`cc_mode: Literal["on", "devtools", "off"] | None = Field(default=None, description="NVIDIA confidential-computing mode when probed")`.
`proto_convert.py`: `gpu_device_to_pb` sets `cc_mode=gpu.cc_mode or ""`; `gpu_device_from_pb` sets `cc_mode=msg.cc_mode or None`. Check the `HostGPU` conversions in the same file (VmInfo gpus) and thread `cc_mode` the same way.

- [ ] **Step 7: Run everything**

Run: `cd rust && cargo fmt --all && cargo clippy --all-targets -- -D warnings && cargo test -p supervisor-daemon` then `pytest tests/supervisor/test_proto_convert.py tests/supervisor/test_host_gpu_detail.py tests/supervisor/test_agent_gpu_annotation.py -q`
Expected: all green; the pre-existing inventory-JSON parity tests still pass because absent modes serialize nothing.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto rust/crates/supervisor-daemon/src src/aleph/vm/resources.py src/aleph/vm/supervisor_interface tests/supervisor
git commit -m "feat(daemon): carry the probed CC mode on the GPU inventory, proto and agent model"
```

---

### Task 6: `tee.nvidia_cc` capability on the agent

**Files:**
- Modify: `src/aleph/vm/agent/resources.py`
- Test: `tests/supervisor/test_agent_capability_nvidia_cc.py` (new)

**Interfaces:**
- Consumes: `GpuDevice.cc_mode` (Task 5), `host_info.available_gpus` dicts from the supervisor client.
- Produces: `class NvidiaCcDevice(BaseModel): device_id: str; model: str | None`, `class NvidiaCcProperties(BaseModel): devices: list[NvidiaCcDevice]`, `TeeProperties.nvidia_cc: NvidiaCcProperties | None`, `def nvidia_cc_properties(available_gpus: list[dict], network_models: dict[str, str]) -> NvidiaCcProperties | None`, `async def get_machine_capability(supervisor) -> MachineCapability` (signature change: the supervisor client is passed in).

- [ ] **Step 1: Write the failing tests**

```python
"""tee.nvidia_cc is advertised only for cards probed in CC mode 'on', and
only when the host can launch SEV-SNP: a confidential GPU on a host that
cannot run a confidential guest is not a capability."""

import pytest

from aleph.vm.agent.resources import NvidiaCcProperties, nvidia_cc_properties


def _gpu(device_id: str, pci_host: str, cc_mode: str | None) -> dict:
    raw = {"vendor": "NVIDIA", "device_name": "GB202", "device_class": "0300", "pci_host": pci_host, "device_id": device_id}
    if cc_mode is not None:
        raw["cc_mode"] = cc_mode
    return raw


def test_only_on_mode_cards_are_listed():
    props = nvidia_cc_properties(
        [_gpu("10de:2b85", "06:00.0", "on"), _gpu("10de:2b85", "07:00.0", "devtools"), _gpu("10de:2b85", "08:00.0", None)],
        {"10de:2b85": "RTX PRO 6000"},
    )
    assert props == NvidiaCcProperties(devices=[{"device_id": "10de:2b85", "model": "RTX PRO 6000"}])


def test_no_on_mode_card_means_no_block():
    assert nvidia_cc_properties([_gpu("10de:2b85", "06:00.0", "off")], {}) is None
    assert nvidia_cc_properties([], {}) is None


@pytest.mark.asyncio
async def test_capability_gates_nvidia_cc_on_snp(mocker):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    from aleph.vm.agent import resources

    mocker.patch.object(resources, "_get_static_machine_capability", AsyncMock(return_value=SimpleNamespace(
        model_copy=lambda update: SimpleNamespace(**update)
    )))
    mocker.patch.object(resources, "check_amd_sev_snp_supported", return_value=False)
    mocker.patch.object(resources, "update_aggregate_settings", AsyncMock())
    mocker.patch.object(resources, "get_compatible_gpus", return_value=[])
    supervisor = SimpleNamespace(get_host_info=AsyncMock(return_value=SimpleNamespace(
        available_gpus=[_gpu("10de:2b85", "06:00.0", "on")]
    )))

    # No SNP launch capability: the GPU block is withheld even though a card is on.
    mocker.patch.object(resources, "get_snp_launch_capability", AsyncMock(return_value=SimpleNamespace(
        supported_vcpu_types=[], unavailable_reason="no qemu"
    )))
    capability = await resources.get_machine_capability(supervisor)
    assert capability.tee is None

    # With SNP, the block appears next to sev_snp.
    mocker.patch.object(resources, "get_snp_launch_capability", AsyncMock(return_value=SimpleNamespace(
        supported_vcpu_types=["EPYC-v4"], unavailable_reason=None
    )))
    capability = await resources.get_machine_capability(supervisor)
    assert capability.tee.sev_snp.supported_vcpu_types == ["EPYC-v4"]
    assert capability.tee.nvidia_cc.devices[0].device_id == "10de:2b85"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/supervisor/test_agent_capability_nvidia_cc.py -q`
Expected: ImportError on `nvidia_cc_properties`.

- [ ] **Step 3: Implement**

In `src/aleph/vm/agent/resources.py`:

```python
class NvidiaCcDevice(BaseModel):
    device_id: str = Field(description="vendor:device id of a card in NVIDIA CC mode")
    model: str | None = Field(default=None, description="GPU model name on Aleph Network")


class NvidiaCcProperties(BaseModel):
    """Cards probed in NVIDIA confidential-computing mode and free to attach."""

    devices: list[NvidiaCcDevice]


class TeeProperties(BaseModel):
    """TEE launch capability, keyed by platform so TDX and friends slot in later."""

    sev_snp: SevSnpProperties | None = None
    nvidia_cc: NvidiaCcProperties | None = None


def nvidia_cc_properties(available_gpus: list[dict], network_models: dict[str, str]) -> NvidiaCcProperties | None:
    """The confidential-GPU block: only cards whose probe said `on`.
    `devtools` lifts the profiling blocks and is not confidential; an
    unprobed card is unknown and advertises nothing."""
    devices = [
        NvidiaCcDevice(device_id=gpu["device_id"], model=network_models.get(gpu["device_id"]))
        for gpu in available_gpus
        if gpu.get("cc_mode") == "on"
    ]
    return NvidiaCcProperties(devices=devices) if devices else None
```

Change `get_machine_capability` to take `supervisor` and build `tee`:

```python
async def get_machine_capability(supervisor) -> MachineCapability:
    static = await _get_static_machine_capability()
    capability = await get_snp_launch_capability()
    tee = None
    if capability.supported_vcpu_types:
        host_info = await supervisor.get_host_info()
        await update_aggregate_settings()
        network_models = {gpu.device_id: gpu.model for gpu in get_compatible_gpus()}
        tee = TeeProperties(
            sev_snp=SevSnpProperties(supported_vcpu_types=capability.supported_vcpu_types),
            nvidia_cc=nvidia_cc_properties(list(host_info.available_gpus), network_models),
        )
    reason = capability.unavailable_reason if check_amd_sev_snp_supported() else None
    return static.model_copy(update={"tee": tee, "tee_unavailable_reason": reason})
```

Update `about_capability` to `get_machine_capability(request.app["supervisor"])` (rename the `_` parameter to `request`), and every other caller (`grep -rn get_machine_capability src tests`). The `MachineUsage.gpu` devices already carry `cc_mode` through `AnnotatedGpuDevice` since Task 5 added the field to `GpuDevice`.

- [ ] **Step 4: Run the tests**

Run: `pytest tests/supervisor/test_agent_capability_nvidia_cc.py tests/supervisor/test_resources.py tests/supervisor/test_agent_gpu_annotation.py -q && ruff check src tests && mypy src/aleph/vm/agent/resources.py`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/agent/resources.py tests/supervisor/test_agent_capability_nvidia_cc.py
git commit -m "feat(agent): advertise CC-mode NVIDIA cards as tee.nvidia_cc, gated on SNP launch capability"
```

---

# PR C: SNP passthrough argv and the daemon gate

### Task 7: `gpu_bar.rs`, the 64-bit MMIO window from sysfs

**Files:**
- Create: `rust/crates/supervisor-daemon/src/gpu_bar.rs` (+ `pub mod gpu_bar;`)

**Interfaces:**
- Produces: `pub fn parse_resource_file(contents: &str) -> Result<u64, DaemonError>` (bytes of 64-bit prefetchable memory BARs), `pub fn mmio64_window_mb(bar_bytes: u64) -> u64`, `pub fn gpu_mmio64_mb(pci_hosts: &[String]) -> Result<u64, DaemonError>` (reads `sysfs_device_dir(bdf)/resource` for each card and sums).

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // Captured from an RTX PRO 6000 Blackwell class card: BAR0 16 MiB 32-bit,
    // BAR1 128 GiB 64-bit prefetchable, BAR3 32 MiB 64-bit prefetchable, I/O
    // port BAR, expansion ROM.
    const RESOURCE: &str = "\
0x00000000f6000000 0x00000000f6ffffff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000002000000000 0x0000003fffffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000004000000000 0x0000004001ffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000000000000e000 0x000000000000e07f 0x0000000000040101
0x00000000f7000000 0x00000000f707ffff 0x0000000000046200
";

    #[test]
    fn sums_only_64bit_prefetchable_memory_bars() {
        let bytes = parse_resource_file(RESOURCE).unwrap();
        assert_eq!(bytes, 128 * (1 << 30) + 32 * (1 << 20));
    }

    #[test]
    fn window_is_next_power_of_two_doubled_with_a_floor() {
        assert_eq!(mmio64_window_mb(128 * (1 << 30) + 32 * (1 << 20)), 512 * 1024);
        assert_eq!(mmio64_window_mb(0), 1024);
        assert_eq!(mmio64_window_mb(256 * (1 << 20)), 1024);
        assert_eq!(mmio64_window_mb(3 * (1 << 30)), 8 * 1024);
    }

    #[test]
    fn malformed_lines_are_errors() {
        assert!(parse_resource_file("0x1 0x2\n").is_err());
        assert!(parse_resource_file("zz 0x2 0x3\n").is_err());
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cd rust && cargo test -p supervisor-daemon gpu_bar::`

- [ ] **Step 3: Implement**

```rust
//! Size the guest's 64-bit PCI MMIO window from the card's real BARs.
//!
//! OVMF places 64-bit BARs inside a window whose size it reads from the
//! `opt/ovmf/X-PciMmio64Mb` fw_cfg entry. A data-center GPU's BAR1 is tens
//! of gigabytes, far beyond OVMF's default, and the next SKU's differs, so
//! the window follows the hardware instead of a constant. fw_cfg values are
//! not measurement inputs, which is what lets the window vary per card
//! without moving the launch digest.

use crate::error::DaemonError;

const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_PREFETCH: u64 = 0x0000_2000;
const IORESOURCE_MEM_64: u64 = 0x0010_0000;
const MIN_WINDOW_MB: u64 = 1024;

/// Sum the sizes of the 64-bit prefetchable memory BARs listed in a sysfs
/// `resource` file (`start end flags` per line, hex).
pub fn parse_resource_file(contents: &str) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for line in contents.lines().filter(|l| !l.trim().is_empty()) {
        let mut fields = line.split_whitespace().map(|f| {
            u64::from_str_radix(f.trim_start_matches("0x"), 16)
                .map_err(|e| DaemonError::GpuProbe(format!("bad resource field {f:?}: {e}")))
        });
        let (start, end, flags) = match (fields.next(), fields.next(), fields.next()) {
            (Some(s), Some(e), Some(f)) => (s?, e?, f?),
            _ => return Err(DaemonError::GpuProbe(format!("malformed resource line {line:?}"))),
        };
        let wanted = IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64;
        if flags & wanted == wanted && end >= start {
            total = total.saturating_add(end - start + 1);
        }
    }
    Ok(total)
}

/// Window size in MiB: the BAR total rounded up to a power of two, doubled
/// so OVMF has alignment slack, never below 1 GiB.
pub fn mmio64_window_mb(bar_bytes: u64) -> u64 {
    let mb = bar_bytes.div_ceil(1 << 20).max(1);
    (mb.next_power_of_two() * 2).max(MIN_WINDOW_MB)
}

/// The window for a set of cards attached to one VM.
pub fn gpu_mmio64_mb(pci_hosts: &[String]) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for pci_host in pci_hosts {
        let path = crate::gpu_cc::sysfs_device_dir(pci_host).join("resource");
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| DaemonError::GpuProbe(format!("cannot read {}: {e}", path.display())))?;
        total = total.saturating_add(parse_resource_file(&contents)?);
    }
    Ok(mmio64_window_mb(total))
}
```

- [ ] **Step 4: Run tests, commit**

Run: `cd rust && cargo test -p supervisor-daemon gpu_bar::`

```bash
git add rust/crates/supervisor-daemon/src/gpu_bar.rs rust/crates/supervisor-daemon/src/lib.rs
git commit -m "feat(daemon): size the OVMF 64-bit MMIO window from the card's sysfs BARs"
```

---

### Task 8: controller: SNP passthrough argv

**Files:**
- Modify: `rust/crates/supervisor-controller/src/config.rs`, `rust/crates/supervisor-controller/src/qemu.rs`
- Create: `rust/crates/supervisor-controller/tests/conformance/controller_argv_snp/gpu.json`
- Modify: `rust/crates/supervisor-controller/tests/argv_parity_snp.rs`

**Interfaces:**
- Produces: `QemuConfig.pci_mmio64_mb: Option<u64>` (serde default), `pub fn snp_gpu_args(gpus: &[Gpu], pci_mmio64_mb: Option<u64>) -> Vec<String>`; `build_snp_argv` emits it between the `-nographic` block and the NIC.

- [ ] **Step 1: Write the failing unit test**

In `qemu.rs` tests:

```rust
    #[test]
    fn snp_gpu_args_emit_root_port_vfio_and_the_mmio_window() {
        let gpus = vec![Gpu { pci_host: "06:00.0".into(), supports_x_vga: true }];
        assert_eq!(
            snp_gpu_args(&gpus, Some(524288)),
            vec![
                "-device", "pcie-root-port,id=rp0,bus=pcie.0,chassis=1",
                "-device", "vfio-pci,host=06:00.0,bus=rp0,rombar=0",
                "-fw_cfg", "name=opt/ovmf/X-PciMmio64Mb,string=524288",
            ]
        );
        // x-vga is never emitted on the SNP path, whatever the card reports:
        // a compute GPU in a headless confidential guest has no display.
        assert!(!snp_gpu_args(&gpus, Some(1024)).iter().any(|a| a.contains("x-vga")));
        assert!(snp_gpu_args(&[], Some(1024)).is_empty());
    }
```

And the fixture `gpu.json`: copy `minimal.json`, set `"gpus": [{"pci_host": "06:00.0", "supports_x_vga": true}]`, add `"pci_mmio64_mb": 524288`, and in `expected_argv` insert after `"-nographic"`:

```json
    "-device",
    "pcie-root-port,id=rp0,bus=pcie.0,chassis=1",
    "-device",
    "vfio-pci,host=06:00.0,bus=rp0,rombar=0",
    "-fw_cfg",
    "name=opt/ovmf/X-PciMmio64Mb,string=524288",
```

Add `parity_case!(gpu, "gpu");` and `"gpu"` to the `declared` list in `argv_parity_snp.rs`.

- [ ] **Step 2: Run to verify failure**

Run: `cd rust && cargo test -p supervisor-controller snp_gpu_args && cargo test -p supervisor-controller --test argv_parity_snp`
Expected: compile error, then fixture mismatch.

- [ ] **Step 3: Implement**

`config.rs`, `QemuConfig`, after `hugepage_size`:

```rust
    // The 64-bit PCI MMIO window (MiB) OVMF should reserve for passthrough
    // BARs, Rust-only, SNP+GPU only. The daemon sizes it from the card's
    // sysfs BARs; absent (and so omitted) on every other config.
    #[serde(default)]
    pub pci_mmio64_mb: Option<u64>,
```

`qemu.rs`:

```rust
/// Confidential GPU passthrough for the SNP path: one PCIe root port plus
/// one `vfio-pci` per card, then the OVMF 64-bit MMIO window. Deliberately
/// NOT `gpu_args`: that helper switches `-cpu` to `host`, and the SNP CPU
/// model is a measurement input that must stay the declared one; it also
/// adds `x-vga`, meaningless for a headless compute guest. The window is a
/// fw_cfg value, not a measured input, so it can follow the card.
pub fn snp_gpu_args(gpus: &[Gpu], pci_mmio64_mb: Option<u64>) -> Vec<String> {
    if gpus.is_empty() {
        return Vec::new();
    }
    let mut args = Vec::with_capacity(gpus.len() * 4 + 2);
    for (index, gpu) in gpus.iter().enumerate() {
        args.push("-device".into());
        args.push(format!("pcie-root-port,id=rp{index},bus=pcie.0,chassis={}", index + 1));
        args.push("-device".into());
        args.push(format!("vfio-pci,host={},bus=rp{index},rombar=0", gpu.pci_host));
    }
    if let Some(mb) = pci_mmio64_mb {
        args.push("-fw_cfg".into());
        args.push(format!("name=opt/ovmf/X-PciMmio64Mb,string={mb}"));
    }
    args
}
```

In `build_snp_argv`, right after the `-nographic` block and before the NIC: `args.extend(snp_gpu_args(&config.gpus, config.pci_mmio64_mb));`. Replace the doc paragraph "Unlike `build_argv` ... emits NO GPU passthrough devices ..." with: "GPU passthrough on this path is confidential-GPU only: `snp_gpu_args` emits a root port and `vfio-pci` per card and the OVMF MMIO window; the daemon admits GPUs onto an SNP spec only when their cards are in NVIDIA CC mode (`snp_config_slice`)."

- [ ] **Step 4: Run tests**

Run: `cd rust && cargo fmt --all && cargo clippy -p supervisor-controller --all-targets -- -D warnings && cargo test -p supervisor-controller`
Expected: green, `minimal` and the other fixtures unchanged (no GPU means no bytes added).

- [ ] **Step 5: Commit**

```bash
git add rust/crates/supervisor-controller
git commit -m "feat(controller): SNP argv passes a confidential GPU through a root port with a BAR-sized MMIO window"
```

---

### Task 9: daemon gate and config plumbing

**Files:**
- Modify: `rust/crates/supervisor-daemon/src/lifecycle.rs`, `rust/crates/supervisor-daemon/src/controller_config.rs`

**Interfaces:**
- Consumes: `cc_mode_of` (Task 5), `gpu_bar::gpu_mmio64_mb` (Task 7).
- Produces: `SnpSlice.pci_mmio64_mb: Option<u64>`; `WrittenQemuVmConfiguration.pci_mmio64_mb: Option<u64>` (skip if none) and `QemuVmConfig.pci_mmio64_mb: Option<u64>` (serde default) so adoption round-trips.

- [ ] **Step 1: Write the failing tests**

Replace `snp_config_slice_rejects_gpus_so_they_are_not_silently_dropped` with three tests. They need an inventory card. The test module's `harness_with_ruleset_and_policy` builds `HostState { ..., gpus: Vec::new(), ... }` directly; refactor it into `harness_full(ruleset, ipv6_allocation_policy, gpus: Vec<crate::lspci::GpuDevice>)` that puts `gpus` into that `HostState`, make `harness_with_ruleset_and_policy` delegate with `Vec::new()`, and add:

```rust
    fn harness_with_gpus(gpus: Vec<crate::lspci::GpuDevice>) -> Harness {
        harness_full(bare_host_ruleset(), crate::config::Ipv6AllocationPolicy::Static, gpus)
    }

    fn nvidia_card(pci_host: &str) -> crate::lspci::GpuDevice {
        crate::lspci::GpuDevice {
            vendor: "NVIDIA".into(),
            device_name: "GB202 [RTX PRO 6000 Blackwell]".into(),
            device_class: "0302".into(),
            pci_host: pci_host.into(),
            device_id: "10de:2b85".into(),
            cc_mode: None,
        }
    }
```

`Harness.state` is an `Arc<DaemonState>`; `gpu_cc_modes` is a `std::sync::Mutex`, so tests seed it through the `Arc` without `mut`.

```rust
    #[test]
    fn snp_config_slice_rejects_a_gpu_not_in_cc_mode() {
        let harness = harness_with_gpus(vec![nvidia_card("06:00.0")]);
        let state = &harness.state;
        // Off, devtools and unknown all fail closed.
        for mode in [None, Some(crate::gpu_cc::CcMode::Off), Some(crate::gpu_cc::CcMode::Devtools)] {
            state.gpu_cc_modes.lock().unwrap().clear();
            if let Some(mode) = mode {
                state.gpu_cc_modes.lock().unwrap().insert("06:00.0".into(), mode);
            }
            let root = state.host.settings.execution_root.clone();
            let firmware = root.join("OVMF.fd");
            std::fs::write(&firmware, b"ovmf").unwrap();
            let mut spec = snp_spec(&hash('j'), &root, &firmware.to_string_lossy());
            spec.gpus = vec![pb::GpuConfig { pci_host: "06:00.0".into(), supports_x_vga: true }];
            match snp_config_slice(state, &spec) {
                Err(RpcError::InvalidBackend(msg)) => assert!(msg.contains("confidential-computing mode"), "{msg}"),
                other => panic!("mode {mode:?} must be InvalidBackend, got {other:?}"),
            }
        }
    }

    #[test]
    fn snp_config_slice_rejects_a_gpu_absent_from_the_inventory() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let mut spec = snp_spec(&hash('j'), &root, &firmware.to_string_lossy());
        spec.gpus = vec![pb::GpuConfig { pci_host: "0000:01:00.0".into(), supports_x_vga: true }];
        assert!(matches!(snp_config_slice(state, &spec), Err(RpcError::InvalidBackend(_))));
    }

    #[test]
    fn snp_config_slice_accepts_a_cc_mode_gpu_and_sizes_the_window() {
        let harness = harness_with_gpus(vec![nvidia_card("06:00.0")]);
        let state = &harness.state;
        state.gpu_cc_modes.lock().unwrap().insert("06:00.0".into(), crate::gpu_cc::CcMode::On);
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let mut spec = snp_spec(&hash('j'), &root, &firmware.to_string_lossy());
        spec.gpus = vec![pb::GpuConfig { pci_host: "06:00.0".into(), supports_x_vga: true }];
        // The window reader is injected so the test needs no sysfs.
        let slice = snp_config_slice_with(state, &spec, |_| Ok(524288)).unwrap().unwrap();
        assert_eq!(slice.pci_mmio64_mb, Some(524288));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cd rust && cargo test -p supervisor-daemon snp_config_slice`

- [ ] **Step 3: Implement**

In `lifecycle.rs`, split the function: `snp_config_slice(state, spec)` calls `snp_config_slice_with(state, spec, crate::gpu_bar::gpu_mmio64_mb)`, where the new function is

```rust
fn snp_config_slice_with(
    state: &DaemonState,
    spec: &pb::VmSpec,
    mmio_window: impl Fn(&[String]) -> Result<u64, DaemonError>,
) -> Result<Option<SnpSlice>, RpcError>
```

(the sysfs reader is injected so the window logic is testable off-hardware, the same way `SevHostInfo` is injected into the controller). Rename the unused `_state` parameter to `state`. Replace the GPU rejection block with:

```rust
    // A GPU may enter a confidential guest only in NVIDIA CC mode: the card
    // then refuses plaintext DMA and answers attestation, and the guest
    // verifies it at boot. Any other card, mode, or an unprobed card, would
    // hand the owner hardware the guest cannot trust. Fail closed.
    for gpu in &spec.gpus {
        let known = state.host.gpus.iter().any(|device| device.pci_host == gpu.pci_host);
        if !known {
            return Err(RpcError::InvalidBackend(format!(
                "GPU at pci_host '{}' is not in the host inventory", gpu.pci_host
            )));
        }
        match crate::service::cc_mode_of(state, &gpu.pci_host) {
            Some(crate::gpu_cc::CcMode::On) => {}
            other => {
                return Err(RpcError::InvalidBackend(format!(
                    "GPU at pci_host '{}' is not in NVIDIA confidential-computing mode (probed: {})",
                    gpu.pci_host,
                    other.map(|m| m.to_string()).unwrap_or_else(|| "unknown".into())
                )));
            }
        }
    }
    let pci_mmio64_mb = if spec.gpus.is_empty() {
        None
    } else {
        let hosts: Vec<String> = spec.gpus.iter().map(|g| g.pci_host.clone()).collect();
        Some(mmio_window(&hosts).map_err(|e| RpcError::InvalidBackend(format!("cannot size the GPU MMIO window: {e}")))?)
    };
```

Add `pci_mmio64_mb` to `SnpSlice` and to both `Ok(Some(SnpSlice { ... }))` returns. In `build_written_config`, thread `snp.pci_mmio64_mb` into the new `WrittenQemuVmConfiguration.pci_mmio64_mb` field (declare it after `hugepage_size` with `skip_serializing_if = "Option::is_none"`; add the matching `#[serde(default)] pub pci_mmio64_mb: Option<u64>` to `QemuVmConfig` in `controller_config.rs`). The existing config-forward-compat Python test (`test_controller_config_forward_compat.py`) keeps passing because the key is absent when None. Note that `validate_spec_gpus` still runs on the SNP path (it did before, the GPU block only fired later), so the "already attached" and "claimed twice" checks stay.

- [ ] **Step 4: The `swiotlb` cmdline token via a validated sidecar**

The daemon derives the measured cmdline from sidecars next to the rootfs (`{rootfs}.roothash`, `.workload_roothash`, `.verified_volumes`); the manifest template never reaches it. The GPU runtime's template carries the fixed token `swiotlb=262144` between `workload_roothash` and `verified_volumes`, so the daemon needs a fourth sidecar, `{rootfs}.cmdline_extra`, spliced at exactly that position. It is validated against a closed allowlist before it touches `-append`: only `swiotlb=<1 to 9 digits>` is accepted, anything else fails the spec closed.

Add tests next to the existing verity-arm tests in `lifecycle.rs`:

```rust
    #[test]
    fn snp_cmdline_extra_sidecar_is_spliced_after_the_workload_roothash() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let vm_id = hash('k');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        std::fs::write(format!("{}.workload_roothash", rootfs.display()), b"beef\n").unwrap();
        std::fs::write(format!("{}.cmdline_extra", rootfs.display()), b"swiotlb=262144\n").unwrap();
        std::fs::write(format!("{}.verified_volumes", rootfs.display()), b"aa,bb\n").unwrap();
        let slice = snp_config_slice(state, &spec).unwrap().unwrap();
        assert_eq!(
            slice.kernel_cmdline,
            "console=ttyS0 root=/dev/mapper/verity-root ro roothash=deadbeef00 workload_roothash=beef swiotlb=262144 verified_volumes=aa,bb"
        );
    }

    #[test]
    fn snp_cmdline_extra_sidecar_rejects_anything_but_swiotlb() {
        for bad in ["console=ttyS1", "swiotlb=262144 init=/bin/sh", "swiotlb=", "swiotlb=1234567890", "root=/dev/vdb"] {
            let harness = harness();
            let state = &harness.state;
            let root = state.host.settings.execution_root.clone();
            let firmware = root.join("OVMF.fd");
            std::fs::write(&firmware, b"ovmf").unwrap();
            let vm_id = hash('l');
            let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
            let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
            std::fs::write(format!("{}.cmdline_extra", rootfs.display()), format!("{bad}\n")).unwrap();
            assert!(matches!(snp_config_slice(state, &spec), Err(RpcError::InvalidBackend(_))), "{bad:?} must be refused");
        }
    }
```

Implement in the verity arm, after the workload roothash splice and before the verified-volumes splice (mirror how those two read their sidecars, including the size cap):

```rust
    // Fixed cmdline text the runtime manifest carries between the workload
    // roothash and the verified volumes (today: the SWIOTLB size a
    // confidential-GPU guest needs). The agent copies it from the manifest
    // into this sidecar; it is spliced verbatim into the measured cmdline,
    // so only a closed allowlist may pass, never free text.
    let extra_path = format!("{rootfs_path}.cmdline_extra");
    if let Some(extra) = read_optional_sidecar(&extra_path)? {
        let extra = extra.trim();
        let allowed = extra
            .strip_prefix("swiotlb=")
            .is_some_and(|digits| (1..=9).contains(&digits.len()) && digits.bytes().all(|b| b.is_ascii_digit()));
        if !allowed {
            return Err(RpcError::InvalidBackend(format!(
                "cmdline_extra sidecar {extra_path} carries {extra:?}; only swiotlb=<digits> is allowed"
            )));
        }
        cmdline.push(' ');
        cmdline.push_str(extra);
    }
```

(`read_optional_sidecar` is whatever helper the workload-roothash splice already uses for a maybe-absent, size-capped sidecar; if it reads inline, factor that read into such a helper first so the three optional sidecars share it.)

- [ ] **Step 5: Run tests, clippy**

Run: `cd rust && cargo fmt --all && cargo clippy -p supervisor-daemon --all-targets -- -D warnings && cargo test -p supervisor-daemon`

- [ ] **Step 6: Update the divergences ledger**

In `docs/architecture/divergences.md` entry 68, replace the sentence starting "GPU passthrough is REJECTED for SNP specs" with: "GPU passthrough on SNP specs is admitted only for cards the daemon probed in NVIDIA CC mode (`gpu_cc.rs`); `build_snp_argv` then emits a root port, `vfio-pci` and a BAR-sized OVMF MMIO window (`snp_gpu_args`, `gpu_bar.rs`). Any other GPU on an SNP spec stays `InvalidBackend`." Update the matching bullet in `docs/architecture/confidential.md` "Key invariants".

- [ ] **Step 6: Commit**

```bash
git add rust/crates/supervisor-daemon docs/architecture
git commit -m "feat(daemon): admit CC-mode GPUs onto SEV-SNP specs and carry the MMIO window to the controller"
```

---

# PR D: Nix GPU image flavor

Every task here builds with `nix build ./nix#<output> --print-build-logs`. A cold build of the kernel takes minutes; cache it once. None of these outputs is in the golden set until Task 13 adds them.

### Task 10: GPU kernel from the base whitelist plus a fragment

**Files:**
- Modify: `nix/kernel.nix` (add `extraFragment ? null`)
- Create: `nix/kernel-config-gpu.fragment`
- Modify: `nix/flake.nix` (`gpuKernel`)

**Interfaces:**
- Produces: `gpuKernel = pkgs.callPackage ./kernel.nix { extraFragment = ./kernel-config-gpu.fragment; }`; the base `kernel` derivation unchanged.

- [ ] **Step 1: Parametrize kernel.nix**

Change the header to `{ pkgs, lib, extraFragment ? null, ... }:`. Replace `fragment = ./kernel-config.fragment;` with:

```nix
  baseFragment = ./kernel-config.fragment;
  # The GPU flavor appends its options to the same whitelist; the concatenated
  # file is what KCONFIG_ALLCONFIG seeds and what the line-by-line check
  # verifies, so a GPU option Kconfig drops fails the build the same way.
  fragment =
    if extraFragment == null then baseFragment
    else pkgs.runCommand "kernel-config-gpu.fragment" { } ''
      cat ${baseFragment} ${extraFragment} > $out
    '';
```

Give the derivation names a suffix when `extraFragment != null` (`pname = "linux-config-snp-guest${lib.optionalString (extraFragment != null) "-gpu"}"`) so the two configs never collide in the store.

- [ ] **Step 2: Write the GPU fragment**

`nix/kernel-config-gpu.fragment`:

```
# Additions for the confidential-GPU guest. Every line is verified against
# the generated .config at build time like the base fragment. Any edit moves
# the gpuImage launch measurement: re-seed nix/golden-measurements.json.
#
# NVIDIA open kernel modules (nvidia.ko, nvidia-uvm.ko) need these.
CONFIG_MMU_NOTIFIER=y
CONFIG_DMA_SHARED_BUFFER=y
CONFIG_PCI_MMCONFIG=y
CONFIG_PCI_MSI=y
CONFIG_PCIEASPM=y
CONFIG_HOTPLUG_PCI=y
CONFIG_HOTPLUG_PCI_PCIE=y
# Resizable BAR support for the 96 GiB-class BAR1 behind the root port.
CONFIG_PCI_REALLOC_ENABLE_AUTO=y
# The CC driver bounces every DMA through SWIOTLB (already selected by
# AMD_MEM_ENCRYPT); the cmdline sizes it (swiotlb=262144).
CONFIG_SWIOTLB=y
# Firmware loading for the GSP blob from the rootfs.
CONFIG_FW_LOADER=y
CONFIG_FW_LOADER_COMPRESS=y
CONFIG_FW_LOADER_COMPRESS_XZ=y
# No display stack in a headless compute guest.
# CONFIG_DRM is not set
# CONFIG_VT is not set
```

- [ ] **Step 3: Expose and build**

In `flake.nix` after `kernel = pkgs.callPackage ./kernel.nix {};` add `gpuKernel = pkgs.callPackage ./kernel.nix { extraFragment = ./kernel-config-gpu.fragment; };` and add `gpuKernel` to `packages`.

Run: `nix build ./nix#gpuKernel --print-build-logs`
Expected: builds. If the fragment check fails on an option (`kernel config: requested ... got ...`), the option has an unmet dependency: add the dependency line to the GPU fragment (never to the base one) and rebuild. Record each addition in the fragment comment. Then `nix build ./nix#kernel` and confirm its store path is unchanged from `git stash`-free baseline: `nix build ./nix#measurement --print-out-paths` must print the same measurement as before this task (compare with `nix/golden-measurements.json`).

- [ ] **Step 4: Commit**

```bash
git add nix/kernel.nix nix/kernel-config-gpu.fragment nix/flake.nix
git commit -m "nix: gpuKernel, the SNP guest whitelist kernel plus the options NVIDIA's open modules need"
```

---

### Task 11: NVIDIA driver: open modules, raw userland, GSP firmware

**Files:**
- Create: `nix/nvidia.nix`
- Modify: `nix/flake.nix` (`nvidiaDriver`)

**Interfaces:**
- Produces: `nvidiaDriver` attrset with `modules` (directory with `nvidia.ko` and `nvidia-uvm.ko`, xz-decompressed), `firmware` (`lib/firmware/nvidia/<version>/*.bin`), `userland` (directory of raw, unpatched `.so` files and `nvidia-smi`), `version` (string).

- [ ] **Step 1: Write nvidia.nix**

```nix
{ pkgs, lib, gpuKernel, ... }:

# The NVIDIA driver pieces the confidential-GPU guest ships.
#
# Kernel side: the open kernel modules built against gpuKernel, nvidia.ko and
# nvidia-uvm.ko only (no drm/modeset: headless compute guest; no peermem).
# GSP firmware is mandatory for CC mode and comes from the driver archive's
# firmware output.
#
# User side: the RAW driver libraries, extracted straight from the .run
# archive with no ELF patching. nixpkgs' `out` patches interpreters and
# rpaths to the nix glibc, which would drag a second libc into whatever
# workload dlopens libcuda. Raw libraries link against the loading
# process's own libc (they only reference old glibc symbol versions), which
# is exactly how the NVIDIA container toolkit hands them to containers.
let
  nvidiaPkgs = (pkgs.linuxKernel.packagesFor gpuKernel).nvidiaPackages.production;
  version = nvidiaPkgs.version;
  open = nvidiaPkgs.open.overrideAttrs (old: {
    makeFlags = (old.makeFlags or [ ]) ++ [
      "NV_EXCLUDE_KERNEL_MODULES=nvidia-drm nvidia-modeset nvidia-peermem"
    ];
  });
  modDir = "${open}/lib/modules/${gpuKernel.modDirVersion}/kernel/drivers/video";
  modules = pkgs.runCommand "nvidia-open-modules-${version}" { nativeBuildInputs = [ pkgs.xz ]; } ''
    mkdir -p $out
    for m in nvidia nvidia-uvm; do
      if [ -f ${modDir}/$m.ko.xz ]; then xz -d -k -c ${modDir}/$m.ko.xz > $out/$m.ko
      elif [ -f ${modDir}/$m.ko ]; then cp ${modDir}/$m.ko $out/$m.ko
      else echo "missing $m.ko in ${modDir}" >&2; exit 1; fi
    done
  '';
  firmware = nvidiaPkgs.firmware;
  # The compute + attestation userland, raw. Wildcards keep the list honest
  # across driver bumps (a renamed library fails the ls, not the boot).
  userland = pkgs.runCommand "nvidia-userland-raw-${version}" { } ''
    mkdir -p src $out
    sh ${nvidiaPkgs.src} --extract-only --target src
    cd src
    for lib in libcuda.so.${version} libnvidia-ml.so.${version} libnvidia-ptxjitcompiler.so.${version} \
               libnvidia-nvvm.so.${version} libnvidia-gpucomp.so.${version} libnvidia-pkcs11-openssl3.so.${version}; do
      cp "$lib" $out/
      base=$(echo $lib | sed 's/\.so\..*$/.so/')
      ln -s $lib $out/$base.1
      ln -s $lib $out/$base
    done
    cp nvidia-smi $out/
    chmod 755 $out/nvidia-smi
  '';
in
{ inherit modules firmware userland version; }
```

`libcuda.so.1` is what CUDA runtimes dlopen; the `.so` and `.so.1` symlinks cover both link-time and run-time names. If the extracted archive names differ on this driver (check with `sh <src> --list`), fix the loop; the build fails loudly on a missing file.

- [ ] **Step 2: Expose and build**

In `flake.nix`: `nvidiaDriver = import ./nvidia.nix { inherit pkgs lib gpuKernel; };` (with `lib = pkgs.lib;` in scope) and expose `nvidiaModules = nvidiaDriver.modules; nvidiaUserland = nvidiaDriver.userland; nvidiaFirmware = nvidiaDriver.firmware;` in `packages`.

Run: `nix build ./nix#nvidiaModules ./nix#nvidiaUserland ./nix#nvidiaFirmware --print-build-logs`
Expected: three store paths. Verify: `ls result*/` shows `nvidia.ko`, `nvidia-uvm.ko`; `file result-1/libcuda.so.*` shows an ELF with no `/nix/store` interpreter (`patchelf --print-rpath` empty); firmware directory holds `gsp_*.bin`. If the open module build stops on a missing kernel option, add it to the GPU fragment (Task 10) and rebuild both. NVIDIA's license: `nvidiaPackages.production` requires `acceptLicense = true` in nixpkgs config when `openSha256` is unset; with the open modules the check is skipped (see nixpkgs `generic.nix`), and `firmware` is extracted because `openSha256 != null`.

- [ ] **Step 3: Commit**

```bash
git add nix/nvidia.nix nix/flake.nix
git commit -m "nix: NVIDIA open modules against gpuKernel, raw userland and GSP firmware"
```

---

### Task 12: libnvat and nvattest built offline

**Files:**
- Create: `nix/nvat.nix`
- Modify: `nix/flake.nix` (`nvat`)

**Interfaces:**
- Produces: `nvat` derivation with `bin/nvattest`, `lib/libnvat.so.1`, plus its runtime closure (nix glibc, OpenSSL, curl, libxml2, xmlsec1, zlib).

- [ ] **Step 1: Write nvat.nix**

```nix
{ pkgs, lib, ... }:

# NVIDIA's attestation SDK (libnvat) and its CLI (nvattest): the in-guest
# verifier that checks the GPU's evidence against NVIDIA's RIMs and OCSP at
# boot and sets the GPU ready state. Pinned by commit; FetchContent inputs
# are supplied from fixed-output fetches so the build is offline and
# reproducible. USE_SYSTEM_DEPS takes OpenSSL, curl, libxml2 and xmlsec1
# from nixpkgs.
let
  version = "1.2.2";
  src = pkgs.fetchFromGitHub {
    owner = "NVIDIA";
    repo = "attestation-sdk";
    # Tag v1.2.2; record the commit and hash after the first `nix build`
    # attempt reports them.
    rev = "REPLACE-WITH-TAG-COMMIT";
    hash = lib.fakeHash;
  };
  fetched = name: owner: repo: rev: hash: pkgs.fetchFromGitHub { inherit owner repo rev hash; };
  corrosion = fetched "corrosion" "corrosion-rs" "corrosion" "6be991bb34c348dfb8344be22f3606288ea5c7fd" lib.fakeHash;
  regorus = fetched "regorus" "microsoft" "regorus" "regorus-v0.4.0" lib.fakeHash;
  jwtcpp = fetched "jwt-cpp" "Thalhammer" "jwt-cpp" "REPLACE" lib.fakeHash;
  fmt = fetched "fmt" "fmtlib" "fmt" "REPLACE" lib.fakeHash;
  spdlog = fetched "spdlog" "gabime" "spdlog" "REPLACE" lib.fakeHash;
  json = pkgs.fetchurl {
    url = "https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz";
    hash = "sha256-QvbpXK1uxTL9NzKQOIsUEHfVJRe5dnfudzr/DDy5R3k=";
  };
  # regorus-ffi is a Rust crate corrosion builds inside the CMake tree; its
  # crates.io dependencies are vendored the crane/rustPlatform way.
  regorusVendor = pkgs.rustPlatform.fetchCargoVendor {
    src = "${regorus}/bindings/ffi";
    hash = lib.fakeHash;
  };
in
pkgs.stdenv.mkDerivation {
  pname = "nv-attestation-sdk";
  inherit version src;
  sourceRoot = "source/nv-attestation-sdk-cpp";
  nativeBuildInputs = with pkgs; [ cmake pkg-config cargo rustc rustPlatform.cargoSetupHook ];
  buildInputs = with pkgs; [ openssl curl libxml2 xmlsec zlib ];
  cargoDeps = regorusVendor;
  cargoRoot = "../regorus-src/bindings/ffi";
  postUnpack = ''
    cp -r ${regorus} $sourceRoot/../regorus-src
    chmod -R u+w $sourceRoot/../regorus-src
    mkdir -p deps && cp -r ${corrosion} deps/corrosion && cp -r ${jwtcpp} deps/jwt-cpp \
      && cp -r ${fmt} deps/fmt && cp -r ${spdlog} deps/spdlog
    mkdir deps/json && tar -xJf ${json} -C deps/json --strip-components=1
    chmod -R u+w deps
  '';
  cmakeFlags = [
    "-DUSE_SYSTEM_DEPS=ON"
    "-DBUILD_TESTING=OFF"
    "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
    "-DFETCHCONTENT_SOURCE_DIR_CORROSION=../deps/corrosion"
    "-DFETCHCONTENT_SOURCE_DIR_REGORUS=../regorus-src"
    "-DFETCHCONTENT_SOURCE_DIR_JWT-CPP=../deps/jwt-cpp"
    "-DFETCHCONTENT_SOURCE_DIR_JSON=../deps/json"
    "-DFETCHCONTENT_SOURCE_DIR_FMT=../deps/fmt"
    "-DFETCHCONTENT_SOURCE_DIR_SPDLOG=../deps/spdlog"
  ];
  postInstall = ''
    # The CLI lives in a sibling directory of the SDK; build it against the
    # freshly installed library.
    cmake -S ../../nv-attestation-cli -B cli-build -DCMAKE_PREFIX_PATH=$out -DCMAKE_INSTALL_PREFIX=$out
    cmake --build cli-build && cmake --install cli-build
    test -x $out/bin/nvattest
  '';
  meta.license = lib.licenses.asl20;
}
```

The `REPLACE` placeholders are filled in during this task: `git -C <clone> rev-parse v1.2.2`, and the FetchContent `GIT_TAG` values in `nv-attestation-sdk-cpp/CMakeLists.txt` lines 40 to 124 give the exact tags for jwt-cpp, fmt and spdlog. `lib.fakeHash` makes the first build print the real hash for each fetch; paste it in. If `nv-attestation-cli` needs its own FetchContent inputs, apply the same pattern.

- [ ] **Step 2: Build and verify offline**

Run: `nix build ./nix#nvat --print-build-logs`
Expected: `result/bin/nvattest version` prints `1.0` (CLI) and `ldd result/bin/nvattest` lists only nix store libraries. Then `result/bin/nvattest attest --device gpu --verifier local --gpu-evidence-source file --gpu-evidence-file <sdk>/common-test-data/serialized_test_evidence/hopper_evidence.json --nonce <nonce from the file> --format json` with network available: expected `result_code: 0` (this touches NVIDIA's RIM and OCSP services, so it is a manual check, not a test).

- [ ] **Step 3: Commit**

```bash
git add nix/nvat.nix nix/flake.nix
git commit -m "nix: libnvat and nvattest, NVIDIA's local GPU verifier, built offline from pinned sources"
```

---

### Task 13: `init-gpu.sh`, the GPU initrd, rootfs, image and golden measurement

**Files:**
- Create: `nix/init-gpu.sh`, `nix/gpu-rootfs.nix`
- Modify: `nix/initrd.nix` (`withNvidia ? null`), `nix/init-common.sh` (`prepare_chroot` GPU binds), `nix/flake.nix`, `nix/golden-measurements.json`, `nix/check-golden-measurements.sh`, `nix/boot-smoke.sh`, `.github/workflows/golden-measurements.yml`

**Interfaces:**
- Produces: flake outputs `gpuInitrd`, `gpuRootfs`, `gpuVerity`, `gpuImage`, `gpuMeasurement`; `gpuImage` directory also holds `gpu.json` (`{"vendor":"nvidia","arch":"blackwell","driver_version":"<v>","accepted_models":[...],"library_path":"/opt/nvidia/lib"}`) for Task 15's bundle builder. In-guest paths: modules at `/lib/modules/nvidia.ko`, `/lib/modules/nvidia-uvm.ko` (initrd); rootfs `/opt/nvidia/lib`, `/lib/firmware/nvidia/<v>/`, `/nix/store/...` (nvat closure), `/etc/ssl/certs/ca-bundle.crt`; claims at `/run/aleph/gpu-boot-claims.json`.

- [ ] **Step 1: `prepare_chroot` learns the GPU binds**

In `nix/init-common.sh` `prepare_chroot`, after the resolv.conf block, add (harmless on non-GPU images: the source directory does not exist):

```sh
    # Confidential-GPU runtimes: hand the workload the raw driver userland
    # and the device nodes. Both sources only exist on the GPU image, so
    # this is a no-op everywhere else. The workload image must ship the
    # /opt/nvidia/lib mount point (runtime contract, manifest gpu.library_path).
    if [ -d /mnt/root/opt/nvidia/lib ]; then
        if [ -d "$target/opt/nvidia/lib" ]; then
            /bin/busybox mount --bind -o ro /mnt/root/opt/nvidia/lib "$target/opt/nvidia/lib" \
                || echo "init: WARNING: driver userland bind-mount failed"
        else
            echo "init: WARNING: ${target} has no /opt/nvidia/lib mount point; the workload cannot use the GPU"
        fi
    fi
```

The `/dev` bind above already carries `/dev/nvidia*` (created in the initramfs `/dev` by `init-gpu.sh` before `prepare_chroot`). This edit touches the base initrd (`init-common.sh` is in every initrd), so the base `measurement`, `composeMeasurement`, `workloadMeasurement` and `instanceMeasurementSmoke` all move: re-seed all of them in this task, and say so in the PR.

- [ ] **Step 2: Write `nix/init-gpu.sh`**

Start from a copy of `nix/init.sh` (the compose flavor did the same with `init-compose.sh`) and insert, right after the verity mounts and before the `prepare_chroot` selection:

```sh
# Confidential GPU: load the driver, verify the GPU against NVIDIA's
# reference manifests, set the ready state, and record the claims for the
# attest-agent. Every failure powers the VM off: a GPU runtime without a
# verified GPU must never present an attested endpoint.
gpu_present() {
    for dev in /sys/bus/pci/devices/*; do
        [ "$(cat "$dev/vendor" 2>/dev/null)" = "0x10de" ] && return 0
    done
    return 1
}

gpu_fatal() {
    echo "init: FATAL: gpu attestation failed: $1"
    exec /bin/busybox poweroff -f
}

gpu_claims=""
if gpu_present; then
    echo "init: NVIDIA GPU present, loading the driver"
    /bin/busybox insmod /lib/modules/nvidia.ko NVreg_EnableGpuFirmware=1 || gpu_fatal "insmod nvidia.ko"
    /bin/busybox insmod /lib/modules/nvidia-uvm.ko || gpu_fatal "insmod nvidia-uvm.ko"
    nvidia_major=$(/bin/busybox awk '$2 == "nvidia" {print $1}' /proc/devices)
    uvm_major=$(/bin/busybox awk '$2 == "nvidia-uvm" {print $1}' /proc/devices)
    [ -n "$nvidia_major" ] && [ -n "$uvm_major" ] || gpu_fatal "driver registered no char devices"
    /bin/busybox mknod -m 666 /dev/nvidiactl c "$nvidia_major" 255 || gpu_fatal "mknod nvidiactl"
    /bin/busybox mknod -m 666 /dev/nvidia0 c "$nvidia_major" 0 || gpu_fatal "mknod nvidia0"
    /bin/busybox mknod -m 666 /dev/nvidia-uvm c "$uvm_major" 0 || gpu_fatal "mknod nvidia-uvm"
    /bin/busybox mknod -m 666 /dev/nvidia-uvm-tools c "$uvm_major" 1 || gpu_fatal "mknod nvidia-uvm-tools"

    /bin/busybox mkdir -p /run/aleph
    gpu_claims=/run/aleph/gpu-boot-claims.json
    boot_nonce=$(/bin/busybox head -c 32 /dev/urandom | /bin/busybox hexdump -ve '1/1 "%02x"')
    # nvattest and nvidia-smi run chrooted into the verity-mounted rootfs and
    # need /proc, /sys and /dev there now, before the workload chroot is
    # prepared. prepare_chroot is idempotent on the mount points but not on
    # the bind mounts, so it runs once here and the later selection skips
    # /mnt/root when it was already prepared (see the flag below).
    prepare_chroot /mnt/root
    gpu_chroot_prepared=1
    # nvattest lives in the rootfs' nix closure; NVML is the raw driver lib.
    if ! /bin/busybox chroot /mnt/root /usr/bin/env \
            LD_LIBRARY_PATH=/opt/nvidia/lib SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt \
            nvattest attest --device gpu --verifier local --nonce "$boot_nonce" \
              --rim-url https://rim.attestation.nvidia.com --ocsp-url https://ocsp.ndis.nvidia.com \
              --format json > /run/aleph/gpu-attest.json 2> /run/aleph/gpu-attest.log; then
        /bin/busybox cat /run/aleph/gpu-attest.log
        gpu_fatal "nvattest exited non-zero"
    fi
    # result_code 0 and every device's measres Success, or power off.
    /bin/busybox grep -q '"result_code" *: *0' /run/aleph/gpu-attest.json || gpu_fatal "result_code != 0"
    if /bin/busybox grep -q '"measres" *: *"Failure"' /run/aleph/gpu-attest.json; then
        gpu_fatal "measurement comparison failed"
    fi
    /bin/busybox grep -q '"measres" *: *"Success"' /run/aleph/gpu-attest.json || gpu_fatal "no Success claim"
    # Extract the claims array for the attest-agent (the EAT is not served).
    /bin/busybox sed -n 's/^.*"claims" *: *\(\[.*\]\) *, *"detached_eat".*$/\1/p' /run/aleph/gpu-attest.json > "$gpu_claims"
    [ -s "$gpu_claims" ] || gpu_fatal "could not extract claims"
    /bin/busybox chmod 0600 "$gpu_claims"
    # Ready state: the driver refuses CUDA work until it is set, and only a
    # verified GPU may be marked ready. nvidia-smi is the raw driver userland
    # in the rootfs; the agent is static and cannot drive NVML itself.
    gpu_smi="/bin/busybox chroot /mnt/root /usr/bin/env LD_LIBRARY_PATH=/opt/nvidia/lib /opt/nvidia/lib/nvidia-smi"
    $gpu_smi conf-compute -srs 1 > /dev/null 2>&1 || gpu_fatal "setting the ready state"
    $gpu_smi conf-compute -grs 2>/dev/null | /bin/busybox grep -qi "ready" || gpu_fatal "ready state did not stick"
    echo "init: GPU verified and ready"
else
    echo "init: no NVIDIA GPU present; running without GPU attestation"
fi
```

The `nvattest` JSON layout (`claims`, `detached_eat`, `result_code`) is the documented CLI output; if the release prints `claims` after `detached_eat`, adjust the `sed` to match and keep the "empty extraction is fatal" check. Then change the agent start line to:

```sh
if [ -n "$gpu_claims" ]; then
    /bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 \
        --gpu-claims "$gpu_claims" \
        --gpu-collector "/bin/busybox chroot /mnt/root /usr/bin/env LD_LIBRARY_PATH=/opt/nvidia/lib nvattest collect-evidence --device gpu --format json --nonce" &
else
    /bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 &
fi
```

The collector chroots into `/mnt/root`, which stays mounted and prepared for the VM's lifetime even when the workload runs from `/mnt/workload`. Guard the later `prepare_chroot` selection so `/mnt/root` is not prepared twice: `if [ -z "$workload_roothash" ] && [ -z "$gpu_chroot_prepared" ]; then prepare_chroot /mnt/root; fi` (the `/mnt/workload` branch is unchanged). Export `LD_LIBRARY_PATH=/opt/nvidia/lib` before the `chroot "$guest_root" /sbin/init` line when `gpu_claims` is set, so the workload finds libcuda (the environment crosses `chroot`). `sed -n` with `\(\[.*\]\)` is greedy; the claims array precedes `detached_eat` in the CLI output, so the match is correct, and a wrong extraction fails at the agent's JSON parse anyway.

- [ ] **Step 3: `initrd.nix` gains `withNvidia`**

Add parameter `withNvidia ? null` (the `nvidiaDriver.modules` derivation or null) and:

```nix
    # NVIDIA open modules for the confidential-GPU flavor.
    ++ pkgs.lib.optionals (withNvidia != null) [
      { source = "${withNvidia}/nvidia.ko"; path = "lib/modules/nvidia.ko"; mode = "644"; }
      { source = "${withNvidia}/nvidia-uvm.ko"; path = "lib/modules/nvidia-uvm.ko"; mode = "644"; }
    ]
```

The kernel passed to the GPU initrd is `gpuKernel` (dm-*/nft modules must come from the same kernel).

- [ ] **Step 4: Write `nix/gpu-rootfs.nix`**

```nix
{ pkgs, nvidiaDriver, nvat, ... }:

# The confidential-GPU platform rootfs: the base busybox rootfs content plus
# the raw driver userland at /opt/nvidia/lib, GSP firmware, NVIDIA's local
# verifier with its nix closure, and a CA bundle for its RIM/OCSP fetches.
# Same reproducibility levers as rootfs.nix.
let
  staticBusybox = pkgs.busybox.override { enableStatic = true; };
  closure = pkgs.closureInfo { rootPaths = [ nvat pkgs.cacert ]; };
in
pkgs.runCommand "gpu-rootfs.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs ];
  SOURCE_DATE_EPOCH = "0";
} ''
  mkdir -p rootfs/sbin rootfs/bin rootfs/srv rootfs/etc/ssl/certs rootfs/proc rootfs/sys rootfs/dev
  mkdir -p rootfs/tmp/secrets rootfs/run rootfs/usr/bin rootfs/opt/nvidia/lib rootfs/lib/firmware/nvidia
  cp ${staticBusybox}/bin/busybox rootfs/bin/
  ln -s /bin/busybox rootfs/usr/bin/env
  touch rootfs/etc/resolv.conf
  chmod 1777 rootfs/tmp
  chmod 0700 rootfs/tmp/secrets

  # Raw driver userland and firmware.
  cp -a ${nvidiaDriver.userland}/. rootfs/opt/nvidia/lib/
  cp -a ${nvidiaDriver.firmware}/lib/firmware/nvidia/. rootfs/lib/firmware/nvidia/

  # The verifier and its closure at their store paths; nvattest on PATH.
  mkdir -p rootfs/nix/store
  while read -r path; do cp -a "$path" rootfs/nix/store/; done < ${closure}/store-paths
  ln -s ${nvat}/bin/nvattest rootfs/usr/bin/nvattest
  ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt rootfs/etc/ssl/certs/ca-bundle.crt

  cat > rootfs/srv/index.html <<'HTML'
<!doctype html>
<title>aleph confidential GPU placeholder</title>
HTML
  cat > rootfs/sbin/init <<'INIT'
#!/bin/busybox sh
exec /bin/busybox httpd -f -v -p 127.0.0.1:8080 -h /srv
INIT
  chmod +x rootfs/sbin/init

  size=$(du -sm rootfs | cut -f1)
  size=$((size + 64))
  truncate -s ''${size}M $out
  mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
    -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal -d rootfs $out
''
```

- [ ] **Step 5: Flake outputs**

In `flake.nix` add, mirroring the compose flavor:

```nix
      nvat = import ./nvat.nix { inherit pkgs; lib = pkgs.lib; };
      gpuInitrd = import ./initrd.nix {
        inherit pkgs attest-agent udhcpc-script udhcpc6-script;
        kernel = gpuKernel;
        init-script = ./init-gpu.sh;
        init-common-script = ./init-common.sh;
        withNvidia = nvidiaDriver.modules;
      };
      gpuRootfs = import ./gpu-rootfs.nix { inherit pkgs nvidiaDriver nvat; };
      # Same fixed salt/uuid as `verity`, applied to the GPU rootfs.
      gpuVerity = pkgs.runCommand "gpu-rootfs-verity" {
        nativeBuildInputs = [ pkgs.cryptsetup ];
      } ''
        mkdir -p $out
        veritysetup format \
          --salt=${veritySalt} \
          --uuid=${verityUuid} \
          ${gpuRootfs} \
          $out/hashtree \
          | tee /dev/stderr \
          | grep "Root hash:" \
          | awk '{print $NF}' \
          | tr -d '\n' > $out/roothash
      '';
      gpuMeasurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", workloadRoothash ? null }:
        measurementFor {
          inherit vcpus vcpuType workloadRoothash;
          initrdDrv = gpuInitrd; verityDrv = gpuVerity; kernelDrv = gpuKernel;
          cmdlineExtra = " swiotlb=262144";
          name = "sev-snp-measurement-gpu-${toString vcpus}vcpus-${vcpuType}";
        };
      gpuMeasurement = gpuMeasurementFor { };
      gpuImage = pkgs.runCommand "aleph-gpu-image" {} ''
        mkdir -p $out
        ln -s ${gpuKernel}/bzImage $out/bzImage
        ln -s ${gpuInitrd}/initrd $out/initrd
        ln -s ${gpuRootfs} $out/rootfs.ext4
        cp ${ovmfFd} $out/OVMF.fd
        cp ${gpuMeasurement} $out/measurement.hex
        cp ${gpuVerity}/hashtree $out/rootfs.ext4.verity
        cp ${gpuVerity}/roothash $out/rootfs.ext4.roothash
        echo "${sourceRev}" > $out/source-rev
        cat > $out/gpu.json <<EOF
{"vendor":"nvidia","arch":"blackwell","driver_version":"${nvidiaDriver.version}","accepted_models":["NVIDIA RTX PRO 6000 Blackwell Server Edition"],"library_path":"/opt/nvidia/lib"}
EOF
      '';
```

`measurementFor` gains two optional arguments: `kernelDrv ? kernel` (used for `--kernel ${kernelDrv}/bzImage`) and `cmdlineExtra ? ""` appended to the cmdline string before `workload_roothash` handling, so that the GPU template reads `... roothash=X swiotlb=262144` platform-only and `... roothash=X workload_roothash=Y swiotlb=262144` with a workload. Keep existing callers' bytes identical (defaults). Add all new outputs to `packages`. Extend `nix/check-golden-measurements.sh` `outputs` with `gpuMeasurement`, and the workflow's `paths` need nothing (they already cover `nix/**`).

- [ ] **Step 6: Build, smoke, seed**

Run: `nix build ./nix#gpuImage --print-build-logs` then `nix/boot-smoke.sh` with the base image (must still boot) and add a `--gpu` mode to `boot-smoke.sh` that boots `gpuImage` under plain QEMU with no device and expects the console line `init: no NVIDIA GPU present; running without GPU attestation` followed by the usual readiness line. Then `nix/check-golden-measurements.sh --update` and inspect the diff: every entry moves (the `init-common.sh` edit) plus the new `gpuMeasurement`. Commit the new golden file.

- [ ] **Step 7: Commit**

```bash
git add nix .github/workflows/golden-measurements.yml
git commit -m "nix: gpuImage flavor, fail-closed GPU verification in init, golden measurements re-seeded"
```

---

# PR E: manifest, bundle and agent

### Task 14: manifest `gpu` block and bundle flavor

**Files:**
- Modify: `src/aleph/vm/vprogram/manifest.py`, `src/aleph/vm/vprogram/bundle.py`, `scripts/vprogram_bundle.py`
- Test: `tests/vprogram/test_manifest.py`, `tests/vprogram/test_bundle.py`

**Interfaces:**
- Produces: `class GpuRuntimeSpec(StrictModel): vendor: Literal["nvidia"]; arch: Literal["blackwell", "hopper"]; driver_version: str; accepted_models: list[str]; library_path: str`, `RuntimeManifest.gpu: GpuRuntimeSpec | None = None`, `BundleInfo.gpu: GpuRuntimeSpec | None = None`, `build_bundle(..., flavor="gpu")` (reads `gpu.json` from the image dir; nix target `gpuImage`), `make_manifest(..., gpu_runtime: bool = False)` selecting `CMDLINE_TEMPLATE_GPU_V1`, `GPU_MEMBER_FILES` identical to `MEMBER_FILES`.

- [ ] **Step 1: Write the failing tests**

`tests/vprogram/test_manifest.py`:

```python
def test_gpu_block_is_optional_and_strict():
    manifest = RuntimeManifest.model_validate(REFERENCE_MANIFEST)
    assert manifest.gpu is None
    with_gpu = deepcopy(REFERENCE_MANIFEST)
    with_gpu["gpu"] = {
        "vendor": "nvidia", "arch": "blackwell", "driver_version": "595.71.05",
        "accepted_models": ["NVIDIA RTX PRO 6000 Blackwell Server Edition"], "library_path": "/opt/nvidia/lib",
    }
    assert RuntimeManifest.model_validate(with_gpu).gpu.driver_version == "595.71.05"
    for bad in ({"vendor": "amd"}, {"driver_version": "r595"}, {"accepted_models": []}, {"library_path": "opt/nvidia"}, {"extra": 1}):
        broken = deepcopy(with_gpu)
        broken["gpu"] = with_gpu["gpu"] | bad
        with pytest.raises(ValidationError):
            RuntimeManifest.model_validate(broken)


def test_gpu_cmdline_template_keeps_swiotlb_as_fixed_text():
    from aleph.vm.vprogram.bundle import CMDLINE_TEMPLATE_GPU_V1

    assert "swiotlb=262144" in CMDLINE_TEMPLATE_GPU_V1
    assert "{swiotlb" not in CMDLINE_TEMPLATE_GPU_V1
    manifest = deepcopy(REFERENCE_MANIFEST)
    manifest["boot"]["cmdline_template"] = CMDLINE_TEMPLATE_GPU_V1
    RuntimeManifest.model_validate(manifest)  # the closed placeholder set still validates
```

`tests/vprogram/test_bundle.py` (using the existing `image_dir` fixture; add a `gpu.json` to it in a new `gpu_image_dir` fixture):

```python
def test_gpu_flavor_records_the_gpu_block(gpu_image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(gpu_image_dir, tmp_path, source_epoch=0, source=SOURCE, flavor="gpu")
    assert info.gpu.vendor == "nvidia"
    manifest = make_manifest(info=info, bundle_ref=BUNDLE_REF, name="aleph-snp-gpu", runtime_version="1", gpu_runtime=True)
    assert manifest.gpu == info.gpu
    assert manifest.boot.cmdline_template == CMDLINE_TEMPLATE_GPU_V1


def test_gpu_flavor_requires_gpu_json(image_dir: Path, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        build_bundle(image_dir, tmp_path, source_epoch=0, source=SOURCE, flavor="gpu")


def test_make_manifest_refuses_gpu_runtime_without_gpu_facts(image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(image_dir, tmp_path, source_epoch=0, source=SOURCE)
    with pytest.raises(ValueError):
        make_manifest(info=info, bundle_ref=BUNDLE_REF, name="x", runtime_version="1", gpu_runtime=True)
```

- [ ] **Step 2: Run to verify failure**

Run: `pytest tests/vprogram -q`

- [ ] **Step 3: Implement**

`manifest.py`:

```python
DRIVER_VERSION_PATTERN = r"^\d+\.\d+(\.\d+)?$"


class GpuRuntimeSpec(StrictModel):
    """What a client pins about the confidential GPU this runtime drives.
    Properties of the measured runtime (the driver is inside the image), so
    they live here, pinned through runtime.ref, and never in the message."""

    vendor: Literal["nvidia"]
    arch: Literal["blackwell", "hopper"]
    driver_version: str = Field(pattern=DRIVER_VERSION_PATTERN)
    accepted_models: list[str] = Field(min_length=1, description="Hardware model strings NVIDIA device certificates carry")
    library_path: str = Field(pattern=r"^/[a-z0-9/_-]+$", description="Where the driver userland is mounted in the workload chroot")
```

`RuntimeManifest.gpu: GpuRuntimeSpec | None = None` after `workload`.

`bundle.py`: `CMDLINE_TEMPLATE_GPU_V1 = "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash} workload_roothash={workload_roothash} swiotlb=262144 {verified_volumes}"` (compare with `CMDLINE_TEMPLATE_EXEC_V1` for the exact placeholder order used today and keep it), `GPU_JSON_FILE = "gpu.json"`, `BundleInfo.gpu: GpuRuntimeSpec | None = None`; in `build_bundle`, when `flavor == "gpu"` read `image_dir / GPU_JSON_FILE` and validate `GpuRuntimeSpec.model_validate_json`; the tar members are the vprogram ones. `make_manifest(..., gpu_runtime: bool = False)`: `if gpu_runtime and info.gpu is None: raise ValueError("gpu_runtime needs the gpu facts recorded by the gpu flavor build")`; select `CMDLINE_TEMPLATE_GPU_V1`, `EXEC_WORKLOAD`, and `gpu=info.gpu`. `scripts/vprogram_bundle.py`: add `gpu` to the `--flavor` choices, map it to `nix#gpuImage` in `_nix_target`, and pass `gpu_runtime=args.flavor == "gpu"`.

- [ ] **Step 4: Run tests, lint, commit**

Run: `pytest tests/vprogram -q && ruff check src scripts tests && mypy src/aleph/vm/vprogram`

```bash
git add src/aleph/vm/vprogram scripts/vprogram_bundle.py tests/vprogram
git commit -m "feat(vprogram): runtime manifest gpu block and the gpu bundle flavor"
```

---

### Task 15: agent resolves a V-PROGRAM's confidential GPU

**Files:**
- Modify: `src/aleph/vm/agent/capacity.py`, `src/aleph/vm/agent/vprogram_launch.py`, `src/aleph/vm/agent/run.py`
- Test: `tests/supervisor/test_agent_capacity.py`, `tests/supervisor/test_vprogram_launch.py`

**Prerequisite:** aleph-message with `VerifiableProgramContent.gpus` (its own plan). Until it is released, pin the git ref in `pyproject.toml` the way `7928a9b6` did for 1.3.1, and refresh `tests/supervisor/fixtures/vprogram_message.json` only if the item hash convention requires it (it does not: `gpus` defaults to empty and is omitted from existing fixtures).

**Interfaces:**
- Consumes: `content.gpus: list[ConfidentialGpu]` (`vendor`, `device_id`), `GpuDevice.cc_mode` (Task 5), `RuntimeManifest.gpu` (Task 14).
- Produces: `CapacityManager.resolve_confidential_gpus(requested_device_ids: list[str], owner: str) -> list[GpuSpec]`, `GPU_VPROGRAM_MIN_MEMORY_MIB = 2048`, `build_vprogram_spec` raising `VmSetupError` for a GPU message without a manifest `gpu` block, more than one GPU, or memory below the floor.

- [ ] **Step 1: Write the failing capacity tests**

In `tests/supervisor/test_agent_capacity.py` (reuse the module's `_manager(gpus)` helper and `_DEVICE_ID`; check the helper's name at the top of the file and use it):

```python
def _cc_gpu(pci_host: str, cc_mode: str | None) -> GpuDevice:
    gpu = GpuDevice(vendor="NVIDIA", device_name="GB202", device_class="0300", pci_host=pci_host, device_id=_DEVICE_ID)
    return gpu.model_copy(update={"cc_mode": cc_mode})


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_takes_only_on_mode_cards():
    manager = _manager([_cc_gpu("06:00.0", "off"), _cc_gpu("07:00.0", None), _cc_gpu("08:00.0", "on")])
    resolved = await manager.resolve_confidential_gpus([_DEVICE_ID], owner="0xUSER")
    assert [str(g.pci_host) for g in resolved] == ["08:00.0"]
    assert resolved[0].supports_x_vga is False


@pytest.mark.asyncio
async def test_resolve_confidential_gpus_names_the_confidential_requirement():
    manager = _manager([_cc_gpu("06:00.0", "devtools")])
    with pytest.raises(InsufficientResourcesError) as excinfo:
        await manager.resolve_confidential_gpus([_DEVICE_ID], owner="0xUSER")
    assert excinfo.value.required == {"confidential_gpu_device_id": _DEVICE_ID}
```

- [ ] **Step 2: Implement `resolve_confidential_gpus`**

In `capacity.py`, next to `resolve_gpus`:

```python
    async def resolve_confidential_gpus(self, requested_device_ids: list[str], owner: str) -> list[GpuSpec]:
        """Like resolve_gpus, restricted to cards probed in NVIDIA CC mode.

        `supports_x_vga` is always False: the SNP launcher never emits x-vga
        for a headless confidential guest. The error names the confidential
        requirement so the scheduler and the log can tell it from a plain
        GPU shortage.
        """
        if not requested_device_ids:
            return []
        async with self._lock:
            confidential = [gpu for gpu in await self._available_gpus() if gpu.cc_mode == "on"]
            try:
                resolved = self._match_requests(confidential, requested_device_ids, owner, consume_own_hold=True)
            except InsufficientResourcesError as error:
                device_id = error.required.get("gpu_device_id", "")
                raise InsufficientResourcesError(
                    f"No available GPU in confidential-computing mode matching device_id {device_id!r}",
                    required={"confidential_gpu_device_id": device_id},
                    available={"confidential_gpus": [gpu.device_id for gpu in confidential]},
                ) from error
        return [GpuSpec(pci_host=PciAddress(gpu.pci_host), supports_x_vga=False) for gpu in resolved]
```

(`InsufficientResourcesError` exposes `required`; check its constructor in `src/aleph/vm/agent/errors.py` or wherever it is defined and match it.)

- [ ] **Step 3: Write the failing launch tests**

In `tests/supervisor/test_vprogram_launch.py`. The module already provides `load_vprogram_message()`, the `storage_files` and `snp_vcpu_types` fixtures, and `_stage_bundle(tmp_path, storage_files, **overrides)` whose dotted-key overrides land in `MANIFEST_TEMPLATE` (a bare key such as `gpu=...` sets a top-level manifest field). Add:

```python
GPU_BLOCK = {
    "vendor": "nvidia", "arch": "blackwell", "driver_version": "595.71.05",
    "accepted_models": ["NVIDIA RTX PRO 6000 Blackwell Server Edition"], "library_path": "/opt/nvidia/lib",
}
VOLUME_SLOT_TEMPLATE = (
    MANIFEST_TEMPLATE["boot"]["cmdline_template"]
    + " workload_roothash={workload_roothash} swiotlb=262144 {verified_volumes}"
)


def _with_gpu(message: VerifiableProgramMessage, *, memory: int = 4096) -> VerifiableProgramMessage:
    content = message.content.model_copy(update={
        "gpus": [{"vendor": "nvidia", "device_id": "10de:2b85"}],
        "resources": message.content.resources.model_copy(update={"memory": memory}),
    })
    return message.model_copy(update={"content": content})


@pytest.mark.asyncio
async def test_gpu_vprogram_needs_a_gpu_runtime(tmp_path, storage_files, snp_vcpu_types):
    _stage_bundle(tmp_path, storage_files)  # MANIFEST_TEMPLATE has no gpu block
    message = _with_gpu(load_vprogram_message())
    with pytest.raises(VmSetupError, match="no gpu block"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_gpu_vprogram_enforces_the_memory_floor(tmp_path, storage_files, snp_vcpu_types):
    _stage_bundle(tmp_path, storage_files, gpu=GPU_BLOCK)
    message = _with_gpu(load_vprogram_message(), memory=1024)
    with pytest.raises(VmSetupError, match="2048"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_gpu_vprogram_spec_leaves_gpus_for_run_to_resolve(tmp_path, storage_files, snp_vcpu_types):
    # The fixture message carries a volume, so the manifest needs the slot
    # for the build to run to completion.
    _stage_bundle(tmp_path, storage_files, gpu=GPU_BLOCK, **{"boot.cmdline_template": VOLUME_SLOT_TEMPLATE})
    message = _with_gpu(load_vprogram_message())
    spec, _ = await build_vprogram_spec(message.item_hash, message.content)
    assert spec.gpus == []  # resolved against the host in run.py, after staging
    assert spec.memory_mib == 4096
    # The fixed swiotlb token reaches the daemon through its own sidecar.
    rootfs = next(disk.path for disk in spec.disks if disk.role is DiskRole.ROOTFS)
    assert (rootfs.parent / f"{rootfs.name}.cmdline_extra").read_text() == "swiotlb=262144\n"


@pytest.mark.asyncio
async def test_non_gpu_vprogram_leaves_no_cmdline_extra_sidecar(tmp_path, storage_files, snp_vcpu_types):
    _stage_bundle(tmp_path, storage_files, **{"boot.cmdline_template": VOLUME_SLOT_TEMPLATE.replace(" swiotlb=262144", "")})
    message = load_vprogram_message()
    spec, _ = await build_vprogram_spec(message.item_hash, message.content)
    rootfs = next(disk.path for disk in spec.disks if disk.role is DiskRole.ROOTFS)
    assert not (rootfs.parent / f"{rootfs.name}.cmdline_extra").exists()
```

The GPU checks in `build_vprogram_spec` run right after the manifest fetch, before the volume-slot check, which is why the first two tests can use the slot-less template.

The sidecar write goes next to the `verified_volumes` sidecar handling in `build_vprogram_spec`:

```python
CMDLINE_EXTRA_TOKEN = re.compile(r"(?<!\S)swiotlb=\d{1,9}(?!\S)")

    # Fixed tokens the template carries that the daemon cannot derive from a
    # roothash: today only the SWIOTLB size of the GPU runtime. Written to a
    # sidecar the daemon validates against the same closed allowlist and
    # splices between workload_roothash and verified_volumes, the template's
    # position. Absent token, absent sidecar: a stale file from a previous
    # staging must not survive into a runtime that never measured it.
    extra_sidecar = rootfs_path.parent / f"{rootfs_path.name}.cmdline_extra"
    extra_tokens = CMDLINE_EXTRA_TOKEN.findall(manifest.boot.cmdline_template)
    if extra_tokens:
        extra_sidecar.write_text(" ".join(extra_tokens) + "\n")
    else:
        extra_sidecar.unlink(missing_ok=True)
```

`_validate_cmdline_template` in `manifest.py` must also accept the fixed token: extend the validator so that, after placeholder checks, every non-placeholder token of the template is either one of the base tokens (`console=ttyS0`, `root=/dev/mapper/verity-root`, `ro`), a `key={placeholder}` pair, or matches `CMDLINE_EXTRA_TOKEN`; add a `test_manifest.py` case that `init=/bin/sh` in a template is rejected. This closes the template as a smuggling channel the same way the placeholder set does.

- [ ] **Step 4: Implement the launch checks**

In `vprogram_launch.py`, after `manifest = await fetch_runtime_manifest(...)` (`content.gpus` is `Optional`: absent and empty both mean no GPU):

```python
GPU_VPROGRAM_MIN_MEMORY_MIB = 2048

    gpus = list(content.gpus or [])
    if gpus:
        if len(gpus) > 1:
            msg = f"V-PROGRAM {vm_hash} declares {len(gpus)} GPUs; one confidential GPU per VM is supported"
            raise VmSetupError(msg)
        if manifest.gpu is None:
            msg = f"V-PROGRAM {vm_hash} declares a GPU but runtime {content.runtime.ref} has no gpu block"
            raise VmSetupError(msg)
        if gpus[0].vendor != manifest.gpu.vendor:
            msg = f"V-PROGRAM {vm_hash} declares a {gpus[0].vendor} GPU but the runtime drives {manifest.gpu.vendor}"
            raise VmSetupError(msg)
        if content.resources.memory < GPU_VPROGRAM_MIN_MEMORY_MIB:
            msg = (
                f"V-PROGRAM {vm_hash} declares a GPU with {content.resources.memory} MiB; the runtime's "
                f"swiotlb reservation needs at least {GPU_VPROGRAM_MIN_MEMORY_MIB} MiB"
            )
            raise VmSetupError(msg)
```

In `run.py`'s V-PROGRAM branch, after `build_vprogram_spec` and before `capacity.check_capacity`:

```python
            if content.gpus:
                resolved = await capacity.resolve_confidential_gpus(
                    [gpu.device_id for gpu in content.gpus], owner=content.address
                )
                spec = replace(spec, gpus=resolved)
```

Add a `run.py` test in `tests/supervisor/test_run_program_path.py`'s style (or `test_snp_instance_run.py`) asserting the spec passed to `supervisor.create_vm` carries the resolved `GpuSpec` when the message declares a GPU and `resolve_confidential_gpus` is mocked to return one.

- [ ] **Step 5: Run, lint, commit**

Run: `pytest tests/supervisor/test_agent_capacity.py tests/supervisor/test_vprogram_launch.py tests/supervisor/test_snp_instance_run.py -q && ruff check src tests && mypy src/aleph/vm/agent`

```bash
git add src/aleph/vm/agent tests/supervisor
git commit -m "feat(agent): resolve a V-PROGRAM's confidential GPU against CC-mode cards, fail closed on a GPU-less runtime"
```

---

### Task 16: operator runbook and architecture docs

**Files:**
- Create: `docs/operators/nvidia-cc.md`
- Modify: `docs/architecture/confidential.md`

- [ ] **Step 1: Write the runbook**

`docs/operators/nvidia-cc.md` with these sections, each concrete:

1. **Requirements**: RTX PRO 6000 Blackwell Server Edition (Workstation and Max-Q have no CC mode), EPYC Genoa or newer with SEV-SNP enabled, IOMMU on, above-4G decoding and resizable BAR on in BIOS, QEMU 9.1 or newer (the SNP requirement), `ENABLE_GPU_SUPPORT=true` and `ENABLE_QEMU_SUPPORT=true`.
2. **Bind the card to vfio-pci at boot**: point at the existing GPU passthrough doc; the host must never load the NVIDIA driver.
3. **Enable CC mode once**:
   ```
   git clone https://github.com/NVIDIA/gpu-admin-tools
   sudo python3 nvidia_gpu_tools.py --devices gpus --query-cc-mode
   sudo python3 nvidia_gpu_tools.py --devices <bdf> --set-cc-mode=on --reset-after-cc-mode-switch
   sudo python3 nvidia_gpu_tools.py --devices <bdf> --query-cc-mode   # expect: on
   ```
   The setting persists across reboots on the card. `devtools` is refused by the CRN.
4. **Confirm the advertisement**: `curl -s http://<crn>/about/capability | jq .tee` shows `nvidia_cc.devices`; `/about/usage/system` shows `cc_mode` per card. If `nvidia_cc` is absent while the card says `on`: check `sev_snp` is advertised (the block is gated on it), check the daemon log for `GPU CC mode probe failed` (the sysfs `resource0` file must be readable by the daemon user, root by default).
5. **Failure signatures**: a V-PROGRAM that powers off within a minute with `init: FATAL: gpu attestation failed: ...` in its console log means the guest could not reach `rim.attestation.nvidia.com` or `ocsp.ndis.nvidia.com` (check egress), or the driver RIM for the shipped driver is not published yet (check NVIDIA's RIM service for the version in the runtime manifest); `InvalidBackend ... not in NVIDIA confidential-computing mode` on create means the probe saw `off`/`devtools`; `confidential_gpu_device_id` in an `InsufficientResources` error means every CC-mode card is held or attached.
6. **What the CRN never does**: no NVIDIA driver on the host, no RIM or OCSP traffic from the host, no reading of the CC register while a VM owns the card.

- [ ] **Step 2: Update the architecture doc**

In `docs/architecture/confidential.md`: add a subsection "Confidential GPUs (NVIDIA CC)" under "The model" summarizing the flow (probe, gate, argv, in-guest verification, the GPU route and nonce derivation) in the doc's existing voice, update the "Key invariants" GPU bullet, and add pointers to `gpu_cc.rs`, `gpu_bar.rs`, `nix/init-gpu.sh`, `aleph-attest-agent/src/gpu.rs`. Bump the "Verified against" line to the PR's head commit.

- [ ] **Step 3: Commit**

```bash
git add docs/operators/nvidia-cc.md docs/architecture/confidential.md
git commit -m "docs: NVIDIA CC operator runbook and architecture notes"
```

---

### Task 17: PR stack assembly and cross-checks

- [ ] **Step 1: Branch layout**

Five branches, each based on the previous, off `origin/dev-2.1`: `od/nvidia-cc-a-attest-agent` (Tasks 1 to 3), `od/nvidia-cc-b-cc-probe` (4 to 6), `od/nvidia-cc-c-snp-argv` (7 to 9), `od/nvidia-cc-d-nix-gpu-image` (10 to 13), `od/nvidia-cc-e-agent` (14 to 16). Open the PRs in order with `gh pr create --base <previous branch>`, each description naming the spec and the golden-measurement impact (D re-seeds everything and adds `gpuMeasurement`; A adds no runtime dependency, so it moves nothing).

- [ ] **Step 2: Whole-stack checks**

From branch E: `cd rust && cargo fmt --all --check && cargo clippy --all-targets -- -D warnings && cargo test` (CI runs the suites; locally at least `-p supervisor-controller -p supervisor-daemon -p aleph-tee` plus the agent crate's own workspace); `pytest tests -q`; `scripts/check_proto_clean.sh`; `nix/check-golden-measurements.sh`.

- [ ] **Step 3: Record follow-ups**

Append to the PR E description the items this plan leaves to the other repos: aleph-message `gpus` field (release gate for E), aleph-rs `attest::nvidia` verifier and `tee_min_tcb.nvidia_cc`, scheduler placement on `tee.nvidia_cc.devices`, and the Tier 2 hardware run (spec section 8) once the SNP host with the card is up.
