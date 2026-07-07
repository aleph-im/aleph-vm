# alephctl Supervisor Debug CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `alephctl`, a Rust CLI in the aleph-vm Rust workspace that speaks the `aleph.supervisor.v1` gRPC contract over the supervisor's Unix socket for on-node debugging and testing.

**Architecture:** New crate `rust/crates/supervisor-cli` (lib + thin `alephctl` bin). Command handlers take a connected `SupervisorClient` and an `impl Write`, so integration tests drive them against an in-process fake `Supervisor` tonic server on a temp-dir Unix socket — no KVM, no real supervisor. `supervisor-proto` gains `serde::Serialize` derives on generated types so `--json` output is free for every command.

**Tech Stack:** Rust (edition 2024, workspace-pinned toolchain), tonic/prost, clap derive, tokio, serde_json, tempfile + tokio-stream (dev).

**Design doc:** `docs/plans/2026-07-07-alephctl-supervisor-cli-design.md`

**Base branch:** the current Rust workspace tip (the phase3 / rust-daemon PR stack, `od/phase3-b2a-nix-measured-image` at time of writing). Create branch `od/supervisor-cli` stacked on it. All paths below are repo-root-relative; the Rust workspace lives in `rust/`.

## Global Constraints

- Workspace edition: `edition = "2024"` (inherit via `edition.workspace = true`).
- Dependencies: workspace-level only (`[workspace.dependencies]` in `rust/Cargo.toml` already has everything needed — do NOT add new external crates; do not bump versions).
- Binary name: `alephctl`; crate name: `supervisor-cli`.
- `proto/supervisor.proto` is frozen: do NOT edit it. Only generated-code attributes may change (Task 1).
- All commands from `rust/`: `cargo test -p supervisor-cli`, `cargo fmt`, `cargo clippy -p supervisor-cli --all-targets -- -D warnings` must pass at every commit.
- Commit messages: conventional style used by the repo (`feat(supervisor-cli): ...`). Do NOT add a `Co-Authored-By` trailer (user preference).
- Env vars carry the `ALEPH_VM_` prefix (`ALEPH_VM_SUPERVISOR_GRPC_SOCKET`, `ALEPH_VM_EXECUTION_ROOT`); an empty value counts as unset, matching the daemon's `config.rs`.
- Streaming commands rely on default SIGINT behavior (process termination) — no custom Ctrl-C handler (YAGNI).

---

### Task 1: serde::Serialize derives on supervisor-proto generated types

**Files:**
- Modify: `rust/crates/supervisor-proto/build.rs`
- Modify: `rust/crates/supervisor-proto/Cargo.toml`
- Test: `rust/crates/supervisor-proto/tests/json.rs` (create)

**Interfaces:**
- Consumes: existing `supervisor_proto::pb` generated module.
- Produces: every generated message/enum in `pb` implements `serde::Serialize`. Later tasks call `serde_json::to_writer_pretty(&mut out, &response)` / `serde_json::to_string(&chunk)` on any `pb` type.

- [ ] **Step 1: Write the failing test**

Create `rust/crates/supervisor-proto/tests/json.rs`:

```rust
//! The generated types must serialize to JSON: alephctl's --json output
//! depends on the serde derives added in build.rs.

use supervisor_proto::pb;

#[test]
fn vm_info_serializes_to_json() {
    let info = pb::VmInfo {
        vm_id: "vm-1".to_string(),
        status: pb::VmStatus::Running as i32,
        numa_node: Some(1),
        ..Default::default()
    };
    let value = serde_json::to_value(&info).unwrap();
    assert_eq!(value["vm_id"], "vm-1");
    assert_eq!(value["status"], 3);
    assert_eq!(value["numa_node"], 1);
}

#[test]
fn nested_messages_and_maps_serialize() {
    let backup = pb::BackupInfo {
        source_sizes: [("rootfs".to_string(), 42u64)].into_iter().collect(),
        ..Default::default()
    };
    let value = serde_json::to_value(&backup).unwrap();
    assert_eq!(value["source_sizes"]["rootfs"], 42);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd rust && cargo test -p supervisor-proto --test json`
Expected: COMPILE ERROR — `serde_json` is not a dependency and `pb::VmInfo` does not implement `Serialize`.

- [ ] **Step 3: Add the serde dependency and the type_attribute**

In `rust/crates/supervisor-proto/Cargo.toml`, extend the dependency sections:

```toml
[dependencies]
prost.workspace = true
serde.workspace = true
tonic.workspace = true

[dev-dependencies]
serde_json.workspace = true

[build-dependencies]
tonic-build.workspace = true
```

In `rust/crates/supervisor-proto/build.rs`, add one call to the existing builder chain:

```rust
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        // serde::Serialize on every generated type: alephctl's --json output.
        // Generated Rust code only; the wire contract is untouched.
        .type_attribute(".", "#[derive(serde::Serialize)]")
        .compile_protos(&[proto], &[include])?;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-proto`
Expected: PASS (the new json tests plus any existing supervisor-proto tests).

- [ ] **Step 5: Verify the workspace still builds (the daemon consumes the same generated code)**

Run: `cd rust && cargo build --workspace && cargo fmt --check && cargo clippy -p supervisor-proto --all-targets -- -D warnings`
Expected: clean build, no fmt/clippy findings.

- [ ] **Step 6: Commit**

```bash
git add rust/crates/supervisor-proto/build.rs rust/crates/supervisor-proto/Cargo.toml rust/crates/supervisor-proto/tests/json.rs rust/Cargo.lock
git commit -m "feat(supervisor-proto): derive serde::Serialize on generated types"
```

---

### Task 2: supervisor-cli crate scaffold, clap surface, socket resolution

**Files:**
- Modify: `rust/Cargo.toml` (workspace members)
- Create: `rust/crates/supervisor-cli/Cargo.toml`
- Create: `rust/crates/supervisor-cli/src/lib.rs`
- Create: `rust/crates/supervisor-cli/src/cli.rs`
- Create: `rust/crates/supervisor-cli/src/client.rs`
- Create: `rust/crates/supervisor-cli/src/main.rs`
- Test: in-module `#[cfg(test)]` blocks in `cli.rs` and `client.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks (proto types come in Task 3).
- Produces:
  - `supervisor_cli::cli::{Cli, Command, VmCommand, PortsCommand}` — the full clap surface (all v1 subcommands, global `--socket: Option<PathBuf>` and `--json: bool`).
  - `supervisor_cli::client::resolve_socket_path(flag: Option<PathBuf>, env: impl Fn(&str) -> Option<String>) -> PathBuf`.

- [ ] **Step 1: Add the crate to the workspace and write its manifest**

In `rust/Cargo.toml`, extend `[workspace] members`:

```toml
members = [
    "crates/supervisor-proto",
    "crates/supervisor-daemon",
    "crates/supervisor-controller",
    "crates/supervisor-cli",
    "crates/aleph-tee",
    "crates/aleph-attest-agent",
]
```

Create `rust/crates/supervisor-cli/Cargo.toml`:

```toml
[package]
name = "supervisor-cli"
version = "0.1.0"
edition.workspace = true
license.workspace = true
repository.workspace = true
description = "alephctl: debug CLI speaking aleph.supervisor.v1 over the supervisor's Unix socket"

[[bin]]
name = "alephctl"
path = "src/main.rs"

[dependencies]
anyhow.workspace = true
clap.workspace = true
hyper-util.workspace = true
prost.workspace = true
serde.workspace = true
serde_json.workspace = true
supervisor-proto.workspace = true
tokio.workspace = true
tonic.workspace = true
tower.workspace = true

[dev-dependencies]
tempfile.workspace = true
tokio-stream.workspace = true
```

(`hyper-util` and `tower` are marked "test-only" in the workspace manifest comment because only daemon tests used them so far; the CLI uses them at runtime for the UDS connector, exactly like aleph-bench's client. No version changes.)

- [ ] **Step 2: Write the failing tests**

Create `rust/crates/supervisor-cli/src/cli.rs` with the clap definitions AND their parse tests:

```rust
//! Command-line surface of alephctl. Parsing only: dispatch lives in
//! main.rs, handlers in commands/.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "alephctl",
    about = "Debug CLI for the aleph-vm supervisor (gRPC over its Unix socket)"
)]
pub struct Cli {
    /// Supervisor Unix socket. Default: $ALEPH_VM_SUPERVISOR_GRPC_SOCKET,
    /// then $ALEPH_VM_EXECUTION_ROOT/supervisor.sock, then
    /// /var/lib/aleph/vm/supervisor.sock.
    #[arg(long, global = true)]
    pub socket: Option<PathBuf>,

    /// Print raw responses as JSON (streams: one JSON object per line).
    #[arg(long, global = true)]
    pub json: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Supervisor health and VM count.
    Health,
    /// Host hardware, TEE and networking facts.
    HostInfo,
    /// VM lifecycle and inspection.
    #[command(subcommand)]
    Vm(VmCommand),
    /// Fetch or follow a VM's logs.
    Logs {
        vm_id: String,
        /// Stream new lines as they arrive (StreamLogs).
        #[arg(long, short = 'f')]
        follow: bool,
        /// Only the most recent N lines (GetLogs from the tail).
        #[arg(long, conflicts_with = "follow")]
        tail: Option<u32>,
    },
    /// Stream VM lifecycle events until interrupted.
    Events,
    /// Port forwards.
    #[command(subcommand)]
    Ports(PortsCommand),
}

#[derive(Subcommand, Debug)]
pub enum VmCommand {
    /// List all VMs.
    List,
    /// Show a VM's current state.
    Get { vm_id: String },
    /// Show the spec a VM was created from.
    Spec { vm_id: String },
    /// Start a stopped VM.
    Start { vm_id: String },
    /// Stop a VM without releasing its definition.
    Stop { vm_id: String },
    /// Reboot a VM (soft reboot).
    Reboot { vm_id: String },
    /// Delete a VM (prompts unless --yes).
    Delete {
        vm_id: String,
        #[arg(long, short = 'y')]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum PortsCommand {
    /// List port forwards (all VMs, or one).
    List { vm_id: Option<String> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_global_flags_and_vm_delete() {
        let cli =
            Cli::try_parse_from(["alephctl", "--json", "vm", "delete", "vm-1", "--yes"]).unwrap();
        assert!(cli.json);
        assert!(cli.socket.is_none());
        match cli.command {
            Command::Vm(VmCommand::Delete { vm_id, yes }) => {
                assert_eq!(vm_id, "vm-1");
                assert!(yes);
            }
            other => panic!("unexpected parse: {other:?}"),
        }
    }

    #[test]
    fn parses_socket_after_the_subcommand() {
        let cli = Cli::try_parse_from(["alephctl", "health", "--socket", "/tmp/s.sock"]).unwrap();
        assert_eq!(cli.socket, Some(std::path::PathBuf::from("/tmp/s.sock")));
        assert!(matches!(cli.command, Command::Health));
    }

    #[test]
    fn logs_tail_conflicts_with_follow() {
        let error =
            Cli::try_parse_from(["alephctl", "logs", "vm-1", "--follow", "--tail", "10"])
                .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
}
```

Create `rust/crates/supervisor-cli/src/client.rs` with resolution tests FIRST (the function body comes in step 4 — write the tests against the signature below):

```rust
//! Socket-path resolution and (from Task 3) the UDS gRPC client plumbing.

use std::path::PathBuf;

const DEFAULT_EXECUTION_ROOT: &str = "/var/lib/aleph/vm";

/// Resolve the supervisor socket path: `--socket` flag, then
/// ALEPH_VM_SUPERVISOR_GRPC_SOCKET, then ALEPH_VM_EXECUTION_ROOT/
/// supervisor.sock, then /var/lib/aleph/vm/supervisor.sock. Empty env
/// values count as unset, matching the daemon's settings resolution.
pub fn resolve_socket_path(
    flag: Option<PathBuf>,
    env: impl Fn(&str) -> Option<String>,
) -> PathBuf {
    todo!("step 4")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn flag_wins_over_everything() {
        let resolved = resolve_socket_path(Some("/tmp/x.sock".into()), |_| {
            Some("/should/not/win".to_string())
        });
        assert_eq!(resolved, PathBuf::from("/tmp/x.sock"));
    }

    #[test]
    fn socket_env_beats_execution_root() {
        let env = |name: &str| match name {
            "ALEPH_VM_SUPERVISOR_GRPC_SOCKET" => Some("/run/sup.sock".to_string()),
            "ALEPH_VM_EXECUTION_ROOT" => Some("/data".to_string()),
            _ => None,
        };
        assert_eq!(resolve_socket_path(None, env), PathBuf::from("/run/sup.sock"));
    }

    #[test]
    fn execution_root_derives_the_socket_path() {
        let env = |name: &str| {
            (name == "ALEPH_VM_EXECUTION_ROOT").then(|| "/data".to_string())
        };
        assert_eq!(
            resolve_socket_path(None, env),
            PathBuf::from("/data/supervisor.sock")
        );
    }

    #[test]
    fn empty_env_values_count_as_unset() {
        let env = |_: &str| Some(String::new());
        assert_eq!(
            resolve_socket_path(None, env),
            PathBuf::from("/var/lib/aleph/vm/supervisor.sock")
        );
    }

    #[test]
    fn defaults_without_flag_or_env() {
        assert_eq!(
            resolve_socket_path(None, no_env),
            PathBuf::from("/var/lib/aleph/vm/supervisor.sock")
        );
    }
}
```

Create `rust/crates/supervisor-cli/src/lib.rs`:

```rust
//! alephctl library: clap surface, supervisor client plumbing and command
//! handlers. main.rs is thin glue so integration tests can drive handlers
//! against an in-process fake supervisor.

pub mod cli;
pub mod client;
```

Create `rust/crates/supervisor-cli/src/main.rs` (temporary stub, replaced in Task 10):

```rust
use clap::Parser;
use supervisor_cli::cli::Cli;

fn main() {
    // Dispatch lands with the command handlers (Task 10); parsing already
    // works so `alephctl --help` documents the full surface.
    let cli = Cli::parse();
    eprintln!("alephctl: {:?}: not implemented yet", cli.command);
    std::process::exit(2);
}
```

- [ ] **Step 3: Run tests to verify the resolution tests fail**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: the three `cli::tests` pass; the five `client::tests` PANIC with `not yet implemented: step 4` (the `todo!`).

- [ ] **Step 4: Implement resolve_socket_path**

Replace the `todo!("step 4")` body in `client.rs`:

```rust
pub fn resolve_socket_path(
    flag: Option<PathBuf>,
    env: impl Fn(&str) -> Option<String>,
) -> PathBuf {
    if let Some(path) = flag {
        return path;
    }
    if let Some(path) = env("ALEPH_VM_SUPERVISOR_GRPC_SOCKET").filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    let root = env("ALEPH_VM_EXECUTION_ROOT")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_EXECUTION_ROOT.to_string());
    PathBuf::from(root).join("supervisor.sock")
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS (8 tests).

Run: `cd rust && cargo run -p supervisor-cli --bin alephctl -- --help`
Expected: help text listing `health`, `host-info`, `vm`, `logs`, `events`, `ports` and the global `--socket` / `--json` flags.

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`
Expected: no findings. (Unused-dependency warnings do not exist in clippy; unused `use` would. The client deps added now are used from Task 3 — cargo does not warn about unused crate deps by default.)

```bash
git add rust/Cargo.toml rust/Cargo.lock rust/crates/supervisor-cli
git commit -m "feat(supervisor-cli): scaffold alephctl crate with clap surface and socket resolution"
```

---

### Task 3: UDS connect and gRPC error rendering

**Files:**
- Modify: `rust/crates/supervisor-cli/src/client.rs`

**Interfaces:**
- Consumes: `supervisor_proto::{pb, ERROR_TRAILER_KEY}`.
- Produces (used by every command handler and main.rs):
  - `pub type SupervisorClient = pb::supervisor_client::SupervisorClient<tonic::transport::Channel>;`
  - `pub async fn connect(path: &Path) -> anyhow::Result<SupervisorClient>`
  - `pub fn status_error(status: tonic::Status) -> anyhow::Error`
  - `pub fn format_status(status: &tonic::Status) -> String`

- [ ] **Step 1: Write the failing tests**

Append to `rust/crates/supervisor-cli/src/client.rs` `tests` module:

```rust
    use prost::Message as _;
    use supervisor_proto::{pb, ERROR_TRAILER_KEY};

    #[tokio::test]
    async fn connect_reports_a_missing_socket_clearly() {
        let error = connect(std::path::Path::new("/nonexistent/supervisor.sock"))
            .await
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("/nonexistent/supervisor.sock"), "{text}");
        assert!(text.contains("is it running"), "{text}");
    }

    #[test]
    fn format_status_includes_the_error_detail_trailer() {
        let detail = pb::ErrorDetail {
            code: pb::ErrorCode::VmNotFound as i32,
            message: "no VM with id ghost".to_string(),
            vm_id: "ghost".to_string(),
        };
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert_bin(
            ERROR_TRAILER_KEY,
            tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
        );
        let status = tonic::Status::with_metadata(
            tonic::Code::NotFound,
            "no VM with id ghost",
            metadata,
        );
        assert_eq!(
            format_status(&status),
            "NotFound: no VM with id ghost [ERROR_CODE_VM_NOT_FOUND]"
        );
    }

    #[test]
    fn format_status_without_trailer_is_code_and_message() {
        let status = tonic::Status::unavailable("socket closed");
        assert_eq!(format_status(&status), "Unavailable: socket closed");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: COMPILE ERROR — `connect` and `format_status` are not defined.

- [ ] **Step 3: Implement connect, format_status, status_error**

Add to `rust/crates/supervisor-cli/src/client.rs` (above the tests module), and extend the imports at the top of the file:

```rust
use std::path::Path;

use anyhow::Context as _;
use hyper_util::rt::TokioIo;
use prost::Message as _;
use supervisor_proto::{pb, ERROR_TRAILER_KEY};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

pub type SupervisorClient = pb::supervisor_client::SupervisorClient<Channel>;

/// Connect to the supervisor over its Unix socket. The endpoint URI is a
/// placeholder tonic requires; every connection goes to the socket.
pub async fn connect(path: &Path) -> anyhow::Result<SupervisorClient> {
    let socket = path.to_path_buf();
    let channel = Endpoint::try_from("http://socket.invalid")
        .context("static endpoint")?
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(
                    tokio::net::UnixStream::connect(socket).await?,
                ))
            }
        }))
        .await
        .with_context(|| {
            format!(
                "cannot reach the supervisor at {}, is it running?",
                path.display()
            )
        })?;
    Ok(SupervisorClient::new(channel))
}

/// Render a gRPC error for stderr: status code, message, and the ErrorCode
/// from the ErrorDetail trailer when the supervisor attached one.
pub fn format_status(status: &tonic::Status) -> String {
    let mut text = format!("{:?}: {}", status.code(), status.message());
    if let Some(value) = status.metadata().get_bin(ERROR_TRAILER_KEY) {
        if let Ok(bytes) = value.to_bytes() {
            if let Ok(detail) = pb::ErrorDetail::decode(bytes.as_ref()) {
                let code = pb::ErrorCode::try_from(detail.code)
                    .unwrap_or(pb::ErrorCode::Unspecified);
                text.push_str(&format!(" [{}]", code.as_str_name()));
            }
        }
    }
    text
}

/// The `map_err` every handler uses on an RPC call.
pub fn status_error(status: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!(format_status(&status))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS (11 tests).

- [ ] **Step 5: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/client.rs
git commit -m "feat(supervisor-cli): UDS connect and gRPC error rendering"
```

---

### Task 4: output helpers (tables, durations, enum names, JSON)

**Files:**
- Create: `rust/crates/supervisor-cli/src/output.rs`
- Modify: `rust/crates/supervisor-cli/src/lib.rs` (add `pub mod output;`)

**Interfaces:**
- Consumes: `supervisor_proto::pb` enums.
- Produces (used by all command handlers):
  - `pub fn write_table(out: &mut impl Write, headers: &[&str], rows: &[Vec<String>]) -> std::io::Result<()>`
  - `pub fn write_json(out: &mut impl Write, value: &impl serde::Serialize) -> anyhow::Result<()>` (pretty JSON + trailing newline)
  - `pub fn format_duration_secs(secs: u64) -> String`
  - `pub fn or_dash(value: &str) -> &str`
  - Enum display names, each `fn(i32) -> String` stripping the proto prefix: `vm_status_name`, `backend_name`, `health_status_name`, `protocol_name`, `confidential_mode_name`, `tee_backend_name`, `disk_format_name`, `disk_role_name`.

- [ ] **Step 1: Write the failing tests**

Create `rust/crates/supervisor-cli/src/output.rs` with the tests and stub-free code order reversed: write ONLY the module doc and the tests first.

```rust
//! Human-readable rendering: aligned tables, key-value blocks, durations,
//! proto enum names, and the --json writer.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_pads_columns_and_trims_trailing_space() {
        let mut out = Vec::new();
        write_table(
            &mut out,
            &["ID", "STATUS"],
            &[
                vec!["vm-1".to_string(), "RUNNING".to_string()],
                vec!["a-much-longer-id".to_string(), "STOPPED".to_string()],
            ],
        )
        .unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(
            text,
            "ID                STATUS\n\
             vm-1              RUNNING\n\
             a-much-longer-id  STOPPED\n"
        );
    }

    #[test]
    fn durations_use_the_two_most_significant_units() {
        assert_eq!(format_duration_secs(0), "0s");
        assert_eq!(format_duration_secs(45), "45s");
        assert_eq!(format_duration_secs(125), "2m 5s");
        assert_eq!(format_duration_secs(7320), "2h 2m");
        assert_eq!(format_duration_secs(183_600), "2d 3h");
    }

    #[test]
    fn enum_names_strip_the_proto_prefix() {
        use supervisor_proto::pb;
        assert_eq!(vm_status_name(pb::VmStatus::Running as i32), "RUNNING");
        assert_eq!(backend_name(pb::Backend::Qemu as i32), "QEMU");
        assert_eq!(health_status_name(pb::HealthStatus::Ok as i32), "OK");
        assert_eq!(protocol_name(pb::Protocol::Tcp as i32), "TCP");
        assert_eq!(
            confidential_mode_name(pb::ConfidentialMode::SevSnp as i32),
            "SEV_SNP"
        );
        assert_eq!(
            disk_format_name(pb::disk_config::Format::Qcow2 as i32),
            "QCOW2"
        );
        assert_eq!(
            disk_role_name(pb::disk_config::DiskRole::Rootfs as i32),
            "ROOTFS"
        );
        assert_eq!(vm_status_name(999), "UNKNOWN(999)");
    }

    #[test]
    fn or_dash_replaces_empty_strings() {
        assert_eq!(or_dash(""), "-");
        assert_eq!(or_dash("value"), "value");
    }

    #[test]
    fn write_json_is_pretty_with_a_trailing_newline() {
        let mut out = Vec::new();
        write_json(&mut out, &serde_json::json!({"a": 1})).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\n  \"a\": 1\n}\n");
    }
}
```

Add `pub mod output;` to `rust/crates/supervisor-cli/src/lib.rs`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: COMPILE ERROR — none of the functions exist.

- [ ] **Step 3: Implement the helpers**

Fill `rust/crates/supervisor-cli/src/output.rs` above the tests module:

```rust
use std::io::Write;

use supervisor_proto::pb;

/// Pad columns to their widest cell, two spaces between columns, no
/// trailing whitespace.
pub fn write_table(
    out: &mut impl Write,
    headers: &[&str],
    rows: &[Vec<String>],
) -> std::io::Result<()> {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate().take(widths.len()) {
            widths[index] = widths[index].max(cell.len());
        }
    }
    let render = |cells: &[String]| -> String {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        padded.join("  ").trim_end().to_string()
    };
    let header_row: Vec<String> = headers.iter().map(|header| header.to_string()).collect();
    writeln!(out, "{}", render(&header_row))?;
    for row in rows {
        writeln!(out, "{}", render(row))?;
    }
    Ok(())
}

/// Pretty JSON plus a trailing newline: the --json output of unary calls.
pub fn write_json(out: &mut impl Write, value: &impl serde::Serialize) -> anyhow::Result<()> {
    serde_json::to_writer_pretty(&mut *out, value)?;
    writeln!(out)?;
    Ok(())
}

/// The two most significant units: "45s", "2m 5s", "2h 2m", "2d 3h".
pub fn format_duration_secs(secs: u64) -> String {
    if secs >= 86_400 {
        format!("{}d {}h", secs / 86_400, (secs % 86_400) / 3_600)
    } else if secs >= 3_600 {
        format!("{}h {}m", secs / 3_600, (secs % 3_600) / 60)
    } else if secs >= 60 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// "-" for empty proto string fields in key-value blocks.
pub fn or_dash(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

/// fn(i32) -> String rendering a proto enum by name, minus the proto
/// prefix; out-of-range values render as UNKNOWN(n) instead of panicking.
macro_rules! enum_name {
    ($fn_name:ident, $enum_type:ty, $prefix:literal) => {
        pub fn $fn_name(value: i32) -> String {
            <$enum_type>::try_from(value)
                .map(|variant| variant.as_str_name().trim_start_matches($prefix).to_string())
                .unwrap_or_else(|_| format!("UNKNOWN({value})"))
        }
    };
}

enum_name!(vm_status_name, pb::VmStatus, "VM_STATUS_");
enum_name!(backend_name, pb::Backend, "BACKEND_");
enum_name!(health_status_name, pb::HealthStatus, "HEALTH_STATUS_");
enum_name!(protocol_name, pb::Protocol, "PROTOCOL_");
enum_name!(confidential_mode_name, pb::ConfidentialMode, "CONFIDENTIAL_MODE_");
enum_name!(tee_backend_name, pb::TeeBackend, "TEE_BACKEND_");
enum_name!(disk_format_name, pb::disk_config::Format, "FORMAT_");
enum_name!(disk_role_name, pb::disk_config::DiskRole, "DISK_ROLE_");
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS (16 tests).

- [ ] **Step 5: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/output.rs rust/crates/supervisor-cli/src/lib.rs
git commit -m "feat(supervisor-cli): output helpers for tables, durations, enum names and JSON"
```

---

### Task 5: fake supervisor harness + health and host-info commands

**Files:**
- Create: `rust/crates/supervisor-cli/tests/support/mod.rs`
- Create: `rust/crates/supervisor-cli/tests/support/fake.rs`
- Create: `rust/crates/supervisor-cli/tests/cli.rs`
- Create: `rust/crates/supervisor-cli/src/commands/mod.rs`
- Create: `rust/crates/supervisor-cli/src/commands/host.rs`
- Modify: `rust/crates/supervisor-cli/src/lib.rs` (add `pub mod commands;`)

**Interfaces:**
- Consumes: `client::{SupervisorClient, connect, status_error}`, `output::*`, `supervisor_proto::pb`.
- Produces:
  - `supervisor_cli::commands::host::health(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> anyhow::Result<()>`
  - `supervisor_cli::commands::host::host_info(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> anyhow::Result<()>`
  - Test harness `tests/support/fake.rs`: `pub struct FakeSupervisor` (all canned-data fields, defined here once and reused by Tasks 6–9) and `pub async fn spawn(fake: FakeSupervisor) -> (tempfile::TempDir, std::path::PathBuf)`.

- [ ] **Step 1: Write the fake supervisor harness**

Create `rust/crates/supervisor-cli/tests/support/mod.rs`:

```rust
pub mod fake;
```

Create `rust/crates/supervisor-cli/tests/support/fake.rs`. The `unimplemented_rpc!` entries are placeholders for RPCs alephctl never calls; Tasks 6–9 replace specific entries with real implementations.

```rust
//! In-process fake supervisor: canned data behind the real tonic server
//! codegen, served on a temp-dir Unix socket. The CLI-relevant RPCs return
//! the struct's canned fields; everything else answers UNIMPLEMENTED.

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use supervisor_proto::pb::supervisor_server::{Supervisor, SupervisorServer};
use supervisor_proto::{pb, ERROR_TRAILER_KEY};
use tokio_stream::wrappers::UnixListenerStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[derive(Default)]
pub struct FakeSupervisor {
    pub host: pb::HostInfo,
    pub vms: Vec<pb::VmInfo>,
    pub spec: Option<pb::VmSpec>,
    pub forwards: Vec<pb::PortForwardInfo>,
    pub logs: Vec<pb::LogChunk>,
    pub events: Vec<pb::VmEvent>,
    /// vm_ids DeleteVm was called with; tests clone the Arc before spawn.
    pub deleted: Arc<Mutex<Vec<String>>>,
    /// Every GetLogsRequest received; tests assert tail/from_tail mapping.
    pub log_requests: Arc<Mutex<Vec<pb::GetLogsRequest>>>,
}

impl FakeSupervisor {
    fn find_vm(&self, vm_id: &str) -> Option<&pb::VmInfo> {
        self.vms.iter().find(|vm| vm.vm_id == vm_id)
    }
}

/// NOT_FOUND with the same ErrorDetail trailer the real daemon attaches,
/// so the CLI's trailer decoding is exercised end-to-end.
fn not_found(vm_id: &str) -> Status {
    let message = format!("no VM with id {vm_id}");
    let detail = pb::ErrorDetail {
        code: pb::ErrorCode::VmNotFound as i32,
        message: message.clone(),
        vm_id: vm_id.to_string(),
    };
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert_bin(
        ERROR_TRAILER_KEY,
        tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
    );
    Status::with_metadata(tonic::Code::NotFound, message, metadata)
}

macro_rules! unimplemented_rpc {
    ($name:ident, $request:ty, $response:ty) => {
        async fn $name(
            &self,
            _request: Request<$request>,
        ) -> Result<Response<$response>, Status> {
            Err(Status::unimplemented("not faked"))
        }
    };
}

#[tonic::async_trait]
impl Supervisor for FakeSupervisor {
    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            status: pb::HealthStatus::Ok as i32,
            vm_count: self.vms.len() as u32,
        }))
    }

    async fn get_host_info(
        &self,
        _request: Request<pb::GetHostInfoRequest>,
    ) -> Result<Response<pb::HostInfo>, Status> {
        Ok(Response::new(self.host.clone()))
    }

    unimplemented_rpc!(create_vm, pb::VmSpec, pb::VmInfo);
    unimplemented_rpc!(get_vm, pb::GetVmRequest, pb::VmInfo);
    unimplemented_rpc!(get_vm_spec, pb::GetVmSpecRequest, pb::VmSpec);
    unimplemented_rpc!(list_vms, pb::ListVmsRequest, pb::ListVmsResponse);
    unimplemented_rpc!(delete_vm, pb::DeleteVmRequest, pb::DeleteVmResponse);
    unimplemented_rpc!(stop_vm, pb::StopVmRequest, pb::VmInfo);
    unimplemented_rpc!(start_vm, pb::StartVmRequest, pb::VmInfo);
    unimplemented_rpc!(reboot_vm, pb::RebootVmRequest, pb::VmInfo);
    unimplemented_rpc!(reinstall_vm, pb::ReinstallVmRequest, pb::VmInfo);
    unimplemented_rpc!(
        run_program_code,
        pb::RunProgramCodeRequest,
        pb::RunProgramCodeResponse
    );
    unimplemented_rpc!(restore_from_image, pb::RestoreFromImageRequest, pb::VmInfo);
    unimplemented_rpc!(add_port_forward, pb::AddPortForwardRequest, pb::PortForwardInfo);
    unimplemented_rpc!(
        remove_port_forward,
        pb::RemovePortForwardRequest,
        pb::RemovePortForwardResponse
    );
    unimplemented_rpc!(
        list_port_forwards,
        pb::ListPortForwardsRequest,
        pb::ListPortForwardsResponse
    );
    unimplemented_rpc!(get_logs, pb::GetLogsRequest, pb::GetLogsResponse);
    unimplemented_rpc!(start_backup, pb::StartBackupRequest, pb::BackupInfo);
    unimplemented_rpc!(get_backup_status, pb::GetBackupStatusRequest, pb::BackupInfo);
    unimplemented_rpc!(list_backups, pb::ListBackupsRequest, pb::ListBackupsResponse);
    unimplemented_rpc!(delete_backup, pb::DeleteBackupRequest, pb::DeleteBackupResponse);
    unimplemented_rpc!(restore_backup, pb::RestoreBackupRequest, pb::VmInfo);
    unimplemented_rpc!(
        initialize_confidential,
        pb::InitializeConfidentialRequest,
        pb::InitializeConfidentialResponse
    );
    unimplemented_rpc!(get_measurement, pb::GetMeasurementRequest, pb::Measurement);
    unimplemented_rpc!(inject_secret, pb::InjectSecretRequest, pb::InjectSecretResponse);
    unimplemented_rpc!(
        recreate_network,
        pb::RecreateNetworkRequest,
        pb::RecreateNetworkResponse
    );

    type WatchEventsStream = BoxStream<pb::VmEvent>;
    async fn watch_events(
        &self,
        _request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    type StreamLogsStream = BoxStream<pb::LogChunk>;
    async fn stream_logs(
        &self,
        _request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    type DownloadBackupStream = BoxStream<pb::BackupChunk>;
    async fn download_backup(
        &self,
        _request: Request<pb::DownloadBackupRequest>,
    ) -> Result<Response<Self::DownloadBackupStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }
}

/// Serve `fake` on a socket in a fresh temp dir. The TempDir keeps the
/// socket alive for the test's lifetime; the server task ends with the
/// runtime.
pub async fn spawn(fake: FakeSupervisor) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("supervisor.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind test socket");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SupervisorServer::new(fake))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
            .expect("fake supervisor server");
    });
    (dir, path)
}
```

Note for the implementer: `find_vm` and `not_found` are `dead_code` until Task 6 replaces the lifecycle stubs. Silence the interim warning with `#[allow(dead_code)]` on both items and REMOVE the allows in Task 6.

- [ ] **Step 2: Write the failing integration tests**

Create `rust/crates/supervisor-cli/tests/cli.rs`:

```rust
//! Integration tests: command handlers against the in-process fake
//! supervisor from tests/support/fake.rs, output captured in a Vec<u8>.

mod support;

use supervisor_cli::{client, commands};
use supervisor_proto::pb;
use support::fake::{spawn, FakeSupervisor};

/// A RUNNING QEMU VM with an IPv4 assignment and 2m5s uptime.
fn running_vm(id: &str) -> pb::VmInfo {
    pb::VmInfo {
        vm_id: id.to_string(),
        status: pb::VmStatus::Running as i32,
        backend: pb::Backend::Qemu as i32,
        ipv4: Some(pb::IpAssignment {
            address: "172.16.3.2".to_string(),
            network_cidr: "172.16.3.0/24".to_string(),
            gateway: "172.16.3.1".to_string(),
        }),
        uptime_secs: 125,
        ..Default::default()
    }
}

fn fake_host() -> pb::HostInfo {
    pb::HostInfo {
        cpu_count: 8,
        cpu_architecture: "x86_64".to_string(),
        cpu_vendor: "AuthenticAMD".to_string(),
        cpu_model: "AMD EPYC 7543".to_string(),
        memory_mib: 16384,
        hostname: "testhost".to_string(),
        kernel_version: "6.8.0-test".to_string(),
        sev_supported: true,
        sev_es_supported: true,
        numa_nodes: vec![pb::NumaNode {
            index: 0,
            cpu_count: 8,
            memory_mib: 16384,
        }],
        ..Default::default()
    }
}

#[tokio::test]
async fn health_prints_status_and_vm_count() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::health(&mut client, &mut out, false).await.unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "status: OK\nvms: 1\n");
}

#[tokio::test]
async fn health_json_is_the_raw_response() {
    let fake = FakeSupervisor::default();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::health(&mut client, &mut out, true).await.unwrap();
    let value: serde_json::Value =
        serde_json::from_slice(&out).expect("valid JSON");
    assert_eq!(value["status"], pb::HealthStatus::Ok as i32);
    assert_eq!(value["vm_count"], 0);
}

#[tokio::test]
async fn host_info_prints_a_key_value_block() {
    let fake = FakeSupervisor {
        host: fake_host(),
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::host::host_info(&mut client, &mut out, false).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    assert_eq!(
        text,
        "hostname: testhost\n\
         kernel: 6.8.0-test\n\
         cpu: 8 x AMD EPYC 7543 (x86_64, AuthenticAMD)\n\
         memory: 16384 MiB\n\
         tee: sev sev-es\n\
         host_ipv4: -\n\
         numa0: 8 cpus, 16384 MiB\n"
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli --test cli`
Expected: COMPILE ERROR — `supervisor_cli::commands` does not exist.

- [ ] **Step 4: Implement the host commands**

Add `pub mod commands;` to `rust/crates/supervisor-cli/src/lib.rs`.

Create `rust/crates/supervisor-cli/src/commands/mod.rs`:

```rust
//! Command handlers. Each takes a connected client and a writer so
//! integration tests capture output; main.rs passes stdout.

pub mod host;
```

Create `rust/crates/supervisor-cli/src/commands/host.rs`:

```rust
//! `alephctl health` and `alephctl host-info`.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{status_error, SupervisorClient};
use crate::output;

pub async fn health(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    json: bool,
) -> Result<()> {
    let response = client
        .health(pb::HealthRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    writeln!(out, "status: {}", output::health_status_name(response.status))?;
    writeln!(out, "vms: {}", response.vm_count)?;
    Ok(())
}

pub async fn host_info(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    json: bool,
) -> Result<()> {
    let info = client
        .get_host_info(pb::GetHostInfoRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &info);
    }
    writeln!(out, "hostname: {}", info.hostname)?;
    writeln!(out, "kernel: {}", info.kernel_version)?;
    writeln!(
        out,
        "cpu: {} x {} ({}, {})",
        info.cpu_count, info.cpu_model, info.cpu_architecture, info.cpu_vendor
    )?;
    let memory = if info.memory_type.is_empty() {
        format!("{} MiB", info.memory_mib)
    } else {
        format!("{} MiB {}", info.memory_mib, info.memory_type)
    };
    writeln!(out, "memory: {memory}")?;
    let mut tee: Vec<&str> = Vec::new();
    if info.sev_supported {
        tee.push("sev");
    }
    if info.sev_es_supported {
        tee.push("sev-es");
    }
    if info.sev_snp_supported {
        tee.push("sev-snp");
    }
    if info.tdx_supported {
        tee.push("tdx");
    }
    let tee_line = if tee.is_empty() { "none".to_string() } else { tee.join(" ") };
    writeln!(out, "tee: {tee_line}")?;
    writeln!(out, "host_ipv4: {}", output::or_dash(&info.host_ipv4))?;
    for node in &info.numa_nodes {
        writeln!(
            out,
            "numa{}: {} cpus, {} MiB",
            node.index, node.cpu_count, node.memory_mib
        )?;
    }
    for gpu in &info.gpus {
        writeln!(out, "gpu: {} {} ({})", gpu.pci_host, gpu.model, gpu.device_id)?;
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS (unit tests + 3 integration tests).

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/commands rust/crates/supervisor-cli/src/lib.rs rust/crates/supervisor-cli/tests
git commit -m "feat(supervisor-cli): health and host-info commands with a fake supervisor harness"
```

---

### Task 6: vm list / get / spec commands

**Files:**
- Create: `rust/crates/supervisor-cli/src/commands/vm.rs`
- Modify: `rust/crates/supervisor-cli/src/commands/mod.rs` (add `pub mod vm;`)
- Modify: `rust/crates/supervisor-cli/tests/support/fake.rs` (replace the `get_vm`, `get_vm_spec`, `list_vms` stubs)
- Modify: `rust/crates/supervisor-cli/tests/cli.rs` (new tests)

**Interfaces:**
- Consumes: Task 3–5 interfaces; the `FakeSupervisor` struct fields `vms`, `spec` and the `not_found` helper defined in Task 5.
- Produces:
  - `commands::vm::list(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> anyhow::Result<()>`
  - `commands::vm::get(client: &mut SupervisorClient, out: &mut impl Write, vm_id: &str, json: bool) -> anyhow::Result<()>`
  - `commands::vm::spec(client: &mut SupervisorClient, out: &mut impl Write, vm_id: &str, json: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Teach the fake the read-side lifecycle RPCs**

In `rust/crates/supervisor-cli/tests/support/fake.rs`, delete these three macro invocations:

```rust
    unimplemented_rpc!(get_vm, pb::GetVmRequest, pb::VmInfo);
    unimplemented_rpc!(get_vm_spec, pb::GetVmSpecRequest, pb::VmSpec);
    unimplemented_rpc!(list_vms, pb::ListVmsRequest, pb::ListVmsResponse);
```

and add in their place (also remove the `#[allow(dead_code)]` from `find_vm` and `not_found`):

```rust
    async fn get_vm(
        &self,
        request: Request<pb::GetVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let vm_id = request.into_inner().vm_id;
        self.find_vm(&vm_id)
            .map(|vm| Response::new(vm.clone()))
            .ok_or_else(|| not_found(&vm_id))
    }

    async fn get_vm_spec(
        &self,
        request: Request<pb::GetVmSpecRequest>,
    ) -> Result<Response<pb::VmSpec>, Status> {
        let vm_id = request.into_inner().vm_id;
        match &self.spec {
            Some(spec) if spec.vm_id == vm_id => Ok(Response::new(spec.clone())),
            _ => Err(not_found(&vm_id)),
        }
    }

    async fn list_vms(
        &self,
        _request: Request<pb::ListVmsRequest>,
    ) -> Result<Response<pb::ListVmsResponse>, Status> {
        Ok(Response::new(pb::ListVmsResponse {
            vms: self.vms.clone(),
        }))
    }
```

- [ ] **Step 2: Write the failing tests**

Append to `rust/crates/supervisor-cli/tests/cli.rs`:

```rust
fn fake_spec(vm_id: &str) -> pb::VmSpec {
    pb::VmSpec {
        vm_id: vm_id.to_string(),
        backend: pb::Backend::Qemu as i32,
        vcpus: 2,
        memory_mib: 2048,
        persistent: true,
        disks: vec![pb::DiskConfig {
            path: "/data/root.qcow2".to_string(),
            readonly: false,
            format: pb::disk_config::Format::Qcow2 as i32,
            role: pb::disk_config::DiskRole::Rootfs as i32,
        }],
        network: Some(pb::NetworkConfig {
            internet_access: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn vm_list_renders_an_aligned_table() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::list(&mut client, &mut out, false).await.unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "VM ID  STATUS   BACKEND  IPV4        UPTIME\n\
         vm-1   RUNNING  QEMU     172.16.3.2  2m 5s\n"
    );
}

#[tokio::test]
async fn vm_get_renders_a_key_value_block() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::get(&mut client, &mut out, "vm-1", false).await.unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "vm_id: vm-1\n\
         status: RUNNING\n\
         backend: QEMU\n\
         ipv4: 172.16.3.2 (gw 172.16.3.1)\n\
         uptime: 2m 5s\n\
         confidential_mode: NONE\n"
    );
}

#[tokio::test]
async fn vm_get_unknown_id_maps_the_error_trailer() {
    let fake = FakeSupervisor::default();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    let error = commands::vm::get(&mut client, &mut out, "ghost", false)
        .await
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "NotFound: no VM with id ghost [ERROR_CODE_VM_NOT_FOUND]"
    );
}

#[tokio::test]
async fn vm_spec_renders_disks_and_network() {
    let fake = FakeSupervisor {
        spec: Some(fake_spec("vm-1")),
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::spec(&mut client, &mut out, "vm-1", false).await.unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "vm_id: vm-1\n\
         backend: QEMU\n\
         vcpus: 2\n\
         memory_mib: 2048\n\
         persistent: true\n\
         kernel: -\n\
         disk: /data/root.qcow2 (QCOW2, ROOTFS, rw)\n\
         internet_access: true\n"
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli --test cli`
Expected: COMPILE ERROR — `commands::vm` does not exist.

- [ ] **Step 4: Implement the read-side vm commands**

Add `pub mod vm;` to `rust/crates/supervisor-cli/src/commands/mod.rs`.

Create `rust/crates/supervisor-cli/src/commands/vm.rs`:

```rust
//! `alephctl vm ...`: list, get, spec (and, from Task 7, lifecycle verbs).

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{status_error, SupervisorClient};
use crate::output;

pub async fn list(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    json: bool,
) -> Result<()> {
    let response = client
        .list_vms(pb::ListVmsRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    let rows: Vec<Vec<String>> = response
        .vms
        .iter()
        .map(|vm| {
            vec![
                vm.vm_id.clone(),
                output::vm_status_name(vm.status),
                output::backend_name(vm.backend),
                vm.ipv4
                    .as_ref()
                    .map(|ip| ip.address.clone())
                    .filter(|address| !address.is_empty())
                    .unwrap_or_else(|| "-".to_string()),
                if vm.status == pb::VmStatus::Running as i32 {
                    output::format_duration_secs(vm.uptime_secs)
                } else {
                    "-".to_string()
                },
            ]
        })
        .collect();
    output::write_table(out, &["VM ID", "STATUS", "BACKEND", "IPV4", "UPTIME"], &rows)?;
    Ok(())
}

pub async fn get(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let vm = client
        .get_vm(pb::GetVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &vm);
    }
    write_vm_info(out, &vm)
}

fn write_vm_info(out: &mut impl Write, vm: &pb::VmInfo) -> Result<()> {
    writeln!(out, "vm_id: {}", vm.vm_id)?;
    writeln!(out, "status: {}", output::vm_status_name(vm.status))?;
    if !vm.status_message.is_empty() {
        writeln!(out, "status_message: {}", vm.status_message)?;
    }
    writeln!(out, "backend: {}", output::backend_name(vm.backend))?;
    if let Some(ipv4) = &vm.ipv4 {
        if !ipv4.address.is_empty() {
            writeln!(out, "ipv4: {} (gw {})", ipv4.address, output::or_dash(&ipv4.gateway))?;
        }
    }
    if let Some(ipv6) = &vm.ipv6 {
        if !ipv6.address.is_empty() {
            writeln!(out, "ipv6: {}", ipv6.address)?;
        }
    }
    if let Some(numa) = vm.numa_node {
        writeln!(out, "numa_node: {numa}")?;
    }
    writeln!(out, "uptime: {}", output::format_duration_secs(vm.uptime_secs))?;
    writeln!(
        out,
        "confidential_mode: {}",
        output::confidential_mode_name(vm.confidential_mode)
    )?;
    if vm.awaiting_confidential_init {
        writeln!(out, "awaiting_confidential_init: true")?;
    }
    for gpu in &vm.gpus {
        writeln!(out, "gpu: {} {}", gpu.pci_host, gpu.model)?;
    }
    if !vm.guest_channel_path.is_empty() {
        writeln!(out, "guest_channel: {}", vm.guest_channel_path)?;
    }
    Ok(())
}

pub async fn spec(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let spec = client
        .get_vm_spec(pb::GetVmSpecRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &spec);
    }
    writeln!(out, "vm_id: {}", spec.vm_id)?;
    writeln!(out, "backend: {}", output::backend_name(spec.backend))?;
    writeln!(out, "vcpus: {}", spec.vcpus)?;
    writeln!(out, "memory_mib: {}", spec.memory_mib)?;
    writeln!(out, "persistent: {}", spec.persistent)?;
    writeln!(out, "kernel: {}", output::or_dash(&spec.kernel_path))?;
    for disk in &spec.disks {
        writeln!(
            out,
            "disk: {} ({}, {}, {})",
            disk.path,
            output::disk_format_name(disk.format),
            output::disk_role_name(disk.role),
            if disk.readonly { "ro" } else { "rw" }
        )?;
    }
    if let Some(network) = &spec.network {
        writeln!(out, "internet_access: {}", network.internet_access)?;
    }
    if let Some(tee) = &spec.tee {
        writeln!(out, "tee: {}", output::tee_backend_name(tee.backend))?;
    }
    for gpu in &spec.gpus {
        writeln!(out, "gpu: {}", gpu.pci_host)?;
    }
    if let Some(numa) = spec.numa_node {
        writeln!(out, "numa_node: {numa}")?;
    }
    if !spec.hostname.is_empty() {
        writeln!(out, "hostname: {}", spec.hostname)?;
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS.

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/commands rust/crates/supervisor-cli/tests
git commit -m "feat(supervisor-cli): vm list/get/spec commands"
```

---

### Task 7: vm start / stop / reboot / delete commands

**Files:**
- Modify: `rust/crates/supervisor-cli/src/commands/vm.rs`
- Modify: `rust/crates/supervisor-cli/tests/support/fake.rs` (replace the `start_vm`, `stop_vm`, `reboot_vm`, `delete_vm` stubs)
- Modify: `rust/crates/supervisor-cli/tests/cli.rs`

**Interfaces:**
- Consumes: Task 6's `commands::vm` module, `FakeSupervisor.deleted: Arc<Mutex<Vec<String>>>` from Task 5.
- Produces:
  - `commands::vm::start / stop / reboot (client: &mut SupervisorClient, out: &mut impl Write, vm_id: &str, json: bool) -> anyhow::Result<()>`
  - `commands::vm::delete(client: &mut SupervisorClient, out: &mut impl Write, input: &mut impl BufRead, vm_id: &str, assume_yes: bool, json: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Teach the fake the lifecycle RPCs**

In `rust/crates/supervisor-cli/tests/support/fake.rs`, delete the `start_vm`, `stop_vm`, `reboot_vm`, `delete_vm` macro invocations and add:

```rust
    async fn start_vm(
        &self,
        request: Request<pb::StartVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let vm_id = request.into_inner().vm_id;
        self.find_vm(&vm_id)
            .map(|vm| Response::new(vm.clone()))
            .ok_or_else(|| not_found(&vm_id))
    }

    async fn stop_vm(
        &self,
        request: Request<pb::StopVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let vm_id = request.into_inner().vm_id;
        self.find_vm(&vm_id)
            .map(|vm| Response::new(vm.clone()))
            .ok_or_else(|| not_found(&vm_id))
    }

    async fn reboot_vm(
        &self,
        request: Request<pb::RebootVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let vm_id = request.into_inner().vm_id;
        self.find_vm(&vm_id)
            .map(|vm| Response::new(vm.clone()))
            .ok_or_else(|| not_found(&vm_id))
    }

    async fn delete_vm(
        &self,
        request: Request<pb::DeleteVmRequest>,
    ) -> Result<Response<pb::DeleteVmResponse>, Status> {
        let request = request.into_inner();
        if self.find_vm(&request.vm_id).is_none() {
            return Err(not_found(&request.vm_id));
        }
        self.deleted.lock().unwrap().push(request.vm_id);
        Ok(Response::new(pb::DeleteVmResponse {}))
    }
```

(The fake returns the VM unchanged: these tests cover request plumbing and output rendering, not supervisor state machines.)

- [ ] **Step 2: Write the failing tests**

Append to `rust/crates/supervisor-cli/tests/cli.rs`:

```rust
#[tokio::test]
async fn vm_stop_reports_the_returned_status() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::stop(&mut client, &mut out, "vm-1", false).await.unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "stopped vm-1: now RUNNING\n"
    );
}

#[tokio::test]
async fn vm_delete_aborts_when_not_confirmed() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(&mut client, &mut out, &mut "n\n".as_bytes(), "vm-1", false, false)
        .await
        .unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("aborted\n"));
    assert!(deleted.lock().unwrap().is_empty());
}

#[tokio::test]
async fn vm_delete_proceeds_on_y() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(&mut client, &mut out, &mut "y\n".as_bytes(), "vm-1", false, false)
        .await
        .unwrap();
    assert!(String::from_utf8(out).unwrap().ends_with("deleted vm-1\n"));
    assert_eq!(*deleted.lock().unwrap(), vec!["vm-1".to_string()]);
}

#[tokio::test]
async fn vm_delete_with_yes_skips_the_prompt() {
    let fake = FakeSupervisor {
        vms: vec![running_vm("vm-1")],
        ..Default::default()
    };
    let deleted = fake.deleted.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::vm::delete(&mut client, &mut out, &mut "".as_bytes(), "vm-1", true, false)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "deleted vm-1\n");
    assert_eq!(*deleted.lock().unwrap(), vec!["vm-1".to_string()]);
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli --test cli`
Expected: COMPILE ERROR — `stop` and `delete` are not defined in `commands::vm`.

- [ ] **Step 4: Implement the lifecycle commands**

Append to `rust/crates/supervisor-cli/src/commands/vm.rs` (also add `use std::io::BufRead;` to the imports):

```rust
pub async fn start(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let vm = client
        .start_vm(pb::StartVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    report_transition(out, "started", &vm, json)
}

pub async fn stop(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let vm = client
        .stop_vm(pb::StopVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    report_transition(out, "stopped", &vm, json)
}

pub async fn reboot(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    json: bool,
) -> Result<()> {
    let vm = client
        .reboot_vm(pb::RebootVmRequest {
            vm_id: vm_id.to_string(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    report_transition(out, "rebooted", &vm, json)
}

fn report_transition(
    out: &mut impl Write,
    verb: &str,
    vm: &pb::VmInfo,
    json: bool,
) -> Result<()> {
    if json {
        return output::write_json(out, vm);
    }
    writeln!(out, "{verb} {}: now {}", vm.vm_id, output::vm_status_name(vm.status))?;
    Ok(())
}

pub async fn delete(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    input: &mut impl BufRead,
    vm_id: &str,
    assume_yes: bool,
    json: bool,
) -> Result<()> {
    if !assume_yes {
        write!(out, "Delete VM {vm_id}? [y/N] ")?;
        out.flush()?;
        let mut answer = String::new();
        input.read_line(&mut answer)?;
        if !matches!(answer.trim(), "y" | "Y" | "yes") {
            writeln!(out, "aborted")?;
            return Ok(());
        }
    }
    let response = client
        .delete_vm(pb::DeleteVmRequest {
            vm_id: vm_id.to_string(),
            wipe: false,
            keep_port_mappings: false,
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    writeln!(out, "deleted {vm_id}")?;
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS.

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/commands/vm.rs rust/crates/supervisor-cli/tests
git commit -m "feat(supervisor-cli): vm start/stop/reboot/delete commands"
```

---

### Task 8: ports list command

**Files:**
- Create: `rust/crates/supervisor-cli/src/commands/ports.rs`
- Modify: `rust/crates/supervisor-cli/src/commands/mod.rs` (add `pub mod ports;`)
- Modify: `rust/crates/supervisor-cli/tests/support/fake.rs` (replace the `list_port_forwards` stub)
- Modify: `rust/crates/supervisor-cli/tests/cli.rs`

**Interfaces:**
- Consumes: `FakeSupervisor.forwards` from Task 5.
- Produces: `commands::ports::list(client: &mut SupervisorClient, out: &mut impl Write, vm_id: Option<String>, json: bool) -> anyhow::Result<()>`

- [ ] **Step 1: Teach the fake ListPortForwards**

In `rust/crates/supervisor-cli/tests/support/fake.rs`, replace the `list_port_forwards` macro invocation with:

```rust
    async fn list_port_forwards(
        &self,
        request: Request<pb::ListPortForwardsRequest>,
    ) -> Result<Response<pb::ListPortForwardsResponse>, Status> {
        let vm_id = request.into_inner().vm_id;
        let forwards = self
            .forwards
            .iter()
            .filter(|forward| vm_id.is_empty() || forward.vm_id == vm_id)
            .cloned()
            .collect();
        Ok(Response::new(pb::ListPortForwardsResponse { forwards }))
    }
```

- [ ] **Step 2: Write the failing test**

Append to `rust/crates/supervisor-cli/tests/cli.rs`:

```rust
#[tokio::test]
async fn ports_list_filters_by_vm_and_renders_a_table() {
    let fake = FakeSupervisor {
        forwards: vec![
            pb::PortForwardInfo {
                vm_id: "vm-1".to_string(),
                host_port: 24001,
                vm_port: 22,
                protocol: pb::Protocol::Tcp as i32,
            },
            pb::PortForwardInfo {
                vm_id: "vm-2".to_string(),
                host_port: 24002,
                vm_port: 80,
                protocol: pb::Protocol::Tcp as i32,
            },
        ],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::ports::list(&mut client, &mut out, Some("vm-1".to_string()), false)
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "VM ID  HOST PORT  VM PORT  PROTOCOL\n\
         vm-1   24001      22       TCP\n"
    );
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli --test cli`
Expected: COMPILE ERROR — `commands::ports` does not exist.

- [ ] **Step 4: Implement ports list**

Add `pub mod ports;` to `rust/crates/supervisor-cli/src/commands/mod.rs`.

Create `rust/crates/supervisor-cli/src/commands/ports.rs`:

```rust
//! `alephctl ports list [vm_id]`.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{status_error, SupervisorClient};
use crate::output;

pub async fn list(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: Option<String>,
    json: bool,
) -> Result<()> {
    let response = client
        .list_port_forwards(pb::ListPortForwardsRequest {
            vm_id: vm_id.unwrap_or_default(),
        })
        .await
        .map_err(status_error)?
        .into_inner();
    if json {
        return output::write_json(out, &response);
    }
    let rows: Vec<Vec<String>> = response
        .forwards
        .iter()
        .map(|forward| {
            vec![
                forward.vm_id.clone(),
                forward.host_port.to_string(),
                forward.vm_port.to_string(),
                output::protocol_name(forward.protocol),
            ]
        })
        .collect();
    output::write_table(out, &["VM ID", "HOST PORT", "VM PORT", "PROTOCOL"], &rows)?;
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS.

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/commands rust/crates/supervisor-cli/tests
git commit -m "feat(supervisor-cli): ports list command"
```

---

### Task 9: logs and events streaming commands

**Files:**
- Create: `rust/crates/supervisor-cli/src/commands/logs.rs`
- Modify: `rust/crates/supervisor-cli/src/commands/mod.rs` (add `pub mod logs;`)
- Modify: `rust/crates/supervisor-cli/tests/support/fake.rs` (replace the `get_logs`, `stream_logs`, `watch_events` stubs)
- Modify: `rust/crates/supervisor-cli/tests/cli.rs`

**Interfaces:**
- Consumes: `FakeSupervisor.{logs, events, log_requests}` from Task 5.
- Produces:
  - `commands::logs::logs(client: &mut SupervisorClient, out: &mut impl Write, vm_id: &str, follow: bool, tail: Option<u32>, json: bool) -> anyhow::Result<()>`
  - `commands::logs::events(client: &mut SupervisorClient, out: &mut impl Write, json: bool) -> anyhow::Result<()>`
- Semantics: without `--follow`, `GetLogs{max_lines: tail.unwrap_or(0), from_tail: tail.is_some()}`; with `--follow`, `StreamLogs{include_history: false}` (only new lines, like `journalctl -f` without history). Streams end when the server closes; Ctrl-C is default process termination. `--json` on streams emits one compact JSON object per line (NDJSON).

- [ ] **Step 1: Teach the fake the log/event RPCs**

In `rust/crates/supervisor-cli/tests/support/fake.rs`, replace the `get_logs` macro invocation and the `watch_events`/`stream_logs` stub bodies:

```rust
    async fn get_logs(
        &self,
        request: Request<pb::GetLogsRequest>,
    ) -> Result<Response<pb::GetLogsResponse>, Status> {
        self.log_requests.lock().unwrap().push(request.into_inner());
        Ok(Response::new(pb::GetLogsResponse {
            lines: self.logs.clone(),
        }))
    }
```

and change the two stream methods (keep the associated `type` declarations exactly as they are):

```rust
    async fn watch_events(
        &self,
        _request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        let events: Vec<Result<pb::VmEvent, Status>> =
            self.events.iter().cloned().map(Ok).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(events))))
    }
```

```rust
    async fn stream_logs(
        &self,
        _request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let chunks: Vec<Result<pb::LogChunk, Status>> =
            self.logs.iter().cloned().map(Ok).collect();
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks))))
    }
```

- [ ] **Step 2: Write the failing tests**

Append to `rust/crates/supervisor-cli/tests/cli.rs`:

```rust
fn log_chunk(line: &str) -> pb::LogChunk {
    pb::LogChunk {
        timestamp_ns: 1_700_000_000_000_000_000,
        line: line.to_string(),
        source: pb::log_chunk::LogSource::Serial as i32,
    }
}

#[tokio::test]
async fn logs_prints_plain_lines() {
    let fake = FakeSupervisor {
        logs: vec![log_chunk("boot ok"), log_chunk("ready")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::logs::logs(&mut client, &mut out, "vm-1", false, None, false)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "boot ok\nready\n");
}

#[tokio::test]
async fn logs_tail_maps_to_max_lines_from_tail() {
    let fake = FakeSupervisor::default();
    let requests = fake.log_requests.clone();
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::logs::logs(&mut client, &mut out, "vm-1", false, Some(50), false)
        .await
        .unwrap();
    let recorded = requests.lock().unwrap();
    assert_eq!(recorded.len(), 1);
    assert_eq!(recorded[0].vm_id, "vm-1");
    assert_eq!(recorded[0].max_lines, 50);
    assert!(recorded[0].from_tail);
}

#[tokio::test]
async fn logs_follow_streams_until_the_server_closes() {
    let fake = FakeSupervisor {
        logs: vec![log_chunk("line-1"), log_chunk("line-2")],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::logs::logs(&mut client, &mut out, "vm-1", true, None, false)
        .await
        .unwrap();
    assert_eq!(String::from_utf8(out).unwrap(), "line-1\nline-2\n");
}

#[tokio::test]
async fn events_prints_one_transition_per_line() {
    let fake = FakeSupervisor {
        events: vec![pb::VmEvent {
            vm_id: "vm-1".to_string(),
            old_status: pb::VmStatus::Booting as i32,
            new_status: pb::VmStatus::Running as i32,
            timestamp_ns: 0,
        }],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::logs::events(&mut client, &mut out, false).await.unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "vm-1 BOOTING -> RUNNING\n"
    );
}

#[tokio::test]
async fn events_json_is_ndjson() {
    let fake = FakeSupervisor {
        events: vec![
            pb::VmEvent {
                vm_id: "vm-1".to_string(),
                old_status: pb::VmStatus::Booting as i32,
                new_status: pb::VmStatus::Running as i32,
                timestamp_ns: 0,
            },
            pb::VmEvent {
                vm_id: "vm-2".to_string(),
                old_status: pb::VmStatus::Running as i32,
                new_status: pb::VmStatus::Stopped as i32,
                timestamp_ns: 0,
            },
        ],
        ..Default::default()
    };
    let (_dir, socket) = spawn(fake).await;
    let mut client = client::connect(&socket).await.unwrap();
    let mut out = Vec::new();
    commands::logs::events(&mut client, &mut out, true).await.unwrap();
    let text = String::from_utf8(out).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).expect("one JSON per line");
        assert!(value["vm_id"].is_string());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd rust && cargo test -p supervisor-cli --test cli`
Expected: COMPILE ERROR — `commands::logs` does not exist.

- [ ] **Step 4: Implement logs and events**

Add `pub mod logs;` to `rust/crates/supervisor-cli/src/commands/mod.rs`.

Create `rust/crates/supervisor-cli/src/commands/logs.rs`:

```rust
//! `alephctl logs` (GetLogs / StreamLogs) and `alephctl events`
//! (WatchEvents). Streams run until the server closes them; Ctrl-C is
//! plain process termination, no custom handler.

use std::io::Write;

use anyhow::Result;
use supervisor_proto::pb;

use crate::client::{status_error, SupervisorClient};
use crate::output;

pub async fn logs(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    vm_id: &str,
    follow: bool,
    tail: Option<u32>,
    json: bool,
) -> Result<()> {
    if follow {
        let mut stream = client
            .stream_logs(pb::StreamLogsRequest {
                vm_id: vm_id.to_string(),
                include_history: false,
            })
            .await
            .map_err(status_error)?
            .into_inner();
        while let Some(chunk) = stream.message().await.map_err(status_error)? {
            write_log_chunk(out, &chunk, json)?;
        }
    } else {
        let response = client
            .get_logs(pb::GetLogsRequest {
                vm_id: vm_id.to_string(),
                max_lines: tail.unwrap_or(0),
                from_tail: tail.is_some(),
            })
            .await
            .map_err(status_error)?
            .into_inner();
        for chunk in &response.lines {
            write_log_chunk(out, chunk, json)?;
        }
    }
    Ok(())
}

/// NDJSON in --json mode (streams must stay line-oriented), bare line
/// otherwise.
fn write_log_chunk(out: &mut impl Write, chunk: &pb::LogChunk, json: bool) -> Result<()> {
    if json {
        writeln!(out, "{}", serde_json::to_string(chunk)?)?;
    } else {
        writeln!(out, "{}", chunk.line)?;
    }
    Ok(())
}

pub async fn events(
    client: &mut SupervisorClient,
    out: &mut impl Write,
    json: bool,
) -> Result<()> {
    let mut stream = client
        .watch_events(pb::WatchEventsRequest {})
        .await
        .map_err(status_error)?
        .into_inner();
    while let Some(event) = stream.message().await.map_err(status_error)? {
        if json {
            writeln!(out, "{}", serde_json::to_string(&event)?)?;
        } else {
            writeln!(
                out,
                "{} {} -> {}",
                event.vm_id,
                output::vm_status_name(event.old_status),
                output::vm_status_name(event.new_status)
            )?;
        }
    }
    Ok(())
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd rust && cargo test -p supervisor-cli`
Expected: PASS.

- [ ] **Step 6: fmt, clippy, commit**

Run: `cd rust && cargo fmt && cargo clippy -p supervisor-cli --all-targets -- -D warnings`

```bash
git add rust/crates/supervisor-cli/src/commands rust/crates/supervisor-cli/tests
git commit -m "feat(supervisor-cli): logs and events streaming commands"
```

---

### Task 10: wire the main dispatch

**Files:**
- Modify: `rust/crates/supervisor-cli/src/main.rs` (replace the Task 2 stub)

**Interfaces:**
- Consumes: everything: `cli::*`, `client::{resolve_socket_path, connect}`, all `commands::*` handlers with the exact signatures from Tasks 5–9.
- Produces: the shipping `alephctl` binary. Errors print to stderr as `alephctl: <message>` and exit 1.

- [ ] **Step 1: Replace the stub main.rs**

```rust
//! alephctl: debug CLI for the aleph-vm supervisor. Thin glue only: parse,
//! resolve the socket, connect, dispatch to supervisor_cli::commands.

use clap::Parser;
use supervisor_cli::cli::{Cli, Command, PortsCommand, VmCommand};
use supervisor_cli::{client, commands};

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(error) = run(cli).await {
        eprintln!("alephctl: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let socket =
        client::resolve_socket_path(cli.socket.clone(), |name| std::env::var(name).ok());
    let mut client = client::connect(&socket).await?;
    let mut out = std::io::stdout().lock();
    let json = cli.json;
    match cli.command {
        Command::Health => commands::host::health(&mut client, &mut out, json).await,
        Command::HostInfo => commands::host::host_info(&mut client, &mut out, json).await,
        Command::Vm(VmCommand::List) => commands::vm::list(&mut client, &mut out, json).await,
        Command::Vm(VmCommand::Get { vm_id }) => {
            commands::vm::get(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Spec { vm_id }) => {
            commands::vm::spec(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Start { vm_id }) => {
            commands::vm::start(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Stop { vm_id }) => {
            commands::vm::stop(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Reboot { vm_id }) => {
            commands::vm::reboot(&mut client, &mut out, &vm_id, json).await
        }
        Command::Vm(VmCommand::Delete { vm_id, yes }) => {
            let mut input = std::io::stdin().lock();
            commands::vm::delete(&mut client, &mut out, &mut input, &vm_id, yes, json).await
        }
        Command::Logs {
            vm_id,
            follow,
            tail,
        } => commands::logs::logs(&mut client, &mut out, &vm_id, follow, tail, json).await,
        Command::Events => commands::logs::events(&mut client, &mut out, json).await,
        Command::Ports(PortsCommand::List { vm_id }) => {
            commands::ports::list(&mut client, &mut out, vm_id, json).await
        }
    }
}
```

- [ ] **Step 2: Verify the binary end-to-end without a supervisor**

Run: `cd rust && cargo run -p supervisor-cli --bin alephctl -- --socket /nonexistent/supervisor.sock health; echo "exit: $?"`
Expected: stderr line `alephctl: cannot reach the supervisor at /nonexistent/supervisor.sock, is it running?: ...` and `exit: 1`.

Run: `cd rust && cargo run -p supervisor-cli --bin alephctl -- vm --help`
Expected: help listing `list`, `get`, `spec`, `start`, `stop`, `reboot`, `delete`.

- [ ] **Step 3: Full-crate check**

Run: `cd rust && cargo test -p supervisor-cli && cargo fmt --check && cargo clippy -p supervisor-cli --all-targets -- -D warnings`
Expected: all green.

- [ ] **Step 4: Commit**

```bash
git add rust/crates/supervisor-cli/src/main.rs
git commit -m "feat(supervisor-cli): wire alephctl main dispatch"
```

---

### Task 11: packaging and docs

**Files:**
- Modify: `packaging/Makefile` (the `debian-package-rust` target; this file has the Rust install lines on the rust stack)
- Modify: `docs/plans/2026-07-07-alephctl-supervisor-cli-design.md` (status line only)

**Interfaces:**
- Consumes: the `alephctl` binary produced by the workspace release build (`cargo build --release --locked` in the existing target already builds every workspace bin).
- Produces: `/opt/aleph-vm/bin/alephctl` in the debian package.

- [ ] **Step 1: Add the install line**

In `packaging/Makefile`, inside the `debian-package-rust` target, after the existing `install -m 0755 ../rust/target/release/aleph-vm-controller ...` line, add:

```make
	install -m 0755 ../rust/target/release/alephctl ./aleph-vm/opt/aleph-vm/bin/alephctl
```

(Tab-indented, like the surrounding recipe lines.)

- [ ] **Step 2: Verify the release build produces the binary**

Run: `cd rust && cargo build --release --locked -p supervisor-cli && ls -la target/release/alephctl`
Expected: the binary exists and is executable. (The full deb build runs in Docker in CI; this validates the piece this task adds.)

- [ ] **Step 3: Mark the design doc implemented**

In `docs/plans/2026-07-07-alephctl-supervisor-cli-design.md`, change the status line:

```markdown
**Status:** implemented (see docs/plans/2026-07-07-alephctl-supervisor-cli-implementation.md)
```

- [ ] **Step 4: Commit**

```bash
git add packaging/Makefile docs/plans/2026-07-07-alephctl-supervisor-cli-design.md docs/plans/2026-07-07-alephctl-supervisor-cli-implementation.md
git commit -m "build(packaging): install alephctl in the debian package"
```

---

## Final Verification

- [ ] `cd rust && cargo test -p supervisor-cli -p supervisor-proto` — all green.
- [ ] `cd rust && cargo fmt --check && cargo clippy -p supervisor-cli --all-targets -- -D warnings` — clean.
- [ ] `cd rust && cargo build --workspace` — daemon and controller still build against the serde-annotated proto types.
- [ ] Optional live smoke (needs a running supervisor, Python or Rust): `alephctl --socket <path> health`, `alephctl vm list`, `alephctl events` against a node or a locally started daemon.
- [ ] Use superpowers:requesting-code-review / open the stacked PR per the repo's od/* convention.
