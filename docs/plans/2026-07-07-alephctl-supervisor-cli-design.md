# alephctl: supervisor debug CLI (design)

**Date:** 2026-07-07
**Status:** implemented (see docs/plans/2026-07-07-alephctl-supervisor-cli-implementation.md)
**Target:** Rust workspace tip (stacked on the phase3 / rust-daemon PR stack)

## Purpose

A Rust CLI shipped with aleph-vm that speaks the `aleph.supervisor.v1` gRPC
contract directly over the supervisor's Unix socket, for immediate debugging
and testing on a node. The Python and Rust supervisors serve the same
contract on the same socket, so `alephctl` works against both without
knowing which one is running.

Primary users: node operators and developers debugging a live node, and
developers exercising supervisor RPCs during development without going
through the agent/orchestrator layer.

## Placement

- New crate: `rust/crates/supervisor-cli`
- Binary name: `alephctl`
- Ships as its own PR stacked on the current Rust workspace tip.
- Depends on `supervisor-proto` for the generated tonic stubs
  (`build_client(true)` is already enabled).
- The UDS connector helper (dummy-URI endpoint + `UnixStream` connector,
  same pattern as aleph-bench's `connect_uds`) lives in the CLI crate.
  `supervisor-proto` stays a pure contract crate.

## Connection resolution

Socket path is resolved in this order, mirroring the daemon's own config
resolution so the CLI finds the right socket on any correctly configured
node with zero flags:

1. `--socket PATH` flag
2. `ALEPH_VM_SUPERVISOR_GRPC_SOCKET` environment variable (empty string =
   unset, matching daemon behavior; the daemon reads `ALEPH_VM_*`-prefixed
   variables, mirroring pydantic's `env_prefix`)
3. `$ALEPH_VM_EXECUTION_ROOT/supervisor.sock`
4. `/var/lib/aleph/vm/supervisor.sock` (default `EXECUTION_ROOT`)

Connection failure produces a clear "is the supervisor running at
\<path\>?" message on stderr, not a tonic error chain.

## Commands (v1: debug essentials)

```
alephctl health
alephctl host-info
alephctl vm list
alephctl vm get <id>
alephctl vm spec <id>
alephctl vm start <id>
alephctl vm stop <id>
alephctl vm reboot <id>
alephctl vm delete <id> [--yes]     # prompts for confirmation unless --yes
alephctl logs <id> [--follow] [--tail N]
alephctl events                     # WatchEvents, streams until Ctrl-C
alephctl ports list [<id>]
```

RPC mapping: `Health`, `GetHostInfo`, `ListVms`, `GetVm`, `GetVmSpec`,
`StartVm`, `StopVm`, `RebootVm`, `DeleteVm`, `GetLogs`/`StreamLogs`,
`WatchEvents`, `ListPortForwards`.

Out of scope for v1 (explicitly deferred, clap structure leaves room for
them as later subcommands): backups, confidential ops
(`InitializeConfidential`/`GetMeasurement`/`InjectSecret`), `CreateVm`,
`ReinstallVm`, `RestoreFromImage`, `RunProgramCode`, port-forward
add/remove, `RecreateNetwork`.

## Output

- Human-readable by default:
  - aligned columns for `vm list` and `ports list`
  - key-value blocks for `vm get` / `vm spec` / `host-info`
  - raw lines for `logs` and `events`
- Global `--json` flag emits the proto response messages as JSON.
  To get this for free across all commands, `supervisor-proto`'s build.rs
  adds `#[derive(serde::Serialize)]` to generated types via
  `type_attribute`. This changes generated Rust code only, not the wire
  contract.
- Errors: stderr, non-zero exit code. gRPC status code and message shown
  plainly (e.g. `NotFound: no VM with id ...`).
- Streaming commands (`logs --follow`, `events`) print items as they
  arrive and exit cleanly on Ctrl-C or server-side stream close.

## Dependencies

clap (derive), tokio, tonic/prost (workspace-shared versions), anyhow,
serde/serde_json. No table or color crates; manual column padding is
enough for a debug tool.

## Testing

- Command handlers take a `SupervisorClient` and an `impl Write`, so tests
  run them against an in-process fake `Supervisor` tonic server bound to a
  temp-dir UDS (same approach as aleph-bench's testfake crate) and assert
  on captured output.
- Coverage: output formatting (tables, key-value, JSON), gRPC error
  mapping, confirmation prompt for `vm delete`, and streaming commands
  (fake emits N events/log chunks then closes the stream).
- Unit tests for socket-path resolution precedence and clap arg parsing.
- No KVM or real supervisor required; everything runs in Tier 1 CI.

## Packaging

- Added to the rust workspace release build.
- Installed by the packaging Makefile to `/opt/aleph-vm/bin/alephctl`,
  next to `aleph-vm-supervisor` (the rust-packaging branch already has the
  install pattern).
