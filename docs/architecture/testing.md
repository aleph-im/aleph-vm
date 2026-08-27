# Testing

> Verified against: b2b31381 (2026-08-14)

## What this covers

How aleph-vm is tested across the Python/Rust port boundary: the Rust
unit/lib tests, the Python conformance suite that drives the compiled Rust
daemon and treats the Python implementation as the parity oracle, the
implementation-agnostic integration matrix (same tests against both daemon
legs), the droplet CI that installs packaged `.deb`s on real cloud VMs, and
the local-dev workflow (compile-only verification locally, CI as the actual
test gate).

## The model

### Five layers, different purposes

1. **Rust unit/lib tests.** `#[cfg(test)] mod tests` blocks inside the
   crate source modules (for example `rust/crates/supervisor-daemon/src/`)
   plus dedicated integration binaries under each crate's `tests/`
   directory: `rust/crates/supervisor-controller/tests/argv_parity.rs`,
   `argv_parity_confidential.rs` and `argv_parity_snp.rs` (QEMU argv byte
   parity, including confidential and SNP variants),
   `rust/crates/supervisor-daemon/tests/grpc.rs` and `read_only.rs`,
   `rust/crates/supervisor-cli/tests/cli.rs`, and
   `rust/crates/supervisor-proto/tests/json.rs`. These run with `cargo
   test --locked` from `rust/` and need no VM boot, no root, and no Python
   interpreter, with one gated exception:
   `rust/crates/supervisor-daemon/src/checks.rs`'s
   `the_local_toolchain_passes_when_gated_paths_exist` additionally needs
   `cloud-localds`, `qemu-system-x86_64` and `setfacl` on `PATH` whenever
   `/dev/kvm` exists (matching the toolchain `test-rust.yml` installs), so
   it can fail on a KVM-enabled dev machine that lacks those tools.

2. **Python conformance suite** (`tests/conformance/`). This is the parity
   oracle in test form: it builds the real `aleph-vm-supervisor` binary,
   boots it on a temporary `EXECUTION_ROOT`, and drives it with the
   production Python gRPC client (`GrpcSupervisor`) exactly as the agent
   would. Expectations come from primary sources (`os.cpu_count`, `psutil`,
   `ip addr`, `lspci`, the pydantic `Configuration` model) and from
   `tests/conformance/oracle.py`, the frozen copy of the Python daemon's
   `PortMapping` schema and `spec_from_controller_configuration` kept when
   that daemon was removed (2026-08), so the assertions keep meaning what the
   port was measured against. The fixtures under
   `rust/crates/supervisor-daemon/tests/fixtures/` and
   `rust/crates/supervisor-controller/tests/conformance/` were generated
   from the Python daemon's models by generators removed with it; they are
   frozen goldens now, edited only to record a deliberate change on the
   Rust side. The suite also covers world-adoption/reconcile replay
   (`test_rust_daemon_lifecycle.py`, `test_rust_daemon_read_only.py`) and
   log/event streaming (`test_rust_daemon_streams.py`).

3. **Integration suite** (`tests/integration/`). Drives the real Rust
   supervisor daemon (built from the tree, `AVM_ITEST_RUST_BINARY` to
   override) over gRPC, agent-free, with the Rust controller installed
   through a systemd drop-in when run as root. It covers VM
   creation, management, volumes, guest quiescence, daemon restart, error
   paths, and resource release. Firecracker legs run unprivileged over the
   vsock guest channel; QEMU legs need root for TAP networking and systemd
   controller units. `tests/supervisor/conformance.py` is a separate,
   narrower thing: an abstract-contract mixin
   (`SupervisorContractTests`) that any `Supervisor` implementation
   (in-process, gRPC client, ...) can subclass to assert the ABC surface is
   fully implemented; `tests/supervisor/` otherwise holds the large,
   Python-only in-process unit suite (firewall, storage pools, DNS,
   authentication, vprogram, and so on).

4. **Droplet CI**
   (`.github/workflows/build-deb-package-and-integration-tests.yml`). This
   is the packaging-and-platform-compatibility gate, distinct from both
   layers above: it builds the `.deb` for debian-12, debian-13,
   ubuntu-22.04 and ubuntu-24.04, and builds two squashfs volumes (the
   Firecracker rootfs and an example venv volume). It then provisions an
   ephemeral DigitalOcean droplet per OS and installs the built package for
   real (not the checked-out source tree); the droplet leg itself only
   covers three of the four built OSes (debian-12 is skipped there: a
   workflow comment notes DigitalOcean removed the debian-12-x64 image
   after Debian 12 reached end of standard support). It waits for
   `systemctl is-active --quiet aleph-vm-supervisor` plus
   port 4020 to be listening, then curls the `/about/usage/system` HTTP
   endpoint (served by the agent, per the workflow's own comment) as an
   indirect check that the agent is up too, and confirms `sevctl` is
   present. It exists to catch packaging and dependency drift across
   target platforms that an in-repo checkout can't exercise.

5. **CodeQL and shellcheck.** `.github/workflows/codeql-analysis.yml` runs
   security scanning on Python on push/PR to `main`/`dev` plus a weekly
   schedule. `code-quality-shell` (inside
   `.github/workflows/test-using-pytest.yml`) shellchecks every `*.sh`,
   every extensionless `*-launcher` script, and every `*.script` file
   (the measured-guest boot scripts that run PID-1-adjacent inside SEV-SNP
   VMs).

### Which workflow runs what

- `.github/workflows/test-using-pytest.yml` (`tests-python` job) runs style
  (ruff/black/isort), mypy, the agent/supervisor/contract import-boundary
  check (import-linter), the proto-bindings-up-to-date check
  (`scripts/check_proto_clean.sh`), and `hatch run testing:cov`
  (`pytest --cov`) over pytest's configured `testpaths`, which is the whole
  `tests/` tree: `tests/supervisor/`, `tests/migration/`, `tests/network/`,
  `tests/vprogram/` and `tests/test_controller_launcher.py`, uploaded to
  Codecov. `tests/integration/` and `tests/conformance/` are collected in
  this same run but skip themselves via their own opt-in gates (`AVM_ITEST`,
  `ALEPH_VM_CONFORMANCE`), not by path exclusion. The
  `tests-integration` job separately runs `tests/integration/` for real,
  twice, once per `supervisor-impl` matrix leg (`python`, `rust`), building
  the Rust daemon only for the rust leg.
- `.github/workflows/test-rust.yml` is path-filtered to changes under
  `rust/`, `proto/`, `tests/conformance/` and the Python modules that feed
  the Rust port, so pure-Python PRs never pay for it. In one job it runs `cargo
  fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`,
  `cargo test --locked`, and then the Python conformance suite
  (`tests/conformance/`) against the just-built daemon with
  `ALEPH_VM_CONFORMANCE=1`.
- `.github/workflows/build-deb-package-and-integration-tests.yml` is the
  droplet CI described above; it runs on push/PR to `main`/`dev` only (no
  `od/**` stacked-branch trigger).
- `.github/workflows/test-build-examples.yml` runs `hatch build` (the
  project's own package build) and then builds a squashfs volume from the
  `examples/example_pip` requirements, to catch packaging regressions in
  the pip-install example flow.
- `.github/workflows/codeql-analysis.yml` and the `code-quality-shell` job
  are the static-analysis and shell-lint gates described above.

Both `test-using-pytest.yml` and `test-rust.yml` trigger on `od/**` branches
in addition to `main`/`dev`, because stacked PRs (`od/errors-*`,
`od/docs-*`, and similar chains) need CI on each increment before the next
one can build on top of it.

### Codecov noise on stacked-base PRs

This is a workflow convention observed by contributors, not something
enforced or documented in the workflow files themselves: when a PR's base
branch is another feature branch rather than `dev` (the normal shape of a
stacked-PR series), Codecov's coverage-diff comparison is against that
non-`dev` base, and the resulting project/patch coverage checks are commonly
noisy or fail spuriously. Treat a codecov/project failure on a stacked-base
PR as a known artifact to verify by eye, not as evidence of an actual
coverage regression, before spending time chasing it.

### Local-dev verification is compile-only; CI is the test gate

Locally, the practical verification loop for Rust changes is `cargo fmt`
and `cargo clippy --workspace --all-targets` (the clippy gate CI enforces is
specifically `cargo clippy --locked --all-targets -- -D warnings` run from
`rust/`), not a full `cargo test` run. The Rust and Python test suites are
treated as CI's job: `test-rust.yml` runs `cargo test --locked` plus the
conformance suite, `test-using-pytest.yml` runs the Python unit and
integration suites, and the droplet workflow runs the system-level legs.
This split is a workflow convention driven by local friction (root
requirements for network/TAP tests, KVM/Firecracker/QEMU binaries, and
build cost) rather than a rule encoded anywhere in the repo.

For contributors who do run the Python suites locally, `Justfile` documents
the supported path: `just install-system-deps` installs the apt `python3-*`
C-extension bindings (nftables, dbus, systemd) plus their dev headers, and
`just setup-venv` creates a `--system-site-packages` virtualenv so those
bindings are visible without vendoring stubs. `just test` points
`ALEPH_VM_CACHE_ROOT`/`ALEPH_VM_EXECUTION_ROOT` at writable directories
under the repo rather than system paths. `just itest` (unprivileged,
Firecracker-only) and `just itest-root` (full set, needs root) instead set
`AVM_ITEST=1` and, for the root recipe, `sudo --preserve-env` the
`AVM_ITEST_FC_KERNEL`/`AVM_ITEST_FC_RUNTIME`/`AVM_ITEST_QEMU_IMAGE`
artifact-path variables through to pytest; neither recipe touches the
cache/execution roots. On a dev machine whose Python
version predates the pinned apt packages (so `--system-site-packages`
doesn't supply the C modules), the fallback is a `PYTHONPATH` that includes
the repo's `src/` plus local stubs for `systemd`/`nftables`/`dbus`; this is
a per-developer workaround, not a checked-in mechanism.

The conformance suite specifically needs `ALEPH_VM_CONFORMANCE=1` and
`cargo` on `PATH` (`tests/conformance/conftest.py`'s `cargo_missing()`
skip predicate); it fails collection outright, rather than skip-passing,
when `CI=true` and `ALEPH_VM_CONFORMANCE=1` are both set but `cargo` is
missing, so a misconfigured CI job cannot pass by silently running zero
tests.

## Key invariants

- **The Python daemon was the parity oracle, and its record survives it.**
  The Rust port was measured against what the Python implementation
  actually did, not against a spec; every difference is in the divergence
  registry (`divergences.md`). The daemon itself is gone (2026-08); the
  frozen fixtures, `tests/conformance/oracle.py` and the registry are the
  oracle now, and a behavior change on the Rust side must update them
  deliberately rather than regenerate them.
- **Conformance fixtures are frozen goldens.** The committed fixtures under
  `rust/crates/supervisor-daemon/tests/fixtures/` were generated from the
  Python daemon's pydantic/SQLAlchemy models, and
  `rust/crates/supervisor-daemon/src/test_fixtures.rs` pins the
  corresponding VM-hash constants; there is no generator to rerun.
- **The integration suite drives the daemon built from the tree.**
  `tests/integration/conftest.py` fails loudly when the Rust binaries are
  missing instead of falling back to anything installed under
  `/opt/aleph-vm`, so CI can never silently test a stale daemon.
- **Proto bindings must stay regenerated and committed.**
  `scripts/check_proto_clean.sh`, run in `test-using-pytest.yml`, reruns
  the Python generator and fails the build if `supervisor_pb2.py` or
  `supervisor_pb2_grpc.py` differ from what's checked in.
- **The Rust clippy gate is `-D warnings`, not advisory.**
  `cargo clippy --locked --all-targets -- -D warnings` from `rust/` is
  enforced in `test-rust.yml`; a clippy warning fails CI.
- **The conformance suite cannot skip-pass in CI.**
  `tests/conformance/conftest.py`'s `cargo_missing()` raises instead of
  skipping when `CI=true` and `ALEPH_VM_CONFORMANCE=1` are both set but
  `cargo` is absent.
- **Rust CI is path-filtered.** `.github/workflows/test-rust.yml` only
  triggers on changes under `rust/`, `proto/`, `tests/conformance/`, and
  the contract-layer Python modules the daemon mirrors, so pure-agent PRs
  do not pay for a Rust build.

## Pointers into code

- `rust/crates/supervisor-daemon/src/`: unit tests live alongside the
  modules they test (`#[cfg(test)] mod tests`).
- `rust/crates/supervisor-controller/tests/argv_parity.rs`,
  `argv_parity_confidential.rs`, `argv_parity_snp.rs`: byte-level QEMU
  argv parity tests.
- `rust/crates/supervisor-daemon/tests/grpc.rs`,
  `rust/crates/supervisor-daemon/tests/read_only.rs`,
  `rust/crates/supervisor-cli/tests/cli.rs`,
  `rust/crates/supervisor-proto/tests/json.rs`: per-crate integration
  binaries.
- `tests/conformance/conftest.py`: daemon build/boot fixture, the
  `ALEPH_VM_CONFORMANCE` and cargo-presence skip gate.
- `tests/conformance/test_rust_daemon.py`,
  `test_rust_daemon_lifecycle.py`, `test_rust_daemon_read_only.py`,
  `test_rust_daemon_streams.py`: the conformance test modules;
  `tests/conformance/oracle.py`: the frozen Python-daemon oracles.
- `tests/integration/conftest.py`: daemon/controller spawn and per-backend
  requirements (Firecracker vs QEMU).
- `tests/integration/`: `test_vm_creation.py`, `test_vm_management.py`,
  `test_volumes.py`, `test_guest_quiesce.py`, `test_daemon_restart.py`,
  `test_error_paths.py`, `test_resource_release.py`.
- `tests/supervisor/conformance.py`: the abstract `Supervisor` contract
  mixin.
- `tests/supervisor/`: the agent and contract-layer unit suite.
- `scripts/check_proto_clean.sh`: the binding generator the CI jobs verify
  is up to date.
- `.github/workflows/test-using-pytest.yml`: Python lint/typing/unit tests
  and the integration suite against the Rust daemon.
- `.github/workflows/test-rust.yml`: fmt, clippy, `cargo test`, and the
  conformance suite against the Rust daemon.
- `.github/workflows/build-deb-package-and-integration-tests.yml`:
  package builds and droplet CI.
- `.github/workflows/test-build-examples.yml`: project build plus the
  example-pip squashfs volume build check.
- `.github/workflows/codeql-analysis.yml`: CodeQL security scanning.
- `Justfile`: the supported local Python dev/test workflow.

See `wire-contract.md` for the proto contract and error-model conventions
the conformance suite is checking, and `divergences.md` for the registry of
accepted Python/Rust behavioral differences.
