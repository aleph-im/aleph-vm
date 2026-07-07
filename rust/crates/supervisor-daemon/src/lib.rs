//! Rust supervisor daemon, increments 1 (Health + GetHostInfo), 2 (the
//! read-only world: GetVm, GetVmSpec, ListVms, ListPortForwards, GetLogs)
//! and 3 (the persistent QEMU lifecycle: CreateVm, StopVm, StartVm,
//! RebootVm, ReinstallVm, DeleteVm, the port-forward mutations,
//! RecreateNetwork, and the boot-time nftables/ndppd reconcile).
//!
//! The parity oracle is the Python daemon (`python3 -m aleph.vm.supervisor`)
//! after a restart: same `ALEPH_VM_*` configuration, same socket lifecycle,
//! same field-level behavior for the RPCs ported so far, with the world
//! rebuilt from disk/systemd/sqlite the way `load_persistent_executions`
//! rebuilds it. Everything else returns UNIMPLEMENTED until its increment
//! lands (design doc docs/plans/2026-07-04-rust-supervisor-daemon-design.md,
//! section 7). Deliberate differences from the oracle live in
//! docs/plans/rust-port-divergences.md.

pub mod checks;
pub mod cloudinit;
pub mod config;
pub mod controller_config;
pub mod envfile;
pub mod error;
pub mod host;
pub mod lifecycle;
pub mod logs;
pub mod lspci;
pub mod ndppd;
pub mod net;
pub mod nft;
pub mod ports;
pub mod server;
pub mod service;
pub mod tap;
pub mod test_fixtures;
pub mod units;
pub mod world;
