//! Rust supervisor daemon, increments 1-6: the host surface (Health,
//! GetHostInfo), the read-only world (GetVm, GetVmSpec, ListVms,
//! ListPortForwards, GetLogs), the persistent QEMU lifecycle and port-forward
//! mutations, RecreateNetwork, the ephemeral Firecracker programs
//! (RunProgramCode, WatchEvents, StreamLogs), the backup/restore surface
//! (StartBackup, GetBackupStatus, ListBackups, DownloadBackup, DeleteBackup,
//! RestoreBackup, RestoreFromImage) and the confidential surface
//! (InitializeConfidential, GetMeasurement, InjectSecret) plus confidential
//! CreateVm. Persistent Firecracker programs are the only UNIMPLEMENTED
//! surface (ledger entry 39; they belong with the controller port).
//!
//! The parity oracle is the Python daemon (`python3 -m aleph.vm.supervisor`)
//! after a restart: same `ALEPH_VM_*` configuration, same socket lifecycle,
//! same field-level behavior, with the world rebuilt from disk/systemd/sqlite
//! the way `load_persistent_executions` rebuilds it (design doc
//! docs/plans/2026-07-04-rust-supervisor-daemon-design.md, section 7).
//! Deliberate differences from the oracle live in
//! docs/plans/rust-port-divergences.md.

pub mod backup;
pub mod checks;
pub mod cloudinit;
pub mod confidential;
pub mod config;
pub mod controller_config;
pub mod envfile;
pub mod error;
pub mod events;
pub mod firecracker;
pub mod host;
pub mod lifecycle;
pub mod logs;
pub mod lspci;
pub mod ndppd;
pub mod net;
pub mod nft;
pub mod numa;
pub mod ports;
pub mod qmp;
pub mod server;
pub mod service;
pub mod tap;
pub mod test_fixtures;
pub mod units;
pub mod world;
