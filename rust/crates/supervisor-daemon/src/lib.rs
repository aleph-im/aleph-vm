//! Rust supervisor daemon, increment 1 (Health + GetHostInfo).
//!
//! The parity oracle is the Python daemon (`python3 -m aleph.vm.supervisor`):
//! same `ALEPH_VM_*` configuration, same socket lifecycle, same field-level
//! behavior for the RPCs ported so far. Everything else returns UNIMPLEMENTED
//! until its increment lands (design doc
//! docs/plans/2026-07-04-rust-supervisor-daemon-design.md, section 7).

pub mod config;
pub mod envfile;
pub mod error;
pub mod host;
pub mod lspci;
pub mod net;
pub mod server;
pub mod service;
