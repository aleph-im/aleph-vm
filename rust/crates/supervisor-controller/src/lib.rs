//! aleph-vm-controller: the per-VM controller process (increment A1).
//!
//! Reads a `{vm_hash}-controller.json` and, for a non-confidential persistent
//! QEMU VM, runs the QEMU process with argv byte-identical to the Python
//! `QemuVM.start()`, streaming its console to the systemd journal and shutting
//! it down gracefully on SIGTERM. Confidential/SEV (increment A2) and
//! packaging/systemd wiring (increment A3) are out of scope here.

pub mod config;
pub mod journal;
pub mod qemu;
pub mod qmp;
