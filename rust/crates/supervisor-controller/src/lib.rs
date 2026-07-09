//! aleph-vm-controller: the per-VM controller process (increment A1).
//!
//! Reads a `{vm_hash}-controller.json` and runs the QEMU process with argv
//! byte-identical to the Python `QemuVM.start()` (non-confidential) or
//! `QemuConfidentialVM.start()` (SEV / SEV-ES, increment A2), streaming its
//! console to the systemd journal and shutting it down gracefully on SIGTERM.
//! SEV-SNP (increment B1) and packaging/systemd wiring (increment A3) are out
//! of scope here.

pub mod config;
pub mod cpuid;
pub mod journal;
pub mod qemu;
pub mod qmp;
