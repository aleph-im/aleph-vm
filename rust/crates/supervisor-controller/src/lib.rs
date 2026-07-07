//! aleph-vm-controller: the per-VM controller process (increment A1).
//!
//! Reads a `{vm_hash}-controller.json` and runs the QEMU process with argv
//! byte-identical to the Python `QemuVM.start()` (non-confidential) or
//! `QemuConfidentialVM.start()` (SEV / SEV-ES, increment A2), or the SEV-SNP
//! measured direct-kernel boot (increment B1, no Python oracle), streaming its
//! console to the systemd journal and shutting it down gracefully on SIGTERM.
//! Packaging/systemd wiring (increment A3) is out of scope here.

pub mod config;
pub mod cpuid;
pub mod journal;
pub mod qemu;
pub mod qmp;
