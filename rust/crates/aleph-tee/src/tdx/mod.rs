//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE.
//!
//! `verify_tdx_quote` is the entry point callers outside the crate use. The
//! steps under it pass certificates around as DER bytes and parsed
//! x509-parser views, both crate-private.
//!
//! Always available: `quote` (structure-only parsing, so the guest can read
//! its own registers and `report_data` back out of a quote), `qemu` (the
//! launch argv generator) and `measure` (MRTD/RTMR1/RTMR2/MRCONFIGID
//! prediction, SHA-384 only).
//!
//! `verify`: the chain, TCB appraisal and collateral clients.

#[cfg(feature = "verify")]
pub mod certs;
#[cfg(feature = "verify")]
pub mod collateral;
pub mod measure;
#[cfg(feature = "verify")]
pub mod pck_extension;
#[cfg(feature = "verify")]
pub mod pcs;
pub mod qemu;
pub mod quote;
#[cfg(feature = "verify")]
pub mod tcb;
#[cfg(feature = "verify")]
pub mod verify;
