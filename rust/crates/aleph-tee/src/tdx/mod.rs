//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE.
//! Quote parsing and the full software verification path (chain, TCB
//! appraisal and platform gates) are implemented; the hardware-backed
//! backend and QGS round trip arrive in a later increment.
//!
//! `verify_tdx_quote` is the entry point callers outside the crate use. The
//! steps under it pass certificates around as DER bytes and parsed
//! x509-parser views, both crate-private.
//!
//! `qemu` (the launch argv generator) has no crypto or HTTP dependency and
//! stays available without the `verify` feature.

#[cfg(feature = "verify")]
pub mod certs;
#[cfg(feature = "verify")]
pub mod collateral;
#[cfg(feature = "verify")]
pub mod pck_extension;
#[cfg(feature = "verify")]
pub mod pcs;
pub mod qemu;
#[cfg(feature = "verify")]
pub mod quote;
#[cfg(feature = "verify")]
pub mod tcb;
#[cfg(feature = "verify")]
pub mod verify;
