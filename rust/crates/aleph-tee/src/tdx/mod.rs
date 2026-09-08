//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE.
//! Quote parsing and the full software verification path (chain, TCB
//! appraisal and platform gates) are implemented; the hardware-backed
//! backend and QGS round trip arrive in a later increment.

pub mod certs;
pub mod collateral;
pub mod pck_extension;
pub mod quote;
pub mod tcb;
pub mod verify;
