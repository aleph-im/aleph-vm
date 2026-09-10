//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE.
//! Quote parsing and the full software verification path (chain, TCB
//! appraisal and platform gates) are implemented; the hardware-backed
//! backend and QGS round trip arrive in a later increment.
//!
//! `verify_tdx_quote` is the entry point callers outside the crate use. The
//! steps under it hand certificates around as `openssl::x509::X509`, and
//! those stay crate-private on purpose: an openssl type in the public
//! signature would make every consumer link the same openssl version and
//! would freeze the choice of TLS stack into this crate's API. Everything
//! the crate returns outward is owned, plain data.

pub mod certs;
pub mod collateral;
pub mod pck_extension;
pub mod quote;
pub mod tcb;
pub mod verify;
