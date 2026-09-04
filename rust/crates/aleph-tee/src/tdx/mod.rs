//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE.
//! Quote parsing and the certificate-chain half of verification are
//! implemented; the TCB walk, platform gates and the hardware-backed
//! backend arrive in later increments.

pub mod certs;
pub mod collateral;
pub mod pck_extension;
pub mod quote;
pub mod tcb;
pub mod verify;
