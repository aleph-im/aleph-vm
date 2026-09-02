//! Intel TDX attestation stack.
//!
//! Sibling of `sev_snp`: same crate-level conventions, different TEE. Only
//! quote parsing is implemented so far; chain verification, collateral
//! handling and the hardware-backed backend arrive in later increments.

pub mod quote;
