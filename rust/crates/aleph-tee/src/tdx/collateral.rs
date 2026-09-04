//! DCAP collateral: the Intel-published material a TDX quote is verified
//! against.
//!
//! The layout mirrors the standard `sgx_ql_qve_collateral` shape that DCAP
//! tooling exchanges as JSON: PEM issuer chains, hex-encoded DER CRLs, and
//! the TCB Info / QE Identity JSON bodies with detached hex ECDSA
//! signatures. Nothing here is trusted as-is; every piece is verified
//! against the pinned Intel root before use.

use anyhow::{Context, Result};
use serde::Deserialize;

/// The collateral set for TDX quote verification.
///
/// The chain verification step consumes only the two CRLs, and checks their
/// signatures against certificates taken from the quote's own (pinned) PCK
/// chain rather than against the issuer chains carried here. The remaining
/// fields (TCB Info, QE Identity, their chains and signatures) feed the TCB
/// walk.
#[derive(Debug, Clone, Deserialize)]
pub struct TdxCollateral {
    /// PEM chain for the PCK CRL issuer.
    pub pck_crl_issuer_chain: String,
    /// Hex DER CRL issued by the root CA; revokes intermediate CA certs.
    pub root_ca_crl: String,
    /// Hex DER CRL issued by the PCK CA; revokes PCK leaf certs.
    pub pck_crl: String,
    /// PEM chain for the TCB Info signer.
    pub tcb_info_issuer_chain: String,
    /// TCB Info body, JSON, signed detached.
    pub tcb_info: String,
    /// Hex ECDSA P-256 signature (r || s) over `tcb_info`.
    pub tcb_info_signature: String,
    /// PEM chain for the QE Identity signer.
    pub qe_identity_issuer_chain: String,
    /// QE Identity body, JSON, signed detached.
    pub qe_identity: String,
    /// Hex ECDSA P-256 signature (r || s) over `qe_identity`.
    pub qe_identity_signature: String,
}

impl TdxCollateral {
    pub fn from_json(json: &[u8]) -> Result<Self> {
        serde_json::from_slice(json).context("failed to parse TDX collateral JSON")
    }

    /// The root CA CRL as DER bytes.
    pub fn root_ca_crl_der(&self) -> Result<Vec<u8>> {
        hex::decode(&self.root_ca_crl).context("root_ca_crl is not valid hex")
    }

    /// The PCK CRL as DER bytes.
    pub fn pck_crl_der(&self) -> Result<Vec<u8>> {
        hex::decode(&self.pck_crl).context("pck_crl is not valid hex")
    }
}
