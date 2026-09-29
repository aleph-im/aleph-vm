//! AMD SEV-SNP and Intel TDX attestation: report and quote parsing, chain
//! and signature verification against pinned vendor roots, collateral
//! clients, and the attestation-embedding X.509 extension.
//!
//! Two feature gates split the crate along its deployment boundary:
//!
//! - `guest`: the SEV-SNP firmware backend, for the in-guest agent.
//! - `verify`: everything a relying party needs, for client SDKs.
//!
//! Both are on by default. The SEV-SNP report parser, the `report_data`
//! binding schemes, the owner-auth envelope and the X.509 extension are
//! always available, since both sides share them. TDX's quote parser and
//! verifier are verify-only (no guest parses quotes); its QEMU argv
//! generator is always available, like the SEV-SNP one.

#[cfg(feature = "verify")]
mod fetch;
pub mod none;
pub mod owner_auth;
#[cfg(feature = "verify")]
mod pki;
pub mod report_data;
pub mod sev_snp;
pub mod tdx;
pub mod traits;
pub mod types;
pub mod x509;
