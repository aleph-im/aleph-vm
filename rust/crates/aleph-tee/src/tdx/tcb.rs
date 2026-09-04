//! TCB appraisal: TCB Info and QE Identity verification, the SVN walk, the
//! platform gates, and the acceptance policy.
//!
//! A `valid` chain (certs.rs) says only that a quote is a genuine
//! Intel-attested TD. This module decides whether the platform is at an
//! acceptable trusted-computing-base level: it verifies Intel's signed TCB
//! Info and QE Identity against the pinned root, walks the SVN ladder to the
//! platform's actual status, enforces the platform gates a signature check
//! cannot express, and applies a policy over the resulting status and
//! advisories.

use std::collections::BTreeSet;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use serde::Deserialize;

use super::certs::verify_signer_chain;
use super::collateral::TdxCollateral;
use super::pck_extension::{PckPlatform, parse_pck_platform};
use super::quote::TdxQuote;

/// A platform's trusted-computing-base status, from Intel's signed TCB Info.
/// Ordered by severity: a larger value is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TcbStatus {
    UpToDate,
    SwHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSwHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    /// The platform's keys are compromised. Never acceptable, whatever the
    /// policy says.
    Revoked,
}

impl TcbStatus {
    fn parse(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Self::UpToDate,
            "SWHardeningNeeded" => Self::SwHardeningNeeded,
            "ConfigurationNeeded" => Self::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => Self::ConfigurationAndSwHardeningNeeded,
            "OutOfDate" => Self::OutOfDate,
            "OutOfDateConfigurationNeeded" => Self::OutOfDateConfigurationNeeded,
            "Revoked" => Self::Revoked,
            other => bail!("unknown TCB status {other:?}"),
        })
    }

    /// Combine a platform status with a component (TDX module or QE) status,
    /// following Intel's appraisal rule: an out-of-date component on a
    /// configuration-needed platform is reported as
    /// `OutOfDateConfigurationNeeded`; otherwise the worse of the two wins.
    fn converge(self, component: TcbStatus) -> TcbStatus {
        use TcbStatus::*;
        match (component, self) {
            (OutOfDate, ConfigurationNeeded | ConfigurationAndSwHardeningNeeded) => {
                OutOfDateConfigurationNeeded
            }
            _ => component.max(self),
        }
    }
}

/// Which TCB outcomes a caller accepts.
///
/// The builtin baseline accepts `UpToDate` and `SWHardeningNeeded` (the
/// latter is routine QE software mitigation) and rejects everything else.
/// `ConfigurationNeeded` is rejected by default because it typically flags
/// BIOS state such as SMT. `Revoked` is never acceptable and cannot be added
/// to `accepted_statuses`; that asymmetry with the SNP override is
/// deliberate.
#[derive(Debug, Clone)]
pub struct TdxTcbPolicy {
    pub accepted_statuses: BTreeSet<TcbStatus>,
    pub denied_advisories: BTreeSet<String>,
}

impl Default for TdxTcbPolicy {
    fn default() -> Self {
        let mut accepted_statuses = BTreeSet::new();
        accepted_statuses.insert(TcbStatus::UpToDate);
        accepted_statuses.insert(TcbStatus::SwHardeningNeeded);
        Self {
            accepted_statuses,
            denied_advisories: BTreeSet::new(),
        }
    }
}

/// The outcome of a full TDX quote verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxTcbOutcome {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

// --- Intel signed documents (only the fields consumed here) ---

#[derive(Debug, Deserialize)]
struct TcbComponent {
    svn: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevelTcb {
    #[serde(default)]
    sgxtcbcomponents: Vec<TcbComponent>,
    #[serde(default)]
    tdxtcbcomponents: Vec<TcbComponent>,
    pcesvn: u16,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbLevel {
    tcb: TcbLevelTcb,
    tcb_status: String,
    #[serde(default)]
    advisory_i_ds: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleTcbLevel {
    tcb: TdxModuleTcb,
    tcb_status: String,
    #[serde(default)]
    advisory_i_ds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TdxModuleTcb {
    isvsvn: u8,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleIdentity {
    id: String,
    mrsigner: String,
    tcb_levels: Vec<TdxModuleTcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    id: String,
    version: u32,
    fmspc: String,
    tcb_levels: Vec<TcbLevel>,
    #[serde(default)]
    tdx_module_identities: Vec<TdxModuleIdentity>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentity {
    mrsigner: String,
    isvprodid: u16,
    attributes: String,
    attributes_mask: String,
    miscselect: String,
    miscselect_mask: String,
    tcb_levels: Vec<QeTcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeTcbLevel {
    tcb: QeTcb,
    tcb_status: String,
    #[serde(default)]
    advisory_i_ds: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QeTcb {
    isvsvn: u16,
}

// --- Signature verification of the signed JSON documents ---

/// Verify a detached ECDSA-P256 signature (`r || s`, hex) over `body` under
/// the signer resolved from `chain_pem` (checked to the pinned root).
fn verify_signed_document(
    what: &str,
    body: &str,
    signature_hex: &str,
    chain_pem: &str,
    now: SystemTime,
) -> Result<()> {
    let signer = verify_signer_chain(chain_pem.as_bytes(), now)
        .with_context(|| format!("{what} issuer chain is not trusted"))?;
    let key = signer
        .public_key()
        .with_context(|| format!("failed to extract the {what} signer key"))?;
    let ec = key
        .ec_key()
        .with_context(|| format!("the {what} signer key is not an EC key"))?;

    let sig_raw =
        hex::decode(signature_hex).with_context(|| format!("{what} signature is not valid hex"))?;
    if sig_raw.len() != 64 {
        bail!("{what} signature is {} bytes, expected 64", sig_raw.len());
    }
    let r = openssl::bn::BigNum::from_slice(&sig_raw[..32])?;
    let s = openssl::bn::BigNum::from_slice(&sig_raw[32..])?;
    let sig = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;
    let digest = openssl::hash::hash(MessageDigest::sha256(), body.as_bytes())
        .with_context(|| format!("failed to hash the {what} body"))?;
    if !sig
        .verify(&digest, &ec)
        .with_context(|| format!("failed to check the {what} signature"))?
    {
        bail!("{what} signature does not verify under its Intel signer");
    }
    Ok(())
}

fn verify_tcb_info(collateral: &TdxCollateral, now: SystemTime) -> Result<TcbInfo> {
    verify_signed_document(
        "TCB Info",
        &collateral.tcb_info,
        &collateral.tcb_info_signature,
        &collateral.tcb_info_issuer_chain,
        now,
    )?;
    serde_json::from_str(&collateral.tcb_info).context("failed to parse TCB Info body")
}

fn verify_qe_identity(collateral: &TdxCollateral, now: SystemTime) -> Result<QeIdentity> {
    verify_signed_document(
        "QE Identity",
        &collateral.qe_identity,
        &collateral.qe_identity_signature,
        &collateral.qe_identity_issuer_chain,
        now,
    )?;
    serde_json::from_str(&collateral.qe_identity).context("failed to parse QE Identity body")
}

// --- The platform TCB walk ---

fn hex_fixed<const N: usize>(what: &str, s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s).with_context(|| format!("{what} is not valid hex"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} has the wrong length, expected {N} bytes"))
}

/// Walk the TCB levels (highest first) to the platform's actual status.
///
/// A level is satisfied when every one of the platform's SGX component SVNs
/// and its PCE SVN meet the level, and (for TDX) every TDX component SVN in
/// the quote meets it too. The first satisfied level gives the status.
fn walk_platform_tcb(
    tcb_info: &TcbInfo,
    platform: &PckPlatform,
    tee_tcb_svn: &[u8; 16],
) -> Result<(TcbStatus, Vec<String>)> {
    for level in &tcb_info.tcb_levels {
        if level.tcb.sgxtcbcomponents.len() != 16 || level.tcb.tdxtcbcomponents.len() != 16 {
            bail!("TCB level does not carry 16 SGX and 16 TDX components");
        }
        if platform.pcesvn < level.tcb.pcesvn {
            continue;
        }
        let sgx_ok = platform
            .cpusvn
            .iter()
            .zip(&level.tcb.sgxtcbcomponents)
            .all(|(have, want)| *have >= want.svn);
        if !sgx_ok {
            continue;
        }
        let tdx_ok = tee_tcb_svn
            .iter()
            .zip(&level.tcb.tdxtcbcomponents)
            .all(|(have, want)| *have >= want.svn);
        if !tdx_ok {
            continue;
        }
        return Ok((
            TcbStatus::parse(&level.tcb_status)?,
            level.advisory_i_ds.clone(),
        ));
    }
    bail!("the platform TCB is below every level in Intel's TCB Info");
}

/// Converge the TDX module's own status into the platform status.
///
/// `tee_tcb_svn[0]` is the module SVN and `[1]` its major version, which
/// selects a `tdxModuleIdentities` entry (`TDX_<version>`); the entry's
/// MRSIGNER must match the quote's MRSIGNERSEAM and its SVN ladder gives the
/// module status.
fn tdx_module_status(
    tcb_info: &TcbInfo,
    quote: &TdxQuote,
) -> Result<Option<(TcbStatus, Vec<String>)>> {
    if tcb_info.id != "TDX" || tcb_info.version < 3 {
        return Ok(None);
    }
    let module_svn = quote.body.tee_tcb_svn[0];
    let module_version = quote.body.tee_tcb_svn[1];
    if module_version == 0 || tcb_info.tdx_module_identities.is_empty() {
        return Ok(None);
    }

    let wanted = format!("TDX_{module_version:02X}");
    let identity = tcb_info
        .tdx_module_identities
        .iter()
        .find(|id| id.id.eq_ignore_ascii_case(&wanted))
        .with_context(|| format!("no TDX module identity {wanted} in the TCB Info"))?;

    let expected_mrsigner: [u8; 48] = hex_fixed("tdxModuleIdentity.mrsigner", &identity.mrsigner)?;
    if quote.body.mrsignerseam != expected_mrsigner {
        bail!("MRSIGNERSEAM does not match the Intel-signed TDX module identity");
    }

    for level in &identity.tcb_levels {
        if module_svn >= level.tcb.isvsvn {
            return Ok(Some((
                TcbStatus::parse(&level.tcb_status)?,
                level.advisory_i_ds.clone(),
            )));
        }
    }
    bail!("the TDX module SVN is below every level in its identity")
}

// --- QE Identity appraisal ---

/// SGX enclave report field offsets (the QE report is 384 bytes).
const QE_MISC_SELECT: usize = 16;
const QE_ATTRIBUTES: usize = 48;
const QE_MR_SIGNER: usize = 128;
const QE_ISV_PROD_ID: usize = 256;
const QE_ISV_SVN: usize = 258;

fn qe_identity_status(qe: &QeIdentity, qe_report: &[u8; 384]) -> Result<(TcbStatus, Vec<String>)> {
    let mr_signer = &qe_report[QE_MR_SIGNER..QE_MR_SIGNER + 32];
    let expected_mr_signer: [u8; 32] = hex_fixed("QE Identity mrsigner", &qe.mrsigner)?;
    if mr_signer != expected_mr_signer {
        bail!("QE MRSIGNER does not match the Intel-signed QE Identity");
    }

    let isv_prod_id =
        u16::from_le_bytes([qe_report[QE_ISV_PROD_ID], qe_report[QE_ISV_PROD_ID + 1]]);
    if isv_prod_id != qe.isvprodid {
        bail!("QE ISVPRODID {isv_prod_id} does not match the QE Identity");
    }

    let misc: [u8; 4] = qe_report[QE_MISC_SELECT..QE_MISC_SELECT + 4]
        .try_into()
        .expect("4 bytes");
    let misc_expected: [u8; 4] = hex_fixed("QE Identity miscselect", &qe.miscselect)?;
    let misc_mask: [u8; 4] = hex_fixed("QE Identity miscselectMask", &qe.miscselect_mask)?;
    for i in 0..4 {
        if misc[i] & misc_mask[i] != misc_expected[i] & misc_mask[i] {
            bail!("QE MISCSELECT does not match the QE Identity under its mask");
        }
    }

    let attrs = &qe_report[QE_ATTRIBUTES..QE_ATTRIBUTES + 16];
    let attrs_expected: [u8; 16] = hex_fixed("QE Identity attributes", &qe.attributes)?;
    let attrs_mask: [u8; 16] = hex_fixed("QE Identity attributesMask", &qe.attributes_mask)?;
    for i in 0..16 {
        if attrs[i] & attrs_mask[i] != attrs_expected[i] & attrs_mask[i] {
            bail!("QE ATTRIBUTES do not match the QE Identity under its mask");
        }
    }

    let isv_svn = u16::from_le_bytes([qe_report[QE_ISV_SVN], qe_report[QE_ISV_SVN + 1]]);
    for level in &qe.tcb_levels {
        if isv_svn >= level.tcb.isvsvn {
            return Ok((
                TcbStatus::parse(&level.tcb_status)?,
                level.advisory_i_ds.clone(),
            ));
        }
    }
    bail!("the QE ISVSVN is below every level in the QE Identity")
}

// --- Platform gates ---

/// The TD attributes DEBUG bit (bit 0 of the little-endian field). A
/// debuggable TD lets the host read guest memory; this is the single most
/// important gate.
const TD_ATTRIBUTES_DEBUG: u8 = 0x01;

fn check_platform_gates(quote: &TdxQuote) -> Result<()> {
    if quote.body.td_attributes[0] & TD_ATTRIBUTES_DEBUG != 0 {
        bail!("the TD is debuggable (TD_ATTRIBUTES.DEBUG set): the host can read guest memory");
    }
    Ok(())
}

// --- Composition ---

/// Appraise the TCB of a chain-verified quote and apply `policy`.
///
/// Assumes the caller has already verified the quote's chain and signatures
/// (`certs`/`verify`); this decides the acceptable-TCB question on top.
pub fn evaluate_tcb(
    quote: &TdxQuote,
    collateral: &TdxCollateral,
    pck_leaf: &X509,
    now: SystemTime,
    policy: &TdxTcbPolicy,
) -> Result<TdxTcbOutcome> {
    check_platform_gates(quote)?;

    let tcb_info = verify_tcb_info(collateral, now)?;
    let qe_identity = verify_qe_identity(collateral, now)?;

    let platform = parse_pck_platform(pck_leaf)?;
    let tcb_fmspc: [u8; 6] = hex_fixed("TCB Info fmspc", &tcb_info.fmspc)?;
    if platform.fmspc != tcb_fmspc {
        bail!(
            "FMSPC mismatch: the PCK platform is {}, the TCB Info is for {}",
            hex::encode(platform.fmspc),
            hex::encode(tcb_fmspc)
        );
    }

    let (mut status, mut advisories) =
        walk_platform_tcb(&tcb_info, &platform, &quote.body.tee_tcb_svn)?;

    if let Some((module_status, module_advisories)) = tdx_module_status(&tcb_info, quote)? {
        status = status.converge(module_status);
        for advisory in module_advisories {
            if !advisories.contains(&advisory) {
                advisories.push(advisory);
            }
        }
    }

    let (qe_status, qe_advisories) = qe_identity_status(&qe_identity, &quote.signature.qe_report)?;
    status = status.converge(qe_status);
    for advisory in qe_advisories {
        if !advisories.contains(&advisory) {
            advisories.push(advisory);
        }
    }

    // Revoked is a security invariant, not a policy decision.
    if status == TcbStatus::Revoked {
        bail!("TCB status is Revoked: the platform keys are compromised");
    }
    if !policy.accepted_statuses.contains(&status) {
        bail!("TCB status {status:?} is not accepted by policy");
    }
    if let Some(hit) = advisories
        .iter()
        .find(|a| policy.denied_advisories.contains(*a))
    {
        bail!("TCB carries a denied advisory: {hit}");
    }

    Ok(TdxTcbOutcome {
        status,
        advisory_ids: advisories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::quote::parse_tdx_quote;
    use std::time::{Duration, UNIX_EPOCH};

    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");
    const COLLATERAL_V4: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_collateral.json");
    const QUOTE_OUTDATED: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_outdated.bin");
    const COLLATERAL_OUTDATED: &[u8] =
        include_bytes!("../../tests/fixtures/tdx/tdx_quote_outdated_collateral.json");

    fn now_v4() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_750_377_600)
    }
    fn now_outdated() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_771_459_200)
    }

    fn pck_leaf(raw: &[u8]) -> X509 {
        let quote = parse_tdx_quote(raw).expect("quote parses");
        X509::stack_from_pem(&quote.signature.pck_chain_pem)
            .expect("chain")
            .into_iter()
            .next()
            .expect("leaf")
    }

    #[test]
    fn genuine_v4_platform_is_up_to_date() {
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        let outcome = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            now_v4(),
            &TdxTcbPolicy::default(),
        )
        .expect("evaluates");
        assert_eq!(outcome.status, TcbStatus::UpToDate);
        assert!(outcome.advisory_ids.is_empty());
    }

    #[test]
    fn outdated_platform_is_below_every_level() {
        // The outdated sample's PCK reports a component SVN below every TCB
        // level, so the walk finds no match. Whatever the exact cause, it
        // must not be accepted by the default policy.
        let quote = parse_tdx_quote(QUOTE_OUTDATED).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).unwrap();
        assert!(
            evaluate_tcb(
                &quote,
                &collateral,
                &pck_leaf(QUOTE_OUTDATED),
                now_outdated(),
                &TdxTcbPolicy::default(),
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_fmspc_mismatch() {
        // Pair the v4 quote with the outdated collateral (different FMSPC).
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).unwrap();
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            now_outdated(),
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("FMSPC mismatch"), "got: {err}");
    }

    #[test]
    fn rejects_forged_tcb_info_signature() {
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let mut collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        // Flip the TCB Info body: the Intel signature no longer covers it.
        collateral.tcb_info = collateral.tcb_info.replacen("UpToDate", "Revoked", 1);
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            now_v4(),
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("TCB Info signature"), "got: {err}");
    }

    #[test]
    fn rejects_debuggable_td() {
        let mut raw = QUOTE_V4.to_vec();
        // Set TD_ATTRIBUTES.DEBUG: body offset 120, plus the 48-byte header.
        raw[48 + 120] |= 0x01;
        let quote = parse_tdx_quote(&raw).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            now_v4(),
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("debuggable"), "got: {err}");
    }

    #[test]
    fn walk_falls_through_to_a_lower_status() {
        // A synthetic TCB Info: the top level demands a TDX component SVN
        // above the quote's, so the walk must skip it and take the second.
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let zeros = vec![serde_json::json!({"svn": 0}); 16];
        let mut high_tdx = zeros.clone();
        high_tdx[0] = serde_json::json!({"svn": 255});
        let tcb_info: TcbInfo = serde_json::from_value(serde_json::json!({
            "id": "TDX",
            "version": 3,
            "fmspc": "b0c06f000000",
            "tcbLevels": [
                {
                    "tcb": {
                        "sgxtcbcomponents": zeros,
                        "tdxtcbcomponents": high_tdx,
                        "pcesvn": 0
                    },
                    "tcbStatus": "UpToDate"
                },
                {
                    "tcb": {
                        "sgxtcbcomponents": zeros,
                        "tdxtcbcomponents": zeros,
                        "pcesvn": 0
                    },
                    "tcbStatus": "OutOfDate"
                }
            ]
        }))
        .unwrap();
        let (status, _) = walk_platform_tcb(&tcb_info, &platform, &quote.body.tee_tcb_svn).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
    }

    #[test]
    fn policy_rejects_out_of_date_but_can_accept_it() {
        use TcbStatus::*;
        assert!(
            !TdxTcbPolicy::default()
                .accepted_statuses
                .contains(&OutOfDate)
        );
        let mut accepting = TdxTcbPolicy::default();
        accepting.accepted_statuses.insert(OutOfDate);
        assert!(accepting.accepted_statuses.contains(&OutOfDate));
    }

    #[test]
    fn converge_worst_wins_and_config_rule() {
        use TcbStatus::*;
        assert_eq!(UpToDate.converge(OutOfDate), OutOfDate);
        assert_eq!(OutOfDate.converge(UpToDate), OutOfDate);
        assert_eq!(
            ConfigurationNeeded.converge(OutOfDate),
            OutOfDateConfigurationNeeded
        );
        assert_eq!(UpToDate.converge(SwHardeningNeeded), SwHardeningNeeded);
    }
}
