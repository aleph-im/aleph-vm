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
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
/// BIOS state such as SMT. `Revoked` is never acceptable: that rejection is
/// enforced in `evaluate_tcb` regardless of `accepted_statuses`, so putting
/// it in the set has no effect. That asymmetry with the SNP override, which
/// admits any concrete named TCB, is deliberate.
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

/// The outcome of a TDX TCB appraisal: the converged status and the union
/// of advisory ids across the platform, module and QE levels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxTcbOutcome {
    pub status: TcbStatus,
    pub advisory_ids: Vec<String>,
}

/// Apply a policy to an appraised status and its advisories.
///
/// `Revoked` is a security invariant, rejected before the policy is even
/// consulted: it cannot be admitted by adding it to `accepted_statuses`.
fn check_policy(status: TcbStatus, advisories: &[String], policy: &TdxTcbPolicy) -> Result<()> {
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
    Ok(())
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
    attributes: String,
    attributes_mask: String,
    tcb_levels: Vec<TdxModuleTcbLevel>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TcbInfo {
    id: String,
    version: u32,
    issue_date: String,
    next_update: String,
    fmspc: String,
    tcb_levels: Vec<TcbLevel>,
    tdx_module: Option<TdxModuleBase>,
    #[serde(default)]
    tdx_module_identities: Vec<TdxModuleIdentity>,
}

/// The base TDX module identity, used when no per-version identity applies.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TdxModuleBase {
    mrsigner: String,
    attributes: String,
    attributes_mask: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct QeIdentity {
    issue_date: String,
    next_update: String,
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

/// Parse the fixed `YYYY-MM-DDTHH:MM:SSZ` timestamp Intel uses in its signed
/// documents into a `SystemTime`. Kept deliberately small: pulling in a date
/// crate would widen the measured agent's dependency tree for one format.
fn parse_rfc3339_z(s: &str) -> Result<SystemTime> {
    let b = s.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        bail!("unexpected date format {s:?}");
    }
    let field = |r: std::ops::Range<usize>| -> Result<i64> {
        s.get(r.clone())
            .and_then(|f| f.parse::<i64>().ok())
            .with_context(|| format!("bad date field in {s:?}"))
    };
    let (year, month, day) = (field(0..4)?, field(5..7)?, field(8..10)?);
    let (hour, minute, second) = (field(11..13)?, field(14..16)?, field(17..19)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        bail!("date out of range in {s:?}");
    }
    // days_from_civil (Howard Hinnant): days since the unix epoch.
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hour * 3600 + minute * 60 + second;
    let secs: u64 = secs
        .try_into()
        .with_context(|| format!("date predates the unix epoch: {s:?}"))?;
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

/// Reject a signed document whose validity window does not contain `now`.
///
/// The signer certificates outlive these documents by years, so without
/// this an old but genuinely-signed document (with lower SVN thresholds)
/// could be replayed to keep an unpatched platform appraising as current.
fn check_document_window(what: &str, issue: &str, next: &str, now: SystemTime) -> Result<()> {
    let issue = parse_rfc3339_z(issue).with_context(|| format!("{what} issueDate"))?;
    let next = parse_rfc3339_z(next).with_context(|| format!("{what} nextUpdate"))?;
    if now < issue {
        bail!("{what} is not yet valid (issueDate {issue:?})");
    }
    if now > next {
        bail!("{what} has expired (nextUpdate {next:?})");
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
    let tcb_info: TcbInfo =
        serde_json::from_str(&collateral.tcb_info).context("failed to parse TCB Info body")?;
    check_document_window("TCB Info", &tcb_info.issue_date, &tcb_info.next_update, now)?;
    Ok(tcb_info)
}

fn verify_qe_identity(collateral: &TdxCollateral, now: SystemTime) -> Result<QeIdentity> {
    verify_signed_document(
        "QE Identity",
        &collateral.qe_identity,
        &collateral.qe_identity_signature,
        &collateral.qe_identity_issuer_chain,
        now,
    )?;
    let qe_identity: QeIdentity = serde_json::from_str(&collateral.qe_identity)
        .context("failed to parse QE Identity body")?;
    check_document_window(
        "QE Identity",
        &qe_identity.issue_date,
        &qe_identity.next_update,
        now,
    )?;
    Ok(qe_identity)
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

    // Expected identity: the base tdxModule, overridden by a per-version
    // entry when the report names one. Falling straight through without
    // checking MRSIGNERSEAM would be fail-open, so the base is required for
    // a v3 TDX document even when no per-version identity applies.
    let base = tcb_info
        .tdx_module
        .as_ref()
        .context("a v3 TDX TCB Info must carry a tdxModule identity")?;
    let mut expected_mrsigner: [u8; 48] = hex_fixed("tdxModule.mrsigner", &base.mrsigner)?;
    let mut expected_attributes: [u8; 8] = hex_fixed("tdxModule.attributes", &base.attributes)?;
    let mut attributes_mask: [u8; 8] =
        hex_fixed("tdxModule.attributesMask", &base.attributes_mask)?;
    let mut identity_levels: Option<&[TdxModuleTcbLevel]> = None;

    if module_version > 0 && !tcb_info.tdx_module_identities.is_empty() {
        let wanted = format!("TDX_{module_version:02X}");
        let identity = tcb_info
            .tdx_module_identities
            .iter()
            .find(|id| id.id.eq_ignore_ascii_case(&wanted))
            .with_context(|| format!("no TDX module identity {wanted} in the TCB Info"))?;
        expected_mrsigner = hex_fixed("tdxModuleIdentity.mrsigner", &identity.mrsigner)?;
        expected_attributes = hex_fixed("tdxModuleIdentity.attributes", &identity.attributes)?;
        attributes_mask = hex_fixed(
            "tdxModuleIdentity.attributesMask",
            &identity.attributes_mask,
        )?;
        identity_levels = Some(&identity.tcb_levels);
    }

    if quote.body.mrsignerseam != expected_mrsigner {
        bail!("MRSIGNERSEAM does not match the Intel-signed TDX module identity");
    }
    // SEAMATTRIBUTES must match the identity under its mask: the masked bits
    // pin the module's own attributes (notably its DEBUG bit).
    for i in 0..8 {
        if quote.body.seam_attributes[i] & attributes_mask[i]
            != expected_attributes[i] & attributes_mask[i]
        {
            bail!("SEAMATTRIBUTES do not match the TDX module identity under its mask");
        }
    }

    // The SVN ladder only exists on a per-version identity; the base entry
    // contributes the MRSIGNER/attributes gate but no status.
    let Some(levels) = identity_levels else {
        return Ok(None);
    };
    for level in levels {
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

    check_policy(status, &advisories, policy)?;

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
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_OUTDATED),
            now_outdated(),
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("below every level"), "got: {err}");
    }

    #[test]
    fn rejects_expired_tcb_info() {
        // 40 days past now_v4() is outside the TCB Info window (nextUpdate
        // 2025-07-19) though still inside the signer certificate's. Without
        // the document-window check this stale collateral would appraise.
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        let stale = now_v4() + Duration::from_secs(40 * 24 * 3600);
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            stale,
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("has expired"), "got: {err}");
    }

    #[test]
    fn parses_intel_document_dates() {
        let t = parse_rfc3339_z("2025-06-19T10:16:03Z").unwrap();
        assert_eq!(
            t.duration_since(UNIX_EPOCH).unwrap(),
            Duration::from_secs(1_750_328_163)
        );
        assert!(parse_rfc3339_z("2025-06-19 10:16:03").is_err());
        assert!(parse_rfc3339_z("2025-13-19T10:16:03Z").is_err());
    }

    #[test]
    fn policy_rejects_revoked_even_when_accepted() {
        // Revoked is never admissible, even inserted into the accept set.
        let mut policy = TdxTcbPolicy::default();
        policy.accepted_statuses.insert(TcbStatus::Revoked);
        let err = check_policy(TcbStatus::Revoked, &[], &policy)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Revoked"), "got: {err}");
    }

    #[test]
    fn policy_rejects_denied_advisory() {
        let mut policy = TdxTcbPolicy::default();
        policy
            .denied_advisories
            .insert("INTEL-SA-00999".to_string());
        // An accepted status still fails when it carries a denied advisory.
        let advisories = vec!["INTEL-SA-00999".to_string()];
        let err = check_policy(TcbStatus::UpToDate, &advisories, &policy)
            .unwrap_err()
            .to_string();
        assert!(err.contains("denied advisory"), "got: {err}");
        // The same advisory is fine when the policy does not deny it.
        assert!(check_policy(TcbStatus::UpToDate, &advisories, &TdxTcbPolicy::default()).is_ok());
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
            "issueDate": "2025-06-19T10:16:03Z",
            "nextUpdate": "2025-07-19T10:16:03Z",
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
