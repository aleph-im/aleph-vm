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

use crate::pki::ecdsa_from_raw;

use super::certs::verify_signer_chain;
use super::collateral::TdxCollateral;
use super::pck_extension::{PckPlatform, parse_pck_platform};
use super::quote::{TdReportBody, TdxQuote};

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

    /// The worse of two peer statuses, on the severity order this enum is
    /// declared in.
    ///
    /// Deliberately not `converge`: that rule is asymmetric (it upgrades an
    /// out-of-date component on a configuration-needed platform), which is
    /// right for a component appraised against a platform but wrong for two
    /// results of the same appraisal, where it would make the outcome depend
    /// on which one happened to be evaluated first.
    fn worse(self, other: TcbStatus) -> TcbStatus {
        self.max(other)
    }
}

/// Which TCB outcomes a caller accepts.
///
/// The builtin baseline accepts `UpToDate` and `SWHardeningNeeded` (the
/// latter is routine QE software mitigation) and rejects everything else.
/// `ConfigurationNeeded` is rejected by default because it typically flags
/// BIOS state such as SMT. `Revoked` is never acceptable: that rejection is
/// enforced in `check_policy` regardless of `accepted_statuses`, so putting
/// it in the set has no effect. That asymmetry with the SEV-SNP side is
/// deliberate: there the aleph-rs SDK's `--min-tcb` floor override
/// (`aleph_sdk::attest::TcbFloorOverride`) admits any concrete named TCB,
/// because an SNP TCB is a set of version numbers with no Intel-style
/// "keys compromised" verdict attached.
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
    let sig =
        ecdsa_from_raw(&sig_raw).with_context(|| format!("failed to read the {what} signature"))?;
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
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => bail!("date out of range in {s:?}"),
    };
    if !(1..=days_in_month).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=59).contains(&second)
    {
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

/// The TCB levels in the order the walk consumes them: highest first, by
/// SGX component SVNs (lexicographic), then PCE SVN, then TDX component SVNs.
///
/// Intel publishes the levels in this order already, but the walk must not
/// depend on it: both DCAP references sort before walking (Intel's
/// `TcbLevel::operator>` over a sorted container, dcap-qvl's
/// `canonicalize_tcb_levels`), and the first satisfied level of an
/// unsorted list could carry a better status than a higher level the
/// platform also satisfies.
fn canonical_levels(tcb_info: &TcbInfo) -> Vec<&TcbLevel> {
    let key = |level: &TcbLevel| -> (Vec<u8>, u16, Vec<u8>) {
        (
            level.tcb.sgxtcbcomponents.iter().map(|c| c.svn).collect(),
            level.tcb.pcesvn,
            level.tcb.tdxtcbcomponents.iter().map(|c| c.svn).collect(),
        )
    };
    let mut levels: Vec<&TcbLevel> = tcb_info.tcb_levels.iter().collect();
    // Stable: levels the key cannot separate keep their document order.
    levels.sort_by_cached_key(|level| std::cmp::Reverse(key(level)));
    levels
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
    for level in canonical_levels(tcb_info) {
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

/// Appraise one TDX SVN vector: the platform level walk plus the TDX
/// module's own identity and SVN ladder for the module that vector names.
fn appraise_tdx_svn_vector(
    tcb_info: &TcbInfo,
    platform: &PckPlatform,
    body: &TdReportBody,
    tee_tcb_svn: &[u8; 16],
) -> Result<(TcbStatus, Vec<String>)> {
    let (mut status, mut advisories) = walk_platform_tcb(tcb_info, platform, tee_tcb_svn)?;
    if let Some((module_status, module_advisories)) =
        tdx_module_status(tcb_info, body, tee_tcb_svn)?
    {
        status = status.converge(module_status);
        merge_advisories(&mut advisories, module_advisories);
    }
    Ok((status, advisories))
}

/// Appraise every TDX SVN vector the report body carries.
///
/// A TD report 1.0 body has one vector. A 1.5 body adds `tee_tcb_svn2`,
/// which exists because a TD-preserving update swaps the TDX module under a
/// running TD: one vector describes the module TCB the TD launched on, the
/// other the one it runs on now, and either can be the lower of the two.
/// Appraising only the first would let a TD whose other vector matches no
/// published level, or names a TDX module Intel does not list, pass on the
/// strength of the vector that happened to be walked. So both are appraised
/// in full (level walk and module identity alike), either one failing fails
/// the appraisal, and the worse of the two statuses is the answer.
///
/// Taking the worse status is stricter than Intel's own handling, which
/// propagates a failure of the second appraisal but otherwise keeps the
/// first vector's status and only flags that a relaunch is advised. There is
/// no such advisory outcome here: a status this policy would refuse for one
/// vector is refused for the TD.
fn appraise_platform_tcb(
    tcb_info: &TcbInfo,
    platform: &PckPlatform,
    body: &TdReportBody,
) -> Result<(TcbStatus, Vec<String>)> {
    // Both vectors name themselves in their failures. Without the first
    // one's context an operator reading "the platform TCB is below every
    // level" off a 1.5 body cannot tell which of the two tripped.
    let (mut status, mut advisories) =
        appraise_tdx_svn_vector(tcb_info, platform, body, &body.tee_tcb_svn)
            .context("appraising the TD report launch TCB vector (tee_tcb_svn)")?;
    if let Some(v15) = &body.v15 {
        let (second_status, second_advisories) =
            appraise_tdx_svn_vector(tcb_info, platform, body, &v15.tee_tcb_svn2)
                .context("appraising the TD report 1.5 second TCB vector (tee_tcb_svn2)")?;
        status = status.worse(second_status);
        merge_advisories(&mut advisories, second_advisories);
    }
    Ok((status, advisories))
}

/// Append the advisories `into` does not already carry, keeping their order.
fn merge_advisories(into: &mut Vec<String>, from: Vec<String>) {
    for advisory in from {
        if !into.contains(&advisory) {
            into.push(advisory);
        }
    }
}

/// The TDX module's own status, for the module the given SVN vector names.
///
/// `tee_tcb_svn[0]` is the module SVN and `[1]` its major version, which
/// selects a `tdxModuleIdentities` entry (`TDX_<version>`); the entry's
/// MRSIGNER must match the quote's MRSIGNERSEAM and its SVN ladder gives the
/// module status. The vector is a parameter rather than read off the body
/// because a TD report 1.5 carries two of them, each naming its own module
/// version, and both have to clear this gate.
fn tdx_module_status(
    tcb_info: &TcbInfo,
    body: &TdReportBody,
    tee_tcb_svn: &[u8; 16],
) -> Result<Option<(TcbStatus, Vec<String>)>> {
    if tcb_info.id != "TDX" || tcb_info.version < 3 {
        return Ok(None);
    }
    let module_svn = tee_tcb_svn[0];
    let module_version = tee_tcb_svn[1];

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

    if body.mrsignerseam != expected_mrsigner {
        bail!("MRSIGNERSEAM does not match the Intel-signed TDX module identity");
    }
    // SEAMATTRIBUTES must match the identity under its mask: the masked bits
    // pin the module's own attributes (notably its DEBUG bit).
    for i in 0..8 {
        if body.seam_attributes[i] & attributes_mask[i]
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
    // Highest ISVSVN first, like the platform walk: never trust the
    // document order.
    let mut levels: Vec<&TdxModuleTcbLevel> = levels.iter().collect();
    levels.sort_by_key(|level| std::cmp::Reverse(level.tcb.isvsvn));
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
    // Highest ISVSVN first, like the platform walk: never trust the
    // document order.
    let mut levels: Vec<&QeTcbLevel> = qe.tcb_levels.iter().collect();
    levels.sort_by_key(|level| std::cmp::Reverse(level.tcb.isvsvn));
    for level in levels {
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
///
/// Crate-private because it takes an openssl certificate: outside callers
/// go through `verify_tdx_quote`, which owns the whole sequence.
pub(crate) fn evaluate_tcb(
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

    // Platform levels and TDX module, for every SVN vector the body carries.
    let (mut status, mut advisories) = appraise_platform_tcb(&tcb_info, &platform, &quote.body)?;

    let (qe_status, qe_advisories) = qe_identity_status(&qe_identity, &quote.signature.qe_report)?;
    status = status.converge(qe_status);
    merge_advisories(&mut advisories, qe_advisories);

    check_policy(status, &advisories, policy)?;

    Ok(TdxTcbOutcome {
        status,
        advisory_ids: advisories,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tdx::quote::{TdReport15Extension, parse_tdx_quote};
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
        // The outdated sample's PCK reports SGX component 7 at SVN 3 while
        // every level of its TCB Info demands 5, so the walk finds no match
        // and the quote is refused before any status is decided. It never
        // reaches an OutOfDate verdict, despite the fixture's name.
        let quote = parse_tdx_quote(QUOTE_OUTDATED).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).unwrap();
        let err = format!(
            "{:#}",
            evaluate_tcb(
                &quote,
                &collateral,
                &pck_leaf(QUOTE_OUTDATED),
                now_outdated(),
                &TdxTcbPolicy::default(),
            )
            .unwrap_err()
        );
        assert!(err.contains("below every level"), "got: {err}");
        // The failure names the vector that tripped, not just the walk.
        assert!(err.contains("tee_tcb_svn)"), "got: {err}");
    }

    #[test]
    fn outdated_collateral_carries_the_published_advisories() {
        // `advisoryIDs` reaches the appraisal through a serde-renamed field
        // (`advisory_i_ds` under camelCase) that also carries a default, so
        // a rename typo would not fail the parse: every level would come
        // back with an empty advisory list and `denied_advisories` would
        // quietly stop matching anything. Pin the real lists from a
        // signature-verified Intel document.
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).unwrap();
        let tcb_info = verify_tcb_info(&collateral, now_outdated()).expect("TCB Info verifies");
        let levels = canonical_levels(&tcb_info);
        assert_eq!(levels.len(), 3, "the fixture publishes three TCB levels");

        // Highest first: the current level, then the two OutOfDate rungs.
        assert_eq!(levels[0].tcb_status, "UpToDate");
        assert!(levels[0].advisory_i_ds.is_empty());
        assert_eq!(levels[1].tcb_status, "OutOfDate");
        assert_eq!(
            levels[1].advisory_i_ds,
            [
                "INTEL-SA-01036",
                "INTEL-SA-01079",
                "INTEL-SA-01099",
                "INTEL-SA-01103",
                "INTEL-SA-01111",
            ]
        );

        // The lowest rung accumulates every advisory Intel has published for
        // this platform family.
        assert_eq!(levels[2].tcb_status, "OutOfDate");
        assert_eq!(levels[2].advisory_i_ds.len(), 19);
        for expected in ["INTEL-SA-00106", "INTEL-SA-00837", "INTEL-SA-01111"] {
            assert!(
                levels[2].advisory_i_ds.iter().any(|a| a == expected),
                "{expected} missing from {:?}",
                levels[2].advisory_i_ds
            );
        }
    }

    #[test]
    fn out_of_date_level_is_refused_by_the_acceptance_policy() {
        // The policy's "not accepted by policy" arm is what stands between a
        // caller and an out-of-date platform, and no fixture reaches it on
        // its own. Take the outdated sample's genuine, signature-verified
        // TCB Info and its real PCK platform, and move two SGX components so
        // the walk lands on a published OutOfDate level: raise component 7
        // (3 in the fixture) to the 5 every level demands, and drop
        // component 4 from 4 to 3, which the top level rules out and the
        // OutOfDate rung allows. The report's own TDX SVN vectors, both of
        // them, are the fixture's.
        let quote = parse_tdx_quote(QUOTE_OUTDATED).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_OUTDATED).unwrap();
        let tcb_info = verify_tcb_info(&collateral, now_outdated()).expect("TCB Info verifies");
        let mut platform = parse_pck_platform(&pck_leaf(QUOTE_OUTDATED)).unwrap();
        platform.cpusvn[7] = 5;
        platform.cpusvn[4] = 3;

        let (status, advisories) = appraise_platform_tcb(&tcb_info, &platform, &quote.body)
            .expect("the raised platform matches a level");
        assert_eq!(status, TcbStatus::OutOfDate);
        assert_eq!(
            advisories,
            [
                "INTEL-SA-01036",
                "INTEL-SA-01079",
                "INTEL-SA-01099",
                "INTEL-SA-01103",
                "INTEL-SA-01111",
            ]
        );

        let err = check_policy(status, &advisories, &TdxTcbPolicy::default())
            .unwrap_err()
            .to_string();
        assert!(err.contains("OutOfDate"), "got: {err}");
        assert!(err.contains("not accepted by policy"), "got: {err}");

        // A caller who deliberately admits OutOfDate gets it through.
        let mut accepting = TdxTcbPolicy::default();
        accepting.accepted_statuses.insert(TcbStatus::OutOfDate);
        check_policy(status, &advisories, &accepting).expect("admitted once the policy says so");

        // Unless one of the advisories that level carries is denied, which
        // is the point of parsing them at all.
        let mut denying = accepting.clone();
        denying
            .denied_advisories
            .insert("INTEL-SA-01099".to_string());
        let err = check_policy(status, &advisories, &denying)
            .unwrap_err()
            .to_string();
        assert!(err.contains("denied advisory"), "got: {err}");
        assert!(err.contains("INTEL-SA-01099"), "got: {err}");
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
        // Time fields and day-of-month are range-checked too: a lenient
        // parser would silently roll these into a neighbouring timestamp.
        assert!(parse_rfc3339_z("2025-06-19T24:00:00Z").is_err());
        assert!(parse_rfc3339_z("2025-06-19T10:60:00Z").is_err());
        assert!(parse_rfc3339_z("2025-06-19T10:16:60Z").is_err());
        assert!(parse_rfc3339_z("2025-02-30T00:00:00Z").is_err());
        assert!(parse_rfc3339_z("2025-04-31T00:00:00Z").is_err());
        assert!(parse_rfc3339_z("2024-02-29T23:59:59Z").is_ok());
    }

    #[test]
    fn rejects_not_yet_valid_tcb_info() {
        // One second before the TCB Info issueDate (2025-06-19T10:16:03Z):
        // the other direction of the document window.
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        let early = UNIX_EPOCH + Duration::from_secs(1_750_328_162);
        let err = evaluate_tcb(
            &quote,
            &collateral,
            &pck_leaf(QUOTE_V4),
            early,
            &TdxTcbPolicy::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not yet valid"), "got: {err}");
    }

    #[test]
    fn rejects_tcb_info_under_an_impostor_chain() {
        // A TCB Info signed by a chain that does not lead to the pinned
        // Intel root: same subject names, fresh keys. verify_signer_chain
        // is what gives the document signatures their meaning, so it needs
        // its own adversarial case, mirroring the PCK chain's foreign-root
        // test in verify.rs. The chain carries the root itself, so the pin
        // on that certificate is what refuses it.
        use openssl::asn1::Asn1Time;
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        use openssl::x509::{X509Builder, X509NameBuilder};

        fn name(cn: &str) -> openssl::x509::X509Name {
            let mut b = X509NameBuilder::new().unwrap();
            b.append_entry_by_text("CN", cn).unwrap();
            b.build()
        }
        fn cert(
            subject: &str,
            issuer: &str,
            key: &PKey<openssl::pkey::Private>,
            signer: &PKey<openssl::pkey::Private>,
        ) -> X509 {
            let mut b = X509Builder::new().unwrap();
            b.set_subject_name(&name(subject)).unwrap();
            b.set_issuer_name(&name(issuer)).unwrap();
            b.set_pubkey(key).unwrap();
            b.set_not_before(&Asn1Time::from_unix(1_700_000_000).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::from_unix(1_900_000_000).unwrap())
                .unwrap();
            b.sign(signer, MessageDigest::sha256()).unwrap();
            b.build()
        }
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let root_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let signer_key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let impostor_root = cert(
            "Intel SGX Root CA",
            "Intel SGX Root CA",
            &root_key,
            &root_key,
        );
        let impostor_signer = cert(
            "Intel SGX TCB Signing",
            "Intel SGX Root CA",
            &signer_key,
            &root_key,
        );
        let mut pem = String::from_utf8(impostor_signer.to_pem().unwrap()).unwrap();
        pem.push_str(&String::from_utf8(impostor_root.to_pem().unwrap()).unwrap());

        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let mut collateral = TdxCollateral::from_json(COLLATERAL_V4).unwrap();
        collateral.tcb_info_issuer_chain = pem;
        let err = format!(
            "{:#}",
            evaluate_tcb(
                &quote,
                &collateral,
                &pck_leaf(QUOTE_V4),
                now_v4(),
                &TdxTcbPolicy::default(),
            )
            .unwrap_err()
        );
        assert!(
            err.contains("is not the pinned Intel SGX Root CA"),
            "got: {err}"
        );
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
    fn walk_does_not_trust_document_order() {
        // Two levels the platform satisfies, listed lowest first, where the
        // lower one carries the better status. Both DCAP references sort
        // the levels highest-first before walking (Intel's TcbLevel
        // operator>, dcap-qvl's canonicalize_tcb_levels), so the higher
        // level's OutOfDate is the answer, not the first match in the
        // document.
        let quote = parse_tdx_quote(QUOTE_V4).unwrap();
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let zeros = vec![serde_json::json!({"svn": 0}); 16];
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
                        "tdxtcbcomponents": zeros,
                        "pcesvn": 0
                    },
                    "tcbStatus": "UpToDate"
                },
                {
                    "tcb": {
                        "sgxtcbcomponents": zeros,
                        "tdxtcbcomponents": zeros,
                        "pcesvn": 1
                    },
                    "tcbStatus": "OutOfDate"
                }
            ]
        }))
        .unwrap();
        let (status, _) = walk_platform_tcb(&tcb_info, &platform, &quote.body.tee_tcb_svn).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
    }

    /// A TCB Info carrying one level per (TDX component ladder, status,
    /// advisories) triple, in the given document order. The SGX side is all
    /// zeros so any real PCK platform satisfies it and the TDX components
    /// decide the walk.
    fn tcb_info_with_tdx_levels(levels: &[([u8; 16], &str, &[&str])]) -> TcbInfo {
        tcb_info_with_module_identities(levels, &[])
    }

    /// The same, plus `tdxModuleIdentities` entries given as
    /// (id, ISVSVN ladder of (isvsvn, status)). Every identity carries the
    /// fixture's own MRSIGNERSEAM and a zero attributes mask, so the module
    /// gate turns on the SVN ladder alone.
    fn tcb_info_with_module_identities(
        levels: &[([u8; 16], &str, &[&str])],
        module_identities: &[(&str, &[(u8, &str)])],
    ) -> TcbInfo {
        let zeros = vec![serde_json::json!({"svn": 0}); 16];
        let levels: Vec<serde_json::Value> = levels
            .iter()
            .map(|(tdx, status, advisories)| {
                serde_json::json!({
                    "tcb": {
                        "sgxtcbcomponents": zeros,
                        "tdxtcbcomponents": tdx.iter().map(|svn| serde_json::json!({"svn": svn}))
                            .collect::<Vec<_>>(),
                        "pcesvn": 0
                    },
                    "tcbStatus": status,
                    "advisoryIDs": advisories
                })
            })
            .collect();
        let mrsigner = hex::encode(parse_tdx_quote(QUOTE_V4).unwrap().body.mrsignerseam);
        let module = serde_json::json!({
            "mrsigner": mrsigner,
            "attributes": "0000000000000000",
            "attributesMask": "0000000000000000"
        });
        let identities: Vec<serde_json::Value> = module_identities
            .iter()
            .map(|(id, ladder)| {
                serde_json::json!({
                    "id": id,
                    "mrsigner": mrsigner,
                    "attributes": "0000000000000000",
                    "attributesMask": "0000000000000000",
                    "tcbLevels": ladder.iter().map(|(isvsvn, status)| serde_json::json!({
                        "tcb": {"isvsvn": isvsvn},
                        "tcbStatus": status
                    })).collect::<Vec<_>>()
                })
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "id": "TDX",
            "version": 3,
            "issueDate": "2025-06-19T10:16:03Z",
            "nextUpdate": "2025-07-19T10:16:03Z",
            "fmspc": "b0c06f000000",
            "tcbLevels": levels,
            "tdxModule": module,
            "tdxModuleIdentities": identities
        }))
        .expect("synthetic TCB Info parses")
    }

    /// The v4 fixture's body with a TD report 1.5 extension bolted on, so
    /// the second SVN vector can be set without a signed 1.5 fixture.
    fn body_with_tee_tcb_svn2(tee_tcb_svn: [u8; 16], tee_tcb_svn2: [u8; 16]) -> TdReportBody {
        let mut body = parse_tdx_quote(QUOTE_V4).unwrap().body;
        body.tee_tcb_svn = tee_tcb_svn;
        body.v15 = Some(TdReport15Extension {
            tee_tcb_svn2,
            mrservicetd: [0u8; 48],
        });
        body
    }

    #[test]
    fn report_15_second_svn_vector_is_appraised_too() {
        // A TD report 1.5 carries a second TDX SVN vector for the module
        // TCB a TD-preserving update moved it to. Appraising only the first
        // one accepts a TD running under a module TCB Intel lists nowhere.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let mut wanted = [0u8; 16];
        wanted[0] = 3;
        let tcb_info = tcb_info_with_tdx_levels(&[(wanted, "UpToDate", &[])]);

        let body = body_with_tee_tcb_svn2([5u8; 16], [0u8; 16]);
        let err = format!(
            "{:#}",
            appraise_platform_tcb(&tcb_info, &platform, &body).unwrap_err()
        );
        assert!(err.contains("tee_tcb_svn2"), "got: {err}");
        assert!(err.contains("below every level"), "got: {err}");

        // The same body with a second vector that does meet the level is
        // accepted: the walk is not simply refusing every 1.5 body.
        let body = body_with_tee_tcb_svn2([5u8; 16], [4u8; 16]);
        let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::UpToDate);
    }

    #[test]
    fn report_15_takes_the_worse_of_the_two_svn_vectors() {
        // Each vector matches a different level: the worse status wins, and
        // the advisories of both levels are reported.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let tcb_info = tcb_info_with_tdx_levels(&[
            ([5u8; 16], "UpToDate", &["INTEL-SA-00100"]),
            ([1u8; 16], "OutOfDate", &["INTEL-SA-00200"]),
        ]);

        let body = body_with_tee_tcb_svn2([5u8; 16], [1u8; 16]);
        let (status, advisories) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
        assert_eq!(advisories, ["INTEL-SA-00100", "INTEL-SA-00200"]);

        // Order does not matter: the worse level is the answer either way.
        let body = body_with_tee_tcb_svn2([1u8; 16], [5u8; 16]);
        let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
    }

    /// An SVN vector carrying a TDX module SVN and module major version in
    /// the two bytes the module identity is selected by, zero elsewhere.
    fn module_svn_vector(module_svn: u8, module_version: u8) -> [u8; 16] {
        let mut svn = [0u8; 16];
        svn[0] = module_svn;
        svn[1] = module_version;
        svn
    }

    #[test]
    fn report_15_second_vector_module_version_must_be_listed() {
        // The second vector names its own TDX module major version. A
        // version Intel does not list is an unknown module, so it fails the
        // appraisal instead of riding on the version the first vector names.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let tcb_info = tcb_info_with_module_identities(
            &[([0u8; 16], "UpToDate", &[])],
            &[("TDX_01", &[(0, "UpToDate")])],
        );

        let body = body_with_tee_tcb_svn2(module_svn_vector(5, 1), module_svn_vector(5, 2));
        let err = format!(
            "{:#}",
            appraise_platform_tcb(&tcb_info, &platform, &body).unwrap_err()
        );
        assert!(err.contains("tee_tcb_svn2"), "got: {err}");
        assert!(err.contains("no TDX module identity TDX_02"), "got: {err}");

        // The listed version on both vectors appraises normally.
        let body = body_with_tee_tcb_svn2(module_svn_vector(5, 1), module_svn_vector(5, 1));
        let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::UpToDate);
    }

    #[test]
    fn report_15_second_vector_walks_the_module_svn_ladder() {
        // The module ISVSVN ladder runs for the second vector too: below
        // every level it fails, and a lower level's status is taken up.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let tcb_info = tcb_info_with_module_identities(
            &[([0u8; 16], "UpToDate", &[])],
            &[("TDX_01", &[(4, "UpToDate")])],
        );
        let body = body_with_tee_tcb_svn2(module_svn_vector(5, 1), module_svn_vector(1, 1));
        let err = format!(
            "{:#}",
            appraise_platform_tcb(&tcb_info, &platform, &body).unwrap_err()
        );
        assert!(err.contains("tee_tcb_svn2"), "got: {err}");
        assert!(
            err.contains("TDX module SVN is below every level"),
            "got: {err}"
        );

        // The same second vector against a ladder that does list its SVN:
        // the module status it lands on is taken up, not the first vector's.
        let tcb_info = tcb_info_with_module_identities(
            &[([0u8; 16], "UpToDate", &[])],
            &[("TDX_01", &[(4, "UpToDate"), (0, "OutOfDate")])],
        );
        let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::OutOfDate);
    }

    #[test]
    fn report_15_status_does_not_depend_on_the_vector_order() {
        // The two vectors are peers, so combining them has to be symmetric.
        // This pair is the case that separates a symmetric worse-of-two from
        // the asymmetric platform-versus-component rule: the latter would
        // answer OutOfDateConfigurationNeeded one way round and OutOfDate
        // the other.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let tcb_info = tcb_info_with_tdx_levels(&[
            ([5u8; 16], "ConfigurationNeeded", &[]),
            ([1u8; 16], "OutOfDate", &[]),
        ]);
        for (first, second) in [([5u8; 16], [1u8; 16]), ([1u8; 16], [5u8; 16])] {
            let body = body_with_tee_tcb_svn2(first, second);
            let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
            assert_eq!(status, TcbStatus::OutOfDate, "first vector {first:?}");
        }
    }

    #[test]
    fn report_10_body_walks_once() {
        // A 1.0 body has no second vector, so nothing changes for it: the
        // level its single vector satisfies gives the status.
        let platform = parse_pck_platform(&pck_leaf(QUOTE_V4)).unwrap();
        let tcb_info = tcb_info_with_tdx_levels(&[([3u8; 16], "UpToDate", &[])]);
        let mut body = parse_tdx_quote(QUOTE_V4).unwrap().body;
        body.tee_tcb_svn = [5u8; 16];
        assert!(body.v15.is_none());
        let (status, _) = appraise_platform_tcb(&tcb_info, &platform, &body).unwrap();
        assert_eq!(status, TcbStatus::UpToDate);
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
        // The rule is deliberately not mirrored: Intel's convergeTcbStatuses
        // (EvaluateTcb.cpp) only reacts to an OutOfDate or Revoked
        // component, so an out-of-date platform under a
        // configuration-needed component stays OutOfDate. dcap-qvl's
        // converge_with_component agrees.
        assert_eq!(OutOfDate.converge(ConfigurationNeeded), OutOfDate);
        assert_eq!(
            OutOfDate.converge(ConfigurationAndSwHardeningNeeded),
            OutOfDate
        );
        assert_eq!(SwHardeningNeeded.converge(Revoked), Revoked);
        // worse() is the peer rule, and unlike converge it is symmetric:
        // this is the pair the two rules disagree on.
        assert_eq!(ConfigurationNeeded.worse(OutOfDate), OutOfDate);
        assert_eq!(OutOfDate.worse(ConfigurationNeeded), OutOfDate);
        assert_eq!(UpToDate.worse(Revoked), Revoked);
        assert_eq!(Revoked.worse(UpToDate), Revoked);
    }
}
