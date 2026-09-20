//! `gpu-policy`: does the hardware match the GPU requirement the measured
//! kernel command line carries?
//!
//! The guest init runs this once, right after NVIDIA's `nvattest` verified the
//! GPU evidence, and powers the VM off on any non-zero exit. nvattest proves
//! the card is a genuine, CC-capable NVIDIA GPU whose measurements match
//! NVIDIA's reference manifests; it says nothing about WHICH board, nor about
//! how many. The requirement travels in the measured command line
//! (`gpu_arch`, `gpu_count`, optional `gpu_models`), so a client that verified
//! the launch measurement knows exactly what was enforced here.
//!
//! Input documents:
//! - `--cmdline`: the kernel command line (init passes `/proc/cmdline`),
//!   whitespace-delimited tokens.
//! - `--gpu-json`: the measured policy, `{"archs":{"<arch>":{"accepted_models":
//!   [...],"boards":{"vvvv:dddd":[{"project","project_sku","chip_sku",...}]}}}}`.
//!   Other keys (vendor, driver version, library path) are not policy inputs.
//! - `--claims`: the claims array init cut out of nvattest's result. GPU claims
//!   v3.0 carries NO architecture string: `hwmodel` plus the boolean
//!   `x-nvidia-gpu-arch-check` are all NVIDIA emits, so a claim is bound to the
//!   requested architecture by its `hwmodel` being one of THAT architecture's
//!   accepted models.
//! - `--evidence`: exactly what `nvattest --format json collect-evidence`
//!   prints: `{"result_code":0,"result_message":"...","evidences":[{"arch",
//!   "nonce","evidence","certificate"}]}`, `evidences` null when collection
//!   failed. `evidence` is base64 of the SPDM exchange, request then response.
//!
//! Board identity comes only from the SPDM opaque data of that response, never
//! from PCI config space, sysfs, nvidia-smi or the claims: the opaque data is
//! inside what the GPU signed and nvattest checked.
//!
//! Exit codes: 0 and a summary line on stdout when every rule holds, 1 and one
//! reason line on stderr when a rule fails, 2 when an input is not the
//! document described above (which points at the image, not at the hardware).

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::Deserialize;

/// One GPU's evidence, in the shape `nvattest collect-evidence` writes.
pub type EvidenceEntry = crate::gpu::GpuEvidence;

#[derive(clap::Args, Debug)]
pub struct GpuPolicyArgs {
    /// File holding the kernel command line carrying the requirement.
    #[arg(long)]
    cmdline: PathBuf,

    /// Measured GPU policy file.
    #[arg(long)]
    gpu_json: PathBuf,

    /// Claims array extracted from nvattest's verification result.
    #[arg(long)]
    claims: PathBuf,

    /// Evidence document written by `nvattest collect-evidence`.
    #[arg(long)]
    evidence: PathBuf,
}

/// The measured policy file. Only the architecture map is policy; the other
/// keys describe the runtime's driver and are ignored here.
#[derive(Debug, Clone, Deserialize)]
pub struct GpuPolicy {
    pub archs: BTreeMap<String, ArchPolicy>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ArchPolicy {
    /// nvattest `hwmodel` values this architecture may report.
    pub accepted_models: Vec<String>,
    /// Board identities per PCI id, absent on an architecture no model token
    /// can name yet.
    #[serde(default)]
    pub boards: BTreeMap<String, Vec<Board>>,
}

/// One board under a PCI id. The human-readable `name` in the file is not a
/// comparison input, so it is not read here.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Board {
    pub project: String,
    pub project_sku: String,
    pub chip_sku: String,
}

/// One per-GPU claim. Everything nvattest emits besides these fields is
/// verification detail it already enforced itself.
#[derive(Debug, Clone, Deserialize)]
pub struct Claim {
    pub hwmodel: String,
    /// No claims version NVIDIA ships names the architecture; enforced if one
    /// ever does.
    #[serde(default)]
    pub arch: Option<String>,
    /// nvattest's own "architecture supported" verdict.
    #[serde(default, rename = "x-nvidia-gpu-arch-check")]
    pub arch_check: Option<bool>,
}

/// What the command line demands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub arch: String,
    pub count: usize,
    pub models: Option<Vec<String>>,
}

/// The board a signed report identifies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoardIdentity {
    pub project: String,
    pub project_sku: String,
    pub chip_sku: String,
}

impl BoardIdentity {
    /// Case-insensitive: NVIDIA carries these strings verbatim from the opaque
    /// data into its RIM ids, and board identity never differs by case alone.
    fn is(&self, board: &Board) -> bool {
        self.project.eq_ignore_ascii_case(&board.project)
            && self.project_sku.eq_ignore_ascii_case(&board.project_sku)
            && self.chip_sku.eq_ignore_ascii_case(&board.chip_sku)
    }
}

impl fmt::Display for BoardIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}/{}", self.project, self.project_sku, self.chip_sku)
    }
}

/// What held, for the one line init logs.
#[derive(Debug, Clone)]
pub struct Summary {
    pub arch: String,
    pub count: usize,
    pub models: Option<Vec<String>>,
    /// Board identities read out of the signed reports, empty when no model
    /// token asked for them.
    pub boards: Vec<BoardIdentity>,
}

impl fmt::Display for Summary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gpu-policy: {} GPU(s) match gpu_arch={} gpu_count={}",
            self.count, self.arch, self.count
        )?;
        if let Some(models) = &self.models {
            write!(f, " gpu_models={}", models.join(","))?;
            let boards: Vec<String> = self.boards.iter().map(BoardIdentity::to_string).collect();
            write!(f, " (boards {})", boards.join(","))?;
        }
        Ok(())
    }
}

/// A rule that did not hold. One variant per rule, so every negative test
/// names what it broke.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    MissingToken {
        key: &'static str,
    },
    DuplicateToken {
        key: &'static str,
    },
    BadCount {
        value: String,
    },
    BadModelId {
        value: String,
    },
    /// Not sorted ascending, or an id twice.
    ModelsNotCanonical {
        value: String,
    },
    UnknownArch {
        arch: String,
    },
    /// Requested id no board in the policy answers for.
    UnknownModel {
        id: String,
    },
    CountMismatch {
        what: &'static str,
        expected: usize,
        found: usize,
    },
    ArchMismatch {
        what: &'static str,
        index: usize,
        found: String,
        want: String,
    },
    /// nvattest itself says the architecture is unsupported.
    ArchCheckFailed {
        index: usize,
    },
    UnacceptedModel {
        index: usize,
        hwmodel: String,
    },
    BoardMismatch {
        index: usize,
        found: BoardIdentity,
    },
    Evidence {
        index: usize,
        source: EvidenceError,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingToken { key } => {
                write!(f, "the kernel command line carries no {key} token")
            }
            Self::DuplicateToken { key } => {
                write!(f, "the kernel command line carries {key} more than once")
            }
            Self::BadCount { value } => write!(
                f,
                "gpu_count={value} is not a decimal 1 to 8 without a leading zero"
            ),
            Self::BadModelId { value } => write!(
                f,
                "gpu_models carries {value}, not a lowercase vvvv:dddd PCI id"
            ),
            Self::ModelsNotCanonical { value } => write!(
                f,
                "gpu_models={value} is not sorted ascending and de-duplicated"
            ),
            Self::UnknownArch { arch } => {
                write!(f, "gpu_arch={arch} is not an architecture of the policy")
            }
            Self::UnknownModel { id } => {
                write!(
                    f,
                    "gpu_models carries {id}, which the policy lists no board for"
                )
            }
            Self::CountMismatch {
                what,
                expected,
                found,
            } => write!(f, "gpu_count demands {expected} GPU(s), {what} has {found}"),
            Self::ArchMismatch {
                what,
                index,
                found,
                want,
            } => write!(
                f,
                "{what} {index} reports architecture {found}, gpu_arch demands {want}"
            ),
            Self::ArchCheckFailed { index } => write!(
                f,
                "claim {index} reports the GPU architecture as unsupported"
            ),
            Self::UnacceptedModel { index, hwmodel } => write!(
                f,
                "claim {index} reports hwmodel {hwmodel}, not an accepted model of this architecture"
            ),
            Self::BoardMismatch { index, found } => write!(
                f,
                "GPU {index} is board {found}, none of the boards gpu_models asked for"
            ),
            Self::Evidence { index, source } => {
                write!(f, "GPU {index} evidence is unusable: {source}")
            }
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Evidence { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// A signed report we could not read a board identity out of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    NotBase64,
    /// The bytes end inside this field.
    Truncated {
        field: &'static str,
    },
    /// Not an SPDM 1.1 MEASUREMENTS response where one must be.
    NotMeasurements,
    /// The opaque data ends inside a field header or value.
    OpaqueTrailing,
    MissingField {
        field: &'static str,
    },
    DuplicateField {
        field: &'static str,
    },
    /// Empty after trailing NULs, or not ASCII alphanumeric.
    BadField {
        field: &'static str,
    },
}

impl fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => write!(f, "the evidence field is not base64"),
            Self::Truncated { field } => write!(f, "the SPDM exchange ends inside its {field}"),
            Self::NotMeasurements => {
                write!(f, "the SPDM response is not a 1.1 MEASUREMENTS response")
            }
            Self::OpaqueTrailing => write!(f, "the SPDM opaque data ends inside a field"),
            Self::MissingField { field } => {
                write!(f, "the SPDM opaque data carries no {field}")
            }
            Self::DuplicateField { field } => {
                write!(f, "the SPDM opaque data carries {field} more than once")
            }
            Self::BadField { field } => {
                write!(f, "the SPDM opaque data's {field} is empty or not ASCII")
            }
        }
    }
}

impl std::error::Error for EvidenceError {}

/// The measured SPDM exchange: a 37-byte GET_MEASUREMENTS request, then the
/// MEASUREMENTS response.
const SPDM_REQUEST_LEN: usize = 37;
/// Version, code, param1, param2, block count, 3-byte record length.
const SPDM_RESPONSE_HEADER_LEN: usize = 8;
const SPDM_VERSION_1_1: u8 = 0x11;
const SPDM_MEASUREMENTS: u8 = 0x60;
const SPDM_NONCE_LEN: usize = 32;
/// ECDSA P-384 over SHA-384 on both Hopper and Blackwell.
const SPDM_SIGNATURE_LEN: usize = 96;

const OPAQUE_CHIP_SKU: u16 = 15;
const OPAQUE_PROJECT: u16 = 17;
const OPAQUE_PROJECT_SKU: u16 = 18;

/// Bounds-checked forward reader: every field is taken through it, so a
/// truncated or lying length is an error and never an index panic.
struct Reader<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn take(&mut self, len: usize, field: &'static str) -> Result<&'a [u8], EvidenceError> {
        let end = self
            .at
            .checked_add(len)
            .ok_or(EvidenceError::Truncated { field })?;
        let slice = self
            .data
            .get(self.at..end)
            .ok_or(EvidenceError::Truncated { field })?;
        self.at = end;
        Ok(slice)
    }

    fn done(&self) -> bool {
        self.at >= self.data.len()
    }
}

/// Read the board identity out of the SPDM opaque data of one signed report.
pub fn board_identity(blob: &[u8]) -> Result<BoardIdentity, EvidenceError> {
    let mut reader = Reader::new(blob);
    reader.take(SPDM_REQUEST_LEN, "request")?;
    let header = reader.take(SPDM_RESPONSE_HEADER_LEN, "response header")?;
    // take() returned exactly SPDM_RESPONSE_HEADER_LEN bytes.
    if header[0] != SPDM_VERSION_1_1 || header[1] != SPDM_MEASUREMENTS {
        return Err(EvidenceError::NotMeasurements);
    }
    let record_len = u32::from_le_bytes([header[5], header[6], header[7], 0]) as usize;
    reader.take(record_len, "measurement record")?;
    reader.take(SPDM_NONCE_LEN, "nonce")?;
    let opaque_len = reader.take(2, "opaque length")?;
    let opaque_len = usize::from(u16::from_le_bytes([opaque_len[0], opaque_len[1]]));
    let opaque = reader.take(opaque_len, "opaque data")?;
    // The signature must be there too: a report that stops before it was never
    // a whole signed report.
    reader.take(SPDM_SIGNATURE_LEN, "signature")?;

    let mut project = None;
    let mut project_sku = None;
    let mut chip_sku = None;
    let mut fields = Reader::new(opaque);
    while !fields.done() {
        let header = fields
            .take(4, "field header")
            .map_err(|_| EvidenceError::OpaqueTrailing)?;
        let kind = u16::from_le_bytes([header[0], header[1]]);
        let len = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let value = fields
            .take(len, "field value")
            .map_err(|_| EvidenceError::OpaqueTrailing)?;
        let (slot, field) = match kind {
            OPAQUE_PROJECT => (&mut project, "PROJECT"),
            OPAQUE_PROJECT_SKU => (&mut project_sku, "PROJECT_SKU"),
            OPAQUE_CHIP_SKU => (&mut chip_sku, "CHIP_SKU"),
            _ => continue,
        };
        if slot.is_some() {
            return Err(EvidenceError::DuplicateField { field });
        }
        *slot = Some(ascii_field(value, field)?);
    }

    Ok(BoardIdentity {
        project: project.ok_or(EvidenceError::MissingField { field: "PROJECT" })?,
        project_sku: project_sku.ok_or(EvidenceError::MissingField {
            field: "PROJECT_SKU",
        })?,
        chip_sku: chip_sku.ok_or(EvidenceError::MissingField { field: "CHIP_SKU" })?,
    })
}

/// Opaque-data strings are fixed-width fields padded with NULs. Anything else
/// non-alphanumeric is refused rather than normalized.
fn ascii_field(raw: &[u8], field: &'static str) -> Result<String, EvidenceError> {
    let trimmed: &[u8] = match raw.iter().rposition(|byte| *byte != 0) {
        Some(last) => raw.get(..=last).unwrap_or_default(),
        None => &[],
    };
    if trimmed.is_empty() || !trimmed.iter().all(u8::is_ascii_alphanumeric) {
        return Err(EvidenceError::BadField { field });
    }
    String::from_utf8(trimmed.to_vec()).map_err(|_| EvidenceError::BadField { field })
}

/// Read the requirement out of the command line.
pub fn requirement(cmdline: &str) -> Result<Requirement, PolicyError> {
    let mut arch: Option<&str> = None;
    let mut count: Option<&str> = None;
    let mut models: Option<&str> = None;
    for token in cmdline.split_ascii_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let (slot, name): (&mut Option<&str>, &'static str) = match key {
            "gpu_arch" => (&mut arch, "gpu_arch"),
            "gpu_count" => (&mut count, "gpu_count"),
            "gpu_models" => (&mut models, "gpu_models"),
            _ => continue,
        };
        if slot.is_some() {
            return Err(PolicyError::DuplicateToken { key: name });
        }
        *slot = Some(value);
    }
    let arch = arch.ok_or(PolicyError::MissingToken { key: "gpu_arch" })?;
    let count = count.ok_or(PolicyError::MissingToken { key: "gpu_count" })?;
    Ok(Requirement {
        arch: arch.to_string(),
        count: parse_count(count)?,
        models: models.map(parse_models).transpose()?,
    })
}

/// Decimal 1 to 8, no leading zero, nothing else.
fn parse_count(value: &str) -> Result<usize, PolicyError> {
    let bad = || PolicyError::BadCount {
        value: value.to_string(),
    };
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(bad());
    }
    let count: usize = value.parse().map_err(|_| bad())?;
    if !(1..=8).contains(&count) {
        return Err(bad());
    }
    Ok(count)
}

/// Lowercase `vvvv:dddd` ids, sorted ascending and de-duplicated: the token is
/// canonical or it is refused, so the measurement is a single spelling of the
/// same requirement.
fn parse_models(value: &str) -> Result<Vec<String>, PolicyError> {
    let ids: Vec<&str> = value.split(',').collect();
    for id in &ids {
        if !is_model_id(id) {
            return Err(PolicyError::BadModelId {
                value: (*id).to_string(),
            });
        }
    }
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(PolicyError::ModelsNotCanonical {
            value: value.to_string(),
        });
    }
    Ok(ids.into_iter().map(str::to_string).collect())
}

fn is_model_id(id: &str) -> bool {
    let Some((vendor, device)) = id.split_once(':') else {
        return false;
    };
    let lower_hex = |part: &str| {
        part.len() == 4
            && part
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    lower_hex(vendor) && lower_hex(device)
}

/// Every rule, on inputs already parsed: no filesystem, no processes.
pub fn evaluate(
    cmdline: &str,
    policy: &GpuPolicy,
    claims: &[Claim],
    evidence: &[EvidenceEntry],
) -> Result<Summary, PolicyError> {
    let want = requirement(cmdline)?;
    let arch = policy
        .archs
        .get(&want.arch)
        .ok_or_else(|| PolicyError::UnknownArch {
            arch: want.arch.clone(),
        })?;

    if evidence.len() != want.count {
        return Err(PolicyError::CountMismatch {
            what: "the evidence",
            expected: want.count,
            found: evidence.len(),
        });
    }
    if claims.len() != want.count {
        return Err(PolicyError::CountMismatch {
            what: "the claims array",
            expected: want.count,
            found: claims.len(),
        });
    }

    for (index, entry) in evidence.iter().enumerate() {
        if !entry.arch.eq_ignore_ascii_case(&want.arch) {
            return Err(PolicyError::ArchMismatch {
                what: "evidence",
                index,
                found: entry.arch.clone(),
                want: want.arch.clone(),
            });
        }
    }

    for (index, claim) in claims.iter().enumerate() {
        if let Some(found) = &claim.arch
            && !found.eq_ignore_ascii_case(&want.arch)
        {
            return Err(PolicyError::ArchMismatch {
                what: "claim",
                index,
                found: found.clone(),
                want: want.arch.clone(),
            });
        }
        if claim.arch_check == Some(false) {
            return Err(PolicyError::ArchCheckFailed { index });
        }
        // The architecture binding of a claim: v3.0 claims name no
        // architecture, and accepted_models is per architecture.
        if !arch
            .accepted_models
            .iter()
            .any(|model| model == &claim.hwmodel)
        {
            return Err(PolicyError::UnacceptedModel {
                index,
                hwmodel: claim.hwmodel.clone(),
            });
        }
    }

    // Board identity is read only when a model token asked for it, so a
    // requirement that names no model does not depend on the SPDM layout.
    let mut boards = Vec::new();
    if let Some(ids) = &want.models {
        let mut allowed: Vec<&Board> = Vec::new();
        for id in ids {
            let listed = arch
                .boards
                .get(id)
                .filter(|boards| !boards.is_empty())
                .ok_or_else(|| PolicyError::UnknownModel { id: id.clone() })?;
            allowed.extend(listed);
        }
        for (index, entry) in evidence.iter().enumerate() {
            let blob = base64::engine::general_purpose::STANDARD
                .decode(&entry.evidence)
                .map_err(|_| PolicyError::Evidence {
                    index,
                    source: EvidenceError::NotBase64,
                })?;
            let found =
                board_identity(&blob).map_err(|source| PolicyError::Evidence { index, source })?;
            if !allowed.iter().any(|board| found.is(board)) {
                return Err(PolicyError::BoardMismatch { index, found });
            }
            boards.push(found);
        }
    }

    Ok(Summary {
        arch: want.arch,
        count: want.count,
        models: want.models,
        boards,
    })
}

/// The `nvattest collect-evidence --format json` document.
#[derive(Debug, Deserialize)]
struct CollectEvidenceDocument {
    result_code: i64,
    #[serde(default)]
    result_message: String,
    /// null when the collection failed.
    evidences: Option<Vec<EvidenceEntry>>,
}

/// Accept only a successful collection: init must never hand us a failed one.
fn parse_evidence_document(raw: &[u8]) -> Result<Vec<EvidenceEntry>> {
    let document: CollectEvidenceDocument =
        serde_json::from_slice(raw).context("not a collect-evidence document")?;
    if document.result_code != 0 {
        bail!(
            "collect-evidence failed: result_code {} ({})",
            document.result_code,
            document.result_message
        );
    }
    document
        .evidences
        .context("the collect-evidence document carries no evidences")
}

/// Either a rule did not hold, or an input was not the document it must be.
enum Failure {
    Policy(PolicyError),
    Usage(anyhow::Error),
}

fn decide(args: &GpuPolicyArgs) -> Result<Summary, Failure> {
    let read = |path: &PathBuf| -> Result<Vec<u8>> {
        std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))
    };
    let inputs = || -> Result<(String, GpuPolicy, Vec<Claim>, Vec<EvidenceEntry>)> {
        // Lossy: a command line that is not UTF-8 cannot spell a token we
        // accept, so it fails on the rules rather than on the encoding.
        let cmdline = String::from_utf8_lossy(&read(&args.cmdline)?).into_owned();
        let policy: GpuPolicy = serde_json::from_slice(&read(&args.gpu_json)?)
            .with_context(|| format!("{} is not a GPU policy", args.gpu_json.display()))?;
        let claims: Vec<Claim> = serde_json::from_slice(&read(&args.claims)?)
            .with_context(|| format!("{} is not a claims array", args.claims.display()))?;
        let evidence = parse_evidence_document(&read(&args.evidence)?)
            .with_context(|| args.evidence.display().to_string())?;
        Ok((cmdline, policy, claims, evidence))
    };
    let (cmdline, policy, claims, evidence) = inputs().map_err(Failure::Usage)?;
    evaluate(&cmdline, &policy, &claims, &evidence).map_err(Failure::Policy)
}

/// Decide and print; the caller exits with what this returns.
pub fn run(args: &GpuPolicyArgs) -> i32 {
    match decide(args) {
        Ok(summary) => {
            println!("{summary}");
            0
        }
        Err(Failure::Policy(error)) => {
            eprintln!("gpu-policy: {error}");
            1
        }
        Err(Failure::Usage(error)) => {
            eprintln!("gpu-policy: {error:#}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real H200 NVL vectors: `responses[i].gpus` are the evidence entries
    /// nvattest wrote, `responses[i].boot_claims` the claims init extracted.
    const VECTORS: &str = include_str!("../tests/fixtures/h200_nvl_gpu_attestation.json");

    /// The measured policy as the runtimes ship it.
    const POLICY: &str = r#"{"vendor":"nvidia","driver_version":"595.71.05","library_path":"/opt/nvidia/lib",
 "archs":{
  "hopper":{"accepted_models":["GH100 A01 GSP BROM"],
   "boards":{
    "10de:233b":[{"name":"H200 NVL","project":"1010","project_sku":"0230","chip_sku":"894"}],
    "10de:2331":[{"name":"H100 PCIe","project":"1010","project_sku":"0200","chip_sku":"882"}],
    "10de:2321":[{"name":"H100 NVL","project":"1010","project_sku":"0210","chip_sku":"886"}],
    "10de:2330":[{"name":"H100 SXM5 80GB","project":"G520","project_sku":"0200","chip_sku":"885"}],
    "10de:2335":[{"name":"H200 SXM5 141GB","project":"G520","project_sku":"0280","chip_sku":"895"}]}},
  "blackwell":{"accepted_models":["NVIDIA RTX PRO 6000 Blackwell Server Edition"],
   "boards":{
    "10de:2bb5":[{"name":"RTX PRO 6000 Blackwell Server Edition","project":"G153","project_sku":"0210","chip_sku":"895"},
                 {"name":"RTX PRO 6000 Blackwell Server Edition","project":"G153","project_sku":"0212","chip_sku":"895"}]}}}}"#;

    fn policy() -> GpuPolicy {
        serde_json::from_str(POLICY).unwrap()
    }

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).unwrap()
    }

    fn real_evidence() -> Vec<EvidenceEntry> {
        serde_json::from_value(vectors()["responses"][0]["gpus"].clone()).unwrap()
    }

    fn real_claims() -> Vec<Claim> {
        serde_json::from_value(vectors()["responses"][0]["boot_claims"].clone()).unwrap()
    }

    fn real_blob() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&real_evidence()[0].evidence)
            .unwrap()
    }

    fn evidence_with_blob(blob: &[u8]) -> Vec<EvidenceEntry> {
        let mut evidence = real_evidence();
        evidence[0].evidence = base64::engine::general_purpose::STANDARD.encode(blob);
        evidence
    }

    /// Offset of the 2-byte opaque length inside the exchange, read the same
    /// way the parser walks it.
    fn opaque_length_offset(blob: &[u8]) -> usize {
        let header = SPDM_REQUEST_LEN + SPDM_RESPONSE_HEADER_LEN;
        let record_len = u32::from_le_bytes([
            blob[SPDM_REQUEST_LEN + 5],
            blob[SPDM_REQUEST_LEN + 6],
            blob[SPDM_REQUEST_LEN + 7],
            0,
        ]) as usize;
        header + record_len + SPDM_NONCE_LEN
    }

    fn check(cmdline: &str) -> Result<Summary, PolicyError> {
        evaluate(cmdline, &policy(), &real_claims(), &real_evidence())
    }

    // The real card: one H200 NVL, HOPPER, hwmodel "GH100 A01 GSP BROM",
    // board 1010/0230/894, which the policy lists under 10de:233b.

    #[test]
    fn the_real_h200_satisfies_arch_and_count() {
        let summary = check("ro console=ttyS0 gpu_arch=hopper gpu_count=1").unwrap();
        assert_eq!(summary.arch, "hopper");
        assert_eq!(summary.count, 1);
        assert!(summary.models.is_none());
        assert!(summary.boards.is_empty());
    }

    #[test]
    fn the_real_h200_satisfies_its_own_model_id() {
        let summary = check("gpu_arch=hopper gpu_count=1 gpu_models=10de:233b").unwrap();
        assert_eq!(
            summary.models.as_deref(),
            Some(["10de:233b".to_string()].as_slice())
        );
        assert_eq!(summary.boards.len(), 1);
        assert_eq!(summary.boards[0].to_string(), "1010/0230/894");
        // One line, so init's console keeps one line per decision.
        assert!(!summary.to_string().contains('\n'));
    }

    #[test]
    fn a_requirement_needs_both_tokens() {
        assert_eq!(
            check("gpu_count=1").unwrap_err(),
            PolicyError::MissingToken { key: "gpu_arch" }
        );
        assert_eq!(
            check("gpu_arch=hopper").unwrap_err(),
            PolicyError::MissingToken { key: "gpu_count" }
        );
        // A token that only looks like ours must not satisfy either.
        assert_eq!(
            check("nvidia_gpu_arch=hopper gpu_count=1").unwrap_err(),
            PolicyError::MissingToken { key: "gpu_arch" }
        );
    }

    #[test]
    fn a_repeated_token_is_fatal() {
        assert_eq!(
            check("gpu_arch=hopper gpu_arch=blackwell gpu_count=1").unwrap_err(),
            PolicyError::DuplicateToken { key: "gpu_arch" }
        );
        assert_eq!(
            check("gpu_arch=hopper gpu_count=1 gpu_count=1").unwrap_err(),
            PolicyError::DuplicateToken { key: "gpu_count" }
        );
        assert_eq!(
            check("gpu_arch=hopper gpu_count=1 gpu_models=10de:233b gpu_models=10de:2331")
                .unwrap_err(),
            PolicyError::DuplicateToken { key: "gpu_models" }
        );
    }

    #[test]
    fn a_count_of_two_is_not_one_gpu() {
        assert_eq!(
            check("gpu_arch=hopper gpu_count=2").unwrap_err(),
            PolicyError::CountMismatch {
                what: "the evidence",
                expected: 2,
                found: 1
            }
        );
    }

    #[test]
    fn only_a_canonical_count_parses() {
        for value in ["0", "01", "9", "10", "", "1x", "+1", "١"] {
            let cmdline = format!("gpu_arch=hopper gpu_count={value}");
            match check(&cmdline).unwrap_err() {
                PolicyError::BadCount { .. } => {}
                other => panic!("{value:?} gave {other}"),
            }
        }
        // Well formed, so it reaches the count rule instead.
        assert!(matches!(
            check("gpu_arch=hopper gpu_count=8").unwrap_err(),
            PolicyError::CountMismatch { .. }
        ));
        assert_eq!(parse_count("1").unwrap(), 1);
        assert_eq!(parse_count("8").unwrap(), 8);
    }

    #[test]
    fn the_architecture_must_be_the_one_attached() {
        // Known to the policy, not what the GPU reports.
        assert_eq!(
            check("gpu_arch=blackwell gpu_count=1").unwrap_err(),
            PolicyError::ArchMismatch {
                what: "evidence",
                index: 0,
                found: "HOPPER".to_string(),
                want: "blackwell".to_string()
            }
        );
        // Not an architecture the policy knows at all.
        assert_eq!(
            check("gpu_arch=ampere gpu_count=1").unwrap_err(),
            PolicyError::UnknownArch {
                arch: "ampere".to_string()
            }
        );
        // The evidence spells it upper case, the token lower case.
        assert!(check("gpu_arch=hopper gpu_count=1").is_ok());
    }

    #[test]
    fn a_model_id_the_policy_does_not_list_is_fatal() {
        assert_eq!(
            check("gpu_arch=hopper gpu_count=1 gpu_models=10de:ffff").unwrap_err(),
            PolicyError::UnknownModel {
                id: "10de:ffff".to_string()
            }
        );
    }

    #[test]
    fn an_h100_requirement_refuses_the_h200_board() {
        // 10de:2331 is the H100 PCIe: same project, different SKUs.
        assert_eq!(
            check("gpu_arch=hopper gpu_count=1 gpu_models=10de:2331").unwrap_err(),
            PolicyError::BoardMismatch {
                index: 0,
                found: BoardIdentity {
                    project: "1010".to_string(),
                    project_sku: "0230".to_string(),
                    chip_sku: "894".to_string()
                }
            }
        );
    }

    #[test]
    fn a_model_list_must_be_canonical() {
        for value in [
            "10DE:233B",
            "10de:233B",
            "10de:23b",
            "10de-233b",
            "",
            "10de:233b,",
        ] {
            let cmdline = format!("gpu_arch=hopper gpu_count=1 gpu_models={value}");
            match check(&cmdline).unwrap_err() {
                PolicyError::BadModelId { .. } => {}
                other => panic!("{value:?} gave {other}"),
            }
        }
        for value in ["10de:2335,10de:2331", "10de:233b,10de:233b"] {
            let cmdline = format!("gpu_arch=hopper gpu_count=1 gpu_models={value}");
            match check(&cmdline).unwrap_err() {
                PolicyError::ModelsNotCanonical { .. } => {}
                other => panic!("{value:?} gave {other}"),
            }
        }
        // Canonical and listed: the second id simply matches no attached GPU.
        assert_eq!(
            parse_models("10de:2331,10de:233b").unwrap(),
            ["10de:2331", "10de:233b"]
        );
    }

    #[test]
    fn a_claim_must_report_an_accepted_model() {
        let mut policy = policy();
        policy
            .archs
            .get_mut("hopper")
            .unwrap()
            .accepted_models
            .clear();
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy,
                &real_claims(),
                &real_evidence()
            )
            .unwrap_err(),
            PolicyError::UnacceptedModel {
                index: 0,
                hwmodel: "GH100 A01 GSP BROM".to_string()
            }
        );
    }

    #[test]
    fn a_claim_that_denies_the_architecture_is_fatal() {
        let mut claims = real_claims();
        claims[0].arch_check = Some(false);
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &claims,
                &real_evidence()
            )
            .unwrap_err(),
            PolicyError::ArchCheckFailed { index: 0 }
        );
        // A future claims version naming the architecture is enforced too.
        let mut claims = real_claims();
        claims[0].arch = Some("BLACKWELL".to_string());
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &claims,
                &real_evidence()
            )
            .unwrap_err(),
            PolicyError::ArchMismatch {
                what: "claim",
                index: 0,
                found: "BLACKWELL".to_string(),
                want: "hopper".to_string()
            }
        );
    }

    #[test]
    fn no_claim_means_no_verified_gpu() {
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &[],
                &real_evidence()
            )
            .unwrap_err(),
            PolicyError::CountMismatch {
                what: "the claims array",
                expected: 1,
                found: 0
            }
        );
    }

    #[test]
    fn the_real_blob_carries_the_h200_nvl_board() {
        let identity = board_identity(&real_blob()).unwrap();
        assert_eq!(identity.project, "1010");
        assert_eq!(identity.project_sku, "0230");
        assert_eq!(identity.chip_sku, "894");
    }

    #[test]
    fn truncated_evidence_is_an_error_and_never_a_panic() {
        let blob = real_blob();
        let mut cut = vec![0, 1, 36, 37, 38, 44, 45, 100, blob.len() - 1];
        cut.extend((0..blob.len()).step_by(257));
        for end in cut {
            let error = board_identity(&blob[..end]).unwrap_err();
            assert!(
                matches!(
                    error,
                    EvidenceError::Truncated { .. }
                        | EvidenceError::NotMeasurements
                        | EvidenceError::OpaqueTrailing
                        | EvidenceError::MissingField { .. }
                ),
                "cut at {end} gave {error}"
            );
            // The same truncation through the whole decision, base64 and all.
            let cmdline = "gpu_arch=hopper gpu_count=1 gpu_models=10de:233b";
            assert!(matches!(
                evaluate(
                    cmdline,
                    &policy(),
                    &real_claims(),
                    &evidence_with_blob(&blob[..end])
                )
                .unwrap_err(),
                PolicyError::Evidence { index: 0, .. }
            ));
        }
    }

    #[test]
    fn an_opaque_length_past_the_end_is_an_error() {
        let mut blob = real_blob();
        let at = opaque_length_offset(&blob);
        blob[at] = 0xff;
        blob[at + 1] = 0xff;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::Truncated {
                field: "opaque data"
            }
        );
        // Zero length: the fields are gone, not readable as something else.
        blob[at] = 0;
        blob[at + 1] = 0;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::MissingField { field: "PROJECT" }
        );
        // An opaque field whose own length lies about the bytes left.
        let mut blob = real_blob();
        let at = opaque_length_offset(&blob);
        blob[at + 4] = 0xff;
        blob[at + 5] = 0xff;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::OpaqueTrailing
        );
    }

    #[test]
    fn a_response_that_is_not_a_measurements_response_is_refused() {
        let mut blob = real_blob();
        blob[SPDM_REQUEST_LEN] = 0x12;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::NotMeasurements
        );
        let mut blob = real_blob();
        blob[SPDM_REQUEST_LEN + 1] = 0x61;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::NotMeasurements
        );
    }

    #[test]
    fn evidence_that_is_not_base64_is_refused() {
        let mut evidence = real_evidence();
        evidence[0].evidence = "not base64!".to_string();
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1 gpu_models=10de:233b",
                &policy(),
                &real_claims(),
                &evidence
            )
            .unwrap_err(),
            PolicyError::Evidence {
                index: 0,
                source: EvidenceError::NotBase64
            }
        );
    }

    #[test]
    fn opaque_strings_are_trimmed_but_never_normalized() {
        assert_eq!(ascii_field(b"894\0\0\0", "CHIP_SKU").unwrap(), "894");
        assert_eq!(ascii_field(b"G520", "PROJECT").unwrap(), "G520");
        assert_eq!(
            ascii_field(b"", "PROJECT").unwrap_err(),
            EvidenceError::BadField { field: "PROJECT" }
        );
        assert_eq!(
            ascii_field(b"\0\0", "PROJECT").unwrap_err(),
            EvidenceError::BadField { field: "PROJECT" }
        );
        // An interior NUL, a space and a high byte are all refused.
        for raw in [b"10\0 0".as_slice(), b"10 0", b"10\xff0"] {
            assert_eq!(
                ascii_field(raw, "PROJECT").unwrap_err(),
                EvidenceError::BadField { field: "PROJECT" }
            );
        }
    }

    #[test]
    fn the_evidence_document_is_what_nvattest_prints() {
        let entries = real_evidence();
        let document = serde_json::json!({
            "result_code": 0,
            "result_message": "Ok",
            "evidences": entries,
        });
        let parsed = parse_evidence_document(document.to_string().as_bytes()).unwrap();
        assert_eq!(parsed, entries);
        // A failed collection prints a non-zero code and a null list.
        let failed = serde_json::json!({
            "result_code": 7, "result_message": "Bad", "evidences": serde_json::Value::Null,
        });
        assert!(parse_evidence_document(failed.to_string().as_bytes()).is_err());
        let null_list = serde_json::json!({
            "result_code": 0, "result_message": "Ok", "evidences": serde_json::Value::Null,
        });
        assert!(parse_evidence_document(null_list.to_string().as_bytes()).is_err());
        assert!(parse_evidence_document(b"not json").is_err());
        assert!(parse_evidence_document(b"[]").is_err());
    }

    #[test]
    fn the_policy_file_shape_deserializes() {
        let policy = policy();
        assert_eq!(policy.archs.len(), 2);
        let hopper = policy.archs.get("hopper").unwrap();
        assert_eq!(hopper.accepted_models, ["GH100 A01 GSP BROM"]);
        assert_eq!(hopper.boards.len(), 5);
        assert_eq!(
            hopper.boards.get("10de:233b").unwrap()[0],
            Board {
                project: "1010".to_string(),
                project_sku: "0230".to_string(),
                chip_sku: "894".to_string()
            }
        );
        // boards is optional per architecture.
        let bare: GpuPolicy =
            serde_json::from_str(r#"{"archs":{"hopper":{"accepted_models":["x"]}}}"#).unwrap();
        assert!(bare.archs.get("hopper").unwrap().boards.is_empty());
        // An id listed with no board answers for nothing.
        let mut policy = policy;
        policy
            .archs
            .get_mut("hopper")
            .unwrap()
            .boards
            .insert("10de:0000".to_string(), Vec::new());
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1 gpu_models=10de:0000",
                &policy,
                &real_claims(),
                &real_evidence()
            )
            .unwrap_err(),
            PolicyError::UnknownModel {
                id: "10de:0000".to_string()
            }
        );
    }
}
