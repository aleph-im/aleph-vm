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
//!   accepted models, and that boolean must be present and true on every claim.
//! - `--evidence`: either a bare array of `{"arch","nonce","evidence",
//!   "certificate"}` entries, or the whole document `nvattest --format json
//!   collect-evidence` prints around one,
//!   `{"result_code":0,"result_message":"...","evidences":[...]}` (`evidences`
//!   null when the collection failed). The bare array is the production form:
//!   it is the only one `nvattest attest --gpu-evidence-source file` reads, so
//!   init hands the same array file to nvattest and to this check. `evidence`
//!   is base64 of the SPDM exchange, request then response.
//! - `--nonce`: this boot's nonce, the one init collected the evidence with
//!   and had nvattest verify it against.
//!
//! Board identity comes only from the SPDM opaque data of that response, never
//! from PCI config space, sysfs, nvidia-smi or the claims. This code verifies
//! no signature and cannot: what ties the bytes to the card is that nvattest
//! verified this very evidence file, and that every blob in it carries this
//! boot's nonce in its SPDM request, so neither file can be a replay from an
//! earlier boot, another machine or a card that was never asked.
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

    /// This boot's nonce, 64 lowercase hex characters: the one init had
    /// nvattest verify the evidence with.
    #[arg(long)]
    nonce: String,

    /// How many NVIDIA display functions init counted on the PCI bus before
    /// loading the driver, in decimal.
    #[arg(long)]
    observed_count: String,
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
    /// nvattest's own statement that the architecture matched the verified
    /// certificate chain. Untyped on purpose: anything but the boolean `true`
    /// is a failed rule rather than a parse error.
    #[serde(default, rename = "x-nvidia-gpu-arch-check")]
    pub arch_check: Option<serde_json::Value>,
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
    /// Byte-exact: NVIDIA builds its RIM ids from these opaque strings as they
    /// come off the card, and the published listing spells them upper case,
    /// which is what the measured table carries.
    fn is(&self, board: &Board) -> bool {
        self.project == board.project
            && self.project_sku == board.project_sku
            && self.chip_sku == board.chip_sku
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
    /// Outside the closed set of architectures this build enforces.
    UnsupportedArch {
        arch: String,
    },
    /// A supported architecture the measured policy file does not describe.
    UnknownArch {
        arch: String,
    },
    /// Refused rather than interpreted: nothing on our side ever renders a
    /// double quote, and the kernel's tokenisation of one is not ours.
    QuoteInCmdline,
    /// Requested id no board in the policy answers for.
    UnknownModel {
        id: String,
    },
    CountMismatch {
        what: &'static str,
        expected: usize,
        found: usize,
    },
    /// init saw a different number of NVIDIA functions than the requirement
    /// demands, so it made a device node for silicon nothing verified.
    ObservedCountMismatch {
        observed: usize,
        required: usize,
    },
    ArchMismatch {
        what: &'static str,
        index: usize,
        found: String,
        want: String,
    },
    /// nvattest itself says the architecture did not match.
    ArchCheckFailed {
        index: usize,
    },
    /// No `x-nvidia-gpu-arch-check` boolean at all: without nvattest's own
    /// verdict the evidence entry's architecture string stands for nothing.
    ArchCheckMissing {
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
            Self::UnsupportedArch { arch } => {
                write!(f, "gpu_arch={arch} is not a supported architecture")
            }
            Self::UnknownArch { arch } => {
                write!(f, "gpu_arch={arch} is not an architecture of the policy")
            }
            Self::QuoteInCmdline => {
                write!(f, "the kernel command line carries a double quote")
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
            Self::ObservedCountMismatch { observed, required } => write!(
                f,
                "gpu_count demands {required} GPU(s), init saw {observed} NVIDIA function(s) on the bus"
            ),
            Self::ArchMismatch {
                what,
                index,
                found,
                want,
            } => write!(
                f,
                "{what} {index} reports architecture {found}, gpu_arch demands {want}"
            ),
            Self::ArchCheckFailed { index } => {
                write!(f, "claim {index} reports the GPU architecture as unmatched")
            }
            Self::ArchCheckMissing { index } => write!(
                f,
                "claim {index} carries no x-nvidia-gpu-arch-check boolean"
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
    /// Bytes after the signature: not one exchange and nothing else.
    TrailingData,
    /// The entry's `nonce` field is not 32 bytes of hex.
    BadNonce,
    /// The request nonce, the entry's `nonce` field and this boot's nonce do
    /// not all agree, so these bytes are not this boot's exchange.
    NonceMismatch,
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
            Self::TrailingData => write!(f, "the SPDM exchange carries bytes after its signature"),
            Self::BadNonce => write!(f, "the evidence nonce is not 32 bytes of hex"),
            Self::NonceMismatch => write!(
                f,
                "the SPDM request nonce, the evidence nonce and this boot's nonce disagree"
            ),
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

/// The fields of one exchange this code reads: the nonce the request asked
/// with, and the opaque data the response answered with.
#[derive(Debug)]
pub struct Exchange<'a> {
    pub request_nonce: &'a [u8],
    pub opaque: &'a [u8],
}

/// Walk one whole exchange, so every later read is inside bytes already
/// bounds-checked and nothing may follow the signature.
pub fn parse_exchange(blob: &[u8]) -> Result<Exchange<'_>, EvidenceError> {
    let mut reader = Reader::new(blob);
    // Request: version, code, param1, param2, nonce, slot mask.
    reader.take(4, "request header")?;
    let request_nonce = reader.take(SPDM_NONCE_LEN, "request nonce")?;
    reader.take(SPDM_REQUEST_LEN - 4 - SPDM_NONCE_LEN, "request tail")?;
    let header = reader.take(SPDM_RESPONSE_HEADER_LEN, "response header")?;
    // take() returned exactly SPDM_RESPONSE_HEADER_LEN bytes.
    if header[0] != SPDM_VERSION_1_1 || header[1] != SPDM_MEASUREMENTS {
        return Err(EvidenceError::NotMeasurements);
    }
    let record_len = u32::from_le_bytes([header[5], header[6], header[7], 0]) as usize;
    reader.take(record_len, "measurement record")?;
    reader.take(SPDM_NONCE_LEN, "response nonce")?;
    let opaque_len = reader.take(2, "opaque length")?;
    let opaque_len = usize::from(u16::from_le_bytes([opaque_len[0], opaque_len[1]]));
    let opaque = reader.take(opaque_len, "opaque data")?;
    // The signature must be there too: a report that stops before it was never
    // a whole signed report.
    reader.take(SPDM_SIGNATURE_LEN, "signature")?;
    if !reader.done() {
        return Err(EvidenceError::TrailingData);
    }
    Ok(Exchange {
        request_nonce,
        opaque,
    })
}

/// The opaque-data TLV walk on its own.
pub fn board_fields(opaque: &[u8]) -> Result<BoardIdentity, EvidenceError> {
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

/// The `nonce` field nvattest writes next to each blob: 32 bytes of hex, in
/// whichever case NVIDIA's formatter chose.
fn hex_nonce(text: &str) -> Result<[u8; 32], EvidenceError> {
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(text, &mut nonce).map_err(|_| EvidenceError::BadNonce)?;
    Ok(nonce)
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

/// The architectures this build enforces. A policy file that grew another key
/// does not widen what the command line may demand.
const ARCHS: [&str; 2] = ["hopper", "blackwell"];

/// Read the requirement out of the command line.
pub fn requirement(cmdline: &str) -> Result<Requirement, PolicyError> {
    if cmdline.contains('"') {
        return Err(PolicyError::QuoteInCmdline);
    }
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
    if !ARCHS.contains(&arch) {
        return Err(PolicyError::UnsupportedArch {
            arch: arch.to_string(),
        });
    }
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
/// `boot_nonce` is the nonce init had nvattest verify this boot's evidence
/// with.
pub fn evaluate(
    cmdline: &str,
    policy: &GpuPolicy,
    claims: &[Claim],
    evidence: &[EvidenceEntry],
    boot_nonce: &[u8; 32],
    observed_count: usize,
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
    // init makes one device node per NVIDIA function it saw, so a bus that
    // carries more cards than the verified set would hand the workload a node
    // for silicon nobody attested.
    if observed_count != want.count {
        return Err(PolicyError::ObservedCountMismatch {
            observed: observed_count,
            required: want.count,
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
        // What makes the evidence entry's architecture string worth anything:
        // that string is unsigned collector metadata, this boolean is
        // nvattest's verdict against the verified certificate chain. It must
        // be there and it must be true.
        match claim.arch_check.as_ref().map(serde_json::Value::as_bool) {
            Some(Some(true)) => {}
            Some(Some(false)) => return Err(PolicyError::ArchCheckFailed { index }),
            _ => return Err(PolicyError::ArchCheckMissing { index }),
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

    // The boards a model token asks for, before any evidence is read, so an
    // id the policy answers for nothing is fatal on its own.
    let mut allowed: Vec<&Board> = Vec::new();
    if let Some(ids) = &want.models {
        for id in ids {
            let listed = arch
                .boards
                .get(id)
                .filter(|boards| !boards.is_empty())
                .ok_or_else(|| PolicyError::UnknownModel { id: id.clone() })?;
            allowed.extend(listed);
        }
    }

    // Every entry is decoded and walked whole, whether or not a model token
    // asked for a board: that is what proves these bytes are this boot's
    // exchange. Board identity is read only when a model token asked for it,
    // so a requirement that names no model does not depend on the opaque data.
    let mut boards = Vec::new();
    for (index, entry) in evidence.iter().enumerate() {
        let fail = |source| PolicyError::Evidence { index, source };
        let blob = base64::engine::general_purpose::STANDARD
            .decode(&entry.evidence)
            .map_err(|_| fail(EvidenceError::NotBase64))?;
        let exchange = parse_exchange(&blob).map_err(fail)?;
        // The nonce ties the file to this boot: the request the card answered,
        // the nonce the collector reported, and the nonce nvattest verified
        // with must be one and the same.
        let reported = hex_nonce(&entry.nonce).map_err(fail)?;
        if exchange.request_nonce != reported.as_slice() || reported != *boot_nonce {
            return Err(fail(EvidenceError::NonceMismatch));
        }
        if want.models.is_some() {
            let found = board_fields(exchange.opaque).map_err(fail)?;
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

/// Both forms of the evidence file. The bare array is the production one: it
/// is the only form `nvattest attest --gpu-evidence-source file` reads, so
/// init cuts the `evidences` array out of the collection and hands the same
/// array file to nvattest and to this check. The wrapper object is what
/// `collect-evidence` prints, and a successful collection is the only one
/// accepted.
fn parse_evidence_file(raw: &[u8]) -> Result<Vec<EvidenceEntry>> {
    let json: serde_json::Value = serde_json::from_slice(raw).context("not JSON")?;
    match json {
        serde_json::Value::Array(_) => {
            serde_json::from_value(json).context("not an array of evidence entries")
        }
        serde_json::Value::Object(_) => {
            let document: CollectEvidenceDocument =
                serde_json::from_value(json).context("not a collect-evidence document")?;
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
        _ => bail!("expected an evidence array or a collect-evidence document"),
    }
}

/// Either a rule did not hold, or an input was not the document it must be.
enum Failure {
    Policy(PolicyError),
    Usage(anyhow::Error),
}

/// A command line, a policy file and a claims array are kilobytes. Anything
/// past this is not the document we were called with.
const MAX_SMALL_INPUT: u64 = 1024 * 1024;

/// Read a whole file, refusing one larger than `cap`. The cap is enforced on
/// the bytes read, not on the metadata: `/proc/cmdline` reports size 0.
fn read_capped(path: &std::path::Path, cap: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut raw = Vec::new();
    file.take(cap + 1)
        .read_to_end(&mut raw)
        .with_context(|| format!("cannot read {}", path.display()))?;
    if raw.len() as u64 > cap {
        bail!("{} is larger than {cap} bytes", path.display());
    }
    Ok(raw)
}

/// Exactly 64 lowercase hex characters, the spelling init generates.
fn parse_boot_nonce(text: &str) -> Result<[u8; 32]> {
    let lowercase_hex = |byte: u8| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
    if text.len() != 64 || !text.bytes().all(lowercase_hex) {
        bail!("--nonce must be 64 lowercase hex characters");
    }
    let mut nonce = [0u8; 32];
    hex::decode_to_slice(text, &mut nonce).context("--nonce is not hex")?;
    Ok(nonce)
}

/// Plain decimal, no sign and no leading zero. Nothing else is a count init
/// wrote.
fn parse_observed_count(text: &str) -> Result<usize> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.starts_with('0') && text.len() > 1)
    {
        bail!("--observed-count must be a decimal number, got: {text}");
    }
    text.parse().context("--observed-count does not fit")
}

fn decide(args: &GpuPolicyArgs) -> Result<Summary, Failure> {
    type Inputs = (
        String,
        GpuPolicy,
        Vec<Claim>,
        Vec<EvidenceEntry>,
        [u8; 32],
        usize,
    );
    let inputs = || -> Result<Inputs> {
        // Lossy: a command line that is not UTF-8 cannot spell a token we
        // accept, so it fails on the rules rather than on the encoding.
        let cmdline =
            String::from_utf8_lossy(&read_capped(&args.cmdline, MAX_SMALL_INPUT)?).into_owned();
        let policy: GpuPolicy =
            serde_json::from_slice(&read_capped(&args.gpu_json, MAX_SMALL_INPUT)?)
                .with_context(|| format!("{} is not a GPU policy", args.gpu_json.display()))?;
        let claims: Vec<Claim> =
            serde_json::from_slice(&read_capped(&args.claims, MAX_SMALL_INPUT)?)
                .with_context(|| format!("{} is not a claims array", args.claims.display()))?;
        // Same bound the GPU route puts on collector output: eight GPUs with
        // full certificate chains stay far under it.
        let evidence =
            parse_evidence_file(&read_capped(&args.evidence, crate::gpu::MAX_OUTPUT_BYTES)?)
                .with_context(|| args.evidence.display().to_string())?;
        let nonce = parse_boot_nonce(&args.nonce)?;
        let observed = parse_observed_count(&args.observed_count)?;
        Ok((cmdline, policy, claims, evidence, nonce, observed))
    };
    let (cmdline, policy, claims, evidence, nonce, observed) = inputs().map_err(Failure::Usage)?;
    evaluate(&cmdline, &policy, &claims, &evidence, &nonce, observed).map_err(Failure::Policy)
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

    /// What init counts on the bus for the one card in the vectors.
    const ONE_GPU: usize = 1;

    /// Both stages on one blob, the way `evaluate` runs them.
    fn board_identity(blob: &[u8]) -> Result<BoardIdentity, EvidenceError> {
        board_fields(parse_exchange(blob)?.opaque)
    }

    /// The nonce response 0's exchange was made with, which the evidence entry
    /// reports and its SPDM request carries.
    fn real_nonce() -> [u8; 32] {
        hex_nonce(&real_evidence()[0].nonce).unwrap()
    }

    /// Response 1 is the same card answering a different nonce.
    fn other_nonce() -> [u8; 32] {
        let entries: Vec<EvidenceEntry> =
            serde_json::from_value(vectors()["responses"][1]["gpus"].clone()).unwrap();
        hex_nonce(&entries[0].nonce).unwrap()
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

    /// Rewrite the PROJECT opaque field in place, same length, so a test can
    /// exercise a board string that carries letters. The TLV walk reads the
    /// bytes and never checks the signature, so patching is enough.
    fn blob_with_project(project: &[u8; 4]) -> Vec<u8> {
        let mut blob = real_blob();
        let pattern = b"\x11\x00\x05\x001010\x00";
        let at = blob
            .windows(pattern.len())
            .position(|window| window == pattern)
            .expect("the PROJECT field is in the real blob");
        blob[at + 4..at + 8].copy_from_slice(project);
        blob
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
        evaluate(
            cmdline,
            &policy(),
            &real_claims(),
            &real_evidence(),
            &real_nonce(),
            ONE_GPU,
        )
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
        // Not an architecture this build enforces at all.
        assert_eq!(
            check("gpu_arch=ampere gpu_count=1").unwrap_err(),
            PolicyError::UnsupportedArch {
                arch: "ampere".to_string()
            }
        );
        // The evidence spells it upper case, the token lower case.
        assert!(check("gpu_arch=hopper gpu_count=1").is_ok());
    }

    /// The closed set is the code's, not the file's: a policy that grew a key
    /// must not widen what the command line may demand, and the token spelling
    /// stays lowercase whatever the file says.
    #[test]
    fn the_policy_file_cannot_widen_the_architecture_set() {
        let mut policy = policy();
        let hopper = policy.archs.get("hopper").unwrap().clone();
        policy.archs.insert("ampere".to_string(), hopper.clone());
        policy.archs.insert("Hopper".to_string(), hopper);
        for arch in ["ampere", "Hopper", "HOPPER", "hopper,blackwell", ""] {
            let cmdline = format!("gpu_arch={arch} gpu_count=1");
            match evaluate(
                &cmdline,
                &policy,
                &real_claims(),
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err()
            {
                PolicyError::UnsupportedArch { .. } => {}
                other => panic!("{arch:?} gave {other}"),
            }
        }
        // A supported architecture the file does not describe is the other
        // error: the requirement is sayable, the policy cannot answer it.
        policy.archs.remove("blackwell");
        assert_eq!(
            evaluate(
                "gpu_arch=blackwell gpu_count=1",
                &policy,
                &real_claims(),
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            PolicyError::UnknownArch {
                arch: "blackwell".to_string()
            }
        );
    }

    /// A double quote is refused outright: the kernel's tokenisation of one is
    /// not this whitespace split, so a command line carrying one is not a
    /// command line we can read.
    #[test]
    fn a_quoted_command_line_is_refused() {
        for cmdline in [
            "gpu_arch=hopper gpu_count=1 init=\"/bin/sh -c x\"",
            "gpu_arch=\"hopper\" gpu_count=1",
            "\"",
        ] {
            assert_eq!(
                check(cmdline).unwrap_err(),
                PolicyError::QuoteInCmdline,
                "{cmdline:?}"
            );
        }
        // A single quote is an ordinary character and changes nothing.
        assert!(check("gpu_arch=hopper gpu_count=1 other='x'").is_ok());
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

    /// The board comparison is byte-exact: the measured table spells these
    /// strings the way the card does, and a table that spells one differently
    /// names a different board.
    #[test]
    fn a_board_string_must_match_byte_for_byte() {
        let cmdline = "gpu_arch=hopper gpu_count=1 gpu_models=10de:233b";
        let evidence = evidence_with_blob(&blob_with_project(b"G520"));
        let with_project = |project: &str| {
            let mut policy = policy();
            policy.archs.get_mut("hopper").unwrap().boards.insert(
                "10de:233b".to_string(),
                vec![Board {
                    project: project.to_string(),
                    project_sku: "0230".to_string(),
                    chip_sku: "894".to_string(),
                }],
            );
            evaluate(
                cmdline,
                &policy,
                &real_claims(),
                &evidence,
                &real_nonce(),
                ONE_GPU,
            )
        };
        assert_eq!(
            with_project("G520").unwrap().boards[0].to_string(),
            "G520/0230/894"
        );
        assert_eq!(
            with_project("g520").unwrap_err(),
            PolicyError::BoardMismatch {
                index: 0,
                found: BoardIdentity {
                    project: "G520".to_string(),
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
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            PolicyError::UnacceptedModel {
                index: 0,
                hwmodel: "GH100 A01 GSP BROM".to_string()
            }
        );
    }

    /// The real claims carry `x-nvidia-gpu-arch-check: true`, and only that
    /// exact boolean passes: it is nvattest's verdict against the verified
    /// certificate chain, and the evidence entry's architecture string is
    /// unsigned collector metadata without it.
    #[test]
    fn the_architecture_check_must_be_present_and_true() {
        let verdict = |value: Option<serde_json::Value>| {
            let mut claims = real_claims();
            claims[0].arch_check = value;
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &claims,
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
        };
        assert!(verdict(Some(serde_json::Value::Bool(true))).is_ok());
        assert_eq!(
            verdict(Some(serde_json::Value::Bool(false))).unwrap_err(),
            PolicyError::ArchCheckFailed { index: 0 }
        );
        // Absent, or anything that is not a boolean, is the same refusal: no
        // verdict was made.
        for value in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!("true")),
            Some(serde_json::json!(1)),
            Some(serde_json::json!({"x-nvidia-gpu-arch-check": true})),
        ] {
            assert_eq!(
                verdict(value.clone()).unwrap_err(),
                PolicyError::ArchCheckMissing { index: 0 },
                "{value:?}"
            );
        }
        // The claims document init extracts really does carry it.
        assert_eq!(
            real_claims()[0].arch_check,
            Some(serde_json::Value::Bool(true))
        );
    }

    #[test]
    fn a_claim_that_names_a_foreign_architecture_is_fatal() {
        // A future claims version naming the architecture is enforced too.
        let mut claims = real_claims();
        claims[0].arch = Some("BLACKWELL".to_string());
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &claims,
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
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
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
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
                    &evidence_with_blob(&blob[..end]),
                    &real_nonce(),
                    ONE_GPU,
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
        // Zero length: the bytes that were the opaque data now sit after the
        // signature, which is refused before any field is looked for.
        blob[at] = 0;
        blob[at + 1] = 0;
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::TrailingData
        );
        // Opaque data with no fields in it names no board.
        assert_eq!(
            board_fields(&[]).unwrap_err(),
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

    /// The nonce is what makes the file this boot's: the SPDM request the card
    /// answered, the nonce the collector reported and the nonce nvattest
    /// verified with must be one and the same, on every entry, whether or not
    /// a model token asked for a board.
    #[test]
    fn every_blob_must_carry_this_boots_nonce() {
        // The request region really is where the nonce sits.
        assert_eq!(
            parse_exchange(&real_blob()).unwrap().request_nonce,
            real_nonce()
        );
        let bound = |cmdline: &str| {
            evaluate(
                cmdline,
                &policy(),
                &real_claims(),
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
        };
        assert!(bound("gpu_arch=hopper gpu_count=1").is_ok());
        assert!(bound("gpu_arch=hopper gpu_count=1 gpu_models=10de:233b").is_ok());

        let mismatch = PolicyError::Evidence {
            index: 0,
            source: EvidenceError::NonceMismatch,
        };
        // Response 1 is the same card answering a different nonce, so response
        // 0's blob is a replay against that boot nonce.
        for cmdline in [
            "gpu_arch=hopper gpu_count=1",
            "gpu_arch=hopper gpu_count=1 gpu_models=10de:233b",
        ] {
            assert_eq!(
                evaluate(
                    cmdline,
                    &policy(),
                    &real_claims(),
                    &real_evidence(),
                    &other_nonce(),
                    ONE_GPU,
                )
                .unwrap_err(),
                mismatch,
                "{cmdline}"
            );
        }
        // The reported nonce is metadata: editing it to anything but what the
        // request carries is fatal, and so is editing it to nothing usable.
        let mut evidence = real_evidence();
        evidence[0].nonce = hex::encode(other_nonce());
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &real_claims(),
                &evidence,
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            mismatch
        );
        for bad in ["", "ab", &"00".repeat(33), &"zz".repeat(32)] {
            let mut evidence = real_evidence();
            evidence[0].nonce = bad.to_string();
            assert_eq!(
                evaluate(
                    "gpu_arch=hopper gpu_count=1",
                    &policy(),
                    &real_claims(),
                    &evidence,
                    &real_nonce(),
                    ONE_GPU,
                )
                .unwrap_err(),
                PolicyError::Evidence {
                    index: 0,
                    source: EvidenceError::BadNonce
                },
                "{bad}"
            );
        }
    }

    /// Only the spelling init generates is accepted for the boot nonce, and a
    /// malformed one is a usage error, never a verdict.
    #[test]
    fn the_boot_nonce_must_be_64_lowercase_hex() {
        assert_eq!(parse_boot_nonce(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        for bad in [
            "".to_string(),
            "ab".repeat(31),
            "ab".repeat(33),
            "AB".repeat(32),
            format!("{}Ab", "ab".repeat(31)),
            "zz".repeat(32),
            format!(" {}", "ab".repeat(32)),
        ] {
            assert!(parse_boot_nonce(&bad).is_err(), "{bad}");
        }
    }

    /// NVIDIA's own parser refuses trailing data, and so does this one: a blob
    /// is one exchange and nothing else.
    #[test]
    fn bytes_after_the_signature_are_refused() {
        let mut blob = real_blob();
        blob.push(0);
        assert_eq!(
            parse_exchange(&blob).unwrap_err(),
            EvidenceError::TrailingData
        );
        assert_eq!(
            board_identity(&blob).unwrap_err(),
            EvidenceError::TrailingData
        );
        // Even without a model token, where no board is read.
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &real_claims(),
                &evidence_with_blob(&blob),
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            PolicyError::Evidence {
                index: 0,
                source: EvidenceError::TrailingData
            }
        );
    }

    /// Input files are read through a cap, and the cap counts bytes read: a
    /// file like /proc/cmdline reports size 0 in its metadata.
    #[test]
    fn oversized_inputs_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "x".repeat(64)).unwrap();
        assert_eq!(read_capped(&path, 64).unwrap().len(), 64);
        assert!(read_capped(&path, 63).is_err());
        assert!(read_capped(&dir.path().join("absent"), 64).is_err());
        // The evidence document gets the same bound as collector output.
        assert_eq!(crate::gpu::MAX_OUTPUT_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_SMALL_INPUT, 1024 * 1024);
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
                &evidence,
                &real_nonce(),
                ONE_GPU,
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

    /// Both forms of the evidence file, on the real blobs: the bare array init
    /// hands nvattest and this check, and the document collect-evidence
    /// prints.
    #[test]
    fn the_evidence_file_is_an_array_or_the_printed_document() {
        let entries = real_evidence();
        let array = serde_json::to_string(&entries).unwrap();
        assert_eq!(parse_evidence_file(array.as_bytes()).unwrap(), entries);
        let document = serde_json::json!({
            "result_code": 0,
            "result_message": "Ok",
            "evidences": entries,
        });
        assert_eq!(
            parse_evidence_file(document.to_string().as_bytes()).unwrap(),
            entries
        );
        // A failed collection prints a non-zero code and a null list.
        let failed = serde_json::json!({
            "result_code": 7, "result_message": "Bad", "evidences": serde_json::Value::Null,
        });
        assert!(parse_evidence_file(failed.to_string().as_bytes()).is_err());
        let null_list = serde_json::json!({
            "result_code": 0, "result_message": "Ok", "evidences": serde_json::Value::Null,
        });
        assert!(parse_evidence_file(null_list.to_string().as_bytes()).is_err());
        assert!(parse_evidence_file(b"not json").is_err());
        assert!(parse_evidence_file(b"3").is_err());
        assert!(parse_evidence_file(br#"[{"arch":"HOPPER"}]"#).is_err());
        // An empty array parses; the count rule is what refuses it, so the
        // failure is a verdict and not a malformed input.
        assert!(parse_evidence_file(b"[]").unwrap().is_empty());
        assert_eq!(
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &real_claims(),
                &[],
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            PolicyError::CountMismatch {
                what: "the evidence",
                expected: 1,
                found: 0
            }
        );
    }

    /// init makes one device node per NVIDIA function it saw before the driver
    /// was loaded, so that count must be the verified count exactly.
    #[test]
    fn the_observed_function_count_must_be_the_required_count() {
        let observed = |count: usize| {
            evaluate(
                "gpu_arch=hopper gpu_count=1",
                &policy(),
                &real_claims(),
                &real_evidence(),
                &real_nonce(),
                count,
            )
        };
        assert!(observed(1).is_ok());
        for count in [0, 2, 8] {
            assert_eq!(
                observed(count).unwrap_err(),
                PolicyError::ObservedCountMismatch {
                    observed: count,
                    required: 1
                },
                "{count}"
            );
        }
        // Only a plain decimal is a count init wrote.
        assert_eq!(parse_observed_count("0").unwrap(), 0);
        assert_eq!(parse_observed_count("1").unwrap(), 1);
        assert_eq!(parse_observed_count("16").unwrap(), 16);
        for bad in ["", "01", "+1", "-1", " 1", "1 ", "0x2", "two", "١"] {
            assert!(parse_observed_count(bad).is_err(), "{bad:?}");
        }
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
                &real_evidence(),
                &real_nonce(),
                ONE_GPU,
            )
            .unwrap_err(),
            PolicyError::UnknownModel {
                id: "10de:0000".to_string()
            }
        );
    }
}
