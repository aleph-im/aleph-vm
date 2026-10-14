//! TDX boot-time subcommands: the descriptor check the measured init runs
//! before it trusts any per-deployment token, and a TDREPORT dump.
//!
//! On TDX nothing per-deployment travels on the kernel command line: the
//! daemon renders the same suffix it appends on SEV-SNP, hashes it into
//! MRCONFIGID at launch, and ships the text on a raw drive. The init finds
//! the drive by its magic line and asks this subcommand to prove the text is
//! the one the TD was launched with; only then are the tokens exported as
//! if `/proc/cmdline` had carried them.

use std::io::Read;
use std::path::{Path, PathBuf};

use aleph_tee::tdx::measure::mrconfigid;
use aleph_tee::tdx::report::{TdReport, local_tdreport};
use anyhow::{Context, Result, bail};

/// First line of the descriptor drive.
pub const DESCRIPTOR_MAGIC: &[u8] = b"ALEPH-TDX-DESCRIPTOR-v1\n";

/// The drive is this large; everything past the suffix line is zero.
pub const DESCRIPTOR_SIZE: usize = 64 * 1024;

#[derive(clap::Args, Debug)]
pub struct TdxDescriptorArgs {
    /// Block device holding the descriptor image.
    #[arg(long)]
    device: PathBuf,

    /// Also dump the TDREPORT registers as JSON on stderr.
    #[arg(long)]
    print_report: bool,
}

#[derive(clap::Args, Debug)]
pub struct TdxReportArgs {
    /// REPORTDATA to bind, 128 hex characters; zero when absent.
    #[arg(long)]
    reportdata: Option<String>,
}

/// The suffix a descriptor image carries: magic line, suffix line, zeros to
/// the end. Anything else is not a descriptor.
pub fn parse_descriptor(image: &[u8]) -> Result<&str> {
    let Some(rest) = image.strip_prefix(DESCRIPTOR_MAGIC) else {
        bail!("no descriptor magic");
    };
    let Some(end) = rest.iter().position(|&b| b == b'\n') else {
        bail!("descriptor suffix line is not terminated");
    };
    let suffix = &rest[..end];
    if !suffix.iter().all(|&b| (0x20..0x7f).contains(&b)) {
        bail!("descriptor suffix is not printable ASCII");
    }
    if rest[end + 1..].iter().any(|&b| b != 0) {
        bail!("descriptor carries data after the suffix line");
    }
    std::str::from_utf8(suffix).context("descriptor suffix is not UTF-8")
}

/// The suffix, once its hash is the MRCONFIGID the TD was launched with.
pub fn check_descriptor<'a>(image: &'a [u8], launched: &[u8; 48]) -> Result<&'a str> {
    let suffix = parse_descriptor(image)?;
    if mrconfigid(suffix) != *launched {
        bail!("descriptor does not match MRCONFIGID");
    }
    Ok(suffix)
}

fn read_descriptor(device: &Path) -> Result<Vec<u8>> {
    let file =
        std::fs::File::open(device).with_context(|| format!("cannot open {}", device.display()))?;
    let mut image = Vec::with_capacity(DESCRIPTOR_SIZE);
    file.take(DESCRIPTOR_SIZE as u64)
        .read_to_end(&mut image)
        .with_context(|| format!("cannot read {}", device.display()))?;
    Ok(image)
}

fn hex_json(report: &TdReport) -> serde_json::Value {
    serde_json::json!({
        "report_type": hex::encode(report.report_type),
        "reportdata": hex::encode(report.reportdata),
        "tee_tcb_svn": hex::encode(report.tee_tcb_svn),
        "mrseam": hex::encode(report.mrseam),
        "attributes": hex::encode(report.attributes),
        "xfam": hex::encode(report.xfam),
        "mrtd": hex::encode(report.mrtd),
        "mrconfigid": hex::encode(report.mrconfigid),
        "mrowner": hex::encode(report.mrowner),
        "mrownerconfig": hex::encode(report.mrownerconfig),
        "rtmr0": hex::encode(report.rtmr[0]),
        "rtmr1": hex::encode(report.rtmr[1]),
        "rtmr2": hex::encode(report.rtmr[2]),
        "rtmr3": hex::encode(report.rtmr[3]),
        "servtd_hash": hex::encode(report.servtd_hash),
    })
}

fn descriptor_suffix(args: &TdxDescriptorArgs) -> Result<String> {
    let image = read_descriptor(&args.device)?;
    let report = local_tdreport(&[0u8; 64]).context("cannot read the local TDREPORT")?;
    if args.print_report {
        eprintln!("{}", hex_json(&report));
    }
    let suffix = check_descriptor(&image, &report.mrconfigid)?;
    Ok(suffix.to_owned())
}

/// Print the verified suffix and exit 0, or one reason on stderr and exit 1.
/// Nothing from the drive reaches stdout unless it matched.
pub fn run_descriptor(args: &TdxDescriptorArgs) -> i32 {
    match descriptor_suffix(args) {
        Ok(suffix) => {
            println!("{suffix}");
            0
        }
        Err(e) => {
            eprintln!("tdx-descriptor: {e:#}");
            1
        }
    }
}

fn reportdata(arg: Option<&str>) -> Result<[u8; 64]> {
    let Some(hex_str) = arg else {
        return Ok([0u8; 64]);
    };
    let bytes = hex::decode(hex_str).context("--reportdata is not hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("--reportdata must be 64 bytes"))
}

/// Dump the local TDREPORT registers as hex JSON on stdout.
pub fn run_report(args: &TdxReportArgs) -> i32 {
    let report = reportdata(args.reportdata.as_deref()).and_then(|data| local_tdreport(&data));
    match report {
        Ok(report) => {
            println!("{}", hex_json(&report));
            0
        }
        Err(e) => {
            eprintln!("tdx-report: {e:#}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(suffix: &str) -> Vec<u8> {
        let mut image = DESCRIPTOR_MAGIC.to_vec();
        image.extend_from_slice(suffix.as_bytes());
        image.push(b'\n');
        image.resize(DESCRIPTOR_SIZE, 0);
        image
    }

    const SUFFIX: &str = "workload_roothash=0123abcd swiotlb=65536 gpu_arch=hopper gpu_count=1";

    #[test]
    fn a_good_descriptor_yields_its_suffix() {
        assert_eq!(parse_descriptor(&image(SUFFIX)).unwrap(), SUFFIX);
        // The minimal VM has no tokens at all.
        assert_eq!(parse_descriptor(&image("")).unwrap(), "");
        // A short read (smaller device) still parses.
        let mut short = image(SUFFIX);
        short.truncate(200);
        assert_eq!(parse_descriptor(&short).unwrap(), SUFFIX);
    }

    #[test]
    fn a_wrong_magic_is_refused() {
        let mut bad = image(SUFFIX);
        bad[0] = b'B';
        let err = parse_descriptor(&bad).unwrap_err().to_string();
        assert!(err.contains("magic"), "got: {err}");
        assert!(parse_descriptor(b"").is_err());
        assert!(parse_descriptor(b"ALEPH-TDX-DESCRIPTOR-v2\nx\n").is_err());
        // Case matters; so does the newline.
        assert!(parse_descriptor(b"ALEPH-TDX-DESCRIPTOR-v1 x\n").is_err());
    }

    #[test]
    fn a_missing_terminator_is_refused() {
        let mut open = DESCRIPTOR_MAGIC.to_vec();
        open.extend_from_slice(SUFFIX.as_bytes());
        let err = parse_descriptor(&open).unwrap_err().to_string();
        assert!(err.contains("not terminated"), "got: {err}");
        // Zero padding without a newline is the same thing.
        open.resize(DESCRIPTOR_SIZE, 0);
        assert!(parse_descriptor(&open).is_err());
    }

    #[test]
    fn trailing_garbage_is_refused() {
        let mut dirty = image(SUFFIX);
        let last = dirty.len() - 1;
        dirty[last] = 1;
        let err = parse_descriptor(&dirty).unwrap_err().to_string();
        assert!(err.contains("after the suffix line"), "got: {err}");
        // A second line, too: exactly one suffix line is the format.
        let mut two = DESCRIPTOR_MAGIC.to_vec();
        two.extend_from_slice(b"a=1\nb=2\n");
        two.resize(DESCRIPTOR_SIZE, 0);
        assert!(parse_descriptor(&two).is_err());
    }

    #[test]
    fn a_non_ascii_suffix_is_refused() {
        let mut odd = DESCRIPTOR_MAGIC.to_vec();
        odd.extend_from_slice(b"a=1\x01\n");
        odd.resize(DESCRIPTOR_SIZE, 0);
        assert!(parse_descriptor(&odd).is_err());
        let mut utf8 = DESCRIPTOR_MAGIC.to_vec();
        utf8.extend_from_slice("a=é\n".as_bytes());
        utf8.resize(DESCRIPTOR_SIZE, 0);
        assert!(parse_descriptor(&utf8).is_err());
    }

    #[test]
    fn the_suffix_must_hash_to_the_launched_mrconfigid() {
        let launched = mrconfigid(SUFFIX);
        assert_eq!(check_descriptor(&image(SUFFIX), &launched).unwrap(), SUFFIX);
        let err = check_descriptor(&image("workload_roothash=ffff"), &launched)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match MRCONFIGID"), "got: {err}");
        // One byte off in the register is a mismatch, and so is a zero
        // register (the QEMU default when no mrconfigid was given).
        let mut off = launched;
        off[47] ^= 1;
        assert!(check_descriptor(&image(SUFFIX), &off).is_err());
        assert!(check_descriptor(&image(SUFFIX), &[0u8; 48]).is_err());
        // A malformed image never reaches the comparison.
        assert!(check_descriptor(b"junk", &launched).is_err());
    }

    #[test]
    fn the_descriptor_is_read_from_the_device_head() {
        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("vdb");
        let mut big = image(SUFFIX);
        big.extend_from_slice(&[0xFF; 4096]);
        std::fs::write(&device, &big).unwrap();
        let read = read_descriptor(&device).unwrap();
        assert_eq!(read.len(), DESCRIPTOR_SIZE);
        assert_eq!(parse_descriptor(&read).unwrap(), SUFFIX);
        assert!(read_descriptor(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn reportdata_is_zero_or_exactly_64_bytes() {
        assert_eq!(reportdata(None).unwrap(), [0u8; 64]);
        assert_eq!(reportdata(Some(&"ab".repeat(64))).unwrap(), [0xAB; 64]);
        assert!(reportdata(Some(&"ab".repeat(63))).is_err());
        assert!(reportdata(Some("zz")).is_err());
    }

    #[test]
    fn the_report_dump_is_hex_per_register() {
        let mut raw = [0u8; 1024];
        raw[576..624].copy_from_slice(&[0xC1; 48]);
        let json = hex_json(&aleph_tee::tdx::report::parse_tdreport(&raw));
        assert_eq!(json["mrconfigid"], "c1".repeat(48));
        assert_eq!(json["mrtd"], "00".repeat(48));
        assert_eq!(json["rtmr3"], "00".repeat(48));
    }
}
