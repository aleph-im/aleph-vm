//! The in-guest TDX backend: quotes over configfs-tsm.
//!
//! One quote is one report entry under `<configfs>/tsm/report/`: mkdir,
//! write the 64-byte `inblob`, read `outblob`. The read blocks while the
//! kernel hands the TDREPORT to QEMU and QEMU asks the host's Quote
//! Generation Service, so it runs on its own thread under a deadline. The
//! `provider` attribute names the driver that will answer; only `tdx_guest`
//! is accepted, since the same ABI serves SEV-SNP guests and an SNP report
//! parsed as a TDX quote is garbage with plausible-looking digests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::traits::TeeBackend;
use crate::types::{AttestationReport, TeeType};

use super::quote::parse_tdx_quote;

/// Where the kernel expects configfs.
pub const DEFAULT_CONFIGFS: &str = "/sys/kernel/config";

/// How long a quote may take end to end. The tdx_guest driver gives QGS 30 s
/// per request; this is the outer bound the agent waits on the read.
pub const QUOTE_TIMEOUT: Duration = Duration::from_secs(90);

/// The configfs-tsm provider that fills the outblob with a TDX quote.
const TDX_PROVIDER: &str = "tdx_guest";

/// TDX attestation backend implementing the `TeeBackend` trait.
pub struct TdxBackend {
    configfs: PathBuf,
    timeout: Duration,
}

impl Default for TdxBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TdxBackend {
    /// A backend over [`DEFAULT_CONFIGFS`].
    pub fn new() -> Self {
        Self::with_configfs(DEFAULT_CONFIGFS)
    }

    /// A backend over a configfs mounted (or to be mounted) at `configfs`.
    pub fn with_configfs(configfs: impl Into<PathBuf>) -> Self {
        Self {
            configfs: configfs.into(),
            timeout: QUOTE_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn quote(&self, report_data: &[u8; 64]) -> Result<Vec<u8>> {
        let reports = ensure_tsm(&self.configfs)?;
        let entry = ReportEntry::create(&reports)?;
        quote_from_entry(&entry.path, report_data, self.timeout)
    }
}

impl TeeBackend for TdxBackend {
    fn tee_type(&self) -> TeeType {
        TeeType::Tdx
    }

    fn get_report(&self, report_data: &[u8; 64]) -> Result<AttestationReport> {
        let raw = self.quote(report_data)?;
        self.parse_report(&raw)
    }

    fn parse_report(&self, raw: &[u8]) -> Result<AttestationReport> {
        // Structure only; the verifier re-parses `data` for every value it
        // trusts.
        parse_tdx_quote(raw).context("outblob is not a TDX quote")?;
        Ok(AttestationReport {
            tee_type: TeeType::Tdx,
            data: raw.to_vec(),
        })
    }
}

/// The `tsm/report` directory under `configfs`, mounting configfs there when
/// nothing is mounted yet. A mount that is already there is left alone.
fn ensure_tsm(configfs: &Path) -> Result<PathBuf> {
    let reports = configfs.join("tsm").join("report");
    if !configfs.join("tsm").exists() {
        mount_configfs(configfs)
            .with_context(|| format!("cannot mount configfs on {}", configfs.display()))?;
    }
    if !reports.is_dir() {
        bail!(
            "{} is missing: the kernel has no configfs-tsm (tsm_report) support",
            reports.display()
        );
    }
    Ok(reports)
}

#[cfg(target_os = "linux")]
fn mount_configfs(target: &Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    std::fs::create_dir_all(target)?;
    let target = CString::new(target.as_os_str().as_bytes()).context("path contains NUL")?;
    // SAFETY: every pointer is a live NUL-terminated string; data is NULL,
    // which configfs accepts.
    let rc = unsafe {
        libc::mount(
            c"configfs".as_ptr(),
            target.as_ptr(),
            c"configfs".as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        // Another mount raced us: fine, as long as tsm shows up below.
        if e.raw_os_error() != Some(libc::EBUSY) {
            return Err(e.into());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount_configfs(_target: &Path) -> Result<()> {
    bail!("configfs is only available on Linux")
}

static ENTRY_COUNTER: AtomicU64 = AtomicU64::new(0);

/// One `tsm/report/<name>` entry, removed on drop whichever way the quote
/// went.
struct ReportEntry {
    path: PathBuf,
}

impl ReportEntry {
    fn create(reports: &Path) -> Result<Self> {
        let name = format!(
            "aleph-{}-{}",
            std::process::id(),
            ENTRY_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = reports.join(name);
        std::fs::create_dir(&path)
            .with_context(|| format!("cannot create tsm report entry {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ReportEntry {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir(&self.path) {
            tracing::warn!(
                "cannot remove tsm report entry {}: {e}",
                self.path.display()
            );
        }
    }
}

fn read_attr(entry: &Path, name: &str) -> Result<Vec<u8>> {
    std::fs::read(entry.join(name)).with_context(|| format!("cannot read tsm attribute {name}"))
}

fn read_generation(entry: &Path) -> Result<u64> {
    let raw = read_attr(entry, "generation")?;
    std::str::from_utf8(&raw)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .context("tsm generation is not a number")
}

/// Run the configfs-tsm exchange on an existing report entry and return the
/// outblob. A missing or late answer is reported as the host's quote
/// service being unreachable: that is what it means, nothing about the TD.
fn quote_from_entry(entry: &Path, report_data: &[u8; 64], timeout: Duration) -> Result<Vec<u8>> {
    let provider = read_attr(entry, "provider")?;
    let provider = String::from_utf8_lossy(&provider);
    let provider = provider.trim();
    if !provider.starts_with(TDX_PROVIDER) {
        bail!("tsm report provider is {provider:?}, not {TDX_PROVIDER}: this is not a TDX guest");
    }

    std::fs::write(entry.join("inblob"), report_data).context("cannot write tsm inblob")?;
    // The inblob write bumped the generation; anyone else writing to this
    // entry before the outblob is read bumps it again.
    let generation = read_generation(entry)?;

    let (tx, rx) = mpsc::channel();
    let outblob = entry.join("outblob");
    std::thread::spawn(move || {
        let _ = tx.send(std::fs::read(&outblob));
    });
    let outblob = match rx.recv_timeout(timeout) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(e)) => bail!("host quote service unreachable: reading tsm outblob: {e}"),
        Err(_) => bail!("host quote service unreachable: no quote after {timeout:?}"),
    };
    if outblob.is_empty() {
        bail!("host quote service unreachable: empty tsm outblob");
    }

    if read_generation(entry)? != generation {
        bail!("tsm report entry was modified while the quote was in flight");
    }
    Ok(outblob)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Provenance and licences: tests/fixtures/tdx/README.md.
    const QUOTE_V4: &[u8] = include_bytes!("../../tests/fixtures/tdx/tdx_quote_v4.bin");

    /// A ready-made report entry the way configfs-tsm presents one after
    /// mkdir: `provider` and `generation` filled in, `outblob` as given.
    fn fake_entry(dir: &Path, provider: &str, outblob: &[u8]) -> PathBuf {
        let entry = dir.join("tsm").join("report").join("aleph-test");
        std::fs::create_dir_all(&entry).unwrap();
        std::fs::write(entry.join("provider"), format!("{provider}\n")).unwrap();
        std::fs::write(entry.join("generation"), "1\n").unwrap();
        std::fs::write(entry.join("outblob"), outblob).unwrap();
        entry
    }

    /// Replace `outblob` with a FIFO served by a thread: `before_quote` runs
    /// once the reader is attached, then the quote bytes are written.
    fn serve_outblob(
        entry: &Path,
        quote: &'static [u8],
        before_quote: impl FnOnce() + Send + 'static,
    ) {
        use std::ffi::CString;
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;

        let fifo = entry.join("outblob");
        let _ = std::fs::remove_file(&fifo);
        let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: `c` is a live NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        std::thread::spawn(move || {
            // Opening for write blocks until the backend opens for read.
            let mut w = std::fs::OpenOptions::new().write(true).open(&fifo).unwrap();
            before_quote();
            w.write_all(quote).unwrap();
        });
    }

    #[test]
    fn backend_is_tdx() {
        assert_eq!(TdxBackend::new().tee_type(), TeeType::Tdx);
        assert_eq!(TdxBackend::new().configfs, Path::new(DEFAULT_CONFIGFS));
        assert_eq!(TdxBackend::new().timeout, QUOTE_TIMEOUT);
    }

    #[test]
    fn parse_report_wraps_a_quote_untouched() {
        let backend = TdxBackend::new();
        let report = backend.parse_report(QUOTE_V4).unwrap();
        assert_eq!(report.tee_type, TeeType::Tdx);
        assert_eq!(report.data, QUOTE_V4);
        let err = backend.parse_report(&[0u8; 100]).unwrap_err().to_string();
        assert!(err.contains("not a TDX quote"), "got: {err}");
    }

    #[test]
    fn a_tdx_provider_yields_the_outblob_and_binds_the_inblob() {
        let dir = tempfile::tempdir().unwrap();
        let entry = fake_entry(dir.path(), "tdx_guest", QUOTE_V4);
        let report_data = [0x5A; 64];
        let outblob = quote_from_entry(&entry, &report_data, QUOTE_TIMEOUT).unwrap();
        assert_eq!(outblob, QUOTE_V4);
        assert_eq!(std::fs::read(entry.join("inblob")).unwrap(), report_data);
    }

    #[test]
    fn a_non_tdx_provider_is_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        // A genuine quote in the outblob must not rescue a sev_guest entry.
        let entry = fake_entry(dir.path(), "sev_guest", QUOTE_V4);
        let err = quote_from_entry(&entry, &[0u8; 64], QUOTE_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a TDX guest"), "got: {err}");
        assert!(!entry.join("inblob").exists());
    }

    #[test]
    fn an_empty_outblob_means_the_quote_service_is_down() {
        let dir = tempfile::tempdir().unwrap();
        let entry = fake_entry(dir.path(), "tdx_guest", b"");
        let err = quote_from_entry(&entry, &[0u8; 64], QUOTE_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("host quote service unreachable"),
            "got: {err}"
        );
    }

    #[test]
    fn a_late_outblob_means_the_quote_service_is_down() {
        let dir = tempfile::tempdir().unwrap();
        let entry = fake_entry(dir.path(), "tdx_guest", b"");
        // A FIFO nobody writes: the reader blocks in open() for good.
        serve_outblob(&entry, QUOTE_V4, || {
            std::thread::sleep(Duration::from_secs(3600))
        });
        let err = quote_from_entry(&entry, &[0u8; 64], Duration::from_millis(200))
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("host quote service unreachable"),
            "got: {err}"
        );
        assert!(err.contains("no quote after"), "got: {err}");
    }

    #[test]
    fn a_generation_bump_during_the_quote_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let entry = fake_entry(dir.path(), "tdx_guest", b"");
        let generation = entry.join("generation");
        serve_outblob(&entry, QUOTE_V4, move || {
            std::fs::write(&generation, "2\n").unwrap();
        });
        let err = quote_from_entry(&entry, &[0u8; 64], QUOTE_TIMEOUT)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("modified while the quote was in flight"),
            "got: {err}"
        );
    }

    #[test]
    fn a_served_fifo_outblob_is_the_quote() {
        let dir = tempfile::tempdir().unwrap();
        let entry = fake_entry(dir.path(), "tdx_guest", b"");
        serve_outblob(&entry, QUOTE_V4, || {});
        let outblob = quote_from_entry(&entry, &[0u8; 64], QUOTE_TIMEOUT).unwrap();
        assert_eq!(outblob, QUOTE_V4);
    }

    #[test]
    fn an_existing_tsm_directory_is_used_without_mounting() {
        let dir = tempfile::tempdir().unwrap();
        let reports = dir.path().join("tsm").join("report");
        std::fs::create_dir_all(&reports).unwrap();
        assert_eq!(ensure_tsm(dir.path()).unwrap(), reports);
    }

    #[test]
    fn report_entries_are_unique_and_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let a = ReportEntry::create(dir.path()).unwrap();
        let b = ReportEntry::create(dir.path()).unwrap();
        assert_ne!(a.path, b.path);
        assert!(a.path.is_dir() && b.path.is_dir());
        let (pa, pb) = (a.path.clone(), b.path.clone());
        drop((a, b));
        assert!(!pa.exists() && !pb.exists());
    }
}
