//! NVIDIA confidential-computing mode probe.
//!
//! A GPU in CC mode refuses plaintext DMA and answers SPDM attestation; the
//! CRN must know which cards are in that mode before advertising them as
//! confidential capacity. The mode lives in a BAR0 register that NVIDIA's
//! gpu-admin-tools reads the same way (offset 0x590 on Blackwell, 0x1182CC
//! on Hopper, bits [1:0]). Reading it needs no driver: the card is bound to
//! vfio-pci, and the register is reachable through the sysfs resource file.
//! The read only ever runs on a card no VM owns, so it never races a guest.
//! An idle card is usually runtime-suspended, and a suspended function
//! answers MMIO with all ones, so the probe pins it awake first and treats
//! an all-ones answer as no answer at all.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::error::DaemonError;

/// Default length, in seconds, of the window a cached answer that decoded
/// to a mode is served for. A card's mode only changes when an operator
/// runs NVIDIA's tool against an idle card, a handful of times in the life
/// of a node, and nothing the daemon decides rests on the cache being
/// current: the create and start gates read the hardware themselves, a stop
/// or a delete forgets the card's entry, and a restart begins with an empty
/// cache. So the window only has to cover "an idle card was re-moded and
/// nothing on this node stopped or was deleted since", and an hour of that
/// costs far less than waking every idle card out of runtime suspend once a
/// minute for the rest of the node's life. Operators who re-mode cards
/// often can shorten it with `ALEPH_VM_GPU_CC_MODE_TTL`.
pub const DEFAULT_CC_MODE_TTL_SECS: u64 = 3600;

/// How long an answer that carries no mode (the probe errored, the register
/// read all ones, the encoding is reserved) is served before the card is
/// read again. Deliberately not a setting: this is transient handling
/// rather than an operator policy. An operator's mode change ends in a card
/// reset, and a sweep landing during the reset reads all ones and caches
/// "unreadable"; held for the long window, that one blink would hide a
/// perfectly good card for an hour. A minute is still long enough to serve
/// the reason failed answers are cached at all, which is to keep a card
/// that cannot be read from being probed again on every request.
pub const UNREADABLE_CC_MODE_TTL: Duration = Duration::from_secs(60);

/// How long each kind of cached answer is served before its card is read
/// again. Both windows do the same job for the unauthenticated host-info
/// path: a card is read at most once per window whatever the request rate,
/// so nobody who can reach the agent's capability endpoint can make the
/// host mmap device memory on demand. Only the length differs, because a
/// decoded mode stays true far longer than a failed read stays worth
/// believing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CcCacheWindows {
    /// For an answer that decoded to a mode.
    pub mode: Duration,
    /// For an answer that carries no mode.
    pub unreadable: Duration,
}

impl CcCacheWindows {
    /// The windows a running daemon serves under: the configured long one
    /// for a decoded mode, the fixed short one for an answer without one.
    pub fn with_mode_ttl(mode: Duration) -> Self {
        Self {
            mode,
            unreadable: UNREADABLE_CC_MODE_TTL,
        }
    }

    /// The shortest window any cached answer can be held under, which is
    /// how long a decision taken over the whole cache at once stays true.
    pub fn shortest(self) -> Duration {
        self.mode.min(self.unreadable)
    }
}

/// How long a runtime-suspended card gets to come back before the register
/// is read anyway. A card that has not resumed reads as all ones, which
/// fails closed, so the wait is a courtesy and not a correctness bound.
const RESUME_TIMEOUT: Duration = Duration::from_millis(200);

/// How often `power/runtime_status` is re-read while waiting to resume.
const RESUME_POLL_INTERVAL: Duration = Duration::from_millis(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CcMode {
    On,
    Devtools,
    Off,
}

impl fmt::Display for CcMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CcMode::On => "on",
            CcMode::Devtools => "devtools",
            CcMode::Off => "off",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GpuArch {
    Hopper,
    Blackwell,
}

impl fmt::Display for GpuArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            GpuArch::Hopper => "hopper",
            GpuArch::Blackwell => "blackwell",
        })
    }
}

/// (first, last, arch) PCI device-id ranges. Blackwell rows are copied from
/// NVIDIA/gpu-admin-tools `gpu/devid_chips.py`; the Hopper row is the GH100
/// block (H100/H200 PCIe, SXM and NVL ids all fall in 0x2300..0x237f).
const DEVICE_ID_RANGES: &[(u16, u16, GpuArch)] = &[
    (0x2300, 0x237f, GpuArch::Hopper),
    (0x2900, 0x297f, GpuArch::Blackwell), // gb100
    (0x2980, 0x29ff, GpuArch::Blackwell), // gb102
    (0x3180, 0x31ff, GpuArch::Blackwell), // gb110
    (0x3200, 0x327f, GpuArch::Blackwell), // gb112
    (0x2b80, 0x2bff, GpuArch::Blackwell), // gb202 (RTX PRO 6000 Blackwell)
    (0x2c00, 0x2c7f, GpuArch::Blackwell), // gb203
    (0x2f00, 0x2f7f, GpuArch::Blackwell), // gb205
    (0x2d00, 0x2d7f, GpuArch::Blackwell), // gb206
    (0x2d80, 0x2dff, GpuArch::Blackwell), // gb207
];

/// `vendor:device` -> architecture, NVIDIA cards with a CC mode only.
pub fn arch_from_device_id(device_id: &str) -> Option<GpuArch> {
    let (vendor, device) = device_id.split_once(':')?;
    if vendor != "10de" {
        return None;
    }
    let device = u16::from_str_radix(device, 16).ok()?;
    DEVICE_ID_RANGES
        .iter()
        .find(|(first, last, _)| (*first..=*last).contains(&device))
        .map(|(_, _, arch)| *arch)
}

pub fn bar0_register_offset(arch: GpuArch) -> u64 {
    match arch {
        GpuArch::Blackwell => 0x590,
        GpuArch::Hopper => 0x1182cc,
    }
}

/// Bits [1:0] of the CC register. `0b10` is reserved and yields None.
pub fn cc_mode_from_register(value: u32) -> Option<CcMode> {
    match value & 0x3 {
        0b00 => Some(CcMode::Off),
        0b01 => Some(CcMode::On),
        0b11 => Some(CcMode::Devtools),
        _ => None,
    }
}

/// Where the kernel lists PCI devices.
pub const SYSFS_PCI_DEVICES: &str = "/sys/bus/pci/devices";

/// The card's directory under `/sys/bus/pci/devices`.
pub fn sysfs_device_dir(pci_host: &str) -> PathBuf {
    sysfs_device_dir_under(Path::new(SYSFS_PCI_DEVICES), pci_host)
}

/// `sysfs_device_dir` under an explicit devices directory, so a fixture
/// tree can stand in for sysfs. A pci_host without a domain gets 0000.
pub fn sysfs_device_dir_under(devices_dir: &Path, pci_host: &str) -> PathBuf {
    let full = if pci_host.matches(':').count() == 1 {
        format!("0000:{pci_host}")
    } else {
        pci_host.to_string()
    };
    devices_dir.join(full)
}

/// An io error with the file it came from, so the caller's message names
/// the register file and not just the errno.
fn at_path(path: &Path, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{}: {error}", path.display()))
}

/// Read one 32-bit register from a BAR0 mapping. sysfs `resourceN` files
/// only support mmap (read() is refused for memory BARs), so map the page
/// holding the offset and do a volatile read.
pub fn read_bar0_u32(resource0: &Path, offset: u64) -> Result<u32, std::io::Error> {
    use std::io::{Error, ErrorKind};
    use std::os::fd::AsRawFd as _;

    if !offset.is_multiple_of(4) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("register offset {offset:#x} is not 4-byte aligned"),
        ));
    }

    let file = std::fs::File::open(resource0).map_err(|error| at_path(resource0, error))?;
    let len = file
        .metadata()
        .map_err(|error| at_path(resource0, error))?
        .len();
    let end = offset.checked_add(4).ok_or_else(|| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("register offset {offset:#x} + 4 would overflow u64"),
        )
    })?;
    if end > len {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!(
                "register offset {offset:#x} is past the end of {} ({len} bytes)",
                resource0.display()
            ),
        ));
    }
    // SAFETY: sysconf reads a constant and has no preconditions.
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .ok()
        .filter(|page| page.is_power_of_two())
        .ok_or_else(|| Error::other("cannot determine the page size"))?;
    let base = offset & !(page - 1);
    let within = (offset - base) as usize;
    // SAFETY: a read-only shared mapping of one page of an open file; the
    // pointer is checked against MAP_FAILED; the offset is 4-byte aligned,
    // so within is 4-aligned and within + 4 <= page, keeping the read inside
    // the mapped page; and the mapping is released before returning.
    unsafe {
        let mapped = libc::mmap(
            std::ptr::null_mut(),
            page as usize,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            base as libc::off_t,
        );
        if mapped == libc::MAP_FAILED {
            let error = std::io::Error::last_os_error();
            return Err(Error::new(
                error.kind(),
                format!(
                    "mmap of {} at {base:#x} failed: {error}",
                    resource0.display()
                ),
            ));
        }
        let value = std::ptr::read_volatile(mapped.cast::<u8>().add(within).cast::<u32>());
        libc::munmap(mapped, page as usize);
        Ok(u32::from_le(value))
    }
}

/// The shape of a CC mode probe: (pci_host, device_id) to the mode, `None`
/// when the card has no mode. `probe_cc_mode` is the real one; hermetic
/// daemon state carries `no_probe` so no test ever opens sysfs.
pub type CcProbe = fn(&str, &str) -> Result<Option<CcMode>, DaemonError>;

/// A probe that never finds a mode: the seam for state that must not touch
/// the host's PCI devices.
pub fn no_probe(_pci_host: &str, _device_id: &str) -> Result<Option<CcMode>, DaemonError> {
    Ok(None)
}

/// What the last probe of one card read: the mode, or `None` when the
/// probe failed or the register held an encoding with no mode, plus when
/// it ran. The `None` answers are cached like the modes are: they are what
/// keeps a card that cannot be read from being probed again on every
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbedCcMode {
    pub mode: Option<CcMode>,
    pub probed_at: Instant,
}

impl ProbedCcMode {
    /// The answer a probe has just given.
    pub fn now(mode: Option<CcMode>) -> Self {
        Self {
            mode,
            probed_at: Instant::now(),
        }
    }

    /// Whether this answer is young enough to serve without reading the
    /// card again. Which window applies is the answer's own business: a
    /// decoded mode gets the long one, an answer with no mode the short
    /// one, so a card that read as unreadable while it was being reset
    /// comes back on its own within the minute instead of staying hidden
    /// for the length of the long window.
    pub fn is_fresh(&self, windows: CcCacheWindows) -> bool {
        let window = if self.mode.is_some() {
            windows.mode
        } else {
            windows.unreadable
        };
        self.probed_at.elapsed() < window
    }
}

/// A card held out of runtime suspend for the length of one probe. The
/// previous `power/control` value goes back on drop, so the card idles
/// again exactly as the host had it configured.
struct RuntimePowerHold {
    control: PathBuf,
    previous: String,
}

impl Drop for RuntimePowerHold {
    fn drop(&mut self) {
        if let Err(error) = std::fs::write(&self.control, format!("{}\n", self.previous)) {
            tracing::warn!(
                path = %self.control.display(),
                previous = %self.previous,
                %error,
                "cannot restore the GPU runtime-PM setting; the card stays powered on"
            );
        }
    }
}

/// Pin a runtime-suspended card awake for a probe. vfio-pci lets a device
/// nobody has opened runtime-suspend, and MMIO reads to a function in
/// D3hot come back as all ones, which the register decoder cannot tell
/// from a real answer. Returns `None`, having written nothing, unless the
/// kernel reports the device on its way into or out of runtime suspend.
/// Waits up to `timeout` for the kernel to report it active.
///
/// Never fails the probe: a device whose runtime-PM files cannot be read
/// or written is read as it is, exactly as it was before there was a
/// resume step. The register still decides, and an all-ones answer from a
/// card that stayed asleep fails closed.
fn hold_runtime_power_on(device_dir: &Path, timeout: Duration) -> Option<RuntimePowerHold> {
    let status_path = device_dir.join("power/runtime_status");
    let status = match std::fs::read_to_string(&status_path) {
        Ok(status) => status,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(path = %status_path.display(), %error, "cannot read the GPU runtime-PM state");
            }
            return None;
        }
    };
    // Only a device on its way into or out of D3 is worth holding. An
    // "active" one is already awake, and a device with no runtime PM says
    // "unsupported" (some drivers report other words still): it is powered,
    // it will never report "active", so writing "on" would change the
    // host's setting for nothing and then burn the whole resume budget
    // waiting for a transition that cannot come. "resuming" stays in: a
    // device mid-resume is exactly what the budget is there to wait for.
    let status = status.trim();
    if !matches!(status, "suspended" | "suspending" | "resuming") {
        return None;
    }
    let control_path = device_dir.join("power/control");
    let previous = match std::fs::read_to_string(&control_path) {
        Ok(previous) => previous.trim().to_string(),
        Err(error) => {
            tracing::warn!(
                path = %control_path.display(),
                %error,
                "cannot read the GPU runtime-PM setting; reading its register without resuming it"
            );
            return None;
        }
    };
    if let Err(error) = std::fs::write(&control_path, "on\n") {
        tracing::warn!(
            path = %control_path.display(),
            %error,
            "cannot pin the GPU awake; reading its register anyway"
        );
        return None;
    }
    // From here on the hold owns the restore, whatever the wait does.
    let hold = RuntimePowerHold {
        control: control_path,
        previous,
    };
    let deadline = Instant::now() + timeout;
    loop {
        if std::fs::read_to_string(&status_path).is_ok_and(|status| status.trim() == "active") {
            break;
        }
        if Instant::now() >= deadline {
            tracing::warn!(
                path = %device_dir.display(),
                "the GPU did not leave runtime suspend in time; reading its register anyway"
            );
            break;
        }
        std::thread::sleep(RESUME_POLL_INTERVAL);
    }
    Some(hold)
}

/// The CC mode of one vfio-bound NVIDIA card, `None` for cards without a
/// CC mode (other vendors, pre-Hopper) or a reserved register encoding.
pub fn probe_cc_mode(pci_host: &str, device_id: &str) -> Result<Option<CcMode>, DaemonError> {
    probe_cc_mode_in(
        &sysfs_device_dir(pci_host),
        pci_host,
        device_id,
        RESUME_TIMEOUT,
    )
}

/// `probe_cc_mode` against an explicit device directory and resume budget,
/// so a fixture tree can stand in for sysfs.
pub(crate) fn probe_cc_mode_in(
    device_dir: &Path,
    pci_host: &str,
    device_id: &str,
    resume_timeout: Duration,
) -> Result<Option<CcMode>, DaemonError> {
    let Some(arch) = arch_from_device_id(device_id) else {
        return Ok(None);
    };
    let _resumed = hold_runtime_power_on(device_dir, resume_timeout);
    let value = read_bar0_u32(&device_dir.join("resource0"), bar0_register_offset(arch)).map_err(
        |source| DaemonError::GpuRegisterRead {
            pci_host: pci_host.to_string(),
            source,
        },
    )?;
    // A function that cannot answer (still in D3hot, a reset in flight, the
    // card gone off the bus) reads back as all ones, and the low two bits
    // of that are the devtools encoding. Reporting devtools for a card
    // nobody could read would advertise confidential capacity the host has
    // no evidence for, so an unreachable card is an error and not a mode.
    if value == u32::MAX {
        return Err(DaemonError::GpuUnreadable {
            pci_host: pci_host.to_string(),
        });
    }
    Ok(cc_mode_from_register(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_id_ranges_follow_gpu_admin_tools() {
        // gpu/devid_chips.py in NVIDIA/gpu-admin-tools, Blackwell rows.
        assert_eq!(arch_from_device_id("10de:2b85"), Some(GpuArch::Blackwell)); // GB202, RTX PRO 6000
        assert_eq!(arch_from_device_id("10de:2901"), Some(GpuArch::Blackwell)); // GB100
        assert_eq!(arch_from_device_id("10de:2331"), Some(GpuArch::Hopper)); // GH100, H100 PCIe
        assert_eq!(arch_from_device_id("10de:20f1"), None); // GA100, no CC
        assert_eq!(arch_from_device_id("1002:744c"), None); // AMD
        assert_eq!(arch_from_device_id("garbage"), None);
    }

    #[test]
    fn register_bits_decode_the_three_modes() {
        assert_eq!(cc_mode_from_register(0x0000_0000), Some(CcMode::Off));
        assert_eq!(cc_mode_from_register(0x0000_0001), Some(CcMode::On));
        assert_eq!(cc_mode_from_register(0x0000_0003), Some(CcMode::Devtools));
        assert_eq!(
            cc_mode_from_register(0x0000_0002),
            None,
            "reserved encoding"
        );
        // Higher bits (BMSAI, boot status) are ignored.
        assert_eq!(cc_mode_from_register(0xffff_ff01), Some(CcMode::On));
    }

    #[test]
    fn register_offsets_per_architecture() {
        assert_eq!(bar0_register_offset(GpuArch::Blackwell), 0x590);
        assert_eq!(bar0_register_offset(GpuArch::Hopper), 0x1182cc);
    }

    #[test]
    fn sysfs_path_adds_the_pci_domain() {
        assert_eq!(
            sysfs_device_dir("06:00.0"),
            PathBuf::from("/sys/bus/pci/devices/0000:06:00.0")
        );
        assert_eq!(
            sysfs_device_dir("0000:06:00.0"),
            PathBuf::from("/sys/bus/pci/devices/0000:06:00.0")
        );
    }

    #[test]
    fn bar0_read_maps_the_page_and_reads_little_endian() {
        // A regular file stands in for resource0: mmap works the same way.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resource0");
        // Large enough to hold both architectures' registers: the Hopper
        // offset sits past the first page, so it also exercises a non-zero
        // mapping base.
        let mut bytes = vec![0u8; 0x1182d0];
        bytes[0x590..0x594].copy_from_slice(&0x0000_0101u32.to_le_bytes());
        bytes[0x1182cc..0x1182d0].copy_from_slice(&3u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read_bar0_u32(&path, 0x590).unwrap(), 0x101);
        assert_eq!(
            cc_mode_from_register(read_bar0_u32(&path, 0x590).unwrap()),
            Some(CcMode::On)
        );
        assert_eq!(read_bar0_u32(&path, 0x1182cc).unwrap(), 3);
        assert_eq!(
            cc_mode_from_register(read_bar0_u32(&path, 0x1182cc).unwrap()),
            Some(CcMode::Devtools)
        );
        // Past the end of the file is a clean error, never a fault.
        assert!(read_bar0_u32(&path, 0x20_0000).is_err());
    }

    #[test]
    fn bar0_read_rejects_misaligned_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resource0");
        let mut bytes = vec![0u8; 0x2000];
        bytes[0x590..0x594].copy_from_slice(&0x0000_0101u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        // Misaligned offset should error with "aligned" in the message.
        let err = read_bar0_u32(&path, 0x591).unwrap_err();
        assert!(err.to_string().contains("aligned"));
        // Aligned offset still reads correctly.
        assert_eq!(read_bar0_u32(&path, 0x590).unwrap(), 0x101);
    }

    /// A fixture card directory: the sysfs files the probe touches.
    fn fake_card(dir: &Path, runtime_status: Option<&str>, register: u32) -> PathBuf {
        let device_dir = dir.join("0000:06:00.0");
        std::fs::create_dir_all(device_dir.join("power")).unwrap();
        if let Some(status) = runtime_status {
            std::fs::write(
                device_dir.join("power/runtime_status"),
                format!("{status}\n"),
            )
            .unwrap();
            std::fs::write(device_dir.join("power/control"), "auto\n").unwrap();
        }
        let mut bytes = vec![0u8; 0x1000];
        bytes[0x590..0x594].copy_from_slice(&register.to_le_bytes());
        std::fs::write(device_dir.join("resource0"), &bytes).unwrap();
        device_dir
    }

    #[test]
    fn an_all_ones_register_is_unreadable_rather_than_devtools() {
        // A card in D3hot answers every MMIO read with all ones, and the
        // low two bits of that answer are the devtools encoding. The
        // decoder cannot tell the difference, so the probe must: an idle
        // card would otherwise be advertised as confidential capacity in
        // devtools mode and then refused at create.
        assert_eq!(cc_mode_from_register(0xffff_ffff), Some(CcMode::Devtools));
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), None, 0xffff_ffff);
        let error = probe_cc_mode_in(&device_dir, "06:00.0", "10de:2b85", Duration::ZERO)
            .expect_err("all ones must not decode to a mode");
        let message = error.to_string();
        assert!(message.contains("06:00.0"), "{message}");
        assert!(message.contains("ffffffff"), "{message}");
    }

    #[test]
    fn a_suspended_card_is_pinned_awake_and_released_afterwards() {
        // vfio-pci lets a card nobody has opened runtime-suspend. The
        // probe pins it awake for the read and hands the host's own
        // setting back, so the card can idle again once the daemon is
        // done with it.
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("suspended"), 0x0000_0001);
        let control = device_dir.join("power/control");
        {
            let hold = hold_runtime_power_on(&device_dir, Duration::ZERO)
                .expect("a suspended card must be held awake");
            assert_eq!(std::fs::read_to_string(&control).unwrap().trim(), "on");
            drop(hold);
        }
        assert_eq!(
            std::fs::read_to_string(&control).unwrap().trim(),
            "auto",
            "the host's runtime-PM setting must survive the probe"
        );
    }

    #[test]
    fn an_active_card_is_never_written_to() {
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("active"), 0x0000_0001);
        assert!(
            hold_runtime_power_on(&device_dir, Duration::ZERO).is_none(),
            "an active card needs no hold"
        );
        assert_eq!(
            std::fs::read_to_string(device_dir.join("power/control"))
                .unwrap()
                .trim(),
            "auto"
        );
    }

    #[test]
    fn a_card_whose_runtime_pm_is_unsupported_is_neither_written_to_nor_waited_for() {
        // A device the kernel does not runtime-manage is powered and stays
        // powered, and its status will never turn "active". Writing "on"
        // there would change the host's setting for nothing and then wait
        // out the whole resume budget, once per probe.
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("unsupported"), 0x0000_0001);
        let started = Instant::now();
        assert!(
            hold_runtime_power_on(&device_dir, Duration::from_secs(3)).is_none(),
            "a device without runtime PM needs no hold"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "and must not wait for a resume that cannot happen"
        );
        assert_eq!(
            std::fs::read_to_string(device_dir.join("power/control"))
                .unwrap()
                .trim(),
            "auto"
        );
        assert_eq!(
            probe_cc_mode_in(&device_dir, "06:00.0", "10de:2b85", Duration::from_secs(3)).unwrap(),
            Some(CcMode::On),
            "the register is read straight away"
        );
    }

    #[test]
    fn a_device_without_runtime_pm_files_probes_as_before() {
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), None, 0x0000_0001);
        assert_eq!(
            probe_cc_mode_in(&device_dir, "06:00.0", "10de:2b85", Duration::ZERO).unwrap(),
            Some(CcMode::On)
        );
    }

    #[test]
    fn a_suspended_card_is_resumed_before_its_register_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("suspended"), 0x0000_0003);
        assert_eq!(
            probe_cc_mode_in(&device_dir, "06:00.0", "10de:2b85", Duration::ZERO).unwrap(),
            Some(CcMode::Devtools)
        );
        assert_eq!(
            std::fs::read_to_string(device_dir.join("power/control"))
                .unwrap()
                .trim(),
            "auto"
        );
    }

    #[test]
    fn a_card_without_a_cc_architecture_is_never_touched() {
        // The device-id check comes first: no runtime-PM write and no
        // register read for a card that has no CC mode to read.
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("suspended"), 0xffff_ffff);
        assert_eq!(
            probe_cc_mode_in(&device_dir, "06:00.0", "10de:20f1", Duration::ZERO).unwrap(),
            None
        );
        assert_eq!(
            std::fs::read_to_string(device_dir.join("power/control"))
                .unwrap()
                .trim(),
            "auto"
        );
    }

    #[test]
    fn an_unreadable_power_control_still_reads_the_register() {
        // The resume step is an improvement on the read, not a condition
        // of it: a device whose runtime-PM files cannot be read must probe
        // exactly as it did before the step existed. Here the card claims
        // to be suspended but has no power/control at all.
        let dir = tempfile::tempdir().unwrap();
        let device_dir = fake_card(dir.path(), Some("suspended"), 0x0000_0001);
        std::fs::remove_file(device_dir.join("power/control")).unwrap();
        assert!(hold_runtime_power_on(&device_dir, Duration::ZERO).is_none());
        assert_eq!(
            probe_cc_mode_in(&device_dir, "06:00.0", "10de:2b85", Duration::ZERO).unwrap(),
            Some(CcMode::On)
        );
    }

    #[test]
    fn a_probe_answer_is_fresh_only_inside_its_window() {
        let answer = ProbedCcMode::now(Some(CcMode::On));
        assert!(
            answer.is_fresh(CcCacheWindows::with_mode_ttl(Duration::from_secs(
                DEFAULT_CC_MODE_TTL_SECS
            )))
        );
        assert!(!answer.is_fresh(CcCacheWindows {
            mode: Duration::ZERO,
            unreadable: Duration::ZERO,
        }));
        assert_eq!(answer.mode, Some(CcMode::On));
    }

    #[test]
    fn cc_mode_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&CcMode::On).unwrap(), "\"on\"");
        assert_eq!(CcMode::Devtools.to_string(), "devtools");
    }

    #[test]
    fn gpu_arch_serializes_lowercase() {
        // The wire spelling the agent and the V-PROGRAM schema share.
        assert_eq!(
            serde_json::to_string(&GpuArch::Blackwell).unwrap(),
            "\"blackwell\""
        );
        assert_eq!(
            serde_json::to_string(&GpuArch::Hopper).unwrap(),
            "\"hopper\""
        );
        assert_eq!(GpuArch::Blackwell.to_string(), "blackwell");
        assert_eq!(GpuArch::Hopper.to_string(), "hopper");
        assert_eq!(
            serde_json::from_str::<GpuArch>("\"hopper\"").unwrap(),
            GpuArch::Hopper
        );
    }
}
