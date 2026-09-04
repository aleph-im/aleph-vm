//! NVIDIA confidential-computing mode probe.
//!
//! A GPU in CC mode refuses plaintext DMA and answers SPDM attestation; the
//! CRN must know which cards are in that mode before advertising them as
//! confidential capacity. The mode lives in a BAR0 register that NVIDIA's
//! gpu-admin-tools reads the same way (offset 0x590 on Blackwell, 0x1182CC
//! on Hopper, bits [1:0]). Reading it needs no driver: the card is bound to
//! vfio-pci, and the register is reachable through the sysfs resource file.
//! The read only ever runs on a card no VM owns, so it never races a guest.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::error::DaemonError;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GpuArch {
    Hopper,
    Blackwell,
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

pub fn sysfs_device_dir(pci_host: &str) -> PathBuf {
    let full = if pci_host.matches(':').count() == 1 {
        format!("0000:{pci_host}")
    } else {
        pci_host.to_string()
    };
    PathBuf::from("/sys/bus/pci/devices").join(full)
}

/// Read one 32-bit register from a BAR0 mapping. sysfs `resourceN` files
/// only support mmap (read() is refused for memory BARs), so map the page
/// holding the offset and do a volatile read.
pub fn read_bar0_u32(resource0: &Path, offset: u64) -> Result<u32, DaemonError> {
    use std::os::fd::AsRawFd as _;
    let file = std::fs::File::open(resource0).map_err(|error| {
        DaemonError::GpuProbe(format!("cannot open {}: {error}", resource0.display()))
    })?;
    let len = file
        .metadata()
        .map_err(|error| {
            DaemonError::GpuProbe(format!("cannot stat {}: {error}", resource0.display()))
        })?
        .len();
    if offset + 4 > len {
        return Err(DaemonError::GpuProbe(format!(
            "register offset {offset:#x} is past the end of {} ({len} bytes)",
            resource0.display()
        )));
    }
    let page = 4096u64;
    let base = offset & !(page - 1);
    let within = (offset - base) as usize;
    // SAFETY: a read-only shared mapping of one page of an open file; the
    // pointer is checked against MAP_FAILED, the read stays inside the page,
    // and the mapping is released before returning.
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
            return Err(DaemonError::GpuProbe(format!(
                "mmap of {} at {base:#x} failed: {}",
                resource0.display(),
                std::io::Error::last_os_error()
            )));
        }
        let value = std::ptr::read_volatile(mapped.cast::<u8>().add(within).cast::<u32>());
        libc::munmap(mapped, page as usize);
        Ok(u32::from_le(value))
    }
}

/// The CC mode of one vfio-bound NVIDIA card, `None` for cards without a
/// CC mode (other vendors, pre-Hopper) or a reserved register encoding.
pub fn probe_cc_mode(pci_host: &str, device_id: &str) -> Result<Option<CcMode>, DaemonError> {
    let Some(arch) = arch_from_device_id(device_id) else {
        return Ok(None);
    };
    let resource0 = sysfs_device_dir(pci_host).join("resource0");
    let value = read_bar0_u32(&resource0, bar0_register_offset(arch))?;
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
        let mut bytes = vec![0u8; 0x2000];
        bytes[0x590..0x594].copy_from_slice(&0x0000_0101u32.to_le_bytes());
        bytes[0x1182cc % 0x2000..][..4].copy_from_slice(&3u32.to_le_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read_bar0_u32(&path, 0x590).unwrap(), 0x101);
        assert_eq!(
            cc_mode_from_register(read_bar0_u32(&path, 0x590).unwrap()),
            Some(CcMode::On)
        );
        // Past the end of the mapping is a clean error, never a fault.
        assert!(read_bar0_u32(&path, 0x4000).is_err());
    }

    #[test]
    fn cc_mode_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&CcMode::On).unwrap(), "\"on\"");
        assert_eq!(CcMode::Devtools.to_string(), "devtools");
    }
}
