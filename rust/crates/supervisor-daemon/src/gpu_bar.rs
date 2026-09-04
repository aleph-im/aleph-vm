//! Size the guest's 64-bit PCI MMIO window from the card's real BARs.
//!
//! OVMF places 64-bit BARs inside a window whose size it reads from the
//! `opt/ovmf/X-PciMmio64Mb` fw_cfg entry. A data-center GPU's BAR1 is tens
//! of gigabytes, far beyond OVMF's default, and the next SKU's differs, so
//! the window follows the hardware instead of a constant. fw_cfg values are
//! not measurement inputs, which is what lets the window vary per card
//! without moving the launch digest.

use crate::error::DaemonError;

const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_PREFETCH: u64 = 0x0000_2000;
const IORESOURCE_MEM_64: u64 = 0x0010_0000;
const MIN_WINDOW_MB: u64 = 1024;

/// Sum the sizes of the 64-bit prefetchable memory BARs listed in a sysfs
/// `resource` file (`start end flags` per line, hex).
pub fn parse_resource_file(contents: &str) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for line in contents.lines().filter(|l| !l.trim().is_empty()) {
        let mut fields = line.split_whitespace().map(|f| {
            u64::from_str_radix(f.trim_start_matches("0x"), 16)
                .map_err(|e| DaemonError::GpuProbe(format!("bad resource field {f:?}: {e}")))
        });
        let (start, end, flags) = match (fields.next(), fields.next(), fields.next()) {
            (Some(s), Some(e), Some(f)) => (s?, e?, f?),
            _ => {
                return Err(DaemonError::GpuProbe(format!(
                    "malformed resource line {line:?}"
                )));
            }
        };
        let wanted = IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64;
        if flags & wanted == wanted && end >= start {
            total = total.saturating_add(end - start + 1);
        }
    }
    Ok(total)
}

/// Window size in MiB: the BAR total rounded up to a power of two, doubled
/// so OVMF has alignment slack, never below 1 GiB.
pub fn mmio64_window_mb(bar_bytes: u64) -> u64 {
    let mb = bar_bytes.div_ceil(1 << 20).max(1);
    (mb.next_power_of_two() * 2).max(MIN_WINDOW_MB)
}

/// The window for a set of cards attached to one VM.
pub fn gpu_mmio64_mb(pci_hosts: &[String]) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for pci_host in pci_hosts {
        let path = crate::gpu_cc::sysfs_device_dir(pci_host).join("resource");
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| DaemonError::GpuProbe(format!("cannot read {}: {e}", path.display())))?;
        total = total.saturating_add(parse_resource_file(&contents)?);
    }
    Ok(mmio64_window_mb(total))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured from an RTX PRO 6000 Blackwell class card: BAR0 16 MiB 32-bit,
    // BAR1 128 GiB 64-bit prefetchable, BAR3 32 MiB 64-bit prefetchable, I/O
    // port BAR, expansion ROM.
    const RESOURCE: &str = "\
0x00000000f6000000 0x00000000f6ffffff 0x0000000000040200
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000002000000000 0x0000003fffffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000004000000000 0x0000004001ffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000000000000e000 0x000000000000e07f 0x0000000000040101
0x00000000f7000000 0x00000000f707ffff 0x0000000000046200
";

    #[test]
    fn sums_only_64bit_prefetchable_memory_bars() {
        let bytes = parse_resource_file(RESOURCE).unwrap();
        assert_eq!(bytes, 128 * (1 << 30) + 32 * (1 << 20));
    }

    #[test]
    fn window_is_next_power_of_two_doubled_with_a_floor() {
        assert_eq!(
            mmio64_window_mb(128 * (1 << 30) + 32 * (1 << 20)),
            512 * 1024
        );
        assert_eq!(mmio64_window_mb(0), 1024);
        assert_eq!(mmio64_window_mb(256 * (1 << 20)), 1024);
        assert_eq!(mmio64_window_mb(3 * (1 << 30)), 8 * 1024);
    }

    #[test]
    fn malformed_lines_are_errors() {
        assert!(parse_resource_file("0x1 0x2\n").is_err());
        assert!(parse_resource_file("zz 0x2 0x3\n").is_err());
    }
}
