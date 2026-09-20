//! Size the guest's 64-bit PCI MMIO window from the card's real BARs.
//!
//! OVMF places 64-bit BARs inside a window whose size it reads from the
//! `opt/ovmf/X-PciMmio64Mb` fw_cfg entry. A data-center GPU's BAR1 is tens
//! of gigabytes, far beyond OVMF's default, and the next SKU's differs, so
//! the window follows the hardware instead of a constant. fw_cfg values are
//! not measurement inputs, which is what lets the window vary per card
//! without moving the launch digest.

use std::path::Path;

use crate::error::DaemonError;

const IORESOURCE_MEM: u64 = 0x0000_0200;
const IORESOURCE_PREFETCH: u64 = 0x0000_2000;
const IORESOURCE_MEM_64: u64 = 0x0010_0000;
/// The flag set a BAR must carry to count towards the window: 64-bit
/// prefetchable memory.
const WANTED_FLAGS: u64 = IORESOURCE_MEM | IORESOURCE_PREFETCH | IORESOURCE_MEM_64;
/// Rows 0..=5 of a sysfs `resource` file are the six standard BARs; rows past
/// that are the expansion ROM, the SR-IOV VF BARs and bridge windows, which
/// vfio-pci never exposes to the guest, so they never reach the window.
const STANDARD_BARS: usize = 6;
const MIN_WINDOW_MB: u64 = 1024;
/// The largest window the daemon will ever ask OVMF for, in MiB (4 TiB), so
/// absurd BARs cannot hand fw_cfg a window no firmware can lay out. It only
/// keeps the arithmetic sane: `check_mmio64_budget` is the tighter gate.
const MAX_WINDOW_MB: u64 = 4 * 1024 * 1024;

/// Guest physical address space, in MiB. The confidential argv names a CPU
/// model with no `phys-bits`, and QEMU defaults a named x86 model to 40 bits
/// whichever model it is, so the firmware has 1 TiB to place everything in.
pub(crate) const GUEST_PHYS_MB: u64 = 1 << 20;

/// What sits below the guest's RAM and is not counted in the RAM figure: the
/// 32-bit MMIO hole under 4 GiB, the firmware's reservations and the ACPI
/// tables. Added before the window is aligned, never after.
const GUEST_LOW_RESERVED_MB: u64 = 4 * 1024;

/// Sum the sizes of the 64-bit prefetchable memory BARs listed in a sysfs
/// `resource` file (`start end flags` per line, hex). Only the first
/// `STANDARD_BARS` rows are considered; later rows (expansion ROM, SR-IOV VF
/// BARs, bridge windows) are ignored entirely, not validated.
pub fn parse_resource_file(contents: &str) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for line in contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(STANDARD_BARS)
    {
        let mut fields = line.split_whitespace().map(|f| {
            u64::from_str_radix(f.trim_start_matches("0x"), 16).map_err(|source| {
                DaemonError::GpuResourceField {
                    field: f.to_string(),
                    source,
                }
            })
        });
        let (start, end, flags) = match (fields.next(), fields.next(), fields.next()) {
            (Some(s), Some(e), Some(f)) => (s?, e?, f?),
            _ => {
                return Err(DaemonError::GpuResourceLine {
                    line: line.to_string(),
                });
            }
        };
        if flags & WANTED_FLAGS != WANTED_FLAGS {
            continue;
        }
        // Only the BARs that count are validated, and a corrupt one is an
        // error: dropping it would under-size the window and leave the card's
        // BARs unassigned in the guest.
        let size = end
            .checked_sub(start)
            .ok_or_else(|| DaemonError::GpuBarRange {
                line: line.to_string(),
                reason: "its end is below its start",
            })?
            .checked_add(1)
            .ok_or_else(|| DaemonError::GpuBarRange {
                line: line.to_string(),
                reason: "its size overflows 64 bits",
            })?;
        total = total
            .checked_add(size)
            .ok_or_else(|| DaemonError::GpuBarRange {
                line: line.to_string(),
                reason: "it pushes the BAR total past 64 bits",
            })?;
    }
    Ok(total)
}

/// Refuse a window the guest could not address.
///
/// OVMF places the 64-bit aperture above the top of RAM, aligned to its own
/// size, so the window ends at `align_up(top_of_ram, window) + window`; past
/// the guest's address width it assigns no window at all and the card's BARs
/// stay unassigned. The model is OVMF's `PlatformDynamicMmioWindow` in
/// `OvmfPkg/Library/PlatformInitLib`; re-read it before changing this.
pub fn check_mmio64_budget(window_mb: u64, guest_ram_mb: u64) -> Result<(), DaemonError> {
    let top_of_ram_mb = guest_ram_mb.saturating_add(GUEST_LOW_RESERVED_MB);
    let base_mb = top_of_ram_mb
        .div_ceil(window_mb.max(1))
        .saturating_mul(window_mb);
    let top_mb = base_mb.saturating_add(window_mb);
    if top_mb > GUEST_PHYS_MB {
        return Err(DaemonError::GpuMmioBudget {
            window_mb,
            guest_ram_mb,
            top_mb,
        });
    }
    Ok(())
}

/// Round a BAR total to a power-of-two window, in MiB, never below 1 GiB and
/// never above 4 TiB. `double` is the alignment-slack doubling OVMF wants;
/// the un-doubled rounding is the fallback when the doubled window cannot fit
/// the guest.
fn round_window_mb(bar_bytes: u64, double: bool) -> u64 {
    let mb = bar_bytes.div_ceil(1 << 20).max(1);
    // Saturating rather than wrapping: a BAR total near u64::MAX must clamp
    // to the ceiling below, not wrap around to a tiny window.
    let rounded = mb.checked_next_power_of_two().unwrap_or(u64::MAX);
    let window = if double {
        rounded.saturating_mul(2)
    } else {
        rounded
    }
    .max(MIN_WINDOW_MB);
    if window > MAX_WINDOW_MB {
        tracing::warn!(
            window_mb = window,
            max_window_mb = MAX_WINDOW_MB,
            "GPU BARs ask for an MMIO64 window past the ceiling; clamping"
        );
        return MAX_WINDOW_MB;
    }
    window
}

/// Window size in MiB: the BAR total rounded up to a power of two, doubled
/// so OVMF has alignment slack, never below 1 GiB and never above 4 TiB.
pub fn mmio64_window_mb(bar_bytes: u64) -> u64 {
    round_window_mb(bar_bytes, true)
}

/// The window to hand OVMF for a BAR total next to this VM's RAM.
///
/// The doubled window (`mmio64_window_mb`) is tried first, unchanged from
/// before. If the guest's address space cannot hold it, the un-doubled
/// power-of-two rounding is tried next: a window that starts exactly at the
/// top of RAM still leaves every BAR placeable, it just gives OVMF no
/// alignment slack. If neither fits, the error names the smaller, un-doubled
/// window, since that is the one that could have worked.
pub fn mmio64_window_for(bar_bytes: u64, guest_ram_mb: u64) -> Result<u64, DaemonError> {
    let doubled = round_window_mb(bar_bytes, true);
    if check_mmio64_budget(doubled, guest_ram_mb).is_ok() {
        return Ok(doubled);
    }
    let undoubled = round_window_mb(bar_bytes, false);
    check_mmio64_budget(undoubled, guest_ram_mb)?;
    Ok(undoubled)
}

/// The BAR total, in bytes, for a set of cards attached to one VM, from
/// their sysfs BARs.
pub fn gpu_bar_bytes(pci_hosts: &[&str]) -> Result<u64, DaemonError> {
    gpu_bar_bytes_under(Path::new(crate::gpu_cc::SYSFS_PCI_DEVICES), pci_hosts)
}

/// `gpu_bar_bytes` over an explicit devices directory, so a fixture tree
/// can stand in for sysfs.
pub fn gpu_bar_bytes_under(devices_dir: &Path, pci_hosts: &[&str]) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for pci_host in pci_hosts {
        let path = crate::gpu_cc::sysfs_device_dir_under(devices_dir, pci_host).join("resource");
        let contents =
            std::fs::read_to_string(&path).map_err(|source| DaemonError::GpuResourceRead {
                path: path.clone(),
                source,
            })?;
        // Saturating would quietly under-size the window and leave the guest's
        // BARs unassigned, the failure this module exists to prevent.
        total = total
            .checked_add(parse_resource_file(&contents)?)
            .ok_or_else(|| DaemonError::GpuBarTotal {
                pci_host: pci_host.to_string(),
            })?;
    }
    Ok(total)
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

    // Captured from an H200 NVL: BAR0 16 MiB, BAR2 256 GiB (both 64-bit
    // prefetchable), BAR4 32 MiB 64-bit prefetchable, expansion ROM, then the
    // SR-IOV VF BARs (PCI_IOV_RESOURCES) sized for 32 VFs: 256 GiB and 1 GiB.
    const H200_RESOURCE: &str = "\
0x000001c042000000 0x000001c042ffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000014000000000 0x0000017fffffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000001c040000000 0x000001c041ffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000094500000 0x0000000094cfffff 0x0000000000040200
0x0000018000000000 0x000001bfffffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x000001c000000000 0x000001c03fffffff 0x000000000014220c
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
";

    #[test]
    fn sums_only_64bit_prefetchable_memory_bars() {
        let bytes = parse_resource_file(RESOURCE).unwrap();
        assert_eq!(bytes, 128 * (1 << 30) + 32 * (1 << 20));
    }

    #[test]
    fn the_h200_fixture_ignores_the_sriov_vf_bars() {
        // Rows 0-5 (BAR0 16 MiB, BAR2 256 GiB, BAR4 32 MiB) count; the VF
        // BARs at rows 8 and 10 do not, even though their flags match.
        let bytes = parse_resource_file(H200_RESOURCE).unwrap();
        assert_eq!(bytes, 256 * (1 << 30) + 16 * (1 << 20) + 32 * (1 << 20));
    }

    #[test]
    fn a_matching_row_past_the_standard_bars_does_not_count() {
        // Six standard-BAR rows (all zero, so nothing matches), then a VF BAR
        // row at index 7 that would match the flags were it counted.
        let fixture = "\
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000000000000000 0x0000000000000000 0x0000000000000000
0x0000018000000000 0x000001bfffffffff 0x000000000014220c
";
        assert_eq!(parse_resource_file(fixture).unwrap(), 0);
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
    fn the_window_is_clamped_to_the_ceiling() {
        // Just under the ceiling still passes through untouched.
        assert_eq!(mmio64_window_mb(1024 * (1 << 30)), 2 * 1024 * 1024);
        // 4 TiB of BARs would ask for 8 TiB; the ceiling holds.
        assert_eq!(mmio64_window_mb(4 * (1u64 << 40)), MAX_WINDOW_MB);
        // And the rounding cannot overflow into a tiny window.
        assert_eq!(mmio64_window_mb(u64::MAX), MAX_WINDOW_MB);
    }

    #[test]
    fn bytes_sum_every_card_under_the_devices_dir() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["0000:06:00.0", "0000:07:00.0"] {
            let card = dir.path().join(name);
            std::fs::create_dir(&card).unwrap();
            std::fs::write(card.join("resource"), RESOURCE).unwrap();
        }
        let one = ["06:00.0"];
        let two = ["06:00.0", "0000:07:00.0"];
        let per_card = 128 * (1u64 << 30) + 32 * (1 << 20);
        // Two cards add their BAR bytes before any rounding; a domain-less
        // pci_host resolves to the same directory.
        assert_eq!(gpu_bar_bytes_under(dir.path(), &one).unwrap(), per_card);
        assert_eq!(gpu_bar_bytes_under(dir.path(), &two).unwrap(), 2 * per_card);
    }

    #[test]
    fn a_bar_total_across_cards_that_overflows_is_an_error() {
        // Each per-card parse succeeds and only the sum overflows, so the
        // guard has to sit in the loop, not inside one resource file.
        let dir = tempfile::tempdir().unwrap();
        let half = "0x0000000000000000 0x7fffffffffffffff 0x000000000014220c\n";
        for name in ["0000:06:00.0", "0000:07:00.0"] {
            let card = dir.path().join(name);
            std::fs::create_dir(&card).unwrap();
            std::fs::write(card.join("resource"), half).unwrap();
        }
        let both = ["06:00.0", "07:00.0"];
        let error = gpu_bar_bytes_under(dir.path(), &both).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuBarTotal { pci_host } if pci_host == "07:00.0"),
            "{error:?}"
        );
    }

    #[test]
    fn a_card_without_a_resource_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = gpu_bar_bytes_under(dir.path(), &["06:00.0"]).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuResourceRead { path, .. }
                if path.ends_with("0000:06:00.0/resource")),
            "{error:?}"
        );
        assert!(error.to_string().contains("0000:06:00.0"), "{error}");
    }

    #[test]
    fn malformed_lines_are_errors() {
        // Each failure carries the offending text in a field, not baked into a
        // pre-formatted message.
        let short = parse_resource_file("0x1 0x2\n").unwrap_err();
        assert!(
            matches!(&short, DaemonError::GpuResourceLine { line } if line == "0x1 0x2"),
            "{short:?}"
        );
        let not_hex = parse_resource_file("zz 0x2 0x3\n").unwrap_err();
        assert!(
            matches!(&not_hex, DaemonError::GpuResourceField { field, .. } if field == "zz"),
            "{not_hex:?}"
        );
        assert!(not_hex.to_string().contains("hexadecimal"), "{not_hex}");
    }

    #[test]
    fn a_reversed_bar_range_is_an_error() {
        // Skipping a reversed range silently would under-size the window and
        // leave the card's BARs unassigned in the guest.
        let line = "0x0000004000000000 0x0000002000000000 0x000000000014220c\n";
        let error = parse_resource_file(line).unwrap_err();
        assert!(error.to_string().contains("below its start"), "{error}");
    }

    #[test]
    fn a_bar_spanning_the_whole_address_space_is_an_error_not_a_panic() {
        let line = "0x0000000000000000 0xffffffffffffffff 0x000000000014220c\n";
        let error = parse_resource_file(line).unwrap_err();
        assert!(error.to_string().contains("overflows"), "{error}");
    }

    #[test]
    fn a_bar_total_that_overflows_is_an_error() {
        let lines = "\
0x0000000000000000 0x7fffffffffffffff 0x000000000014220c
0x8000000000000000 0xffffffffffffffff 0x000000000014220c
";
        let error = parse_resource_file(lines).unwrap_err();
        assert!(error.to_string().contains("BAR total"), "{error}");
    }

    #[test]
    fn the_budget_takes_one_cards_window_next_to_ordinary_ram() {
        // The 512 GiB window a 128 GiB BAR1 card asks for is aligned to its
        // own size, so it starts at 512 GiB and ends exactly at the ceiling.
        assert!(check_mmio64_budget(512 * 1024, 64 * 1024).is_ok());
        assert!(check_mmio64_budget(1024, 256).is_ok());
    }

    #[test]
    fn the_budget_refuses_a_window_the_guest_cannot_address() {
        let error = check_mmio64_budget(1024 * 1024, 64 * 1024).unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("1048576") && text.contains("65536"),
            "the refusal must name the window and the RAM: {text}"
        );
    }

    #[test]
    fn the_budget_refuses_ram_that_pushes_the_window_over_the_ceiling() {
        // The window fits on its own, but this much RAM forces the firmware
        // to align it up to the next boundary, which is past the ceiling.
        assert!(check_mmio64_budget(512 * 1024, 600 * 1024).is_err());
    }

    #[test]
    fn a_window_that_hits_the_clamp_is_refused_by_the_budget() {
        // The clamp only keeps the fw_cfg number finite; the budget is what
        // refuses the create, so reaching the clamp must not mean a launch.
        let clamped = mmio64_window_mb(u64::MAX);
        assert_eq!(clamped, MAX_WINDOW_MB);
        assert!(check_mmio64_budget(clamped, 2048).is_err());
    }

    const H200_BAR_BYTES: u64 = 256 * (1 << 30) + 16 * (1 << 20) + 32 * (1 << 20);

    #[test]
    fn window_for_falls_back_to_the_undoubled_window_when_the_doubled_one_does_not_fit() {
        // The doubled window (1 TiB) would end at 2 TiB next to a 4 GiB
        // guest, past the 1 TiB the guest can address; the un-doubled window
        // (512 GiB) ends exactly at 1 TiB, which is what boots on hardware.
        assert_eq!(mmio64_window_for(H200_BAR_BYTES, 4096).unwrap(), 512 * 1024);
    }

    #[test]
    fn window_for_keeps_the_doubled_window_when_it_fits() {
        // A card small enough that its doubled window already fits gets no
        // fallback: unchanged behaviour from before this function existed.
        let bar_bytes = 128 * (1u64 << 30) + 32 * (1 << 20);
        assert_eq!(mmio64_window_for(bar_bytes, 64 * 1024).unwrap(), 512 * 1024);
    }

    #[test]
    fn window_for_reports_the_undoubled_window_when_neither_fits() {
        // 600 GiB of BARs: both the doubled (2 TiB) and the un-doubled
        // (1 TiB) window overshoot a 4 GiB guest. The error names the
        // smaller, un-doubled window, since that is the one that could have
        // worked with a bit less RAM.
        let bar_bytes = 600 * (1u64 << 30);
        let error = mmio64_window_for(bar_bytes, 4096).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuMmioBudget { window_mb, .. } if *window_mb == 1024 * 1024),
            "{error:?}"
        );
    }

    #[test]
    fn window_for_errors_when_guest_ram_alone_crowds_out_even_the_undoubled_window() {
        // The H200's un-doubled 512 GiB window fits next to a small guest,
        // but 600 GiB of guest RAM pushes it past the ceiling too.
        let error = mmio64_window_for(H200_BAR_BYTES, 600 * 1024).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuMmioBudget { .. }),
            "{error:?}"
        );
    }
}
