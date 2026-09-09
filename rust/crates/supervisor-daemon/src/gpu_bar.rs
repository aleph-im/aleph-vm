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
const MIN_WINDOW_MB: u64 = 1024;
/// The largest window the daemon will ever ask OVMF for, in MiB (4 TiB). The
/// doubling above is unbounded on its own, so a card (or a kernel that
/// reports nonsense in its `resource` file) with absurd BARs would otherwise
/// hand fw_cfg a window no firmware can lay out, and the VM would fail deep
/// inside OVMF instead of here. Far above any real card: today's largest is
/// 128 GiB of BAR1, which asks for 512 GiB.
///
/// This caps the number handed to fw_cfg; it is not a statement about what a
/// guest can reach. `check_mmio64_budget` is the tighter and later gate: it
/// refuses anything the guest's own address space cannot hold, which today
/// is a quarter of this. A window that reaches this clamp is therefore
/// refused rather than launched, and the clamp is there so the arithmetic
/// stays sane on the way to that refusal.
const MAX_WINDOW_MB: u64 = 4 * 1024 * 1024;

/// Guest physical address space, in MiB. A confidential VM launches with
/// `-cpu EPYC-v4` unless the spec names another model, and that model's
/// default physical address width is 40 bits, so the firmware has 1 TiB to
/// place everything in.
///
/// A spec-supplied `cpu_model` does not move this figure. The confidential
/// argv passes the model name on its own, with no `phys-bits` and no
/// `host-phys-bits`, and QEMU's own default for a named x86 model is 40
/// bits whichever model it is: the width follows the option, not the model.
/// Should a future argv widen it, the only effect here is that this check
/// refuses a window the guest could in fact have addressed, which fails a
/// create that would have worked rather than booting a card into a guest
/// that cannot reach it.
const GUEST_PHYS_MB: u64 = 1 << 20;

/// What sits below the guest's RAM and is not counted in the RAM figure:
/// the 32-bit MMIO hole under 4 GiB that QEMU makes the RAM skip over, plus
/// the firmware's own reservations and the ACPI tables. Added to the RAM
/// before the window is aligned, so a VM whose RAM stops just short of an
/// alignment boundary is not sized as if the window could start there.
const GUEST_LOW_RESERVED_MB: u64 = 4 * 1024;

/// Sum the sizes of the 64-bit prefetchable memory BARs listed in a sysfs
/// `resource` file (`start end flags` per line, hex).
pub fn parse_resource_file(contents: &str) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for line in contents.lines().filter(|l| !l.trim().is_empty()) {
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
        // Only the BARs that count are validated: an unused or 32-bit BAR
        // contributes nothing, so whatever it holds cannot mis-size the
        // window. A counted BAR that is reversed or spans the whole address
        // space is a corrupt read, and silently dropping it would under-size
        // the window and leave the card's BARs unassigned in the guest.
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
/// The firmware places the 64-bit window above the guest's RAM, on a
/// boundary of the window's own size (`mmio64_window_mb` always returns a
/// power of two, and the alignment matches it), so the window ends at
/// `align_up(top_of_ram, window) + window`. That has to stay inside the
/// address space the guest's physical address width gives it, or the
/// firmware assigns no window at all and the guest finds the card's BARs
/// unassigned: a device that enumerates and then does nothing.
///
/// The placement model above is OVMF's, in `OvmfPkg/Library/PlatformInitLib`
/// (`PlatformDynamicMmioWindow` and `PlatformAddressWidthFromCpuid`): it
/// derives the address width from CPUID, puts the 64-bit PCI MMIO aperture
/// above the top of low and high RAM, and aligns the aperture to its own
/// size. Re-read that code before changing anything here.
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
            budget_mb: GUEST_PHYS_MB,
        });
    }
    Ok(())
}

/// Window size in MiB: the BAR total rounded up to a power of two, doubled
/// so OVMF has alignment slack, never below 1 GiB and never above 4 TiB.
pub fn mmio64_window_mb(bar_bytes: u64) -> u64 {
    let mb = bar_bytes.div_ceil(1 << 20).max(1);
    // Saturating rather than wrapping: a BAR total near u64::MAX must clamp
    // to the ceiling below, not wrap around to a tiny window.
    let window = mb
        .checked_next_power_of_two()
        .and_then(|rounded| rounded.checked_mul(2))
        .unwrap_or(u64::MAX)
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

/// The window for a set of cards attached to one VM, from their sysfs BARs.
pub fn gpu_mmio64_mb(pci_hosts: &[String]) -> Result<u64, DaemonError> {
    gpu_mmio64_mb_under(Path::new(crate::gpu_cc::SYSFS_PCI_DEVICES), pci_hosts)
}

/// `gpu_mmio64_mb` over an explicit devices directory, so a fixture tree
/// can stand in for sysfs.
pub fn gpu_mmio64_mb_under(devices_dir: &Path, pci_hosts: &[String]) -> Result<u64, DaemonError> {
    let mut total = 0u64;
    for pci_host in pci_hosts {
        let path = crate::gpu_cc::sysfs_device_dir_under(devices_dir, pci_host).join("resource");
        let contents =
            std::fs::read_to_string(&path).map_err(|source| DaemonError::GpuResourceRead {
                path: path.clone(),
                source,
            })?;
        // Saturating here would quietly under-size the window, which is the
        // failure this module exists to prevent: the guest would enumerate
        // the card and find its BARs unassigned.
        total = total
            .checked_add(parse_resource_file(&contents)?)
            .ok_or_else(|| DaemonError::GpuBarTotal {
                pci_host: pci_host.to_string(),
            })?;
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
    fn the_window_is_clamped_to_the_ceiling() {
        // Just under the ceiling still passes through untouched.
        assert_eq!(mmio64_window_mb(1024 * (1 << 30)), 2 * 1024 * 1024);
        // 4 TiB of BARs would ask for 8 TiB; the ceiling holds.
        assert_eq!(mmio64_window_mb(4 * (1u64 << 40)), MAX_WINDOW_MB);
        // And the rounding cannot overflow into a tiny window.
        assert_eq!(mmio64_window_mb(u64::MAX), MAX_WINDOW_MB);
    }

    #[test]
    fn window_sums_every_card_under_the_devices_dir() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["0000:06:00.0", "0000:07:00.0"] {
            let card = dir.path().join(name);
            std::fs::create_dir(&card).unwrap();
            std::fs::write(card.join("resource"), RESOURCE).unwrap();
        }
        let one = ["06:00.0".to_string()];
        let two = ["06:00.0".to_string(), "0000:07:00.0".to_string()];
        // One card: 128 GiB + 32 MiB rounds to 256 GiB, doubled. Two cards
        // add up before the rounding, so the window doubles again; a
        // domain-less pci_host resolves to the same directory.
        assert_eq!(gpu_mmio64_mb_under(dir.path(), &one).unwrap(), 512 * 1024);
        assert_eq!(gpu_mmio64_mb_under(dir.path(), &two).unwrap(), 1024 * 1024);
    }

    #[test]
    fn a_bar_total_across_cards_that_overflows_is_an_error() {
        // Two cards whose BARs each fill half the address space: the per-card
        // parse succeeds and only the sum overflows, so the guard has to sit
        // in the loop over the cards, not just inside one resource file.
        let dir = tempfile::tempdir().unwrap();
        let half = "0x0000000000000000 0x7fffffffffffffff 0x000000000014220c\n";
        for name in ["0000:06:00.0", "0000:07:00.0"] {
            let card = dir.path().join(name);
            std::fs::create_dir(&card).unwrap();
            std::fs::write(card.join("resource"), half).unwrap();
        }
        let both = ["06:00.0".to_string(), "07:00.0".to_string()];
        let error = gpu_mmio64_mb_under(dir.path(), &both).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuBarTotal { pci_host } if pci_host == "07:00.0"),
            "{error:?}"
        );
    }

    #[test]
    fn a_card_without_a_resource_file_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let error = gpu_mmio64_mb_under(dir.path(), &["06:00.0".to_string()]).unwrap_err();
        assert!(
            matches!(&error, DaemonError::GpuResourceRead { path, .. }
                if path.ends_with("0000:06:00.0/resource")),
            "{error:?}"
        );
        assert!(error.to_string().contains("0000:06:00.0"), "{error}");
    }

    #[test]
    fn malformed_lines_are_errors() {
        // Each failure names what it saw, and carries the offending text in a
        // field rather than in a pre-formatted string, so a caller can log the
        // line or the field without re-parsing the message.
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
        // A region whose end is below its start is not a BAR any window can
        // be sized from. Skipping it silently would under-size the window,
        // and the guest would find the card's BARs unassigned.
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
        // The two ceilings are not alternatives: the clamp keeps the number
        // handed to fw_cfg finite, and the budget is what actually refuses
        // the create. A card absurd enough to reach the clamp must not be
        // launched just because the clamp made its window representable.
        let clamped = mmio64_window_mb(u64::MAX);
        assert_eq!(clamped, MAX_WINDOW_MB);
        assert!(check_mmio64_budget(clamped, 2048).is_err());
    }
}
