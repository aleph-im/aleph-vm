//! SEV host CPUID reader: the Rust equivalent of the Python
//! `cpuid.features.secure_encryption_info()`
//! (venv `cpuid/features.py`, leaf `0x8000001F`).
//!
//! The confidential `-object sev-guest` argv carries two values that cannot be
//! taken from the on-disk config: `cbitpos` (the memory-encryption C-bit
//! position) and `reduced-phys-bits` (the guest physical-address-space
//! reduction). The Python controller reads them at launch from host CPUID via
//! `secure_encryption_info()`. This module reproduces that read.
//!
//! These values are unreadable on a non-SEV CI host, so the argv builder takes
//! a [`SevHostInfo`] by injection (fixtures and tests pass fixed values). The
//! runtime reader [`SevHostInfo::read`] is only called on the real launch path
//! and reports "not an SEV platform" off-SEV.

/// The SEV C-bit position and physical-address reduction, read from host CPUID
/// leaf `0x8000001F` (EBX). Feeds the `-object sev-guest` `cbitpos` /
/// `reduced-phys-bits` fields. Injected into the argv builder so tests and
/// fixtures can pass fixed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevHostInfo {
    /// `SecureEncryptionEbx.c_bit_position` (EBX bits 0..6).
    pub cbitpos: u32,
    /// `SecureEncryptionEbx.phys_addr_reduction` (EBX bits 6..12).
    pub reduced_phys_bits: u32,
}

/// AMD "Encrypted Memory Capabilities" CPUID leaf.
const SEV_CPUID_LEAF: u32 = 0x8000_001F;

/// Highest-extended-leaf query (`__cpuid(0x80000000).eax` is the max leaf).
const CPUID_EXT_MAX_LEAF: u32 = 0x8000_0000;

/// `SecureEncryptionEax.has_sev` (EAX bit 1) in the SEV leaf.
const HAS_SEV_BIT: u32 = 1 << 1;

impl SevHostInfo {
    /// Decode the EBX register of CPUID leaf `0x8000001F` into the two fields,
    /// matching the Python `SecureEncryptionEbx` `RegisterField` masks:
    /// `c_bit_position = RegisterField(int, 0, 6)` (bits 0..6) and
    /// `phys_addr_reduction = RegisterField(int, 6, 6)` (bits 6..12), where a
    /// `RegisterField(_, offset, length)` extracts `(reg >> offset) & mask`.
    fn decode_ebx(ebx: u32) -> Self {
        Self {
            cbitpos: ebx & 0x3F,
            reduced_phys_bits: (ebx >> 6) & 0x3F,
        }
    }

    /// Read the SEV info from host CPUID, the equivalent of the Python
    /// `secure_encryption_info()`. Returns `None` when not on an AMD SEV
    /// platform: the extended leaf is unsupported, or the SEV feature bit is
    /// clear. The launch path turns a `None` into a clear "not an SEV
    /// platform" refusal (see `rust-port-divergences.md`: the Python only
    /// refuses when the raw `cpuid` call raises, so a non-SEV host would slip
    /// through with `cbitpos=0`; the Rust fails closed on the SEV bit instead).
    #[cfg(target_arch = "x86_64")]
    pub fn read() -> Option<Self> {
        // SAFETY: `__cpuid` is safe to execute on any x86_64 CPU; the leaves
        // are compile-time constants. On a CPU that does not implement the
        // extended leaf we bail out before reading it.
        let max_leaf = unsafe { std::arch::x86_64::__cpuid(CPUID_EXT_MAX_LEAF).eax };
        if max_leaf < SEV_CPUID_LEAF {
            return None;
        }
        let result = unsafe { std::arch::x86_64::__cpuid(SEV_CPUID_LEAF) };
        if result.eax & HAS_SEV_BIT == 0 {
            return None;
        }
        Some(Self::decode_ebx(result.ebx))
    }

    /// Off-x86_64 there is no SEV; always `None` (the launch path refuses).
    #[cfg(not(target_arch = "x86_64"))]
    pub fn read() -> Option<Self> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The EBX decode matches the Python `RegisterField` masks: cbitpos is the
    /// low 6 bits, reduced-phys-bits the next 6. Pin the arithmetic with the
    /// fixture values (cbitpos=51, reduced=1): `51 | (1 << 6) == 115`.
    #[test]
    fn decode_ebx_splits_the_two_six_bit_fields() {
        let info = SevHostInfo::decode_ebx(51 | (1 << 6));
        assert_eq!(info.cbitpos, 51);
        assert_eq!(info.reduced_phys_bits, 1);
    }

    /// High bits above bit 12 (other EBX fields, e.g. num_vm_permission_levels)
    /// must not bleed into either field: both are masked to 6 bits.
    #[test]
    fn decode_ebx_masks_out_unrelated_high_bits() {
        let info = SevHostInfo::decode_ebx(0xFFFF_FFFF);
        assert_eq!(info.cbitpos, 0x3F);
        assert_eq!(info.reduced_phys_bits, 0x3F);
    }
}
