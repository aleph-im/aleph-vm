{ pkgs, lib, ... }:

# LTS 6.18 (the 2025 LTS line), not 6.6 or 6.12: the #VC-handler hardening
# against malicious-hypervisor interrupt/exception injection (HECKLER
# CVE-2024-25743/25744, WeSee CVE-2024-25742) landed in 6.7-rc5/6.9-rc1 and
# was never backported to 6.6, and the pvalidate cache-line-eviction fix
# (CVE-2025-38560) landed in mainline before 6.18.0 (6.12 needed the
# 6.12.93 backport). 6.12 reaches EOL around Dec 2026; 6.18 is maintained
# until ~end of 2027. Newer non-LTS lines (7.x) add nothing from that list
# and would EOL under us within months, recreating the frozen-EOL-kernel
# failure mode the nixos-26.05 re-pin fixed.
let
  base = pkgs.linuxPackages_6_18.kernel;
in

# Fail evaluation, not review, if a future channel or package change lowers
# the kernel below the security floor above. 6.18.0 already carries the full
# set, so the floor is simply the pinned LTS line itself.
assert lib.assertMsg (lib.versionAtLeast base.version "6.18")
  ''
    SNP guest kernel ${base.version} is below the security floor (6.18):
    it may lack the HECKLER/WeSee #VC-handler hardening (CVE-2024-25742/
    -25743/-25744, Linux >= 6.9) or the pvalidate cache-line-eviction fix
    (CVE-2025-38560). Do not ship it to confidential guests.
  '';

base.override {
  structuredExtraConfig = with lib.kernel; {
    # SEV-SNP guest support (mkForce to override base config "m" → "y")
    AMD_MEM_ENCRYPT = lib.mkForce yes;
    SEV_GUEST = lib.mkForce yes;
    CRYPTO_DEV_CCP = lib.mkForce yes;
    CRYPTO_DEV_CCP_DD = lib.mkForce yes;
    CRYPTO_DEV_SP_PSP = lib.mkForce yes;

    # Networking (built-in, since we boot from initrd without module loading)
    PACKET = lib.mkForce yes;         # AF_PACKET sockets (required by udhcpc/DHCP)
    UNIX = lib.mkForce yes;           # AF_UNIX sockets

    # Filesystems (built-in for initrd boot)
    EXT4_FS = lib.mkForce yes;        # ext4 rootfs support

    # dm-verity / dm-crypt: BLK_DEV_DM, DM_VERITY, DM_CRYPT default to =m.
    # We load them as modules from the initrd rather than forcing =y, because
    # the kconfig dependency chain (DM_VERITY → BLK_DEV_DM → DAX) conflicts
    # with nixpkgs' generate-config.pl interactive config generator.
    #
    # Disable trusted/encrypted kernel key types — dm-crypt optionally depends
    # on these, but they pull in TPM/TEE subsystems we don't have. cryptsetup
    # manages keys in userspace, so the kernel keyring integration is unnecessary.
    TRUSTED_KEYS = lib.mkForce no;
    ENCRYPTED_KEYS = lib.mkForce no;

    # The platform rootfs integrity chain is dm-verity, which needs
    # CRYPTO_SHA256 only. CRYPTO_AES/XTS/ESSIV are the LUKS2/dm-crypt
    # algorithms (aes-xts-plain64), built in so the confidential-instance
    # image's cryptsetup luksOpen never needs a crypto module load.
    CRYPTO_AES = lib.mkForce yes;
    CRYPTO_XTS = lib.mkForce yes;
    CRYPTO_SHA256 = lib.mkForce yes;
    CRYPTO_ESSIV = lib.mkForce yes;

    # Virtio (for disk and network)
    VIRTIO = lib.mkForce yes;
    VIRTIO_PCI = lib.mkForce yes;
    VIRTIO_BLK = lib.mkForce yes;
    VIRTIO_NET = lib.mkForce yes;
    VIRTIO_CONSOLE = lib.mkForce yes;

    # Hardening — these are default=y upstream, but we set them explicitly
    # so a config change never silently drops them.
    RANDOMIZE_BASE = lib.mkForce yes;       # KASLR
    STACKPROTECTOR_STRONG = lib.mkForce yes;
    FORTIFY_SOURCE = lib.mkForce yes;
    HARDENED_USERCOPY = lib.mkForce yes;

    # Compile out the 32-bit syscall entry paths entirely. Since 6.9 the
    # kernel disables them at runtime on SEV/TDX guests (the CVE-2024-25744
    # mitigation for HECKLER-style int 0x80 injection); removing the code
    # from the build makes that stance unbypassable and shrinks the #VC
    # attack surface. The guest userland is 64-bit-only static musl, so
    # nothing needs compat.
    IA32_EMULATION = lib.mkForce no;
    X86_X32_ABI = lib.mkForce no;

    # Note: MODULES left as default (yes) to avoid interactive config questions.
    # For a minimal production kernel, use a fully custom .config instead.
  };
}
