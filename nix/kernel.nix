{ pkgs, lib, ... }:

# LTS 6.12, not 6.6: the #VC-handler hardening against malicious-hypervisor
# interrupt/exception injection (HECKLER CVE-2024-25743/25744, WeSee
# CVE-2024-25742) landed in 6.7-rc5/6.9-rc1 and was never backported to 6.6,
# and the pvalidate cache-line-eviction fix (CVE-2025-38560) needs >= 6.12.93.
pkgs.linuxPackages_6_12.kernel.override {
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

    # The current rootfs integrity chain is dm-verity, which needs CRYPTO_SHA256
    # only. CRYPTO_AES/XTS/ESSIV are LUKS/dm-crypt algorithms (aes-xts-plain64),
    # retained for a possible future encrypted-rootfs path; LUKS is a non-goal
    # today, so they are not exercised by the verity-only chain.
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
