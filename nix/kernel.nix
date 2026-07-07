{ pkgs, lib, ... }:

pkgs.linuxPackages_6_6.kernel.override {
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

    # Crypto algorithms required by dm-crypt / LUKS (aes-xts-plain64).
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

    # Note: MODULES left as default (yes) to avoid interactive config questions.
    # For a minimal production kernel, use a fully custom .config instead.
  };
}
