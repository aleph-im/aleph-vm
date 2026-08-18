{ pkgs, attest-agent, kernel, init-script, init-common-script, udhcpc-script, udhcpc6-script, ... }:

let
  # veritysetup needs to be statically linked for the initrd environment.
  staticCryptsetup = pkgs.pkgsStatic.cryptsetup;

  # Statically-linked nft for the guest firewall (init.sh). withCli = false drops
  # the interactive-shell libedit dependency (not needed: init.sh drives nft in
  # batch mode via `nft -f -`), which also lets it link statically for the initrd.
  staticNft = pkgs.pkgsStatic.nftables.override { withCli = false; };

  # dm-verity kernel modules (default =m in the kernel config).
  # Load order: dm-mod -> dm-bufio -> dm-verity. dax.ko is gone: nixos-26.05
  # kernels build CONFIG_DAX=y (built in), so dm-mod no longer has a dax
  # module dependency. Modules also moved out of the kernel's main output
  # into a dedicated `modules` output on that channel.
  #
  # The measured-boot chain here is dm-verity for rootfs INTEGRITY only. The
  # aleph-cvm donor also baked dm-crypt.ko for its LUKS encrypted-rootfs mode;
  # that mode is out of scope for this backport (design section 6 non-goals),
  # so dm-crypt is deliberately NOT included. See rust-port-divergences.
  modDir = "${kernel.modules}/lib/modules/${kernel.modDirVersion}/kernel";
  dmModules = pkgs.runCommand "dm-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/drivers/md/dm-mod.ko.xz > $out/dm-mod.ko
    xz -d -k -c ${modDir}/drivers/md/dm-bufio.ko.xz > $out/dm-bufio.ko
    xz -d -k -c ${modDir}/drivers/md/dm-verity.ko.xz > $out/dm-verity.ko
  '';

  # init.sh treats a failing `udhcpc6` as "stay IPv4-only" (deliberate, to
  # tolerate daemon/image version skew), so a busybox built without the
  # applet would silently defeat guest IPv6 instead of failing loudly.
  # Assert at image build time that the applet is present: the only drift
  # vector is a nixpkgs flake.lock bump changing the default busybox config,
  # which is exactly when this check runs again.
  checkedBusybox = pkgs.runCommand "busybox-with-udhcpc6" { } ''
    ${pkgs.busybox}/bin/busybox --list | grep -qx udhcpc6 || {
      echo "error: busybox lacks the udhcpc6 applet; guest DHCPv6 would silently no-op." >&2
      echo "Enable CONFIG_UDHCPC6 via a busybox extraConfig override." >&2
      exit 1
    }
    mkdir -p $out/bin
    cp ${pkgs.busybox}/bin/busybox $out/bin/busybox
  '';

  # nftables kernel modules for the guest firewall. NF_TABLES is =m in the
  # kernel config (NETFILTER and NF_TABLES_INET are built in), so the guest
  # firewall needs nf_tables.ko plus its dependency (from modules.dep:
  # nf_tables.ko -> nfnetlink.ko). libcrc32c.ko is gone: kernels >= 6.15
  # removed it and provide crc32c as a built-in library (NET_CRC32C=y here).
  # A stateless input filter (iif lo / tcp dport accept, drop policy) needs
  # no conntrack module. Load order: nfnetlink -> nf_tables.
  nftModules = pkgs.runCommand "nft-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/net/netfilter/nfnetlink.ko.xz > $out/nfnetlink.ko
    xz -d -k -c ${modDir}/net/netfilter/nf_tables.ko.xz > $out/nf_tables.ko
  '';
in
pkgs.makeInitrd {
  contents = [
    { object = "${checkedBusybox}/bin/busybox"; symlink = "/bin/busybox"; }
    { object = init-script; symlink = "/init"; }
    { object = init-common-script; symlink = "/bin/init-common.sh"; }
    { object = udhcpc-script; symlink = "/bin/udhcpc.script"; }
    { object = udhcpc6-script; symlink = "/bin/udhcpc6.script"; }
    { object = "${attest-agent}/bin/aleph-attest-agent"; symlink = "/bin/aleph-attest-agent"; }
    { object = "${staticCryptsetup}/bin/veritysetup"; symlink = "/bin/veritysetup"; }
    { object = "${staticNft}/bin/nft"; symlink = "/bin/nft"; }
    # dm-verity kernel modules (loaded by init.sh).
    { object = "${dmModules}/dm-mod.ko"; symlink = "/lib/modules/dm-mod.ko"; }
    { object = "${dmModules}/dm-bufio.ko"; symlink = "/lib/modules/dm-bufio.ko"; }
    { object = "${dmModules}/dm-verity.ko"; symlink = "/lib/modules/dm-verity.ko"; }
    # netfilter modules for the guest firewall (loaded by init.sh).
    { object = "${nftModules}/nfnetlink.ko"; symlink = "/lib/modules/nfnetlink.ko"; }
    { object = "${nftModules}/nf_tables.ko"; symlink = "/lib/modules/nf_tables.ko"; }
  ];
}
