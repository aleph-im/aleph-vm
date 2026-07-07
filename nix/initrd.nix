{ pkgs, attest-agent, kernel, init-script, ... }:

let
  # veritysetup needs to be statically linked for the initrd environment.
  staticCryptsetup = pkgs.pkgsStatic.cryptsetup;

  # Statically-linked nft for the guest firewall (init.sh). withCli = false drops
  # the interactive-shell libedit dependency (not needed: init.sh drives nft in
  # batch mode via `nft -f -`), which also lets it link statically for the initrd.
  staticNft = pkgs.pkgsStatic.nftables.override { withCli = false; };

  # dm-verity kernel modules (default =m in the kernel config).
  # Load order: dax -> dm-mod -> dm-bufio -> dm-verity.
  #
  # The measured-boot chain here is dm-verity for rootfs INTEGRITY only. The
  # aleph-cvm donor also baked dm-crypt.ko for its LUKS encrypted-rootfs mode;
  # that mode is out of scope for this backport (design section 6 non-goals),
  # so dm-crypt is deliberately NOT included. See rust-port-divergences.
  modDir = "${kernel}/lib/modules/${kernel.modDirVersion}/kernel";
  dmModules = pkgs.runCommand "dm-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/drivers/dax/dax.ko.xz > $out/dax.ko
    xz -d -k -c ${modDir}/drivers/md/dm-mod.ko.xz > $out/dm-mod.ko
    xz -d -k -c ${modDir}/drivers/md/dm-bufio.ko.xz > $out/dm-bufio.ko
    xz -d -k -c ${modDir}/drivers/md/dm-verity.ko.xz > $out/dm-verity.ko
  '';

  # nftables kernel modules for the guest firewall. NF_TABLES is =m in the
  # kernel config (NETFILTER and NF_TABLES_INET are built in), so the guest
  # firewall needs nf_tables.ko plus its two dependencies (from modules.dep:
  # nf_tables.ko -> nfnetlink.ko, libcrc32c.ko). A stateless input filter
  # (iif lo / tcp dport accept, drop policy) needs no conntrack module.
  # Load order: nfnetlink -> libcrc32c -> nf_tables.
  nftModules = pkgs.runCommand "nft-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/net/netfilter/nfnetlink.ko.xz > $out/nfnetlink.ko
    xz -d -k -c ${modDir}/lib/libcrc32c.ko.xz > $out/libcrc32c.ko
    xz -d -k -c ${modDir}/net/netfilter/nf_tables.ko.xz > $out/nf_tables.ko
  '';
in
pkgs.makeInitrd {
  contents = [
    { object = "${pkgs.busybox}/bin/busybox"; symlink = "/bin/busybox"; }
    { object = init-script; symlink = "/init"; }
    { object = "${attest-agent}/bin/aleph-attest-agent"; symlink = "/bin/aleph-attest-agent"; }
    { object = "${staticCryptsetup}/bin/veritysetup"; symlink = "/bin/veritysetup"; }
    { object = "${staticNft}/bin/nft"; symlink = "/bin/nft"; }
    # dm-verity kernel modules (loaded by init.sh).
    { object = "${dmModules}/dax.ko"; symlink = "/lib/modules/dax.ko"; }
    { object = "${dmModules}/dm-mod.ko"; symlink = "/lib/modules/dm-mod.ko"; }
    { object = "${dmModules}/dm-bufio.ko"; symlink = "/lib/modules/dm-bufio.ko"; }
    { object = "${dmModules}/dm-verity.ko"; symlink = "/lib/modules/dm-verity.ko"; }
    # netfilter modules for the guest firewall (loaded by init.sh).
    { object = "${nftModules}/nfnetlink.ko"; symlink = "/lib/modules/nfnetlink.ko"; }
    { object = "${nftModules}/libcrc32c.ko"; symlink = "/lib/modules/libcrc32c.ko"; }
    { object = "${nftModules}/nf_tables.ko"; symlink = "/lib/modules/nf_tables.ko"; }
  ];
}
