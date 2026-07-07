{ pkgs, attest-agent, kernel, init-script, ... }:

let
  # veritysetup needs to be statically linked for the initrd environment.
  staticCryptsetup = pkgs.pkgsStatic.cryptsetup;

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
in
pkgs.makeInitrd {
  contents = [
    { object = "${pkgs.busybox}/bin/busybox"; symlink = "/bin/busybox"; }
    { object = init-script; symlink = "/init"; }
    { object = "${attest-agent}/bin/aleph-attest-agent"; symlink = "/bin/aleph-attest-agent"; }
    { object = "${staticCryptsetup}/bin/veritysetup"; symlink = "/bin/veritysetup"; }
    # dm-verity kernel modules (loaded by init.sh).
    { object = "${dmModules}/dax.ko"; symlink = "/lib/modules/dax.ko"; }
    { object = "${dmModules}/dm-mod.ko"; symlink = "/lib/modules/dm-mod.ko"; }
    { object = "${dmModules}/dm-bufio.ko"; symlink = "/lib/modules/dm-bufio.ko"; }
    { object = "${dmModules}/dm-verity.ko"; symlink = "/lib/modules/dm-verity.ko"; }
  ];
}
