{ pkgs, attest-agent, kernel, init-script, init-common-script, udhcpc-script, udhcpc6-script
, withVerity ? true, withNft ? true, withLuks ? false, ... }:

let
  # veritysetup/cryptsetup need to be statically linked for the initrd
  # environment. One derivation covers both: the cryptsetup package builds
  # cryptsetup, veritysetup and integritysetup as separate binaries from the
  # same source tree and output.
  staticCryptsetup = pkgs.pkgsStatic.cryptsetup;

  # Statically-linked nft for the guest firewall (init.sh). withCli = false drops
  # the interactive-shell libedit dependency (not needed: init.sh drives nft in
  # batch mode via `nft -f -`), which also lets it link statically for the initrd.
  staticNft = pkgs.pkgsStatic.nftables.override { withCli = false; };

  # dm-* kernel modules (default =m in the kernel config). Load order:
  # dm-mod -> dm-bufio -> dm-verity (verity mode) / dm-mod -> dm-crypt (luks
  # mode). dax.ko is gone: nixos-26.05 kernels build CONFIG_DAX=y (built in),
  # so dm-mod no longer has a dax module dependency. Modules also moved out
  # of the kernel's main output into a dedicated `modules` output on that
  # channel.
  #
  # dm-mod and dm-bufio are in the always-on base module set below: dm-bufio
  # is needed only by dm-verity, but it is harmless (unused) on a luks-only
  # image, and keeping it out of the per-flavor split avoids a third
  # conditional list for a single small module.
  modDir = "${kernel.modules}/lib/modules/${kernel.modDirVersion}/kernel";
  dmModules = pkgs.runCommand "dm-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/drivers/md/dm-mod.ko.xz > $out/dm-mod.ko
    xz -d -k -c ${modDir}/drivers/md/dm-bufio.ko.xz > $out/dm-bufio.ko
    xz -d -k -c ${modDir}/drivers/md/dm-verity.ko.xz > $out/dm-verity.ko
  '';

  # dm-crypt kernel module for the LUKS instance image. modules.dep is the
  # source of truth for its dependency closure; the build fails loudly if it
  # ever grows beyond dm-mod (which the instance initrd ships anyway).
  dmCryptModules = pkgs.runCommand "dm-crypt-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    dep=$(grep '/dm-crypt.ko.xz:' ${kernel.modules}/lib/modules/${kernel.modDirVersion}/modules.dep)
    extra=$(echo "$dep" | cut -d: -f2- | tr ' ' '\n' | grep -v '^$' | grep -v 'dm-mod.ko' || true)
    if [ -n "$extra" ]; then
      echo "error: dm-crypt.ko has unexpected module deps: $extra" >&2
      exit 1
    fi
    mkdir -p $out
    xz -d -k -c ${modDir}/drivers/md/dm-crypt.ko.xz > $out/dm-crypt.ko
  '';

  # init.sh treats a failing `udhcpc6` as "stay IPv4-only" (deliberate, to
  # tolerate daemon/image version skew), so a busybox built without the
  # applet would silently defeat guest IPv6 instead of failing loudly.
  # Assert at image build time that the applet is present: the only drift
  # vector is a nixpkgs flake.lock bump changing the default busybox config,
  # which is exactly when this check runs again.
  #
  # pkgsStatic: the initrd below ships REGULAR FILES only (no nix store
  # closure), so every binary in it must be statically linked. pkgs.busybox
  # is a dynamically linked glibc build and would fail to exec.
  checkedBusybox = pkgs.runCommand "busybox-with-udhcpc6" { } ''
    ${pkgs.pkgsStatic.busybox}/bin/busybox --list | grep -qx udhcpc6 || {
      echo "error: busybox lacks the udhcpc6 applet; guest DHCPv6 would silently no-op." >&2
      echo "Enable CONFIG_UDHCPC6 via a busybox extraConfig override." >&2
      exit 1
    }
    mkdir -p $out/bin
    cp ${pkgs.pkgsStatic.busybox}/bin/busybox $out/bin/busybox
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
  # Archive contents: one entry per file that must exist in the guest, at its
  # final path, as a regular file with a fixed mode. This replaces
  # pkgs.makeInitrd, which copies the nix CLOSURE of each object into the
  # cpio (nix/store/<hash>-.../...) and symlinks the final path to it. That
  # closure form embeds every object's store path, so the initrd bytes, and
  # with them the SEV-SNP launch measurement, changed whenever a store path
  # changed, even with byte-identical binaries (the attest-agent derivation
  # hash covers the whole cargo workspace, so any Rust change anywhere moved
  # the measurement). It also dragged glibc, headers and man pages into the
  # guest. Here the measurement is a function of file CONTENT only.
  entries =
    [
      { source = "${checkedBusybox}/bin/busybox"; path = "bin/busybox"; mode = "755"; }
      { source = init-script; path = "init"; mode = "755"; }
      { source = init-common-script; path = "bin/init-common.sh"; mode = "755"; }
      { source = udhcpc-script; path = "bin/udhcpc.script"; mode = "755"; }
      { source = udhcpc6-script; path = "bin/udhcpc6.script"; mode = "755"; }
      { source = "${attest-agent}/bin/aleph-attest-agent"; path = "bin/aleph-attest-agent"; mode = "755"; }
      # dm-mod/dm-bufio are always shipped: dm-bufio is dm-verity-only but
      # harmless on a luks image (see the dmModules comment above).
      { source = "${dmModules}/dm-mod.ko"; path = "lib/modules/dm-mod.ko"; mode = "644"; }
      { source = "${dmModules}/dm-bufio.ko"; path = "lib/modules/dm-bufio.ko"; mode = "644"; }
    ]
    # dm-verity rootfs integrity (v-program image).
    ++ pkgs.lib.optionals withVerity [
      { source = "${staticCryptsetup}/bin/veritysetup"; path = "bin/veritysetup"; mode = "755"; }
      { source = "${dmModules}/dm-verity.ko"; path = "lib/modules/dm-verity.ko"; mode = "644"; }
    ]
    # Guest firewall (v-program image only; instances get no in-guest
    # firewall, see init-instance.sh).
    ++ pkgs.lib.optionals withNft [
      { source = "${staticNft}/bin/nft"; path = "bin/nft"; mode = "755"; }
      { source = "${nftModules}/nfnetlink.ko"; path = "lib/modules/nfnetlink.ko"; mode = "644"; }
      { source = "${nftModules}/nf_tables.ko"; path = "lib/modules/nf_tables.ko"; mode = "644"; }
    ]
    # LUKS encrypted rootfs (confidential-instance image).
    ++ pkgs.lib.optionals withLuks [
      { source = "${staticCryptsetup}/bin/cryptsetup"; path = "bin/cryptsetup"; mode = "755"; }
      { source = "${dmCryptModules}/dm-crypt.ko"; path = "lib/modules/dm-crypt.ko"; mode = "644"; }
    ];

  installEntries = pkgs.lib.concatMapStringsSep "\n"
    (e: "install -D -m ${e.mode} ${e.source} root/${e.path}")
    entries;
in
pkgs.runCommand "initrd" {
  nativeBuildInputs = [ pkgs.cpio pkgs.gzip pkgs.file ];
} ''
  mkdir -p root/dev root/proc root/sys
  ${installEntries}

  # Every executable must be static: there is no loader or libc in here.
  for f in root/bin/* root/init; do
    if file -b "$f" | grep -q 'dynamically linked'; then
      echo "error: $f is dynamically linked; the content-only initrd cannot run it" >&2
      exit 1
    fi
  done

  # Same reproducible cpio recipe as nixpkgs' makeInitrd (fixed mtime,
  # sorted entries, root ownership, gzip -9n) minus the store closure.
  (cd root && find . -mindepth 1 -exec touch -h -d '@1' '{}' +)
  (cd root && find . -mindepth 1 -printf '%P\0' | sort -z \
    | cpio --quiet -o -H newc -R +0:+0 --reproducible --null \
    | gzip -9n > ../initrd.gz)

  # Contract check: no store path may ever end up in the archive again.
  if gzip -dc initrd.gz | cpio -t --quiet | grep -q '^nix/'; then
    echo "error: initrd embeds nix store paths; the launch measurement would track derivation hashes" >&2
    exit 1
  fi

  mkdir -p $out
  mv initrd.gz $out/initrd
  ln -s initrd $out/initrd.gz
''
