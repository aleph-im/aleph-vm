{ pkgs, lib, ... }:

# SEV-SNP guest kernel: a whitelist configuration (kernel-config.fragment)
# on top of `make allnoconfig`, built with nixpkgs' manual-config kernel
# builder from the nixpkgs-pinned 6.18 LTS source.
#
# Why not `linuxPackages_6_18.kernel.override { structuredExtraConfig }`
# (the previous form): that layers a few dozen options over nixpkgs' distro
# config, which compiles ~7000 modules (every driver nixpkgs enables) for a
# guest whose initrds ship seven. Any override also loses the binary-cache
# hit, so every golden-measurement CI run spent 2h+ of its 2h20m compiling
# that distro kernel on a 4-vCPU runner. The whitelist builds in minutes and
# is the smaller attack surface a confidential guest wants anyway.
#
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

  fragment = ./kernel-config.fragment;

  # The complete .config: allnoconfig seeded with the fragment
  # (KCONFIG_ALLCONFIG), then olddefconfig to settle the dependencies the
  # fragment's choices pull in. Kconfig silently drops a requested option
  # whose dependencies are unmet (or that no longer exists), and a silently
  # dropped VIRTIO_BLK or SEV_GUEST is a guest that does not boot, so the
  # result is checked line by line against the fragment and the build fails
  # on the first divergence.
  configfile = pkgs.stdenv.mkDerivation {
    pname = "linux-config-snp-guest";
    inherit (base) version src;
    nativeBuildInputs = with pkgs; [ bison flex perl ];
    # The kernel's own Makefiles, nothing from the tree is patched.
    dontPatch = true;
    dontFixup = true;
    buildPhase = ''
      runHook preBuild
      export KCONFIG_NOTIMESTAMP=1
      make ARCH=x86_64 KCONFIG_ALLCONFIG=${fragment} allnoconfig
      make ARCH=x86_64 olddefconfig
      runHook postBuild
    '';
    checkPhase = ''
      runHook preCheck
      status=0
      while IFS= read -r line; do
        case "$line" in
          CONFIG_*=*)
            if ! grep -qxF "$line" .config; then
              echo "kernel config: requested '$line', got '$(grep -E "^(# )?''${line%%=*}[= ]" .config || echo "<absent>")'" >&2
              status=1
            fi
            ;;
          "# CONFIG_"*" is not set")
            sym=''${line#\# }
            sym=''${sym%% is not set}
            if grep -qE "^$sym=" .config; then
              echo "kernel config: requested '$line', got '$(grep -E "^$sym=" .config)'" >&2
              status=1
            fi
            ;;
        esac
      done < ${fragment}
      if [ "$status" -ne 0 ]; then
        echo "kernel config: the fragment was not honoured, see above (missing dependency or renamed symbol?)" >&2
        exit 1
      fi
      runHook postCheck
    '';
    doCheck = true;
    installPhase = ''
      runHook preInstall
      cp .config $out
      runHook postInstall
    '';
  };

  kernel = pkgs.linuxKernel.manualConfig {
    inherit (base) version src modDirVersion;
    inherit configfile;
    # manual-config only needs to know whether the config is modular (it
    # splits out the `modules` output initrd.nix reads from) and whether
    # Rust is on; giving it that directly avoids import-from-derivation on
    # the generated .config.
    config = { CONFIG_MODULES = "y"; };
  };
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

kernel
