# Build OVMF firmware with the AmdSev variant (OvmfPkg/AmdSev/AmdSevX64.dsc).
#
# This variant includes kernel hashing metadata, so the SEV-SNP launch
# measurement covers OVMF + kernel + initrd + cmdline — not just the firmware.
# The standard OvmfPkgX64.dsc does NOT include this metadata.
#
# Uses the upstream EDK2 source from nixpkgs (AmdSev support merged upstream).
# BaseTools are taken pre-built from pkgs.edk2 (already compiled + patched).
{ pkgs }:

pkgs.stdenv.mkDerivation {
  pname = "ovmf-amdsev";
  inherit (pkgs.edk2) version;

  # Full EDK2 source with submodules (OpenSSL, etc.).
  src = pkgs.edk2.srcWithVendoring;

  nativeBuildInputs = with pkgs; [
    python3
    nasm
    acpica-tools
    which       # grub.sh uses `which` to find grub-mkimage
    # AmdSev prebuild step embeds a GRUB image for measured direct boot.
    grub2_efi
    dosfstools  # mkfs.msdos
    mtools      # mcopy
  ];

  # Match the GCC prefix that EDK2 expects for the GCC5 toolchain.
  inherit (pkgs.edk2) GCC5_X64_PREFIX;

  # EDK2 uses -Wno-format which conflicts with Nix's -Wformat-security hardening.
  hardeningDisable = [ "format" ];

  # Remove GRUB modules not available in nixpkgs' grub 2.12:
  # - linuxefi: merged into the linux module in GRUB 2.12
  # - sevsecret: SEV secret injection, not built by nixpkgs
  # (We use direct kernel boot, so the embedded GRUB is unused anyway.)
  postPatch = ''
    sed -i '/linuxefi/d; /sevsecret/d' OvmfPkg/AmdSev/Grub/grub.sh
  '';

  buildPhase = ''
    runHook preBuild

    # Use pre-built BaseTools from the nixpkgs edk2 package.
    # This avoids rebuilding the C tools (GenFv, GenFw, etc.) and
    # gives us already-patched shebangs.
    export WORKSPACE="$PWD"
    export EDK_TOOLS_PATH="${pkgs.edk2}/BaseTools"
    export PATH="${pkgs.edk2}/BaseTools/BinWrappers/PosixLike:$PATH"
    export PYTHON_COMMAND="${pkgs.python3}/bin/python3"

    # Seed Conf/ templates from the pre-built BaseTools.
    mkdir -p Conf
    cp ${pkgs.edk2}/BaseTools/Conf/build_rule.template Conf/build_rule.txt
    cp ${pkgs.edk2}/BaseTools/Conf/tools_def.template  Conf/tools_def.txt
    cp ${pkgs.edk2}/BaseTools/Conf/target.template     Conf/target.txt

    # AmdSevX64.dsc produces a single OVMF.fd (no CODE/VARS split)
    # with SEV-SNP kernel hashing metadata embedded.
    # RELEASE build eliminates verbose debug output over serial,
    # significantly reducing boot time.
    build -a X64 -t GCC5 -b RELEASE \
      -p OvmfPkg/AmdSev/AmdSevX64.dsc \
      -n $NIX_BUILD_CORES

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    install -m644 Build/AmdSev/RELEASE_GCC5/FV/OVMF.fd $out/OVMF.fd
    runHook postInstall
  '';
}
