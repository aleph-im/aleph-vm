# Build TDVF, the Intel TDX flavour of OVMF (OvmfPkg/IntelTdx/IntelTdxX64.dsc).
#
# TDVF measures itself into MRTD and the kernel, initrd and cmdline it direct-
# boots into RTMR1/RTMR2, so the TDX runtime pins this exact binary the way
# the SNP runtime pins ovmf.nix's AmdSev build. Same toolchain and pre-built
# BaseTools as ovmf.nix, so both firmwares come out of one edk2 pin.
{ pkgs }:

pkgs.stdenv.mkDerivation {
  pname = "tdvf";
  inherit (pkgs.edk2) version;

  src = pkgs.edk2.srcWithVendoring;

  nativeBuildInputs = with pkgs; [
    python3
    nasm
    acpica-tools
  ];

  inherit (pkgs.edk2) GCC5_X64_PREFIX;

  # EDK2 uses -Wno-format which conflicts with Nix's -Wformat-security hardening.
  hardeningDisable = [ "format" ];

  buildPhase = ''
    runHook preBuild

    export WORKSPACE="$PWD"
    export EDK_TOOLS_PATH="${pkgs.edk2}/BaseTools"
    export PATH="${pkgs.edk2}/BaseTools/BinWrappers/PosixLike:$PATH"
    export PYTHON_COMMAND="${pkgs.python3}/bin/python3"

    mkdir -p Conf
    cp ${pkgs.edk2}/BaseTools/Conf/build_rule.template Conf/build_rule.txt
    cp ${pkgs.edk2}/BaseTools/Conf/tools_def.template  Conf/tools_def.txt
    cp ${pkgs.edk2}/BaseTools/Conf/target.template     Conf/target.txt

    # IntelTdxX64.dsc produces a single OVMF.fd carrying the TDX metadata
    # (TD HOB, CFV, TDVF descriptor) that the TDX module measures into MRTD.
    build -a X64 -t GCC5 -b RELEASE \
      -p OvmfPkg/IntelTdx/IntelTdxX64.dsc \
      -n $NIX_BUILD_CORES

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    install -m644 Build/IntelTdx/RELEASE_GCC5/FV/OVMF.fd $out/OVMF.fd
    runHook postInstall
  '';
}
