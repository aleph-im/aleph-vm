{ pkgs, lib, ... }:

# NVIDIA's attestation SDK (libnvat) and its CLI (nvattest): the in-guest
# verifier that checks the GPU's evidence against NVIDIA's RIMs and OCSP at
# boot and sets the GPU ready state. Pinned by commit; every FetchContent
# input is supplied from a fixed-output fetch so the build never touches the
# network and is reproducible. USE_SYSTEM_DEPS takes OpenSSL, curl, libxml2
# and xmlsec1 from nixpkgs instead of the ExternalProject source builds
# upstream uses for RHEL8 compatibility.
let
  version = "1.2.2";

  # attestation-sdk has no v1.2.2 git tag: upstream tags are date-stamped
  # (2026.06.09 is the newest) and both it and main carry
  # `project(... VERSION 1.2.2)`. main is pinned rather than the tag because
  # the two commits past it are exactly what an offline build needs: the
  # nlohmann json FetchContent URL gained its URL_HASH (the tag fetches an
  # unverified tarball) and libnvat gained the explicit ZLIB link it was
  # relying on the system to provide.
  src = pkgs.fetchFromGitHub {
    owner = "NVIDIA";
    repo = "attestation-sdk";
    rev = "73efa3ac1bec28ed7d7f0c0811a6c993e722dbd4";
    hash = "sha256-UwtGFFODCIGP62JSTrPBHSSVc7Il0mxI1QqnSoMttvA=";
  };

  # The FetchContent inputs, at the exact GIT_TAGs the two CMakeLists declare.
  # Bumping any of these means bumping the corresponding upstream declaration
  # too, otherwise the build silently compiles against a different version
  # than upstream tests.
  corrosion = pkgs.fetchFromGitHub {
    owner = "corrosion-rs";
    repo = "corrosion";
    rev = "6be991bb34c348dfb8344be22f3606288ea5c7fd";
    hash = "sha256-38l0lVWoloQ/F9eflag3kCwIMUeDvUWGLZKtKrk/UKs=";
  };
  regorus = pkgs.fetchFromGitHub {
    owner = "microsoft";
    repo = "regorus";
    rev = "regorus-v0.4.0";
    hash = "sha256-bb4rCGFItwXQB+JlIObzkVOfEi8y+PFR3xMufTwB94U=";
  };
  jwt-cpp = pkgs.fetchFromGitHub {
    owner = "Thalhammer";
    repo = "jwt-cpp";
    rev = "v0.7.1";
    hash = "sha256-neOCARLkeB1kCYGIkm5BKK+MWF1T830xRNzpdE0SSWM=";
  };
  fmt = pkgs.fetchFromGitHub {
    owner = "fmtlib";
    repo = "fmt";
    rev = "10.2.1";
    hash = "sha256-pEltGLAHLZ3xypD/Ur4dWPWJ9BGVXwqQyKcDWVmC3co=";
  };
  spdlog = pkgs.fetchFromGitHub {
    owner = "gabime";
    repo = "spdlog";
    rev = "v1.14.1";
    hash = "sha256-F7khXbMilbh5b+eKnzcB0fPPWQqUHqAYPWJb83OnUKQ=";
  };
  cli11 = pkgs.fetchFromGitHub {
    owner = "CLIUtils";
    repo = "CLI11";
    rev = "v2.6.1";
    hash = "sha256-q5q6TgSex0xjdWFf/4e6dhrN0qWPDjIgWBpdkCTlLys=";
  };
  # Same tarball and SHA-256 the CMakeLists pins in its URL_HASH, restated as
  # SRI so nix verifies the identical bytes.
  json = pkgs.fetchurl {
    url = "https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz";
    hash = "sha256-QvbpXK1uxTL9NyORNzNjtioUr213EFbb/IYWDm3/96o=";
  };

  # regorus-ffi is the Rust static library corrosion builds from inside the
  # CMake tree (the Rego policy engine libnvat evaluates relying-party
  # policies with). regorus ships no Cargo.lock, so one was generated once
  # from bindings/ffi/Cargo.toml and committed next to this file: without it
  # there is nothing to derive per-crate fixed-output fetches from, and cargo
  # would have to resolve against crates.io at build time. Regenerate with
  # `cargo generate-lockfile` in the regorus checkout's bindings/ffi when the
  # regorus pin moves.
  regorusVendor = pkgs.rustPlatform.importCargoLock {
    lockFile = ./regorus-ffi-Cargo.lock;
  };
in
pkgs.stdenv.mkDerivation {
  pname = "nvat";
  inherit version src;

  # Build the CLI project, not the SDK: nv-attestation-cli/CMakeLists.txt
  # pulls the SDK in with add_subdirectory when USE_SYSTEM_NVAT is OFF (the
  # default), so one configure produces both libnvat.so and nvattest, with
  # both sets of install rules, and the CLI reuses the fmt/spdlog FetchContent
  # populations from the SDK instead of needing its own copies.
  cmakeDir = "../nv-attestation-cli";

  # git is a build tool here, not a fetcher: regorus's build.rs shells out to
  # `git rev-parse HEAD` under its opa-runtime feature and panics if the
  # binary is missing. In an unpacked tarball there is no repository, so git
  # exits non-zero, Command::output() still returns Ok and the crate compiles
  # with an empty GIT_HASH. That is deterministic (the source tree is never a
  # repository) and only affects a version string OPA reports.
  nativeBuildInputs = with pkgs; [ cmake pkg-config cargo rustc git ];
  # libtool is here for libltdl: xmlsec1-openssl.pc lists -lltdl (xmlsec's
  # crypto backend loader) in its Libs, and nixpkgs' xmlsec does not
  # propagate it, so the libnvat link fails without it.
  buildInputs = with pkgs; [ openssl curl libxml2 xmlsec libtool zlib ];

  # CMake and corrosion write into the FetchContent source trees (regorus's
  # build.rs writes its generated regorus.h back into the crate directory,
  # which is also where the SDK looks for it), so every input is copied in
  # writable rather than referenced in the store.
  postUnpack = ''
    mkdir -p "$sourceRoot/deps"
    cp -r ${corrosion} "$sourceRoot/deps/corrosion"
    cp -r ${regorus} "$sourceRoot/deps/regorus"
    cp -r ${jwt-cpp} "$sourceRoot/deps/jwt-cpp"
    cp -r ${fmt} "$sourceRoot/deps/fmt"
    cp -r ${spdlog} "$sourceRoot/deps/spdlog"
    cp -r ${cli11} "$sourceRoot/deps/cli11"
    mkdir -p "$sourceRoot/deps/json"
    tar -xJf ${json} -C "$sourceRoot/deps/json" --strip-components=1
    chmod -R u+w "$sourceRoot/deps"
  '';

  preConfigure = ''
    depsDir="$PWD/deps"

    # Offline cargo for the corrosion-driven regorus-ffi build. The config
    # goes in CARGO_HOME rather than the crate's .cargo/config.toml because
    # corrosion runs cargo from the CMake binary directory, and cargo reads
    # config files relative to its working directory, not to --manifest-path.
    # The same file carries the rustc path remaps, the Rust half of the
    # -ffile-prefix-map below: rustc bakes a panic location per source file,
    # so without them libnvat.so keeps literal store paths into the vendored
    # crate sources and nix reads those as runtime references, pulling 220 MiB
    # of Rust source into the closure this library ships in.
    export CARGO_HOME="$NIX_BUILD_TOP/cargo-home"
    mkdir -p "$CARGO_HOME"
    cat > "$CARGO_HOME/config.toml" <<EOF
    [source.crates-io]
    replace-with = "vendored-sources"

    [source.vendored-sources]
    directory = "${regorusVendor}"

    [build]
    rustflags = ["--remap-path-prefix=$PWD/=", "--remap-path-prefix=${regorusVendor}/="]
    EOF
    cp ${./regorus-ffi-Cargo.lock} "$depsDir/regorus/bindings/ffi/Cargo.lock"
    chmod u+w "$depsDir/regorus/bindings/ffi/Cargo.lock"

    # Upstream maps its own source prefix out of __FILE__ so log lines read
    # relative, but it computes that prefix from CMAKE_SOURCE_DIR, which is
    # the CLI project here, not the SDK. Redo it from the unpack root so
    # neither library nor CLI bakes the build directory into every log line,
    # and so the binaries do not depend on where the build tree happened to
    # live.
    cmakeFlagsArray+=(
      "-DCMAKE_CXX_FLAGS=-ffile-prefix-map=$PWD/="
      "-DFETCHCONTENT_SOURCE_DIR_CORROSION=$depsDir/corrosion"
      "-DFETCHCONTENT_SOURCE_DIR_REGORUS=$depsDir/regorus"
      "-DFETCHCONTENT_SOURCE_DIR_JWT-CPP=$depsDir/jwt-cpp"
      "-DFETCHCONTENT_SOURCE_DIR_JSON=$depsDir/json"
      "-DFETCHCONTENT_SOURCE_DIR_FMT=$depsDir/fmt"
      "-DFETCHCONTENT_SOURCE_DIR_SPDLOG=$depsDir/spdlog"
      "-DFETCHCONTENT_SOURCE_DIR_CLI11=$depsDir/cli11"
    )
  '';

  # Belt and braces next to the vendored-sources replacement: any cargo
  # invocation that still wants the registry fails loudly instead of hanging
  # on a network the sandbox does not have.
  CARGO_NET_OFFLINE = "true";

  cmakeFlags = [
    "-DUSE_SYSTEM_DEPS=ON"
    "-DBUILD_TESTING=OFF"
    "-DFETCHCONTENT_FULLY_DISCONNECTED=ON"
    # nvattest loads libnvat.so.1 from the same output; the linker wrapper
    # only adds RPATH entries for store paths it sees in -L, and the library
    # is still in the build tree at link time. Baking the install RPATH at
    # link time (rather than letting CMake rewrite it during install) keeps
    # the wrapper's entries for OpenSSL, curl and xmlsec untouched.
    "-DCMAKE_BUILD_WITH_INSTALL_RPATH=ON"
    "-DCMAKE_INSTALL_RPATH=${placeholder "out"}/lib"
  ];

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    test -e "$out/lib/libnvat.so.${lib.versions.major version}"
    "$out/bin/nvattest" version
    runHook postInstallCheck
  '';

  meta = {
    description = "NVIDIA attestation SDK (libnvat) and the nvattest CLI";
    homepage = "https://github.com/NVIDIA/attestation-sdk";
    license = lib.licenses.asl20;
    platforms = [ "x86_64-linux" ];
  };
}
