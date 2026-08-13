{
  description = "aleph-vm confidential measured-boot images (SEV-SNP)";

  # Backport of aleph-cvm's nix/flake.nix, reduced to the CORE measured-boot
  # chain (design section 6 non-goals + section 7 minimal dm-verity):
  #   measured OVMF (AmdSev, kernel-hashing) + kernel + initrd (baking the
  #   aleph-attest-agent static-musl binary and init.sh) + a minimal
  #   dm-verity-protected rootfs + a precomputed, reproducible sev-snp-measure
  #   launch measurement.
  # Excluded from the donor: compose-rootfs / compose-demo and the
  # encrypted-rootfs (LUKS) mode. The fib-service demo app is NOT excluded
  # here: it now exists as the V-PROGRAM workload (see workload.nix), baked
  # into its own measured dm-verity volume that the guest init mounts and
  # execs when a workload_roothash is present on the cmdline. The trivial
  # busybox httpd remains the platform rootfs's baked /sbin/init, used as the
  # no-workload fallback. See rust-port-divergences.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      craneLib = crane.mkLib pkgs;

      # Rust toolchain with musl target for static linking.
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [ "x86_64-unknown-linux-musl" ];
      };
      craneToolchain = craneLib.overrideToolchain rustToolchain;

      # Musl cross-compiler for C dependencies (openssl-sys, etc.).
      muslCC = pkgs.pkgsCross.musl64.stdenv.cc;

      # This repo's Rust workspace lives at <repo>/rust; this flake lives at
      # <repo>/nix. Point crane at the workspace root so it sees Cargo.lock and
      # every member. The attest-agent crate does not depend on the proto/tonic
      # crates, so no .proto files or protoc are needed (the -p filter below
      # keeps cargo from building them).
      workspaceSrc = craneToolchain.cleanCargoSource ../rust;

      # Attestation agent (static musl binary), built from THIS repo's crate.
      # Needs static openssl for openssl-sys (the sev crate dependency pulled in
      # transitively via aleph-tee).
      staticOpenssl = pkgs.pkgsStatic.openssl;
      attest-agent = craneToolchain.buildPackage {
        src = workspaceSrc;
        # Build only the agent crate and its dependency subtree.
        cargoExtraArgs = "-p aleph-attest-agent";
        # There is no test harness to run for a musl cross build here.
        doCheck = false;
        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        nativeBuildInputs = [ pkgs.pkg-config muslCC ];
        buildInputs = [ staticOpenssl.dev ];
        OPENSSL_DIR = "${staticOpenssl.dev}";
        OPENSSL_LIB_DIR = "${staticOpenssl.out}/lib";
        OPENSSL_STATIC = "1";
        OPENSSL_NO_VENDOR = "1";
        # Use the musl-targeting C compiler for all C dependencies.
        CC_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
        AR_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-ar";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
      };

      # Attestation CLI (static musl binary), the client-side SEV-SNP verifier.
      # Built like the agent (static openssl for the aleph-tee/sev KDS chain) so
      # it runs on any host regardless of glibc, e.g. a testnets SNP node.
      attest-cli = craneToolchain.buildPackage {
        src = workspaceSrc;
        cargoExtraArgs = "-p aleph-attest-cli";
        doCheck = false;
        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        nativeBuildInputs = [ pkgs.pkg-config muslCC ];
        buildInputs = [ staticOpenssl.dev ];
        OPENSSL_DIR = "${staticOpenssl.dev}";
        OPENSSL_LIB_DIR = "${staticOpenssl.out}/lib";
        OPENSSL_STATIC = "1";
        OPENSSL_NO_VENDOR = "1";
        CC_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
        AR_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-ar";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
      };

      # fib-service demo workload (static musl binary): a trivial actix-web app
      # exposing GET /fib/{n} (saturating u64 Fibonacci) and GET /health, later
      # baked into the measured guest as a V-PROGRAM workload. It has no C
      # dependencies (plain actix-web HTTP, no TLS/openssl), so unlike
      # attest-agent/attest-cli it needs only the musl cross-CC env, not the
      # static-openssl buildInputs/OPENSSL_* env those carry.
      fib-service = craneToolchain.buildPackage {
        src = craneToolchain.cleanCargoSource ./fib-service;
        # There is no test harness to run for a musl cross build here.
        doCheck = false;
        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        # Use the musl-targeting C compiler for any C dependencies.
        nativeBuildInputs = [ muslCC ];
        CC_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
        AR_x86_64_unknown_linux_musl = "${muslCC}/bin/x86_64-unknown-linux-musl-ar";
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCC}/bin/x86_64-unknown-linux-musl-cc";
      };

      # OVMF firmware built with the AmdSev variant (kernel hashing support), so
      # the SEV-SNP launch measurement covers OVMF + kernel + initrd + cmdline.
      ovmf = import ./ovmf.nix { inherit pkgs; };
      ovmfFd = "${ovmf}/OVMF.fd";

      # nixpkgs 24.11 ships sev-snp-measure 0.0.11 which has a measurement
      # calculation bug. Override to 0.0.12 which produces correct results.
      sev-snp-measure = pkgs.python3Packages.sev-snp-measure.overridePythonAttrs (old: rec {
        version = "0.0.12";
        src = pkgs.fetchFromGitHub {
          owner = "virtee";
          repo = "sev-snp-measure";
          rev = "v${version}";
          hash = "sha256-UcXU6rNjcRN1T+iWUNrqeJCkSa02WU1/pBwLqHVPRyw=";
        };
      });

      kernel = pkgs.callPackage ./kernel.nix {};
      initrd = pkgs.callPackage ./initrd.nix {
        inherit attest-agent kernel;
        init-script = ./init.sh;
        udhcpc-script = ./udhcpc.script;
        udhcpc6-script = ./udhcpc6.script;
      };
      rootfs = pkgs.callPackage ./rootfs.nix {};

      # fib-service V-PROGRAM workload volume: a content-only ext4 carrying the
      # fib-service binary as /sbin/init, delivered to the measured guest as an
      # extra disk (see workload.nix). Distinct from `rootfs`, which is the
      # platform image (kernel/initrd/OS chain).
      workloadImage = pkgs.callPackage ./workload.nix { inherit fib-service; };

      # dm-verity hash tree + root hash for the rootfs. The root hash is baked
      # into the kernel cmdline, binding rootfs integrity into the SEV-SNP
      # measurement.
      #
      # A FIXED salt and UUID make the root hash reproducible: veritysetup format
      # uses a random salt by default, which alone would make the measurement
      # non-reproducible run to run even with an identical rootfs. Combined with
      # the deterministic mkfs (rootfs.nix), this yields a stable measurement.
      # This is a deliberate reproducibility hardening over the aleph-cvm donor
      # (design section 8 top risk). See rust-port-divergences.
      veritySalt = "0000000000000000000000000000000000000000000000000000000000000000";
      verityUuid = "00000000-0000-0000-0000-000000000000";
      verity = pkgs.runCommand "rootfs-verity" {
        nativeBuildInputs = [ pkgs.cryptsetup ];
      } ''
        mkdir -p $out
        veritysetup format \
          --salt=${veritySalt} \
          --uuid=${verityUuid} \
          ${rootfs} \
          $out/hashtree \
          | tee /dev/stderr \
          | grep "Root hash:" \
          | awk '{print $NF}' \
          | tr -d '\n' > $out/roothash
      '';

      # dm-verity hash tree + root hash for the fib-service workload volume.
      # Same mechanism as `verity` above (identical fixed salt/uuid), applied to
      # workloadImage instead of rootfs, so the workload_roothash is reproducible
      # too and can be baked into the guest config the same way the platform
      # rootfs roothash is.
      workloadVerity = pkgs.runCommand "workload-verity" {
        nativeBuildInputs = [ pkgs.cryptsetup ];
      } ''
        mkdir -p $out
        veritysetup format \
          --salt=${veritySalt} \
          --uuid=${verityUuid} \
          ${workloadImage} \
          $out/hashtree \
          | tee /dev/stderr \
          | grep "Root hash:" \
          | awk '{print $NF}' \
          | tr -d '\n' > $out/roothash
      '';

      # Convenience: the workload volume + its dm-verity sidecars, staged with
      # the .verity/.roothash suffix convention the launch path and daemon
      # expect for extra-disk sidecars.
      workload = pkgs.runCommand "aleph-vm-workload" {} ''
        mkdir -p $out
        ln -s ${workloadImage} $out/workload.ext4
        cp ${workloadVerity}/hashtree $out/workload.ext4.verity
        cp ${workloadVerity}/roothash $out/workload.ext4.roothash
      '';

      # Parameterized SEV-SNP launch measurement builder.
      # vcpus:            number of vCPUs (affects the launch measurement)
      # vcpuType:         QEMU CPU model ("EPYC-v4" for Genoa, "EPYC-v3" for Milan)
      # workloadRoothash: when null (default), the cmdline is the
      #   platform-only form `...roothash=<platform>` (workload-less parity,
      #   what test_vm_snp and the baked `measurement` below expect). When
      #   set to a dm-verity root hash, the cmdline is extended to the
      #   workload form `...roothash=<platform> workload_roothash=<hex>`,
      #   matching byte-for-byte what the daemon emits when a V-PROGRAM
      #   workload is attached (lifecycle.rs) and the CMDLINE_TEMPLATE_EXEC_V1
      #   manifest template (src/aleph/vm/vprogram/bundle.py). Per-workload
      #   measurements are computed by passing this argument; they are never
      #   baked into the platform bundle's own measurement.hex.
      # The measurement is a function of (OVMF + kernel + initrd + cmdline +
      # vCPU count + CPU type), so each configuration needs its own value.
      measurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", workloadRoothash ? null }: let
        platformRoothash = builtins.readFile "${verity}/roothash";
        kernelCmdline =
          if workloadRoothash == null
          then "console=ttyS0 root=/dev/mapper/verity-root ro roothash=${platformRoothash}"
          else "console=ttyS0 root=/dev/mapper/verity-root ro roothash=${platformRoothash} workload_roothash=${workloadRoothash}";
      in pkgs.runCommand "sev-snp-measurement-${toString vcpus}vcpus-${vcpuType}" {
        nativeBuildInputs = [ sev-snp-measure ];
      } ''
        sev-snp-measure \
          --mode snp \
          --vcpus ${toString vcpus} \
          --vcpu-type ${vcpuType} \
          --ovmf ${ovmfFd} \
          --kernel ${kernel}/bzImage \
          --initrd ${initrd}/initrd \
          --append "${kernelCmdline}" \
          | tr -d '\n' > $out
      '';

      # Default measurement: 2 vCPUs, EPYC-v4 (Genoa), platform-only cmdline
      # (no workload_roothash). This is the value baked into image/measurement.hex
      # below and MUST stay platform-only for workload-less parity (test_vm_snp).
      measurement = measurementFor { vcpus = 2; vcpuType = "EPYC-v4"; };

      # Convenience: the workload-form measurement for THIS repo's fib-service
      # demo workload (2 vCPUs, EPYC-v4), using workloadVerity's root hash.
      # Exposed for sanity-checking the workload cmdline template end-to-end;
      # NOT baked into the platform image's measurement.hex (see above). Real
      # per-workload measurements at launch time are computed by the daemon's
      # own helper from the workload's actual root hash, not by this flake.
      workloadMeasurement = measurementFor {
        vcpus = 2;
        vcpuType = "EPYC-v4";
        workloadRoothash = builtins.readFile "${workloadVerity}/roothash";
      };

      # Convenience: all measured-image artifacts in one directory.
      image = pkgs.runCommand "aleph-cvm-image" {} ''
        mkdir -p $out
        ln -s ${kernel}/bzImage $out/bzImage
        ln -s ${initrd}/initrd $out/initrd
        ln -s ${rootfs} $out/rootfs.ext4
        cp ${ovmfFd} $out/OVMF.fd
        cp ${measurement} $out/measurement.hex
        cp ${verity}/hashtree $out/rootfs.ext4.verity
        cp ${verity}/roothash $out/rootfs.ext4.roothash
      '';
    in {
      # Only concrete derivations are exposed as packages (a function like
      # measurementFor is not a valid flake package and would fail flake check);
      # measurementFor stays internal for callers that import the flake directly.
      packages.${system} = {
        inherit
          attest-agent
          attest-cli
          fib-service
          ovmf
          kernel
          initrd
          rootfs
          verity
          workloadImage
          workloadVerity
          workload
          measurement
          workloadMeasurement
          image;
        default = image;
      };
    };
}
