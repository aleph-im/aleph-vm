{
  description = "aleph-vm confidential measured-boot images (SEV-SNP)";

  # Backport of aleph-cvm's nix/flake.nix, reduced to the CORE measured-boot
  # chain (design section 6 non-goals + section 7 minimal dm-verity):
  #   measured OVMF (AmdSev, kernel-hashing) + kernel + initrd (baking the
  #   aleph-attest-agent static-musl binary and init.sh) + a minimal
  #   dm-verity-protected rootfs + a precomputed, reproducible sev-snp-measure
  #   launch measurement.
  # Excluded from the donor: compose-demo (compose-rootfs, initially excluded
  # too, returned as the aleph.compose/1 flavor: composeRootfs /
  # composeInitrd / composeImage below, sharing initrd.nix with init-compose.sh
  # as /init; see docs/plans/2026-08-19-compose-runtime-port-design.md). The
  # encrypted-rootfs (LUKS) mode returns as a second, separate image flavor
  # for confidential instances (instanceInitrd / instanceImage below), built
  # from the same initrd.nix with withVerity=false withNft=false withLuks=true;
  # it does not touch the v-program image's measured initrd contents. The
  # fib-service demo app is NOT excluded here: it now exists as the V-PROGRAM
  # workload (see workload.nix), baked
  # into its own measured dm-verity volume that the guest init mounts and
  # execs when a workload_roothash is present on the cmdline. The trivial
  # busybox httpd remains the platform rootfs's baked /sbin/init, used as the
  # no-workload fallback. See rust-port-divergences.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
        # Only the NVIDIA driver (nvidia-x11's open kernel modules + raw
        # userland) is unfree in this flake; everything else stays gated by
        # nixpkgs' default (no blanket allowUnfree). nvidia.acceptLicense
        # covers nvidia-x11's own license gate (nixpkgs generic.nix), which
        # the open-modules build sidesteps but the userland .run extraction
        # (openSha256 != null) still exercises.
        config = {
          allowUnfreePredicate = pkg: builtins.elem (nixpkgs.lib.getName pkg) [
            "nvidia-x11"
            "nvidia-open"
            "nvidia-settings"
            "nvidia-persistenced"
          ];
          nvidia.acceptLicense = true;
        };
      };
      lib = pkgs.lib;
      craneLib = crane.mkLib pkgs;

      # Rust toolchain with musl target for static linking.
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [ "x86_64-unknown-linux-musl" ];
      };
      craneToolchain = craneLib.overrideToolchain rustToolchain;

      # Musl cross-compiler for C dependencies (openssl-sys, etc.).
      muslCC = pkgs.pkgsCross.musl64.stdenv.cc;

      # The attest-agent is the MEASURED guest binary and its own cargo
      # workspace (rust/crates/aleph-attest-agent, own Cargo.lock). Its source
      # is narrowed to exactly its measured inputs: the agent crate, aleph-tee
      # (path dependency) and the root Cargo.toml (aleph-tee inherits its
      # dependency versions from it; cargo accepts the root's other members
      # being absent). Any other file under rust/ cannot change this
      # derivation, so a supervisor-side change never rebuilds or re-measures
      # the agent.
      agentSrc = pkgs.lib.fileset.toSource {
        root = ../rust;
        fileset = pkgs.lib.fileset.unions [
          ../rust/Cargo.toml
          (craneToolchain.fileset.commonCargoSources ../rust/crates/aleph-tee)
          (craneToolchain.fileset.commonCargoSources ../rust/crates/aleph-attest-agent)
        ];
      };

      # Attestation agent (static musl binary), built from THIS repo's crate.
      # Needs static openssl for openssl-sys (the sev crate dependency pulled in
      # transitively via aleph-tee).
      staticOpenssl = pkgs.pkgsStatic.openssl;
      attest-agent = craneToolchain.buildPackage {
        src = agentSrc;
        cargoToml = ../rust/crates/aleph-attest-agent/Cargo.toml;
        cargoLock = ../rust/crates/aleph-attest-agent/Cargo.lock;
        # The cargo root is the nested agent workspace, not the source root
        # (crane FAQ "workspace not at source root"): jump into it after
        # unpacking and pin sourceRoot so later phases stay there. ../aleph-tee
        # and ../../Cargo.toml remain reachable in the unpacked tree.
        postUnpack = ''
          cd $sourceRoot/crates/aleph-attest-agent
          sourceRoot="."
        '';
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

      # fib-service demo workload (static musl binary): a trivial actix-web app
      # exposing GET /fib/{n} (saturating u64 Fibonacci) and GET /health, later
      # baked into the measured guest as a V-PROGRAM workload. It has no C
      # dependencies (plain actix-web HTTP, no TLS/openssl), so unlike the
      # attest-agent it needs only the musl cross-CC env, not the
      # static-openssl buildInputs/OPENSSL_* env that carries.
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

      # sev-snp-measure 0.0.11 had a measurement calculation bug; nixos-26.05
      # ships 0.0.12 (the fixed release the flake previously pinned by hand),
      # so the nixpkgs package is used as-is. Keep any future channel bump
      # honest: measurements must stay reproducible across sev-snp-measure
      # updates or every pinned launch measurement silently changes.
      sev-snp-measure = pkgs.python3Packages.sev-snp-measure;

      # Source revision the image outputs were built from, for audit and
      # rebuild. Written to $out/source-rev of the image directories ONLY:
      # never into anything measured (initrd, cmdline), or every commit
      # would move the launch measurement. `self.rev` exists for a clean git
      # checkout, `self.dirtyRev` for a dirty one (nix >= 2.19); "unknown"
      # covers flakes evaluated outside git. Interpolating it makes the
      # three image directories rebuild on every commit; they are cheap
      # (symlinks and a few cp), so that is accepted rather than moving the
      # file into anything measured.
      sourceRev = self.rev or self.dirtyRev or "unknown";

      kernel = pkgs.callPackage ./kernel.nix {};

      # GPU flavor of the guest kernel: the same whitelist base fragment plus
      # the options NVIDIA's open kernel modules (nvidia.ko, nvidia-uvm.ko)
      # need (see kernel-config-gpu.fragment). Not referenced by any of the
      # base image/measurement derivations below, so it never moves the
      # base `kernel` or `measurement` outputs.
      gpuKernel = pkgs.callPackage ./kernel.nix { extraFragment = ./kernel-config-gpu.fragment; };

      # NVIDIA open kernel modules (against gpuKernel), raw userland and GSP
      # firmware for the confidential-GPU guest. See nvidia.nix for the
      # extraction rationale (raw, unpatched ELF; open modules only).
      nvidiaDriver = import ./nvidia.nix { inherit pkgs lib gpuKernel; };
      nvidiaModules = nvidiaDriver.modules;
      nvidiaUserland = nvidiaDriver.userland;
      nvidiaFirmware = nvidiaDriver.firmware;

      # NVIDIA's attestation SDK and its nvattest CLI, the in-guest GPU
      # verifier. Like the driver pieces above it is only referenced by the
      # confidential-GPU rootfs, so it never moves the base image outputs.
      nvat = import ./nvat.nix { inherit pkgs lib; };

      initrd = pkgs.callPackage ./initrd.nix {
        inherit attest-agent kernel;
        init-script = ./init.sh;
        init-common-script = ./init-common.sh;
        udhcpc-script = ./udhcpc.script;
        udhcpc6-script = ./udhcpc6.script;
      };

      # Confidential-instance initrd: LUKS encrypted rootfs, no dm-verity, no
      # in-guest firewall (firewall policy belongs to the user rootfs on
      # instances, design section 3 decision 6).
      instanceInitrd = pkgs.callPackage ./initrd.nix {
        inherit attest-agent kernel;
        init-script = ./init-instance.sh;
        init-common-script = ./init-common.sh;
        udhcpc-script = ./udhcpc.script;
        udhcpc6-script = ./udhcpc6.script;
        withVerity = false;
        withNft = false;
        withLuks = true;
      };

      # Compose flavor of the initrd (aleph.compose/1): identical to `initrd`
      # except for /init (init-compose.sh instead of init.sh), which inverts
      # the launch topology to bind-mount the workload data volume into the
      # platform chroot instead of chrooting the workload directly. Same
      # dm-verity + nft firewall contents as the v-program initrd (the
      # withVerity/withNft defaults). See init-compose.sh for the exact
      # deltas from init.sh.
      composeInitrd = pkgs.callPackage ./initrd.nix {
        inherit attest-agent kernel;
        init-script = ./init-compose.sh;
        init-common-script = ./init-common.sh;
        udhcpc-script = ./udhcpc.script;
        udhcpc6-script = ./udhcpc6.script;
      };

      # Confidential-GPU initrd: the v-program contents (dm-verity + nft
      # firewall) built against gpuKernel, plus NVIDIA's open kernel modules
      # and init-gpu.sh as /init. The kernel MUST be gpuKernel: the dm-*/nft
      # modules shipped alongside nvidia.ko have to come from the same build.
      gpuInitrd = pkgs.callPackage ./initrd.nix {
        inherit attest-agent;
        kernel = gpuKernel;
        init-script = ./init-gpu.sh;
        init-common-script = ./init-common.sh;
        udhcpc-script = ./udhcpc.script;
        udhcpc6-script = ./udhcpc6.script;
        withNvidia = nvidiaDriver.modules;
      };

      rootfs = pkgs.callPackage ./rootfs.nix {};

      # Compose-runner platform rootfs (aleph.compose/1): podman + podman-compose
      # userland that boots a docker-compose workload from a separate measured
      # volume. See compose-rootfs.nix for the donor deltas (determinism,
      # ownership, fail-closed init).
      composeRootfs = pkgs.callPackage ./compose-rootfs.nix { inherit kernel; };

      # Confidential-GPU platform rootfs: the base busybox content plus the
      # raw driver userland, GSP firmware and NVIDIA's local verifier. See
      # gpu-rootfs.nix.
      gpuRootfs = import ./gpu-rootfs.nix { inherit pkgs nvidiaDriver nvat; };

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

      # dm-verity hash tree + root hash for the compose-runner platform rootfs.
      # Same mechanism as `verity` above (identical fixed salt/uuid), applied to
      # composeRootfs instead of rootfs, so composeImage gets its own
      # reproducible root hash baked into its cmdline/measurement.
      composeVerity = pkgs.runCommand "compose-rootfs-verity" {
        nativeBuildInputs = [ pkgs.cryptsetup ];
      } ''
        mkdir -p $out
        veritysetup format \
          --salt=${veritySalt} \
          --uuid=${verityUuid} \
          ${composeRootfs} \
          $out/hashtree \
          | tee /dev/stderr \
          | grep "Root hash:" \
          | awk '{print $NF}' \
          | tr -d '\n' > $out/roothash
      '';

      # dm-verity hash tree + root hash for the confidential-GPU platform
      # rootfs. Same mechanism as `verity` above (identical fixed salt/uuid),
      # applied to gpuRootfs.
      gpuVerity = pkgs.runCommand "gpu-rootfs-verity" {
        nativeBuildInputs = [ pkgs.cryptsetup ];
      } ''
        mkdir -p $out
        veritysetup format \
          --salt=${veritySalt} \
          --uuid=${verityUuid} \
          ${gpuRootfs} \
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
      # initrdDrv/verityDrv/kernelDrv: which initrd, platform-rootfs verity and
      #   kernel derivation to measure. Default to `initrd`/`verity`/`kernel`
      #   (the base flavor), so existing callers are unaffected; the compose
      #   flavor below passes composeInitrd/composeVerity and the GPU flavor
      #   additionally passes gpuKernel, to reuse this same cmdline template
      #   instead of duplicating it.
      # cmdlineExtra: appended verbatim to the cmdline built above (so it
      #   carries its own leading space). Empty by default, which keeps every
      #   existing caller's cmdline BYTE-identical; the GPU flavor passes
      #   " swiotlb=262144", which the guest needs for the driver's bounce
      #   buffers under SEV-SNP.
      # name: the derivation name. Defaults to the exact string this function
      #   has always used, so the base flavor's `#measurement` store path is
      #   unchanged; the compose flavor below passes a compose-tagged name so
      #   `#composeMeasurement` gets its own store path instead of colliding
      #   with (and being deduplicated to) `#measurement`'s, which it would
      #   otherwise do purely by having the same derivation name even though
      #   its inputs (initrd/verity vs composeInitrd/composeVerity) differ.
      # The measurement is a function of (OVMF + kernel + initrd + cmdline +
      # vCPU count + CPU type), so each configuration needs its own value.
      measurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", workloadRoothash ? null, initrdDrv ? initrd, verityDrv ? verity, kernelDrv ? kernel, cmdlineExtra ? "", name ? "sev-snp-measurement-${toString vcpus}vcpus-${vcpuType}" }: let
        platformRoothash = builtins.readFile "${verityDrv}/roothash";
        baseCmdline =
          if workloadRoothash == null
          then "console=ttyS0 root=/dev/mapper/verity-root ro roothash=${platformRoothash}"
          else "console=ttyS0 root=/dev/mapper/verity-root ro roothash=${platformRoothash} workload_roothash=${workloadRoothash}";
        kernelCmdline = baseCmdline + cmdlineExtra;
      in pkgs.runCommand name {
        nativeBuildInputs = [ sev-snp-measure ];
      } ''
        sev-snp-measure \
          --mode snp \
          --vcpus ${toString vcpus} \
          --vcpu-type ${vcpuType} \
          --ovmf ${ovmfFd} \
          --kernel ${kernelDrv}/bzImage \
          --initrd ${initrdDrv}/initrd \
          --append "${kernelCmdline}" \
          | tr -d '\n' > $out
      '';

      # Default measurement: 2 vCPUs, EPYC-v4 (Genoa), platform-only cmdline
      # (no workload_roothash). This is the value baked into image/measurement.hex
      # below and MUST stay platform-only for workload-less parity (test_vm_snp).
      measurement = measurementFor { vcpus = 2; vcpuType = "EPYC-v4"; };

      # Compose-flavor measurement builder: same measurementFor machinery (one
      # cmdline template, no duplication), pinned to composeInitrd and
      # composeVerity's root hash instead of the base initrd/verity.
      composeMeasurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", workloadRoothash ? null }:
        measurementFor {
          inherit vcpus vcpuType workloadRoothash;
          initrdDrv = composeInitrd;
          verityDrv = composeVerity;
          name = "sev-snp-measurement-compose-${toString vcpus}vcpus-${vcpuType}";
        };

      # Default compose measurement: 2 vCPUs, EPYC-v4 (Genoa), platform-only
      # cmdline. Mirrors `measurement` above for the compose flavor; this is
      # the value baked into composeImage/measurement.hex below.
      composeMeasurement = composeMeasurementFor { vcpus = 2; vcpuType = "EPYC-v4"; };

      # Confidential-GPU measurement builder: same measurementFor machinery,
      # pinned to gpuInitrd, gpuVerity's root hash and gpuKernel, with the
      # GPU flavor's extra cmdline token.
      gpuMeasurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", workloadRoothash ? null }:
        measurementFor {
          inherit vcpus vcpuType workloadRoothash;
          initrdDrv = gpuInitrd;
          verityDrv = gpuVerity;
          kernelDrv = gpuKernel;
          cmdlineExtra = " swiotlb=262144";
          name = "sev-snp-measurement-gpu-${toString vcpus}vcpus-${vcpuType}";
        };

      # Default GPU measurement: 2 vCPUs, EPYC-v4 (Genoa), platform-only
      # cmdline. Mirrors `measurement` above for the GPU flavor; this is the
      # value baked into gpuImage/measurement.hex below.
      gpuMeasurement = gpuMeasurementFor { vcpus = 2; vcpuType = "EPYC-v4"; };

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
        echo "${sourceRev}" > $out/source-rev
      '';

      # Convenience: all measured-image artifacts in one directory, for the
      # compose flavor (aleph.compose/1). Mirrors `image` above exactly, with
      # composeInitrd/composeRootfs/composeMeasurement/composeVerity in place
      # of the base flavor's derivations.
      composeImage = pkgs.runCommand "aleph-compose-image" {} ''
        mkdir -p $out
        ln -s ${kernel}/bzImage $out/bzImage
        ln -s ${composeInitrd}/initrd $out/initrd
        ln -s ${composeRootfs} $out/rootfs.ext4
        cp ${ovmfFd} $out/OVMF.fd
        cp ${composeMeasurement} $out/measurement.hex
        cp ${composeVerity}/hashtree $out/rootfs.ext4.verity
        cp ${composeVerity}/roothash $out/rootfs.ext4.roothash
        echo "${sourceRev}" > $out/source-rev
      '';

      # Convenience: all measured-image artifacts in one directory, for the
      # confidential-GPU flavor. Mirrors `image` above, plus gpu.json: the
      # runtime's GPU contract (vendor, architecture, driver version, the
      # models the node will accept, and the in-guest library path the
      # workload gets its driver userland at), which the bundle builder
      # copies into the published manifest.
      gpuImage = pkgs.runCommand "aleph-gpu-image" {} ''
        mkdir -p $out
        ln -s ${gpuKernel}/bzImage $out/bzImage
        ln -s ${gpuInitrd}/initrd $out/initrd
        ln -s ${gpuRootfs} $out/rootfs.ext4
        cp ${ovmfFd} $out/OVMF.fd
        cp ${gpuMeasurement} $out/measurement.hex
        cp ${gpuVerity}/hashtree $out/rootfs.ext4.verity
        cp ${gpuVerity}/roothash $out/rootfs.ext4.roothash
        echo "${sourceRev}" > $out/source-rev
        cat > $out/gpu.json <<EOF
{"vendor":"nvidia","arch":"blackwell","driver_version":"${nvidiaDriver.version}","accepted_models":["NVIDIA RTX PRO 6000 Blackwell Server Edition"],"library_path":"/opt/nvidia/lib"}
EOF
      '';

      # Per-deployment measurement helper for the instance image: the owner
      # address is a measured cmdline slot, so there is no fixed baked
      # measurement (unlike the v-program image). Unlike `measurementFor`
      # (which callers only ever reach by importing this flake file
      # directly), Tasks 8/11/13 call this one from ordinary flake
      # consumers (the daemon's launch path, tests), so it is also exposed
      # below as `lib.${system}.instanceMeasurementFor`. Its mandatory
      # `owner` argument still keeps it out of `packages` (a function is not
      # a valid flake package); `instanceMeasurementSmoke` below gives it
      # build coverage so evaluation and the sev-snp-measure invocation are
      # never dead code.
      instanceMeasurementFor = { vcpus ? 2, vcpuType ? "EPYC-v4", owner }:
        # `owner` is interpolated into the measured kernel cmdline (and thus a
        # shell argument to sev-snp-measure); only trusted nix callers reach
        # here, but assert the EVM-address shape so a stray value fails the
        # build rather than producing a bogus measurement or injecting tokens.
        assert (builtins.match "0x[0-9a-fA-F]{40}" owner) != null;
        let
        kernelCmdline = "console=ttyS0 luks=1 owner=${owner}";
      in pkgs.runCommand "snp-instance-measurement-${toString vcpus}vcpus-${vcpuType}" {
        nativeBuildInputs = [ sev-snp-measure ];
      } ''
        sev-snp-measure --mode snp --vcpus ${toString vcpus} --vcpu-type ${vcpuType} \
          --ovmf ${ovmfFd} --kernel ${kernel}/bzImage --initrd ${instanceInitrd}/initrd \
          --append "${kernelCmdline}" | tr -d '\n' > $out
      '';

      # Confidential-instance image artifacts: OVMF firmware, kernel and
      # initrd only. Unlike `image`, there is no rootfs and no baked
      # measurement.hex: the LUKS-encrypted rootfs is provided by the caller
      # at launch time (whole-device LUKS2 on /dev/vda) and the measurement
      # depends on the per-deployment owner address (instanceMeasurementFor).
      instanceImage = pkgs.runCommand "aleph-snp-instance-image" {} ''
        mkdir -p $out
        ln -s ${kernel}/bzImage $out/bzImage
        ln -s ${instanceInitrd}/initrd $out/initrd
        cp ${ovmfFd} $out/OVMF.fd
        echo "${sourceRev}" > $out/source-rev
      '';

      # Build-covers instanceMeasurementFor with a fixed placeholder owner
      # address: a plain `inherit` cannot expose a function through
      # `packages` (see above), so nothing would otherwise evaluate its body
      # or invoke sev-snp-measure. `nix build ./nix#instanceMeasurementSmoke`
      # exercises exactly that.
      instanceMeasurementSmoke = instanceMeasurementFor {
        owner = "0x0000000000000000000000000000000000000000";
      };

      # Test fixture for the confidential-instance E2E scenario (Task 14): a
      # plain ext4 rootfs booting a statically linked dropbear SSH server.
      # NOT part of the measured chain (no dm-verity, not referenced by any
      # cmdline roothash) and NOT bit-reproducible (build-time host key). See
      # test-rootfs.nix for the full rationale.
      instanceTestRootfs = pkgs.callPackage ./test-rootfs.nix {};
    in {
      # Only concrete derivations are exposed as packages (a function like
      # measurementFor is not a valid flake package and would fail flake check);
      # measurementFor stays internal for callers that import the flake directly.
      packages.${system} = {
        inherit
          attest-agent
          fib-service
          ovmf
          kernel
          gpuKernel
          nvidiaModules
          nvidiaUserland
          nvidiaFirmware
          nvat
          initrd
          instanceInitrd
          composeInitrd
          gpuInitrd
          rootfs
          composeRootfs
          gpuRootfs
          verity
          composeVerity
          gpuVerity
          workloadImage
          workloadVerity
          workload
          measurement
          workloadMeasurement
          composeMeasurement
          gpuMeasurement
          image
          composeImage
          gpuImage
          instanceImage
          instanceMeasurementSmoke
          instanceTestRootfs;
        default = image;
      };

      # instanceMeasurementFor takes a mandatory `owner` argument, so unlike
      # the packages above it cannot be a flake package; expose it here so
      # Tasks 8/11/13 (and any other flake consumer, not just direct
      # importers of this file) can call
      # `(builtins.getFlake ...).lib.${system}.instanceMeasurementFor { ... }`.
      # gpuMeasurementFor takes only optional arguments, so `gpuMeasurement`
      # above already gives it build coverage; it is exposed here for the
      # same reason as instanceMeasurementFor, so a flake consumer can
      # compute a workload-form GPU measurement without importing this file.
      lib.${system} = {
        inherit instanceMeasurementFor gpuMeasurementFor;
      };
    };
}
