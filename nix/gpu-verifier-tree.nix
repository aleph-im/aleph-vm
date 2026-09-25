{ pkgs, nvidiaDriver, nvat, gpuFacts, ... }:

# The GPU verifier tree overlaid on the confidential-instance initramfs.
#
# An instance has no Aleph rootfs to run the verifier from: the owner's disk
# is still LUKS-locked when the GPU has to be proven, so NVIDIA's nvattest,
# its nix closure and the only driver pieces it drives (NVML and nvidia-smi)
# ride in the measured initrd instead. The owner installs the CUDA userland
# in their own rootfs at the manifest's driver_version, so libcuda and the
# rest of the userland stay out of here.
#
# $out is a root-relative tree: initrd.nix copies it into the archive root.
let
  # glibc is already in nvat's closure; naming it pins the SAME libc for the
  # raw nvidia-smi below rather than risking a second one.
  glibc = pkgs.stdenv.cc.libc;
  closure = pkgs.closureInfo { rootPaths = [ nvat pkgs.cacert glibc ]; };
  version = nvidiaDriver.version;
in
pkgs.runCommand "gpu-verifier-tree" { } ''
  mkdir -p $out/nix/store $out/usr/bin $out/lib64 $out/etc/ssl/certs $out/etc/aleph
  mkdir -p $out/opt/nvidia/lib $out/lib/firmware/nvidia/${version}

  # The verifier's closure at its real store paths, so nvattest's baked
  # interpreter and RPATH resolve unchanged; cacert comes along for the RIM
  # and OCSP TLS fetches. cp -a, not install: the closure holds symlinks.
  while read -r path; do cp -a "$path" $out/nix/store/; done < ${closure}/store-paths
  ln -s ${nvat}/bin/nvattest $out/usr/bin/nvattest
  ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt $out/etc/ssl/certs/ca-bundle.crt
  # busybox provides env; the init drives nvattest through it.
  ln -s /bin/busybox $out/usr/bin/env

  # nvidia-smi is the raw, unpatched driver binary, so its PT_INTERP is the
  # literal /lib64/ld-linux-x86-64.so.2 and its DT_NEEDED names are bare
  # sonames. Point that interpreter path at the glibc in the closure and
  # expose the same directory under a stable name for LD_LIBRARY_PATH.
  ln -s ${glibc}/lib/ld-linux-x86-64.so.2 $out/lib64/ld-linux-x86-64.so.2
  ln -s ${glibc}/lib $out/opt/nvidia/glibc

  # Only what the boot-time verifier needs: NVML for nvattest, nvidia-smi for
  # persistence mode, the CC readback and the ready state.
  cp ${nvidiaDriver.userland}/libnvidia-ml.so.${version} $out/opt/nvidia/lib/
  ln -s libnvidia-ml.so.${version} $out/opt/nvidia/lib/libnvidia-ml.so.1
  ln -s libnvidia-ml.so.${version} $out/opt/nvidia/lib/libnvidia-ml.so
  cp ${nvidiaDriver.userland}/nvidia-smi $out/opt/nvidia/lib/
  chmod 0644 $out/opt/nvidia/lib/libnvidia-ml.so.${version}
  chmod 0755 $out/opt/nvidia/lib/nvidia-smi

  # GSP firmware: the open driver asks for the blob when the card is first
  # opened, and the kernel resolves that request against PID 1's root, which
  # is this initramfs. No firmware_class path override is needed.
  cp ${nvidiaDriver.firmware}/lib/firmware/nvidia/${version}/gsp_ga10x.bin \
     $out/lib/firmware/nvidia/${version}/

  # The GPU policy the init checks the measured requirement against; the same
  # bytes are published as the instance manifest's gpu block.
  install -m 0444 ${gpuFacts} $out/etc/aleph/gpu.json
''
