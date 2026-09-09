{ pkgs, nvidiaDriver, nvat, ... }:

# The confidential-GPU platform rootfs: the base busybox rootfs content plus
# the raw driver userland at /opt/nvidia/lib, GSP firmware, NVIDIA's local
# verifier with its nix closure, and a CA bundle for its RIM/OCSP fetches.
# Same reproducibility levers as rootfs.nix (fixed UUID, non-zero hash seed,
# SOURCE_DATE_EPOCH, no journal, non-lazy inode init), because this image is
# dm-verity-hashed into the GPU flavor's measured kernel cmdline too.
let
  staticBusybox = pkgs.busybox.override { enableStatic = true; };
  # The verifier's nix closure, shipped at its real store paths so nvattest's
  # baked interpreter and RPATH resolve unchanged inside the chroot. cacert
  # comes along for the RIM and OCSP TLS fetches. glibc is already in nvat's
  # closure; it is named explicitly because the raw nvidia-smi needs it too
  # (below), and listing it here pins the SAME libc rather than risking a
  # second one.
  glibc = pkgs.stdenv.cc.libc;
  closure = pkgs.closureInfo { rootPaths = [ nvat pkgs.cacert glibc ]; };
in
pkgs.runCommand "gpu-rootfs.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs ];
  SOURCE_DATE_EPOCH = "0";
} ''
  mkdir -p rootfs/sbin rootfs/bin rootfs/srv rootfs/etc/ssl/certs rootfs/proc rootfs/sys rootfs/dev
  mkdir -p rootfs/tmp/secrets rootfs/run rootfs/usr/bin rootfs/lib64 rootfs/opt/nvidia/lib rootfs/lib/firmware/nvidia
  cp ${staticBusybox}/bin/busybox rootfs/bin/
  ln -s /bin/busybox rootfs/usr/bin/env
  # Same read-only-verity constraints as rootfs.nix: the resolv.conf
  # placeholder and the secrets directory are bind-mount targets init.sh
  # cannot create at boot, so they ship in the image.
  touch rootfs/etc/resolv.conf
  chmod 1777 rootfs/tmp
  chmod 0700 rootfs/tmp/secrets

  # Raw driver userland and GSP firmware. /opt/nvidia/lib is the runtime
  # contract with the workload (manifest gpu.library_path): init-common.sh
  # bind-mounts it into the workload chroot at the same path.
  cp -a ${nvidiaDriver.userland}/. rootfs/opt/nvidia/lib/
  cp -a ${nvidiaDriver.firmware}/lib/firmware/nvidia/. rootfs/lib/firmware/nvidia/

  # The verifier and its closure at their store paths; nvattest on PATH.
  mkdir -p rootfs/nix/store
  while read -r path; do cp -a "$path" rootfs/nix/store/; done < ${closure}/store-paths
  ln -s ${nvat}/bin/nvattest rootfs/usr/bin/nvattest
  ln -s ${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt rootfs/etc/ssl/certs/ca-bundle.crt

  # nvidia-smi is the raw, unpatched driver binary (nvidia.nix keeps it that
  # way on purpose), so its PT_INTERP is the literal
  # /lib64/ld-linux-x86-64.so.2 and its DT_NEEDED names are the bare
  # libc/libm/libpthread/libdl/librt sonames. Point that interpreter path at
  # the glibc already in the closure and expose the same directory under a
  # stable name, so init-gpu.sh can put it on LD_LIBRARY_PATH without knowing
  # a store hash. /opt/nvidia/glibc is deliberately NOT under
  # /opt/nvidia/lib: only the driver libraries are handed to the workload.
  ln -s ${glibc}/lib/ld-linux-x86-64.so.2 rootfs/lib64/ld-linux-x86-64.so.2
  ln -s ${glibc}/lib rootfs/opt/nvidia/glibc

  cat > rootfs/srv/index.html <<'HTML'
<!doctype html>
<title>aleph confidential GPU placeholder</title>
<h1>aleph confidential GPU placeholder workload</h1>
<p>Served by busybox httpd behind aleph-attest-agent.</p>
HTML

  # /sbin/init is the rootfs entrypoint convention; the no-workload fallback
  # is the same trivial httpd the base rootfs bakes.
  # Heredoc must not be indented (shebang needs to start at column 0).
  cat > rootfs/sbin/init <<'INIT'
#!/bin/busybox sh
exec /bin/busybox httpd -f -v -p 127.0.0.1:8080 -h /srv
INIT
  chmod +x rootfs/sbin/init

  size=$(du -sm rootfs | cut -f1)
  size=$((size + 64))
  truncate -s ''${size}M $out
  mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
    -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal -d rootfs $out
''
