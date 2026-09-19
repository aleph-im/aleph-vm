{ pkgs, cuda-probe, ... }:

# Reproducible ext4 volume for the cuda-probe V-PROGRAM workload (NVIDIA CC
# smoke test). Mirrors workload.nix, with one structural difference: unlike
# fib-service (static musl), cuda-probe dlopens libcuda.so.1 at runtime via
# libloading, so it must be a normal glibc dynamic binary. The GPU chroot
# only injects the driver's own libraries at /opt/nvidia/lib (see
# gpu-rootfs.nix); this volume has to bring its own libc, dynamic linker and
# any other runtime deps, so it ships the binary's whole nix closure at its
# real store paths instead of a single copied file.
let closure = pkgs.closureInfo { rootPaths = [ cuda-probe ]; };
in pkgs.runCommand "cuda-workload.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs ];
  # Reproducible mkfs: mirrors workload.nix's determinism levers (fixed
  # timestamps, UUID and hash seed).
  SOURCE_DATE_EPOCH = "0";
} ''
  mkdir -p w/sbin w/nix/store w/opt/nvidia/lib w/proc w/sys w/dev w/etc w/tmp/secrets w/volumes
  while read -r path; do cp -a "$path" w/nix/store/; done < ${closure}/store-paths

  # /sbin/init must be a regular file, not a symlink into the closure: the
  # initrd tests it for executability from OUTSIDE the chroot (init.sh,
  # init-gpu.sh), before /nix/store is reachable at that absolute path, so
  # an absolute symlink fails that check even though it would resolve fine
  # once chrooted.
  cp ${cuda-probe}/bin/cuda-probe w/sbin/init
  chmod +x w/sbin/init

  # Mount-point targets for init.sh's prepare_chroot, same rationale as
  # workload.nix: the volume is read-only under dm-verity, so these can't be
  # created at boot. /opt/nvidia/lib is where init-gpu.sh bind-mounts the
  # driver userland (LD_LIBRARY_PATH=/opt/nvidia/lib), on top of this
  # volume's own glibc under /nix/store.
  touch w/etc/resolv.conf
  chmod 1777 w/tmp
  chmod 0700 w/tmp/secrets

  size=$(( $(du -sm w | cut -f1) + 10 ))
  truncate -s ''${size}M $out
  mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
    -E hash_seed=a1e5c0de-1111-2222-3333-444455556667,lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal -d w $out
''
