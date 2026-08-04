{ pkgs, fib-service, ... }:

# Reproducible ext4 volume for the fib-service V-PROGRAM workload (Task 6).
#
# Content-only volume: the platform rootfs (rootfs.nix) already supplies the
# kernel/initrd measured-boot chain; this volume just carries the workload
# binary that the guest init (Task 7) mounts as an extra disk and execs.
#
# /sbin/init IS the fib-service binary itself (copied, not a wrapper script):
# it is the simplest form that "actually boots" per the task brief, and it
# sidesteps needing a shell (e.g. busybox) inside this volume just to `exec`
# the real binary via a "#!/bin/sh" entrypoint. fib-service is a static-musl,
# statically-PIE-linked binary (see flake.nix), so the kernel can load it
# directly with no interpreter/dynamic linker present in this volume.
pkgs.runCommand "workload.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs ];
  # Reproducible mkfs: fixed timestamps (superblock + inodes). Nix-store source
  # files already carry a fixed mtime, so with a fixed UUID and hash seed the
  # image bytes (and thus the dm-verity root hash) are reproducible. Mirrors
  # rootfs.nix's determinism levers.
  SOURCE_DATE_EPOCH = "0";
} ''
  mkdir -p workload/sbin
  cp ${fib-service}/bin/fib-service workload/sbin/init
  chmod +x workload/sbin/init

  # Calculate size (add 10MB padding).
  size=$(du -sm workload | cut -f1)
  size=$((size + 10))

  # Create a reproducible ext4 image so the dm-verity root hash is stable
  # across builds. Determinism levers (mirrors rootfs.nix):
  #   - fixed UUID and directory hash seed (no random per-build values),
  #   - SOURCE_DATE_EPOCH (fixed superblock/inode timestamps),
  #   - no journal (^has_journal): this volume is mounted read-only under
  #     dm-verity, so a journal is useless AND a nondeterminism source,
  #   - non-lazy inode-table/journal init so nothing is written lazily/randomly.
  truncate -s ''${size}M $out
  mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
    -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal \
    -d workload $out
''
