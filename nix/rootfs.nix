{ pkgs, ... }:

# Minimal dm-verity-protected rootfs for the measured-boot chain.
#
# The aleph-cvm donor baked its `fib-service` demo binary here. That demo app is
# out of scope for this backport (design section 6 non-goals), so it is replaced
# with a trivial placeholder workload: a static busybox httpd on 127.0.0.1:8080,
# which is exactly the upstream the aleph-attest-agent reverse-proxies to. This
# is enough to boot the measured image and exercise the attest-agent in front of
# a real workload, without importing the demo app.
let
  staticBusybox = pkgs.busybox.override { enableStatic = true; };
in
pkgs.runCommand "rootfs.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs ];
  # Reproducible mkfs: fixed timestamps (superblock + inodes). Nix-store source
  # files already carry a fixed mtime, so with a fixed UUID and hash seed the
  # image bytes (and thus the dm-verity root hash and SEV-SNP measurement) are
  # reproducible. This hardens design section 8's top risk (measurement
  # reproducibility) beyond the aleph-cvm donor, which left mkfs nondeterministic.
  SOURCE_DATE_EPOCH = "0";
} ''
  # Create a minimal ext4 image with /sbin/init entrypoint.
  mkdir -p rootfs/sbin rootfs/bin rootfs/srv rootfs/etc
  # Mount-point targets for init.sh's prepare_chroot proc/sys/dev bind mounts:
  # like the resolv.conf and secrets targets below, these cannot be created at
  # boot on the read-only verity mount, so they must ship in the image.
  mkdir -p rootfs/proc rootfs/sys rootfs/dev
  cp ${staticBusybox}/bin/busybox rootfs/bin/

  # Empty resolv.conf placeholder: the rootfs is mounted read-only under
  # dm-verity, so init.sh cannot create files in it at boot. It instead
  # bind-mounts the initramfs /etc/resolv.conf (the DHCP-provided nameservers
  # written by udhcpc.script) over this placeholder so the chrooted workload
  # gets DNS. A file bind-mount needs an existing target.
  touch rootfs/etc/resolv.conf

  # Same read-only constraint for the secrets bind-mount target: init.sh's
  # `mkdir -p /mnt/root/tmp/secrets` cannot create directories on the verity
  # mount, so ship them in the image (mkdir -p then no-ops and the bind-mount
  # of the initramfs /tmp/secrets finds its target).
  mkdir -p rootfs/tmp/secrets
  chmod 1777 rootfs/tmp
  chmod 0700 rootfs/tmp/secrets

  # Placeholder workload page served by busybox httpd.
  cat > rootfs/srv/index.html <<'HTML'
<!doctype html>
<title>aleph confidential placeholder</title>
<h1>aleph confidential placeholder workload</h1>
<p>Served by busybox httpd behind aleph-attest-agent.</p>
HTML

  # /sbin/init is the rootfs entrypoint convention.
  # Heredoc must not be indented (shebang needs to start at column 0).
  cat > rootfs/sbin/init <<'INIT'
#!/bin/busybox sh
# Trivial workload: serve a static page on the port the attest-agent proxies to.
exec /bin/busybox httpd -f -v -p 127.0.0.1:8080 -h /srv
INIT
  chmod +x rootfs/sbin/init

  # Calculate size (add 10MB padding).
  size=$(du -sm rootfs | cut -f1)
  size=$((size + 10))

  # Create a reproducible ext4 image so the dm-verity root hash and thus the
  # SEV-SNP measurement are stable across builds. Determinism levers:
  #   - fixed UUID and directory hash seed (no random per-build values),
  #   - SOURCE_DATE_EPOCH (fixed superblock/inode timestamps; nix-store source
  #     files already carry a fixed mtime),
  #   - no journal (^has_journal): the rootfs is mounted read-only under
  #     dm-verity, so a journal is useless AND its contents are a nondeterminism
  #     source; dropping it also shrinks the image,
  #   - non-lazy inode-table/journal init so nothing is written lazily/randomly.
  truncate -s ''${size}M $out
  # Note: the hash seed must be NON-zero. mke2fs treats an all-zero hash_seed as
  # "unset" and generates a random one (leaving s_hash_seed + the superblock
  # checksum nondeterministic), so a fixed NON-zero hash_seed is used below. The
  # UUID is deliberately all-zero (-U 00000000-...); it is the hash_seed, not the
  # UUID, that must be non-zero for reproducibility.
  mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
    -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
    -O ^has_journal \
    -d rootfs $out
''
