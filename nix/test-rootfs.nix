{ pkgs, ... }:

# Test fixture: a plain (NOT dm-verity, NOT measured) ext4 rootfs that boots
# a statically linked dropbear SSH server. This is what the aleph-testnets
# SNP-instance E2E scenario (Task 14) LUKS2-wraps at RUN time (a fresh,
# per-run passphrase) and publishes as the instance's `rootfs.parent`; the
# per-run SSH public key is written into /root/.ssh/authorized_keys inside
# the opened LUKS container before boot. The measured instance init
# (init-instance.sh) chroots into it and execs this image's /sbin/init,
# itself, NOT as PID 1 and with no systemd (see init-instance.sh).
#
# Unlike rootfs.nix / workload.nix, this is deliberately NOT part of the
# measured chain: it carries no dm-verity hash tree, it is never referenced
# by a kernel cmdline roothash, and its own launch measurement is irrelevant
# (instanceMeasurementFor only covers OVMF+kernel+instanceInitrd+cmdline; the
# LUKS-encrypted rootfs contents are explicitly NOT measured, design section
# 3). It exists purely so the E2E harness has something to SSH into and
# assert against inside the confidential instance.
#
# Bit-reproducibility is NOT a goal here (and is impossible in the way that
# matters): the dropbear host key is generated at BUILD time below, so two
# builds never produce byte-identical images. The deterministic-mkfs flags
# (fixed UUID/hash_seed, no journal, SOURCE_DATE_EPOCH) are kept anyway, for
# consistency with rootfs.nix/workload.nix and because they cost nothing.
#
# Chroot environment recap (see init-common.sh's prepare_chroot): ONLY
# /proc, /sys, /dev, /tmp/secrets and /etc/resolv.conf are bind-mounted in
# from the initramfs. Nothing else is shared. Every binary this image's
# /sbin/init needs at runtime (busybox, dropbear) must therefore ship here.
let
  staticBusybox = pkgs.busybox.override { enableStatic = true; };
  staticDropbear = pkgs.pkgsStatic.dropbear;

  # The build script below runs under `fakeroot` (see the runCommand call):
  # a build that genuinely ran as uid 0 inside its own user namespace could
  # skip this, but this Nix installation cannot create nested user
  # namespaces here (no CAP_SYS_ADMIN), so it falls back to building as the
  # plain invoking user -- a non-zero uid/gid. `mkfs.ext4 -d` bakes whatever
  # uid/gid it reads from the source directory into the image verbatim, and
  # dropbear enforces strict ownership on the host key file and on
  # ~/.ssh/authorized_keys (checkpubkeyperms-style checks): at guest runtime
  # "owned by root" means numeric uid/gid 0 in the image's OWN namespace, not
  # whatever uid happened to build it on this machine. `fakeroot` intercepts
  # stat()/chown(), so the `chown -R 0:0` below and mke2fs's read of that
  # metadata -- run in the SAME fakeroot session -- agree on uid/gid 0 for
  # everything, without needing real root privilege.
  buildScript = pkgs.writeShellScript "build-test-rootfs" ''
    set -euo pipefail

    mkdir -p rootfs/sbin rootfs/bin rootfs/etc/dropbear rootfs/root/.ssh
    mkdir -p rootfs/proc rootfs/sys rootfs/dev rootfs/run rootfs/var rootfs/tmp/secrets

    cp ${staticBusybox}/bin/busybox rootfs/bin/
    # dropbear looks up the shell named in /etc/passwd (/bin/sh below) and
    # execs it directly; busybox dispatches on argv[0], so a plain symlink
    # named "sh" is enough to make it behave as the ash applet.
    ln -s busybox rootfs/bin/sh

    cp ${staticDropbear}/bin/dropbear rootfs/bin/dropbear
    chmod +x rootfs/bin/dropbear

    # Host key generated at BUILD time (see file header: this is why the
    # image is not bit-reproducible). dropbear (like openssh) refuses a host
    # key file with loose permissions or wrong ownership, hardened below via
    # 0600 + the blanket `chown -R 0:0` near the end of this script.
    dropbearkey -t ed25519 -f rootfs/etc/dropbear/dropbear_ed25519_host_key
    chmod 0600 rootfs/etc/dropbear/dropbear_ed25519_host_key
    chmod 0700 rootfs/etc/dropbear

    # Empty placeholder: the E2E harness overwrites this with the real,
    # per-run public key after LUKS2-opening the volume (see file header).
    # 0700/0600 because dropbear is picky about both the ~/.ssh directory
    # and the authorized_keys file it reads from it (root ownership is
    # handled by the blanket chown below).
    touch rootfs/root/.ssh/authorized_keys
    chmod 0600 rootfs/root/.ssh/authorized_keys
    chmod 0700 rootfs/root/.ssh
    chmod 0700 rootfs/root

    # dropbear parses /etc/passwd directly (no NSS in a static musl build) to
    # resolve root's home directory and login shell; the shell path it names
    # must exist in this image (bin/sh above). Heredoc bodies below must not
    # be indented: this is a Nix indented string, and any indentation on
    # these lines would land literally inside /etc/passwd et al, which
    # getpwnam-style parsers do not tolerate (same reasoning as the /sbin/init
    # heredoc further down).
    cat > rootfs/etc/passwd <<'PASSWD'
root:x:0:0:root:/root:/bin/sh
PASSWD
    cat > rootfs/etc/group <<'GROUP'
root:x:0:
GROUP
    # Locked password (no valid hash): this fixture is pubkey-only. dropbear
    # tolerates a missing /etc/shadow too, but a locked entry is the more
    # standard/explicit way to say "no password login".
    cat > rootfs/etc/shadow <<'SHADOW'
root:!:1:0:99999:7:::
SHADOW
    chmod 0600 rootfs/etc/shadow

    # Bind-mount target for prepare_chroot's /etc/resolv.conf file bind-mount
    # (same reasoning as rootfs.nix: needs an existing target file).
    touch rootfs/etc/resolv.conf

    chmod 1777 rootfs/tmp
    chmod 0700 rootfs/tmp/secrets

    # dropbear's compiled-in default pidfile path is /var/run/dropbear.pid
    # (see `dropbear -h`); /sbin/init below mounts a tmpfs on /run, so
    # symlinking /var/run -> /run keeps the pidfile on that tmpfs (never
    # persisted into the image) without needing an explicit -P flag, matching
    # the brief's minimal invocation.
    ln -s /run rootfs/var/run

    # Heredoc must not be indented (shebang needs to start at column 0).
    cat > rootfs/sbin/init <<'INIT'
#!/bin/busybox sh
# Test-instance init: run chrooted by the measured instance init. Networking
# is already configured by the initramfs; just serve SSH.
#
# prepare_chroot (init-common.sh) bind-mounts /dev in from the initramfs,
# but never mounts devpts anywhere, so /dev/pts (and thus pty allocation for
# an interactive `ssh` session) would otherwise be missing. Best-effort mount
# it here: a non-interactive `ssh host cmd` does not need a pty, so this must
# never block boot -- hence `|| true` throughout.
/bin/busybox mkdir -p /dev/pts 2>/dev/null || true
/bin/busybox mount -t devpts devpts /dev/pts 2>/dev/null || true

/bin/busybox mount -t tmpfs tmpfs /run 2>/dev/null
exec /bin/dropbear -F -E -p 22 -r /etc/dropbear/dropbear_ed25519_host_key
INIT
    chmod +x rootfs/sbin/init

    # Blanket root ownership (see the comment above buildScript): this must
    # run, under fakeroot, in the SAME process tree as the mke2fs -d call
    # below so the faked uid/gid 0 is what mke2fs actually reads back.
    chown -R 0:0 rootfs

    # Fixed, generous size (this is a test fixture, not a tightly packed
    # measured image): actual content is a few MB, but the E2E harness
    # LUKS2-wraps this image and needs headroom for the LUKS header plus
    # whatever else gets written into the opened container at test time.
    truncate -s 96M "$out"
    # Deterministic-mkfs flags kept for consistency with rootfs.nix/workload.nix
    # even though the host key above already makes this image non-reproducible
    # (see file header). Note: the hash_seed must be NON-zero (mke2fs treats an
    # all-zero hash_seed as "unset" and randomizes it); the UUID may be all-zero.
    mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
      -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
      -O ^has_journal \
      -d rootfs "$out"
  '';
in
pkgs.runCommand "test-rootfs.ext4" {
  # dropbearkey (host-key generation) and mkfs.ext4 are build-time tools
  # invoked by buildScript; the same static dropbear package also supplies
  # the /bin/dropbear runtime binary that script copies in. fakeroot fakes
  # the ownership mkfs.ext4 -d bakes into the image (see buildScript above).
  nativeBuildInputs = [ pkgs.e2fsprogs staticDropbear pkgs.fakeroot ];
  SOURCE_DATE_EPOCH = "0";
} ''
  fakeroot ${buildScript}
''
