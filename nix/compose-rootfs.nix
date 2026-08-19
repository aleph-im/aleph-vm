{ pkgs, kernel, ... }:

# Compose-runner platform rootfs (aleph.compose/1): a podman + podman-compose
# userland that boots a docker-compose workload delivered as a separate
# measured volume (compose file + OCI image tarballs under /mnt/workload).
#
# Ported from the aleph-cvm donor (nix/compose-rootfs.nix) with five deltas:
#   1. Determinism: donor's plain `mkfs.ext4 -b 4096 -d` is replaced with the
#      SAME reproducible-mkfs recipe rootfs.nix uses (fixed UUID, non-zero
#      hash_seed, SOURCE_DATE_EPOCH, no journal, non-lazy init), so this
#      image's dm-verity root hash and thus the SEV-SNP measurement are
#      stable across builds too. See rootfs.nix for the full rationale.
#   2. Ownership: built under `fakeroot` with a blanket `chown -R 0:0 rootfs`
#      immediately before mkfs (test-rootfs.nix's pattern on
#      origin/od/snp-inst-2-images), because this Nix installation cannot
#      create nested user namespaces (no CAP_SYS_ADMIN) and podman/crun
#      enforce root-owned config (containers.conf, storage.conf,
#      /etc/subuid, /etc/subgid) at runtime, checked against the image's OWN
#      uid/gid namespace, not the uid that happened to build it.
#   3. Fail-closed init: the donor's init either has no fatal-error handling
#      (module load failure just prints a warning) or ends by `exec`ing
#      podman-compose without checking its exit status, meaning a broken
#      workload can leave the attested VM's TLS listener (aleph-attest-agent
#      on 8443) up and answering with no real workload behind it. This port
#      treats every step as fatal: any failure powers the VM off
#      (`busybox poweroff -f`) rather than presenting a live-but-empty
#      attested endpoint.
#   4. Read-only mount targets: pre-create the directories/files the initrd
#      bind-mounts and podman's own bind mounts need, matching rootfs.nix's
#      comment about verity read-only mounts (the image cannot create these
#      at boot once mounted read-only under dm-verity).
#   5. fuse.ko sourcing: extracted from the STOCK kernel module output
#      (kernel.modules, unmodified nix/kernel.nix) rather than by adding a
#      module to structuredExtraConfig. That kernel derivation is shared
#      with the exec-flavor image; changing it would change the shared
#      kernel store path and thus the existing #image/#measurement outputs,
#      which must stay byte-identical to base. nixpkgs' default kernel
#      config already ships CONFIG_FUSE_FS=m (confirmed by building
#      kernel.modules and finding fs/fuse/fuse.ko.xz under it), so no
#      kernel-config change is needed at all.
#
# Everything else -- the package set, the buildEnv/closureInfo full-closure
# copy, the podman/CNI/crun config files -- is donor-identical.
let
  staticBusybox = pkgs.busybox.override { enableStatic = true; };

  # Kernel module needed by fuse-overlayfs (container layer storage).
  # The stock kernel (nix/kernel.nix, UNMODIFIED by this file: that
  # derivation is shared with the exec-flavor image, and changing its
  # structuredExtraConfig would change the shared kernel store path and
  # force a from-source rebuild) already ships CONFIG_FUSE_FS=m by nixpkgs
  # default, confirmed by building kernel.modules and finding
  # lib/modules/<modDirVersion>/kernel/fs/fuse/fuse.ko.xz there. Same modDir
  # shape initrd.nix uses for its dm-*/nf_tables modules.
  modDir = "${kernel.modules}/lib/modules/${kernel.modDirVersion}/kernel";
  containerModules = pkgs.runCommand "container-modules" {
    nativeBuildInputs = [ pkgs.xz ];
  } ''
    mkdir -p $out
    xz -d -k -c ${modDir}/fs/fuse/fuse.ko.xz > $out/fuse.ko
  '';

  # All packages needed in the compose-runner rootfs.
  runtimePackages = [
    pkgs.podman
    pkgs.crun
    pkgs.conmon
    pkgs.fuse-overlayfs
    pkgs.cni-plugins
    pkgs.podman-compose
    pkgs.slirp4netns
    staticBusybox
  ];

  # Merged environment with bin/, etc. symlinks.
  composeEnv = pkgs.buildEnv {
    name = "compose-runner-env";
    paths = runtimePackages;
    pathsToLink = [ "/bin" "/libexec" "/share" "/etc" ];
  };

  # Full Nix store closure needed by the environment.
  closure = pkgs.closureInfo { rootPaths = runtimePackages; };

  # The build script below runs under `fakeroot` (see the runCommand call):
  # a build that genuinely ran as uid 0 inside its own user namespace could
  # skip this, but this Nix installation cannot create nested user
  # namespaces here (no CAP_SYS_ADMIN), so it falls back to building as the
  # plain invoking user -- a non-zero uid/gid. `mkfs.ext4 -d` bakes whatever
  # uid/gid it reads from the source directory into the image verbatim, and
  # podman/crun enforce strict ownership on containers.conf, storage.conf
  # and /etc/subuid/subgid: at guest runtime "owned by root" means numeric
  # uid/gid 0 in the image's OWN namespace, not whatever uid happened to
  # build it on this machine. `fakeroot` intercepts stat()/chown(), so the
  # `chown -R 0:0` below and mke2fs's read of that metadata -- run in the
  # SAME fakeroot session -- agree on uid/gid 0 for everything, without
  # needing real root privilege.
  buildScript = pkgs.writeShellScript "build-compose-rootfs" ''
    set -euo pipefail

    mkdir -p rootfs/nix/store rootfs/sbin rootfs/bin rootfs/mnt/workload rootfs/etc rootfs/var rootfs/run rootfs/tmp rootfs/dev rootfs/proc rootfs/sys rootfs/root rootfs/sys/fs/cgroup rootfs/etc/containers/networks rootfs/dev/shm rootfs/tmp/secrets

    # Bind-mount target for the initrd's /etc/resolv.conf file bind-mount
    # (same reasoning as rootfs.nix: a file bind-mount needs an existing
    # target, and the rootfs is read-only under dm-verity so init cannot
    # create it at boot).
    touch rootfs/etc/resolv.conf

    # Same read-only constraint for the secrets bind-mount target.
    chmod 1777 rootfs/tmp
    chmod 0700 rootfs/tmp/secrets

    # Copy the full Nix store closure into the rootfs.
    for path in $(cat ${closure}/store-paths); do
      cp -a "$path" rootfs/nix/store/
    done

    # Create /bin symlinks from the merged environment.
    for bin in ${composeEnv}/bin/*; do
      name=$(basename "$bin")
      # Resolve the symlink to an absolute /nix/store path.
      target=$(readlink -f "$bin")
      ln -s "$target" "rootfs/bin/$name"
    done

    # Static busybox goes directly into /bin (overwrite symlink if any).
    rm -f rootfs/bin/busybox
    cp ${staticBusybox}/bin/busybox rootfs/bin/busybox

    # Kernel modules for container runtime.
    mkdir -p rootfs/lib/modules
    cp ${containerModules}/fuse.ko rootfs/lib/modules/

    # /sbin/init entrypoint: fail-closed compose-init. Any failure powers the
    # VM off rather than leaving an attested VM answering on 8443 with no
    # workload behind it. Heredoc must not be indented (shebang needs to
    # start at column 0).
    cat > rootfs/sbin/init <<'INIT'
#!/bin/busybox sh
# Compose-runner init. Fail closed: any failure powers the VM off rather
# than leaving an attested VM answering on 8443 with no workload behind it.

fatal() {
    echo "compose-init: FATAL: $1"
    exec /bin/busybox poweroff -f
}

export HOME=/root
export PATH=/bin
export XDG_RUNTIME_DIR=/run
export CONTAINERS_STORAGE_CONF=/etc/containers/storage.conf

/bin/busybox mount -t tmpfs tmpfs /run || fatal "mount /run failed"
/bin/busybox mount -t tmpfs tmpfs /tmp || fatal "mount /tmp failed"
/bin/busybox mount -t tmpfs tmpfs /var || fatal "mount /var failed"
/bin/busybox mkdir -p /var/lib/containers /var/tmp /var/run /run/containers
/bin/busybox mkdir -p /dev/shm
/bin/busybox mount -t tmpfs tmpfs /dev/shm || fatal "mount /dev/shm failed"
/bin/busybox mount -t cgroup2 cgroup2 /sys/fs/cgroup || fatal "mount cgroup2 failed"

# fuse-overlayfs is mandatory (storage.conf mount_program); failing here is
# clearer than the podman error a missing fuse module produces later.
/bin/busybox insmod /lib/modules/fuse.ko || fatal "insmod fuse.ko failed"

# aleph.compose/1 layout: compose file at the volume root, images under
# images/, at least one archive required.
[ -f /mnt/workload/docker-compose.yml ] || fatal "no docker-compose.yml in workload volume"

loaded=0
for tarball in /mnt/workload/images/*.tar; do
    [ -f "$tarball" ] || continue
    echo "compose-init: loading image $tarball"
    podman load -i "$tarball" || fatal "podman load $tarball failed"
    loaded=$((loaded + 1))
done
[ "$loaded" -gt 0 ] || fatal "no image archives under /mnt/workload/images"

cd /mnt/workload || fatal "cd /mnt/workload failed"
echo "compose-init: starting stack"
podman-compose up --no-build
fatal "compose stack exited with status $?"
INIT
    chmod +x rootfs/sbin/init

    # Podman needs basic configs -- no leading whitespace (TOML/JSON).
    mkdir -p rootfs/etc/containers
    cat > rootfs/etc/containers/policy.json <<'POLICY'
{"default": [{"type": "insecureAcceptAnything"}]}
POLICY

    cat > rootfs/etc/containers/storage.conf <<'STORAGE'
[storage]
driver = "overlay"
graphroot = "/var/lib/containers/storage"
runroot = "/run/containers/storage"

[storage.options.overlay]
mount_program = "/bin/fuse-overlayfs"
STORAGE

    # CNI networking config for podman.
    mkdir -p rootfs/etc/cni/net.d
    cat > rootfs/etc/cni/net.d/87-podman-bridge.conflist <<'CNI'
{
  "cniVersion": "0.4.0",
  "name": "podman",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "cni-podman0",
      "isGateway": true,
      "ipMasq": true,
      "hairpinMode": true,
      "ipam": {
        "type": "host-local",
        "routes": [{ "dst": "0.0.0.0/0" }],
        "ranges": [[{ "subnet": "10.88.0.0/16", "gateway": "10.88.0.1" }]]
      }
    },
    {
      "type": "portmap",
      "capabilities": { "portMappings": true }
    },
    {
      "type": "firewall"
    },
    {
      "type": "tuning"
    }
  ]
}
CNI

    # containers.conf to tell podman where to find crun and conmon.
    cat > rootfs/etc/containers/containers.conf <<'CONTAINERS'
[engine]
runtime = "crun"

[network]
cni_plugin_dirs = ["/bin"]
CONTAINERS

    # Minimal system files needed by podman/crun.
    echo "root:x:0:0:root:/root:/bin/sh" > rootfs/etc/passwd
    echo "root:x:0:" > rootfs/etc/group
    echo "root:100000:65536" > rootfs/etc/subuid
    echo "root:100000:65536" > rootfs/etc/subgid
    mkdir -p rootfs/root

    # Blanket root ownership (see the comment above buildScript): this must
    # run, under fakeroot, in the SAME process tree as the mke2fs -d call
    # below so the faked uid/gid 0 is what mke2fs actually reads back.
    chown -R 0:0 rootfs

    # Calculate size (donor's 50MB padding; this closure is large).
    size=$(du -sm rootfs | cut -f1)
    size=$((size + 50))

    truncate -s ''${size}M "$out"
    # Reproducible mkfs (rootfs.nix's recipe): fixed UUID and hash_seed, no
    # journal (rootfs is mounted read-only under dm-verity, so a journal is
    # both useless and a nondeterminism source), non-lazy inode-table/journal
    # init so nothing is written lazily/randomly. See rootfs.nix for why the
    # hash_seed must be non-zero while the UUID may be all-zero.
    mkfs.ext4 -b 4096 -U 00000000-0000-0000-0000-000000000000 \
      -E hash_seed=a1e5c0de-1111-2222-3333-444455556666,lazy_itable_init=0,lazy_journal_init=0 \
      -O ^has_journal \
      -d rootfs "$out"
  '';
in
pkgs.runCommand "compose-rootfs.ext4" {
  nativeBuildInputs = [ pkgs.e2fsprogs pkgs.fakeroot ];
  SOURCE_DATE_EPOCH = "0";
} ''
  fakeroot ${buildScript}
''
