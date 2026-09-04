#!/bin/busybox sh
# /init for the COMPOSE flavor of the V-PROGRAM image (aleph.compose/1).
#
# Same measured-boot chain as nix/init.sh (the aleph.exec/1 / builtin
# flavor): networking, dm-verity-verified platform rootfs and workload
# volume, guest firewall, attestation agent. The mounts/networking prologue
# and the wait_for_rootfs_blkdev/wait_for_dev/prepare_chroot helpers live in
# init-common.sh, shared with init.sh and init-instance.sh.
#
# Deltas from init.sh (diff against it to verify; everything not listed is
# byte-identical):
#   1. roothash is REQUIRED: init.sh's no-verity fallback (plain mount +
#      "NOT integrity-protected" warning) becomes a fatal poweroff (a
#      compose runtime is always measured).
#   2. workload_roothash is REQUIRED: missing -> fatal poweroff (the compose
#      contract has no workload-less mode).
#   3. Launch topology inversion: /mnt/workload is bind-mounted at
#      /mnt/root/mnt/workload instead of being chrooted directly, so the
#      platform's /sbin/init (the podman/podman-compose runner, see
#      compose-rootfs.nix) is the chroot entrypoint, never the workload.
#   4. The chroot target is always /mnt/root (init.sh picks /mnt/workload
#      when a workload volume is present). The fatal check on
#      $root/sbin/init, the agent-before-chroot start ordering (so `$!`
#      after `chroot ... &` is the guest's own pid) and the fail-closed
#      supervision (wait on that pid, power off when it exits) are the same
#      in both scripts.

# shellcheck disable=SC1091  # /bin/init-common.sh only exists inside the initrd
. /bin/init-common.sh

# Parse boot mode from kernel command line.
roothash=$(/bin/busybox sed -n 's/.*\broothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)
# Parse the V-PROGRAM workload root hash, if present. `\b` requires a
# non-word character immediately before the match: since "_" and letters are
# both word characters, `\broothash=` above never matches inside
# "workload_roothash=" (no boundary between the "d" of "workload" and the "_"
# that follows, nor between that "_" and "r"), and this `\bworkload_roothash=`
# match is unambiguous on its own. The two tokens never cross-match.
workload_roothash=$(/bin/busybox sed -n 's/.*\bworkload_roothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)

# Verified data volumes: comma-joined roothashes, lowercase hex only (the
# schema and daemon both pin lowercase). Same \b reasoning as above. Capture
# up to the next space (not a charset restricted to [0-9a-f,]): a malformed
# token must reach mount_verified_volumes' anchored grep so it is the one
# gate that decides well-formedness, rather than silently truncating to an
# empty capture here.
# shellcheck disable=SC2034  # verified_volumes is consumed by mount_verified_volumes (init-common.sh), not here
verified_volumes=$(/bin/busybox sed -n 's/.*\bverified_volumes=\([^ ]*\).*/\1/p' /proc/cmdline)

# Wait for the rootfs block device to appear.
wait_for_rootfs_blkdev
if [ -z "$blkdev" ]; then
    echo "init: FATAL: no block device found"
    exec /bin/busybox poweroff -f
fi

/bin/busybox mkdir -p /mnt/root

# Install a minimal guest firewall so only the attested TLS port is reachable
# from outside the VM. Everything the workload binds (e.g. the upstream on
# 127.0.0.1:8080, or anything it accidentally binds on 0.0.0.0) stays
# unreachable, so a client cannot bypass the attest-agent and hit the raw app.
# Loopback stays fully open (the agent proxies to the upstream over lo).
#
# The ruleset is STATELESS on purpose: for a TCP connection to the server the
# inbound packets always carry dport 8443, so `tcp dport 8443 accept` covers the
# whole flow without a conntrack module. Load order matches modules.dep.
#
# The `inet` table family filters BOTH IPv4 and IPv6 with one ruleset, so
# `tcp dport 8443` already covers v6 connections. The icmpv6 accept rule is
# control-plane only (no app data crosses it), but without it the firewall
# would break IPv6 on its own: Router Advertisements refresh the SLAAC-free
# default route's lifetime, Neighbor Solicitation/Advertisement keep
# resolving the gateway (NUD re-probes after ~30s idle), and Packet Too Big
# drives Path MTU Discovery. Dropping any of those silently blackholes v6
# minutes into the VM's life, not at boot. No DHCP rules (udp 68/546): both
# clients run with -q and exit before this firewall exists (see init
# networking above).
setup_firewall() {
    /bin/busybox insmod /lib/modules/nfnetlink.ko 2>&1 || echo "init: warning: insmod nfnetlink.ko failed"
    /bin/busybox insmod /lib/modules/nf_tables.ko 2>&1 || echo "init: warning: insmod nf_tables.ko failed"
    if /bin/nft -f - <<'NFT'
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		tcp dport 8443 accept
		icmpv6 type { nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept
	}
}
NFT
    then
        echo "init: firewall active (drop inbound except tcp/8443, loopback, and ND/PMTU icmpv6)"
    else
        echo "init: FATAL: failed to install guest firewall"
        exec /bin/busybox poweroff -f
    fi
}

# Load dm-verity kernel modules if verity is requested (platform rootfs
# and/or workload volume: either token alone is enough to need dm-verity).
if [ -n "$roothash" ] || [ -n "$workload_roothash" ]; then
    echo "init: loading dm-verity kernel modules"
    /bin/busybox insmod /lib/modules/dm-mod.ko 2>&1 || echo "init: warning: insmod dm-mod.ko failed"
    /bin/busybox insmod /lib/modules/dm-bufio.ko 2>&1 || echo "init: warning: insmod dm-bufio.ko failed"
    /bin/busybox insmod /lib/modules/dm-verity.ko 2>&1 || echo "init: warning: insmod dm-verity.ko failed"
    # Create device-mapper control node (not auto-created without udev).
    /bin/busybox mkdir -p /dev/mapper
    /bin/busybox mknod /dev/mapper/control c 10 236
fi

if [ -n "$roothash" ]; then
    # dm-verity: wait for the platform hash tree device (/dev/vdb).
    if wait_for_dev /dev/vdb; then
        hashdev="/dev/vdb"
    else
        echo "init: FATAL: roothash set but /dev/vdb (hash tree) not found"
        exec /bin/busybox poweroff -f
    fi

    echo "init: setting up dm-verity on ${blkdev} with hash tree ${hashdev}"
    echo "init: roothash=${roothash}"
    if /bin/veritysetup open "$blkdev" verity-root "$hashdev" "$roothash" 2>&1; then
        echo "init: mounting /dev/mapper/verity-root"
        if ! /bin/busybox mount -t ext4 -o ro /dev/mapper/verity-root /mnt/root; then
            echo "init: FATAL: verity mount failed"
            exec /bin/busybox poweroff -f
        fi
    else
        echo "init: FATAL: dm-verity verification failed - rootfs may be tampered"
        exec /bin/busybox poweroff -f
    fi
else
    # Compose delta 1: roothash is REQUIRED (a compose runtime is always
    # measured); init.sh's no-verity fallback (plain mount + "NOT
    # integrity-protected" warning) becomes a fatal poweroff here.
    echo "init: FATAL: roothash not set; the compose runtime requires a measured rootfs"
    exec /bin/busybox poweroff -f
fi

# V-PROGRAM workload volume: verity-verify and mount the workload data disk
# (/dev/vdc) against its hash tree (/dev/vdd), distinct devices from the
# platform rootfs (/dev/vda) and its hash tree (/dev/vdb) above. Compose
# delta 2: workload_roothash is REQUIRED here (see the fatal else below), so
# unlike init.sh this block always runs.
if [ -n "$workload_roothash" ]; then
    if ! wait_for_dev /dev/vdc; then
        echo "init: FATAL: workload_roothash set but /dev/vdc (workload data) not found"
        exec /bin/busybox poweroff -f
    fi
    if ! wait_for_dev /dev/vdd; then
        echo "init: FATAL: workload_roothash set but /dev/vdd (workload hash tree) not found"
        exec /bin/busybox poweroff -f
    fi

    echo "init: setting up dm-verity on /dev/vdc with hash tree /dev/vdd (workload)"
    echo "init: workload_roothash=${workload_roothash}"
    if /bin/veritysetup open /dev/vdc verity-workload /dev/vdd "$workload_roothash" 2>&1; then
        /bin/busybox mkdir -p /mnt/workload
        echo "init: mounting /dev/mapper/verity-workload"
        if ! /bin/busybox mount -t ext4 -o ro /dev/mapper/verity-workload /mnt/workload; then
            echo "init: FATAL: workload verity mount failed"
            exec /bin/busybox poweroff -f
        fi
    else
        echo "init: FATAL: dm-verity verification failed for the workload volume - it may be tampered"
        exec /bin/busybox poweroff -f
    fi
else
    # Compose delta 2: workload_roothash is REQUIRED; the compose contract
    # has no workload-less mode.
    echo "init: FATAL: workload_roothash not set; the compose runtime requires a workload volume"
    exec /bin/busybox poweroff -f
fi

# Compose delta 3: launch topology inversion. The platform's /sbin/init (the
# podman/podman-compose runner, see compose-rootfs.nix) is always the chroot
# entrypoint, never the workload. Prepare /mnt/root as usual, then bind-mount
# the already-verified /mnt/workload data volume at /mnt/root/mnt/workload so
# the platform init can read it from inside the chroot.
prepare_chroot /mnt/root
/bin/busybox mkdir -p /mnt/root/mnt/workload
if ! /bin/busybox mount --bind /mnt/workload /mnt/root/mnt/workload; then
    echo "init: FATAL: workload bind mount failed"
    exec /bin/busybox poweroff -f
fi

# Verified data volumes land in the PLATFORM chroot for compose (unlike
# exec, where they land in the workload chroot): podman runs chrooted into
# /mnt/root and resolves compose-file bind sources like /volumes/0 there.
mount_verified_volumes /mnt/root

# Install the guest firewall BEFORE starting the workload, so the app can never
# be reached directly even during the window before the agent is up.
setup_firewall

# Compose delta 4: the chroot target is always /mnt/root, with the same
# fatal check on /sbin/init (missing or non-executable -> poweroff) as
# init.sh.
if [ ! -x /mnt/root/sbin/init ]; then
    echo "init: FATAL: no /sbin/init found in rootfs"
    exec /bin/busybox poweroff -f
fi

# Start the attestation agent (after rootfs mount). Plain HTTP in local
# mode, see start_attest_agent in init-common.sh.
start_attest_agent

echo "init: starting /sbin/init from rootfs"

# Fail-closed supervision (same as init.sh / init-instance.sh): wait
# specifically on the guest's PID and power off as soon as it exits, so a
# dead compose stack takes the VM down instead of leaving a live attested
# endpoint proxying to nothing.
/bin/busybox chroot /mnt/root /sbin/init &
guest_pid=$!
wait "$guest_pid"
echo "init: compose runtime exited; powering off"
exec /bin/busybox poweroff -f
