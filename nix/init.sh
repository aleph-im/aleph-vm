#!/bin/busybox sh
# /init - runs inside the VM as PID 1
#
# Minimal measured-boot init for the aleph-vm SEV-SNP backport. Adapted from the
# aleph-cvm donor: the LUKS encrypted-rootfs branch and the compose workload
# volume branch are stripped (design section 6 non-goals). What remains is the
# core measured-boot chain: bring up networking, verify + mount the
# dm-verity-protected rootfs (or plain-mount if no roothash), start the
# attestation agent, chroot into the rootfs and wait on that /sbin/init,
# powering off when it exits. See rust-port-divergences.
#
# The mounts/networking prologue and the wait_for_rootfs_blkdev/wait_for_dev/
# prepare_chroot helpers live in init-common.sh, shared with init-instance.sh.

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
    # No dm-verity: direct mount (backwards compatible)
    echo "init: mounting ${blkdev} (no dm-verity)"
    if ! /bin/busybox mount -o ro "$blkdev" /mnt/root; then
        echo "init: WARNING: read-only mount failed; falling back to a writable mount"
        echo "init: WARNING: the rootfs is NOT integrity-protected on this path"
        if ! /bin/busybox mount "$blkdev" /mnt/root; then
            # Nothing to run: without a rootfs the rest of this script would
            # prepare an empty chroot and start the attest-agent proxying to
            # nothing. Fail closed like every other flavor does.
            echo "init: FATAL: rootfs mount failed"
            exec /bin/busybox poweroff -f
        fi
    fi
fi

# V-PROGRAM workload volume: verity-verify and mount the workload data disk
# (/dev/vdc) against its hash tree (/dev/vdd), distinct devices from the
# platform rootfs (/dev/vda) and its hash tree (/dev/vdb) above. Only present
# when the daemon attached a workload; when workload_roothash is empty this
# whole block is skipped and behavior is unchanged (platform /sbin/init runs
# below, as today).
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
fi

# Prepare only the chroot that will actually run its /sbin/init: when a
# workload volume is mounted, the workload runs INSTEAD OF the platform
# /sbin/init, so the bind mounts (proc, sys, dev, secrets, DNS) belong in
# /mnt/workload and preparing /mnt/root would be wasted work (and vice versa).
if [ -n "$workload_roothash" ]; then
    prepare_chroot /mnt/workload
else
    prepare_chroot /mnt/root
fi

# Install the guest firewall BEFORE starting the workload, so the app can never
# be reached directly even during the window before the agent is up.
setup_firewall

# When a V-PROGRAM workload is mounted, its /sbin/init (the workload
# entrypoint, e.g. fib-service) runs INSTEAD OF the baked platform
# /sbin/init (the busybox httpd fallback used when no workload is present).
if [ -n "$workload_roothash" ]; then
    guest_root=/mnt/workload
else
    guest_root=/mnt/root
fi
if [ ! -x "$guest_root/sbin/init" ]; then
    # dm-verity already proved the volume authentic, so a missing /sbin/init
    # means a malformed image: fail closed like every other error path
    # instead of leaving the attest-agent proxying to a dead upstream.
    echo "init: FATAL: no /sbin/init found in $guest_root"
    exec /bin/busybox poweroff -f
fi

# Start the attestation agent (after rootfs mount).
/bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 &

# Fail-closed supervision (same as init-compose.sh): wait on the guest's PID
# specifically, not on all children. A bare `wait` would keep the VM, and its
# live attested TLS endpoint, up after the workload died, with the agent
# proxying to a dead upstream; instead a dead workload takes the VM down.
echo "init: starting /sbin/init from $guest_root"
/bin/busybox chroot "$guest_root" /sbin/init &
guest_pid=$!
wait "$guest_pid"
echo "init: /sbin/init exited; powering off"
exec /bin/busybox poweroff -f
