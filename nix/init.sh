#!/bin/busybox sh
# /init - runs inside the VM as PID 1
#
# Minimal measured-boot init for the aleph-vm SEV-SNP backport. Adapted from the
# aleph-cvm donor: the LUKS encrypted-rootfs branch and the compose workload
# volume branch are stripped (design section 6 non-goals). What remains is the
# core measured-boot chain: bring up networking, verify + mount the
# dm-verity-protected rootfs (or plain-mount if no roothash), chroot into it,
# and start the attestation agent. See rust-port-divergences.

# Mount essential filesystems.
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev
/bin/busybox mkdir -p /etc /tmp

# Bring up loopback.
/bin/busybox ip link set lo up

# Wait for a network interface to appear (virtio-net may take a moment).
n=0
while [ "$n" -lt 30 ]; do
    iface=$(/bin/busybox ls /sys/class/net/ | /bin/busybox grep -v lo | /bin/busybox head -1)
    if [ -n "$iface" ]; then
        break
    fi
    /bin/busybox sleep 0.1
    n=$((n + 1))
done

if [ -z "$iface" ]; then
    echo "init: no network interface found"
else
    # Parse ip= from kernel command line: ip=<client>:::<gateway>:<mask>::<iface>:off
    kernel_ip=$(/bin/busybox sed -n 's/.*ip=\([^ ]*\).*/\1/p' /proc/cmdline)
    if [ -n "$kernel_ip" ]; then
        client_ip=$(echo "$kernel_ip" | /bin/busybox cut -d: -f1)
        gateway=$(echo "$kernel_ip" | /bin/busybox cut -d: -f4)
        mask=$(echo "$kernel_ip" | /bin/busybox cut -d: -f5)
        echo "init: static IP ${client_ip}/${mask} gw ${gateway} on ${iface}"
        /bin/busybox ip link set "$iface" up
        /bin/busybox ip addr add "${client_ip}/${mask}" dev "$iface"
        /bin/busybox ip route add default via "$gateway"
    else
        echo "init: bringing up ${iface} via DHCP"
        /bin/busybox ip link set "$iface" up
        # -s: busybox udhcpc leases an address but only APPLIES it (ip addr/route)
        # by running this script; without it the guest would lease from the host's
        # per-tap dnsmasq but never configure its IP. See udhcpc.script.
        /bin/busybox udhcpc -i "$iface" -q -n -t 5 -A 2 -s /bin/udhcpc.script 2>&1 || echo "init: DHCP failed on ${iface}"

        # IPv6: stateful DHCPv6 from the same per-tap dnsmasq that served the
        # IPv4 lease above, handing this guest EXACTLY its allocated
        # /124-scheme address; the default route comes from the kernel
        # processing that dnsmasq's Router Advertisements (DHCPv6 cannot
        # convey routes). Never a kernel-cmdline address: baking the per-VM
        # address into the measured cmdline would break the publisher's
        # precomputed SNP measurement, the exact reason the IPv4 path above
        # uses DHCP. accept_ra=2 keeps RA processing on regardless of
        # forwarding settings; both sysctls are best-effort (a v6-less
        # kernel stays IPv4-only). The client is bounded and non-fatal like
        # udhcpc above: `-n` makes it exit 1 (instead of retrying forever)
        # once its solicit retries are exhausted, so `||` below always runs
        # and the guest simply stays IPv4-only when no DHCPv6 server answers.
        # -q exits after the lease (the script applies the address
        # permanently), so no client survives into the firewalled steady
        # state and no DHCP firewall rule is needed.
        echo 0 > "/proc/sys/net/ipv6/conf/${iface}/disable_ipv6" 2>/dev/null || true
        echo 2 > "/proc/sys/net/ipv6/conf/${iface}/accept_ra" 2>/dev/null || true
        /bin/busybox udhcpc6 -i "$iface" -q -n -t 5 -A 2 -s /bin/udhcpc6.script 2>&1 || echo "init: DHCPv6 failed on ${iface}; continuing IPv4-only"
    fi
fi

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
blkdev=""
n=0
while [ "$n" -lt 30 ]; do
    for dev in /dev/vda /dev/sda; do
        if [ -b "$dev" ]; then
            blkdev="$dev"
            break 2
        fi
    done
    /bin/busybox sleep 0.1
    n=$((n + 1))
done

if [ -z "$blkdev" ]; then
    echo "init: FATAL: no block device found"
    exec /bin/busybox poweroff -f
fi

# Wait (up to 3s) for a block device to appear, e.g. a dm-verity hash tree
# disk attached by QEMU as an extra virtio-blk device. Used for both the
# platform hash tree (/dev/vdb) and the workload data + hash tree devices
# (/dev/vdc, /dev/vdd) below, so each disk is waited for explicitly instead
# of assuming a single fixed device name.
wait_for_dev() {
    local dev n
    dev="$1"
    n=0
    while [ "$n" -lt 30 ]; do
        if [ -b "$dev" ]; then
            return 0
        fi
        /bin/busybox sleep 0.1
        n=$((n + 1))
    done
    return 1
}

/bin/busybox mkdir -p /mnt/root

# Prepare a chroot environment: bind-mount /proc, /sys, /dev, the secret dir,
# and set up DNS in the given target. Called with the chroot that will
# actually run its /sbin/init (/mnt/workload when a V-PROGRAM workload volume
# is mounted, /mnt/root otherwise), after mounting it.
#
# The target is mounted read-only under dm-verity, so the mkdirs below cannot
# create anything there: the mount-point directories (and the resolv.conf
# placeholder file) are shipped in the image (rootfs.nix / workload.nix) and
# the mkdirs no-op. They only do real work on the legacy writable-mount path.
prepare_chroot() {
    local target
    target="$1"
    /bin/busybox mkdir -p "$target/proc" "$target/sys" "$target/dev" "$target/etc"
    /bin/busybox mount --bind /proc "$target/proc"
    /bin/busybox mount --bind /sys "$target/sys"
    /bin/busybox mount --bind /dev "$target/dev"
    # Secret delivery: the attest-agent writes injected secrets under /tmp/secrets
    # in THIS (initramfs) mount namespace, but the workload runs chrooted into
    # the target, where /tmp/secrets is a different filesystem. Bind-mount the
    # agent's secret dir into the chroot so the app reads exactly what the agent
    # writes. The source path matches the agent's DEFAULT_SECRETS_DIR
    # (/tmp/secrets in secrets.rs); pre-create it 0700 so the agent's hardened
    # directory check accepts it (real dir, agent-owned, owner-only).
    /bin/busybox mkdir -m 0700 -p /tmp/secrets
    /bin/busybox mkdir -m 0700 -p "$target/tmp/secrets"
    /bin/busybox mount --bind /tmp/secrets "$target/tmp/secrets"
    # DNS for the chrooted workload. The target is mounted read-only under
    # dm-verity, so writing its /etc/resolv.conf directly cannot work
    # there (the old `echo >` only ever worked on legacy writable mounts).
    # Instead, expose the initramfs /etc/resolv.conf (written by udhcpc.script
    # from the DHCP option-6 nameservers) via a file bind-mount over the
    # image's placeholder. On the static ip= path there is no DHCP lease, so
    # seed the initramfs copy from the gateway first (common for VM bridges).
    if [ ! -f /etc/resolv.conf ] && [ -n "$gateway" ]; then
        /bin/busybox mkdir -p /etc
        echo "nameserver ${gateway}" > /etc/resolv.conf
    fi
    if [ -f /etc/resolv.conf ]; then
        if [ -f "$target/etc/resolv.conf" ]; then
            /bin/busybox mount --bind /etc/resolv.conf "$target/etc/resolv.conf" \
                || echo "init: WARNING: resolv.conf bind-mount failed; workload DNS unavailable"
        else
            # Legacy image without the placeholder: best-effort copy (works
            # only if the target is mounted writable).
            /bin/busybox cp /etc/resolv.conf "$target/etc/resolv.conf" 2>/dev/null \
                || echo "init: WARNING: ${target} has no /etc/resolv.conf placeholder; workload DNS unavailable"
        fi
    fi
    echo "init: chroot environment prepared at ${target} (proc, sys, dev, secrets, DNS)"
}

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
        /bin/busybox mount "$blkdev" /mnt/root || echo "init: mount failed completely"
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
    if [ -x /mnt/workload/sbin/init ]; then
        echo "init: starting /sbin/init from workload volume"
        /bin/busybox chroot /mnt/workload /sbin/init &
    else
        # dm-verity already proved the volume authentic, so a missing
        # /sbin/init means a malformed workload image: fail closed like every
        # other error path instead of leaving the attest-agent proxying to a
        # dead upstream.
        echo "init: FATAL: no /sbin/init found in workload volume"
        exec /bin/busybox poweroff -f
    fi
elif [ -x /mnt/root/sbin/init ]; then
    echo "init: starting /sbin/init from rootfs"
    /bin/busybox chroot /mnt/root /sbin/init &
else
    echo "init: WARNING: no /sbin/init found in rootfs"
fi

# Start the attestation agent (after rootfs mount).
/bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 &

# Wait for children.
wait
