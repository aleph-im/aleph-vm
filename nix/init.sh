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
        /bin/busybox udhcpc -i "$iface" -q -t 5 -A 2 -s /bin/udhcpc.script 2>&1 || echo "init: DHCP failed on ${iface}"
    fi
fi

# Parse boot mode from kernel command line.
roothash=$(/bin/busybox sed -n 's/.*\broothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)

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

/bin/busybox mkdir -p /mnt/root

# Prepare the chroot environment: bind-mount /proc, /sys, /dev, the secret dir,
# and set up DNS. Called after mounting rootfs, before starting /sbin/init.
prepare_chroot() {
    /bin/busybox mkdir -p /mnt/root/proc /mnt/root/sys /mnt/root/dev /mnt/root/etc
    /bin/busybox mount --bind /proc /mnt/root/proc
    /bin/busybox mount --bind /sys /mnt/root/sys
    /bin/busybox mount --bind /dev /mnt/root/dev
    # Secret delivery: the attest-agent writes injected secrets under /tmp/secrets
    # in THIS (initramfs) mount namespace, but the workload runs chrooted into
    # /mnt/root, where /tmp/secrets is a different filesystem. Bind-mount the
    # agent's secret dir into the chroot so the app reads exactly what the agent
    # writes. The source path matches the agent's DEFAULT_SECRETS_DIR
    # (/tmp/secrets in secrets.rs); pre-create it 0700 so the agent's hardened
    # directory check accepts it (real dir, agent-owned, owner-only).
    /bin/busybox mkdir -m 0700 -p /tmp/secrets
    /bin/busybox mkdir -m 0700 -p /mnt/root/tmp/secrets
    /bin/busybox mount --bind /tmp/secrets /mnt/root/tmp/secrets
    # DNS for the chrooted workload. The rootfs is mounted read-only under
    # dm-verity, so writing /mnt/root/etc/resolv.conf directly cannot work
    # there (the old `echo >` only ever worked on legacy writable mounts).
    # Instead, expose the initramfs /etc/resolv.conf (written by udhcpc.script
    # from the DHCP option-6 nameservers) via a file bind-mount over the
    # rootfs placeholder. On the static ip= path there is no DHCP lease, so
    # seed the initramfs copy from the gateway first (common for VM bridges).
    if [ ! -f /etc/resolv.conf ] && [ -n "$gateway" ]; then
        /bin/busybox mkdir -p /etc
        echo "nameserver ${gateway}" > /etc/resolv.conf
    fi
    if [ -f /etc/resolv.conf ]; then
        if [ -f /mnt/root/etc/resolv.conf ]; then
            /bin/busybox mount --bind /etc/resolv.conf /mnt/root/etc/resolv.conf \
                || echo "init: WARNING: resolv.conf bind-mount failed; workload DNS unavailable"
        else
            # Legacy rootfs without the placeholder: best-effort copy (works
            # only if the rootfs is mounted writable).
            /bin/busybox cp /etc/resolv.conf /mnt/root/etc/resolv.conf 2>/dev/null \
                || echo "init: WARNING: rootfs has no /etc/resolv.conf placeholder; workload DNS unavailable"
        fi
    fi
    echo "init: chroot environment prepared (proc, sys, dev, secrets, DNS)"
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
setup_firewall() {
    /bin/busybox insmod /lib/modules/nfnetlink.ko 2>&1 || echo "init: warning: insmod nfnetlink.ko failed"
    /bin/busybox insmod /lib/modules/libcrc32c.ko 2>&1 || echo "init: warning: insmod libcrc32c.ko failed"
    /bin/busybox insmod /lib/modules/nf_tables.ko 2>&1 || echo "init: warning: insmod nf_tables.ko failed"
    if /bin/nft -f - <<'NFT'
table inet filter {
	chain input {
		type filter hook input priority 0; policy drop;
		iif "lo" accept
		tcp dport 8443 accept
	}
}
NFT
    then
        echo "init: firewall active (drop inbound except tcp/8443 and loopback)"
    else
        echo "init: FATAL: failed to install guest firewall"
        exec /bin/busybox poweroff -f
    fi
}

# Load dm-verity kernel modules if verity is requested.
if [ -n "$roothash" ]; then
    echo "init: loading dm-verity kernel modules"
    /bin/busybox insmod /lib/modules/dax.ko 2>&1 || echo "init: warning: insmod dax.ko failed"
    /bin/busybox insmod /lib/modules/dm-mod.ko 2>&1 || echo "init: warning: insmod dm-mod.ko failed"
    /bin/busybox insmod /lib/modules/dm-bufio.ko 2>&1 || echo "init: warning: insmod dm-bufio.ko failed"
    /bin/busybox insmod /lib/modules/dm-verity.ko 2>&1 || echo "init: warning: insmod dm-verity.ko failed"
    # Create device-mapper control node (not auto-created without udev).
    /bin/busybox mkdir -p /dev/mapper
    /bin/busybox mknod /dev/mapper/control c 10 236
fi

if [ -n "$roothash" ]; then
    # dm-verity: wait for hash tree device (/dev/vdb)
    hashdev=""
    n=0
    while [ "$n" -lt 30 ]; do
        if [ -b /dev/vdb ]; then
            hashdev="/dev/vdb"
            break
        fi
        /bin/busybox sleep 0.1
        n=$((n + 1))
    done

    if [ -z "$hashdev" ]; then
        echo "init: FATAL: roothash set but /dev/vdb (hash tree) not found"
        exec /bin/busybox poweroff -f
    else
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

prepare_chroot

# Install the guest firewall BEFORE starting the workload, so the app can never
# be reached directly even during the window before the agent is up.
setup_firewall

if [ -x /mnt/root/sbin/init ]; then
    echo "init: starting /sbin/init from rootfs"
    /bin/busybox chroot /mnt/root /sbin/init &
else
    echo "init: WARNING: no /sbin/init found in rootfs"
fi

# Start the attestation agent (after rootfs mount).
/bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 &

# Wait for children.
wait
