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
        /bin/busybox udhcpc -i "$iface" -q -t 5 -A 2 2>&1 || echo "init: DHCP failed on ${iface}"
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

# Prepare the chroot environment: bind-mount /proc, /sys, /dev and set up DNS.
# Called after mounting rootfs, before starting /sbin/init.
prepare_chroot() {
    /bin/busybox mkdir -p /mnt/root/proc /mnt/root/sys /mnt/root/dev /mnt/root/etc
    /bin/busybox mount --bind /proc /mnt/root/proc
    /bin/busybox mount --bind /sys /mnt/root/sys
    /bin/busybox mount --bind /dev /mnt/root/dev
    # DNS: use gateway as nameserver (common for VM bridges).
    if [ -n "$gateway" ]; then
        echo "nameserver ${gateway}" > /mnt/root/etc/resolv.conf
    fi
    echo "init: chroot environment prepared (proc, sys, dev, DNS)"
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
        echo "init: mount failed, trying without readonly"
        /bin/busybox mount "$blkdev" /mnt/root || echo "init: mount failed completely"
    fi
fi

prepare_chroot
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
