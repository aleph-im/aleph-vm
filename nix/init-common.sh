#!/bin/busybox sh
# /bin/init-common.sh - shared prologue sourced by both measured-guest inits
# (nix/init.sh for the platform image, nix/init-instance.sh for instances).
#
# Sourced with `. /bin/init-common.sh` from busybox sh, so this runs in the
# caller's own shell: everything below runs immediately, in order, at source
# time, right through the DHCPv6 block, and plain (non-`local`) assignments
# (e.g. $iface, $gateway) stay set in the caller after the source returns.
# The functions defined at the end (wait_for_rootfs_blkdev, wait_for_dev,
# prepare_chroot) are only defined here; the caller decides when to call them.

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
        # udhcpc6 needs a usable link-local source address and bails out with
        # "can't get link-local IPv6 address" while the freshly created
        # link-local is still tentative: the sysctl above (re-)enables IPv6
        # moments before, so DAD (~1s) is still running when udhcpc6 starts
        # (seen on the SNP testnet, run 32147657203). Wait for DAD to finish,
        # bounded: v6 stays best-effort and a v6-less environment must not
        # stall boot.
        dad_tries=5
        while [ "$dad_tries" -gt 0 ]; do
            ll=$(/bin/busybox ip addr show dev "$iface" 2>/dev/null | /bin/busybox grep 'inet6 fe80' || true)
            if [ -n "$ll" ] && ! echo "$ll" | /bin/busybox grep -q tentative; then
                break
            fi
            dad_tries=$((dad_tries - 1))
            /bin/busybox sleep 1
        done
        /bin/busybox udhcpc6 -i "$iface" -q -n -t 5 -A 2 -s /bin/udhcpc6.script 2>&1 || echo "init: DHCPv6 failed on ${iface}; continuing IPv4-only"
    fi
fi

# Wait for the rootfs block device to appear, scanning /dev/vda then
# /dev/sda on each pass (30 x 0.1s, i.e. up to 3s). Sets $blkdev to the
# device found; leaves it empty on timeout. The CALLER decides fatality
# (both inits poweroff on empty), so this function only reshapes the wait
# loop, it does not exec poweroff itself.
wait_for_rootfs_blkdev() {
    blkdev=""
    n=0
    while [ "$n" -lt 30 ]; do
        for dev in /dev/vda /dev/sda; do
            if [ -b "$dev" ]; then
                # shellcheck disable=SC2034  # blkdev is consumed by the caller (init.sh), not here
                blkdev="$dev"
                return 0
            fi
        done
        /bin/busybox sleep 0.1
        n=$((n + 1))
    done
}

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

# Verified data volumes (V-PROGRAM content.volumes): comma-joined dm-verity
# roothashes from the measured `verified_volumes=` cmdline token, in message
# list order. Device order is positional and load-bearing: volume i's data
# disk is the (5+2i)-th virtio disk and its hash tree the next one, i.e. the
# pairs (vde,vdf), (vdg,vdh), ... after vda-vdd (rootfs, platform hash tree,
# workload data, workload hash tree). Verifies pair i against roothash i and
# mounts it read-only at <guest_root>/volumes/<i>.
#
# The guest root is a read-only verity mount, so per-index mount-point
# directories cannot be created there at boot; the image ships an empty
# /volumes directory (workload.nix / compose-rootfs.nix) and a tmpfs mounted
# over it holds the per-index directories. Fail closed on any mismatch: a
# missing device, a failed verity open, a guest root without /volumes, or
# volumes without a workload all power the VM off.
#
# Expects the caller to have set $verified_volumes and $workload_roothash
# from /proc/cmdline. No-op when no volumes are declared.
mount_verified_volumes() {
    local guest_root volume_count volume_index vol_roothash data_letter hash_letter datadev hashdev
    guest_root="$1"
    [ -n "$verified_volumes" ] || return 0
    # Strict shape check before anything is touched: exactly comma-joined
    # 64-char lowercase hex roothashes, no empty segments. Word-splitting
    # below would otherwise collapse "a,,b" into two entries and silently
    # re-index every volume after the gap.
    if ! echo "$verified_volumes" | /bin/busybox grep -Eq '^[0-9a-f]{64}(,[0-9a-f]{64})*$'; then
        echo "init: FATAL: verified_volumes token is malformed (expected comma-joined 64-hex roothashes)"
        exec /bin/busybox poweroff -f
    fi
    if [ -z "$workload_roothash" ]; then
        echo "init: FATAL: verified_volumes set without workload_roothash (volume devices start after the workload pair)"
        exec /bin/busybox poweroff -f
    fi
    volume_count=$(echo "$verified_volumes" | /bin/busybox tr ',' ' ' | /bin/busybox wc -w)
    if [ "$volume_count" -gt 8 ]; then
        echo "init: FATAL: ${volume_count} verified volumes declared; at most 8 are supported"
        exec /bin/busybox poweroff -f
    fi
    if [ ! -d "${guest_root}/volumes" ]; then
        echo "init: FATAL: verified_volumes set but ${guest_root} ships no /volumes mount-point directory"
        exec /bin/busybox poweroff -f
    fi
    if ! /bin/busybox mount -t tmpfs tmpfs "${guest_root}/volumes"; then
        echo "init: FATAL: tmpfs mount on ${guest_root}/volumes failed"
        exec /bin/busybox poweroff -f
    fi
    volume_index=0
    for vol_roothash in $(echo "$verified_volumes" | /bin/busybox tr ',' ' '); do
        data_letter=$(echo "e g i k m o q s" | /bin/busybox cut -d' ' -f$((volume_index + 1)))
        hash_letter=$(echo "f h j l n p r t" | /bin/busybox cut -d' ' -f$((volume_index + 1)))
        datadev="/dev/vd${data_letter}"
        hashdev="/dev/vd${hash_letter}"
        if ! wait_for_dev "$datadev"; then
            echo "init: FATAL: verified volume ${volume_index} data device ${datadev} not found"
            exec /bin/busybox poweroff -f
        fi
        if ! wait_for_dev "$hashdev"; then
            echo "init: FATAL: verified volume ${volume_index} hash tree device ${hashdev} not found"
            exec /bin/busybox poweroff -f
        fi
        echo "init: setting up dm-verity on ${datadev} with hash tree ${hashdev} (volume ${volume_index})"
        if ! /bin/veritysetup open "$datadev" "verity-volume-${volume_index}" "$hashdev" "$vol_roothash" 2>&1; then
            echo "init: FATAL: dm-verity verification failed for volume ${volume_index} - it may be tampered"
            exec /bin/busybox poweroff -f
        fi
        /bin/busybox mkdir -p "${guest_root}/volumes/${volume_index}"
        if ! /bin/busybox mount -t ext4 -o ro "/dev/mapper/verity-volume-${volume_index}" "${guest_root}/volumes/${volume_index}"; then
            echo "init: FATAL: verity mount failed for volume ${volume_index}"
            exec /bin/busybox poweroff -f
        fi
        volume_index=$((volume_index + 1))
    done
    echo "init: ${volume_index} verified volume(s) mounted under ${guest_root}/volumes"
}
