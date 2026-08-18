#!/bin/busybox sh
# /init for the SNP confidential-INSTANCE image: LUKS encrypted-rootfs boot.
#
# The owner verifies the launch measurement over attested TLS, then injects
# the LUKS passphrase (EIP-191 owner-signed, enforced by the attest-agent's
# --owner mode). The init waits INDEFINITELY: a host reboot re-enters this
# wait until the owner re-injects. A wrong passphrase zeroizes the attempt
# and resumes waiting (the agent allows authenticated re-injection).
# No guest firewall in this mode: firewall policy belongs to the user rootfs,
# as on classic instances (design section 3, decision 6).

# shellcheck disable=SC1091  # /bin/init-common.sh only exists inside the initrd
. /bin/init-common.sh

# Parse the luks-mode cmdline (normative template: console=ttyS0 luks=1
# owner=0x<40 hex>). This image boots ONLY in luks mode: fail closed on
# anything else rather than half-boot an unmeasurable configuration.
luks=$(/bin/busybox sed -n 's/.*\bluks=\([^ ]*\).*/\1/p' /proc/cmdline)
owner=$(/bin/busybox sed -n 's/.*\bowner=\(0x[0-9a-fA-F]*\).*/\1/p' /proc/cmdline)
if [ "$luks" != "1" ] || [ -z "$owner" ]; then
    echo "init: FATAL: instance image booted without luks=1 owner=0x... cmdline"
    exec /bin/busybox poweroff -f
fi

echo "init: loading dm-crypt kernel modules"
/bin/busybox insmod /lib/modules/dm-mod.ko 2>&1 || echo "init: warning: insmod dm-mod.ko failed"
/bin/busybox insmod /lib/modules/dm-crypt.ko 2>&1 || echo "init: warning: insmod dm-crypt.ko failed"
/bin/busybox mkdir -p /dev/mapper /run/cryptsetup
/bin/busybox mknod /dev/mapper/control c 10 236 2>/dev/null

wait_for_rootfs_blkdev
if [ -z "$blkdev" ]; then
    echo "init: FATAL: no block device found"
    exec /bin/busybox poweroff -f
fi

# Start the attestation agent EARLY, in owner-auth mode, so the owner can
# verify and inject the passphrase. 0700 pre-creation matches the agent's
# hardened directory check.
/bin/busybox mkdir -m 0700 -p /tmp/secrets
echo "init: starting attestation agent (owner-auth mode, owner=${owner})"
/bin/aleph-attest-agent --port 8443 --upstream http://127.0.0.1:8080 --owner "$owner" &

zeroize_passphrase() {
    size=$(/bin/busybox stat -c%s /tmp/secrets/luks_passphrase 2>/dev/null)
    if [ -n "$size" ]; then
        /bin/busybox dd if=/dev/zero of=/tmp/secrets/luks_passphrase bs=1 count="$size" conv=notrunc 2>/dev/null
    fi
    /bin/busybox rm -f /tmp/secrets/luks_passphrase
}

echo "init: waiting for LUKS passphrase at /tmp/secrets/luks_passphrase (no timeout)"
waited=0
while true; do
    if [ -f /tmp/secrets/luks_passphrase ]; then
        echo "init: unlocking LUKS volume on ${blkdev}"
        if /bin/cryptsetup luksOpen "$blkdev" cryptroot < /tmp/secrets/luks_passphrase 2>&1; then
            zeroize_passphrase
            break
        fi
        zeroize_passphrase
        echo "init: cryptsetup luksOpen failed (wrong passphrase or corrupt header); waiting for a new injection"
    fi
    /bin/busybox sleep 1
    waited=$((waited + 1))
    if [ $((waited % 60)) -eq 0 ]; then
        echo "init: still waiting for LUKS passphrase (${waited}s)"
    fi
done

/bin/busybox mkdir -p /mnt/root
echo "init: mounting /dev/mapper/cryptroot"
if ! /bin/busybox mount -t ext4 /dev/mapper/cryptroot /mnt/root; then
    echo "init: FATAL: failed to mount /dev/mapper/cryptroot"
    exec /bin/busybox poweroff -f
fi

prepare_chroot /mnt/root
if [ -x /mnt/root/sbin/init ]; then
    echo "init: starting /sbin/init from rootfs"
    /bin/busybox chroot /mnt/root /sbin/init &
else
    echo "init: WARNING: no /sbin/init found in rootfs"
fi

# Wait for children (the attest-agent keeps serving re-attestation for the
# VM's lifetime; the initramfs /tmp/secrets is invisible to the chroot except
# through prepare_chroot's bind mount).
wait
