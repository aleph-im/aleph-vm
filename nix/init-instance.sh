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

# --- Untrusted host-supplied LUKS header defense -----------------------------
# The block device and its LUKS2 header come from the untrusted host (the CRN
# operator). The SEV-SNP launch measurement covers the kernel, initrd, cmdline
# and owner key -- it does NOT cover the disk. So a malicious host can keep the
# genuine keyslot and digest (the owner's real passphrase still validates) while
# downgrading the DATA SEGMENT cipher to the null cipher
# (segments.0.encryption: aes-xts-plain64 -> cipher_null-ecb). The genuine
# passphrase then "unlocks" a PLAINTEXT volume the host pre-filled with its own
# rootfs, under a genuine attestation -- a full guest takeover. The related
# keyslot-null variant (CVE-2025-59054, fixed in cryptsetup 2.8.1) forges a
# keyslot the same way; the data-segment variant is NOT fixed at the cryptsetup
# layer and must be caught here, by the consumer (Trail of Bits, 2025-10-30:
# https://blog.trailofbits.com/2025/10/30/vulnerabilities-in-luks2-disk-encryption-for-confidential-vms/).
#
# Defense: copy the header off the untrusted device into initrd RAM ONCE,
# validate the RAM copy, then luksOpen --header the RAM copy so the on-disk
# header can never be swapped between the check and the open (TOCTOU). The
# rootfs is formatted by examples/instance_confidential_snp/build_luks_rootfs.sh
# with the cryptsetup LUKS2 default -- aes-xts-plain64 for every keyslot area
# AND the data segment -- so the invariant is exact: every "encryption" field
# in the header must read aes-xts-plain64, and there must be at least one crypt
# data segment. Any other cipher (a null-cipher downgrade above all) fails
# closed: a tampered header is never fixed by re-injecting the passphrase, so we
# power off rather than wait. The FATAL line is captured on the guest serial
# (owner-readable), and a STOPPED VM is an unambiguous "the host tampered with
# the disk" signal.
luks_header=/run/cryptsetup/luks_header.img
if ! /bin/cryptsetup luksHeaderBackup "$blkdev" --header-backup-file "$luks_header" 2>&1; then
    echo "init: FATAL: no readable LUKS2 header on ${blkdev} (host-supplied disk rejected)"
    exec /bin/busybox poweroff -f
fi
# stderr is left on the serial console so a parse failure names its cause.
meta=$(/bin/cryptsetup luksDump --dump-json-metadata "$luks_header")
# --dump-json-metadata re-serializes the header through OUR cryptsetup, so the
# JSON escaping is ours, not the attacker's: a field smuggled inside a string
# value comes out as \"encryption\" and cannot match. grep -o emits one line
# per match, so wc -l counts fields regardless of how many share a line, and
# the optional whitespace after ':' tolerates a pretty-printing change.
# Only the cipher string is policed, not key_size or sector_size: a tampered
# key_size or a forged keyslot is rejected at luksOpen anyway, because the
# digest binds the volume key and, without the owner's passphrase, the host
# cannot build a self-consistent keyslot+digest pair. The data-segment cipher
# is the one field the digest does NOT bind, so it is the one we must check.
enc_total=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"encryption":[[:space:]]*"' | /bin/busybox wc -l)
enc_ok=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"encryption":[[:space:]]*"aes-xts-plain64"' | /bin/busybox wc -l)
seg_crypt=$(printf '%s\n' "$meta" | /bin/busybox grep -o '"type":[[:space:]]*"crypt"' | /bin/busybox wc -l)
if [ "$enc_total" -lt 1 ] || [ "$enc_total" != "$enc_ok" ] || [ "$seg_crypt" -lt 1 ]; then
    echo "init: FATAL: untrusted LUKS header rejected -- expected aes-xts-plain64 on every"
    echo "init:        keyslot area and data segment, got ${enc_ok}/${enc_total} matching and"
    echo "init:        ${seg_crypt} crypt segment(s). Possible host cipher_null downgrade"
    echo "init:        (Trail of Bits 2025-10-30). Refusing to unlock the rootfs."
    exec /bin/busybox poweroff -f
fi
echo "init: LUKS header validated (${enc_ok}/${enc_total} aes-xts-plain64, ${seg_crypt} crypt segment)"

# Start the attestation agent EARLY, in owner-auth mode, so the owner can
# verify and inject the passphrase. 0700 pre-creation matches the agent's
# hardened directory check.
/bin/busybox mkdir -m 0700 -p /tmp/secrets
echo "init: starting attestation agent (owner-auth mode, owner=${owner})"
run_attest_agent --owner "$owner"

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
    # The agent writes the passphrase atomically (temp file + rename() into
    # place), so this poll never has to worry about landing mid-write; [ -s ]
    # (non-empty, not just present) is defense in depth against a legacy or
    # third-party agent build that writes create+truncate-then-write_all,
    # where a poll landing right after the truncate would otherwise see an
    # empty file and feed cryptsetup zero bytes.
    if [ -s /tmp/secrets/luks_passphrase ]; then
        echo "init: unlocking LUKS volume on ${blkdev}"
        # --header pins the open to the RAM copy we validated above; the on-disk
        # header is never re-read, closing the check-vs-use TOCTOU.
        if /bin/cryptsetup luksOpen --header "$luks_header" "$blkdev" cryptroot < /tmp/secrets/luks_passphrase 2>&1; then
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
if [ ! -x /mnt/root/sbin/init ]; then
    # A missing /sbin/init means the owner's decrypted rootfs is malformed
    # (the same failure class as a v-program workload with no /sbin/init, which
    # also powers off). Fail closed rather than leaving a RUNNING-but-useless VM
    # that looks healthy: the FATAL line is captured on the guest serial (owner-
    # readable via the logs endpoint), and a STOPPED VM is an unambiguous signal
    # to redeploy a fixed rootfs.
    echo "init: FATAL: no /sbin/init in the unlocked rootfs (malformed user image)"
    exec /bin/busybox poweroff -f
fi

# Fail-closed supervision (same as init.sh / init-compose.sh): wait on the
# guest's PID specifically, not on all children. The attest-agent keeps
# serving re-attestation for the VM's lifetime, so a bare `wait` would keep
# the VM and its live attested endpoint up after the owner's /sbin/init
# died; instead a dead guest takes the VM down. (The initramfs /tmp/secrets
# is invisible to the chroot except through prepare_chroot's bind mount.)
echo "init: starting /sbin/init from rootfs"
/bin/busybox chroot /mnt/root /sbin/init &
guest_pid=$!
wait "$guest_pid"
echo "init: /sbin/init exited; powering off"
exec /bin/busybox poweroff -f
