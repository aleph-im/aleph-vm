#!/bin/bash
# Build a LUKS2-encrypted SNP instance rootfs from a plain ext4 rootfs image.
#
# Usage: build_luks_rootfs.sh <plain-rootfs.ext4> <output.img> [size-mib]
# Prompts for the passphrase (or reads LUKS_PASSPHRASE from the environment).
#
# Contract (docs/plans/2026-08-18-snp-confidential-instances-design.md):
# whole-device LUKS2 container, ext4 inside, an executable /sbin/init run
# CHROOTED by the measured init (not PID 1: systemd images will not work),
# SSH keys and all provisioning inside the image. The CRN never sees the
# passphrase; it is injected post-attestation via aleph-attest-cli
# inject-secret --owner-key.
set -euo pipefail
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <plain-rootfs.ext4> <output.img> [size-mib]" >&2
    exit 1
fi
PLAIN="$1"; OUT="$2"; SIZE_MIB="${3:-$(( ($(stat -c%s "$PLAIN") / 1048576) + 64 ))}"
PASS="${LUKS_PASSPHRASE:-}"
if [ -z "$PASS" ]; then read -r -s -p "LUKS passphrase: " PASS; echo; fi
truncate -s "${SIZE_MIB}M" "$OUT"
LOOP=$(losetup --find --show "$OUT")
trap 'losetup -d "$LOOP"' EXIT
printf '%s' "$PASS" | cryptsetup luksFormat --type luks2 --batch-mode "$LOOP" -
printf '%s' "$PASS" | cryptsetup luksOpen "$LOOP" snp-rootfs-build -
trap 'cryptsetup luksClose snp-rootfs-build; losetup -d "$LOOP"' EXIT
dd if="$PLAIN" of=/dev/mapper/snp-rootfs-build bs=4M status=progress conv=fsync
# resize2fs refuses to grow a filesystem whose last-check time predates its
# last-modify time (true of any image just copied onto by dd), so force a
# check first. e2fsck's exit code is a bitwise OR: 1 = errors corrected,
# 2 = corrected and a reboot is advised (irrelevant for a loop-mounted build
# image), 4 = errors left UNCORRECTED, 8 and above = operational failures.
# So anything below 4 (including 3 = 1|2) means the check succeeded.
e2fsck -fp /dev/mapper/snp-rootfs-build || [ $? -lt 4 ]
resize2fs /dev/mapper/snp-rootfs-build
echo "wrote LUKS2 rootfs to $OUT"
