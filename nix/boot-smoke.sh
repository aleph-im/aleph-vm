#!/usr/bin/env bash
# Boot smoke for the measured v-program image under plain QEMU (KVM when
# available, TCG otherwise), WITHOUT SEV-SNP. It proves the initrd still
# boots: busybox runs, the dm-verity modules load, the platform rootfs
# verifies and mounts, the nft firewall installs and /sbin/init is handed
# off. It is not a measurement check (see check-golden-measurements.sh) and
# the attest-agent is expected to fail without /dev/sev-guest.
#
# Usage: nix/boot-smoke.sh
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image="$(nix build "$repo_root/nix#image" --no-link --print-out-paths)"
roothash="$(cat "$image/rootfs.ext4.roothash")"

log="$(mktemp)"
cleanup() {
  if [ -n "${qemu_pid:-}" ] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  rm -f "$log"
}
trap cleanup EXIT

qemu-system-x86_64 \
  -machine q35,accel=kvm:tcg -cpu max -m 1024 -smp 2 \
  -nographic -no-reboot \
  -kernel "$image/bzImage" \
  -initrd "$image/initrd" \
  -append "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash" \
  -drive "file=$image/rootfs.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$image/rootfs.ext4.verity,format=raw,if=virtio,readonly=on" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
  > "$log" 2>&1 &
qemu_pid=$!

markers=(
  "init: mounting /dev/mapper/verity-root"
  "init: firewall active"
  "init: starting /sbin/init from rootfs"
)

deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
  all_present=1
  for marker in "${markers[@]}"; do
    grep -qF "$marker" "$log" || { all_present=0; break; }
  done
  if [ "$all_present" -eq 1 ]; then
    echo "boot smoke OK: initrd booted, rootfs verified and mounted, firewall up, /sbin/init started" >&2
    exit 0
  fi
  if ! kill -0 "$qemu_pid" 2>/dev/null; then
    break
  fi
  sleep 1
done

echo "boot smoke FAILED; serial log follows:" >&2
cat "$log" >&2
exit 1
