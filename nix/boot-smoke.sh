#!/usr/bin/env bash
# Boot smoke for the measured v-program image under plain QEMU (KVM when
# available, TCG otherwise), WITHOUT SEV-SNP. It proves the initrd still
# boots: busybox runs, the dm-verity modules load, the platform rootfs
# verifies and mounts, the nft firewall installs and /sbin/init is handed
# off. It is not a measurement check (see check-golden-measurements.sh) and
# the attest-agent is expected to fail without /dev/sev-guest. Phase 2
# additionally boots the fib workload with one verified data volume and
# proves the positional device binding (vde/vdf) and the /volumes mount.
#
# `--gpu` instead boots the confidential-GPU image (gpuImage) on a host with
# no NVIDIA device, which is the flavor's own no-GPU path: init-gpu.sh must
# find no 0x10de PCI device, say so, and boot on exactly like the base image.
# It does not exercise the driver, the verifier or the ready state; those
# need real Blackwell hardware.
#
# Usage: nix/boot-smoke.sh [--gpu]
# Local tool, not a CI gate: it needs KVM (or a slow TCG boot).
set -euo pipefail

gpu_mode=0
case "${1:-}" in
  "") ;;
  --gpu) gpu_mode=1 ;;
  *) echo "usage: $0 [--gpu]" >&2; exit 2 ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ "$gpu_mode" -eq 1 ]; then
  image="$(nix build "$repo_root/nix#gpuImage" --no-link --print-out-paths)"
else
  image="$(nix build "$repo_root/nix#image" --no-link --print-out-paths)"
fi
roothash="$(cat "$image/rootfs.ext4.roothash")"

# Guest RAM. The GPU cmdline reserves a 512 MiB swiotlb (swiotlb=262144
# slabs x 2 KiB), so that flavor needs more than the 1 GiB the base image
# boots in.
mem=1024

log="$(mktemp)"
# shellcheck disable=SC2329  # invoked via the EXIT trap
cleanup() {
  if [ -n "${qemu_pid:-}" ] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  rm -f "$log"
}
trap cleanup EXIT

run_phase() {
  local phase="$1"; shift
  local append="$1"; shift
  local -a extra_drives=("$@")
  # Drop the previous phase's log before reassigning the global, or the
  # EXIT trap only ever removes the latest one.
  rm -f "$log"
  log="$(mktemp)"
  qemu-system-x86_64 \
    -machine q35,accel=kvm:tcg -cpu max -m "$mem" -smp 2 \
    -nographic -no-reboot \
    -kernel "$image/bzImage" \
    -initrd "$image/initrd" \
    -append "$append" \
    -drive "file=$image/rootfs.ext4,format=raw,if=virtio,readonly=on" \
    -drive "file=$image/rootfs.ext4.verity,format=raw,if=virtio,readonly=on" \
    "${extra_drives[@]}" \
    -netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
    > "$log" 2>&1 &
  qemu_pid=$!

  deadline=$((SECONDS + 120))
  while [ "$SECONDS" -lt "$deadline" ]; do
    all_present=1
    for marker in "${markers[@]}"; do
      grep -qF "$marker" "$log" || { all_present=0; break; }
    done
    if [ "$all_present" -eq 1 ]; then
      kill "$qemu_pid" 2>/dev/null || true
      wait "$qemu_pid" 2>/dev/null || true
      return 0
    fi
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
      break
    fi
    sleep 1
  done
  echo "boot smoke FAILED ($phase); serial log follows:" >&2
  cat "$log" >&2
  exit 1
}

# GPU mode: the confidential-GPU image, platform-only cmdline, no NVIDIA
# device attached. The GPU stage must take its no-GPU branch and the rest of
# the boot must be indistinguishable from the base image's phase 1.
if [ "$gpu_mode" -eq 1 ]; then
  mem=2048
  markers=(
    "init: no NVIDIA GPU present; running without GPU attestation"
    "init: mounting /dev/mapper/verity-root"
    "init: firewall active"
    "init: starting /sbin/init from "
  )
  run_phase "gpu" "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash swiotlb=262144"
  echo "boot smoke --gpu OK: GPU image booted with no GPU, rootfs verified and mounted, firewall up, /sbin/init started" >&2
  exit 0
fi

# Phase 1: platform-only boot (volume-less cmdline must stay bootable).
markers=(
  "init: mounting /dev/mapper/verity-root"
  "init: firewall active"
  # init.sh names the mount point ("from /mnt/root"), so match the prefix.
  "init: starting /sbin/init from "
)
run_phase "phase 1" "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash"
echo "boot smoke phase 1 OK: initrd booted, rootfs verified and mounted, firewall up, /sbin/init started" >&2

# Phase 2: workload + one verified volume. Requires veritysetup and
# mkfs.ext4 on the host (local tool; fail with a clear message otherwise).
for tool in veritysetup mkfs.ext4; do
  command -v "$tool" >/dev/null || { echo "boot smoke: $tool not found on PATH (needed for phase 2)" >&2; exit 1; }
done
work="$(mktemp -d)"
trap 'rm -rf "$work"; cleanup' EXIT

workload_src="$(nix build "$repo_root/nix#workload" --no-link --print-out-paths)"
cp "$workload_src/workload.ext4" "$work/workload.ext4"
chmod +w "$work/workload.ext4"
wl_roothash="$(veritysetup format "$work/workload.ext4" "$work/workload.verity" | awk '/Root hash/ {print $3}')"

mkdir -p "$work/volcontent"
echo "hello from volume 0" > "$work/volcontent/hello.txt"
truncate -s 4M "$work/volume0.ext4"
mkfs.ext4 -q -b 4096 -d "$work/volcontent" "$work/volume0.ext4"
vol_roothash="$(veritysetup format "$work/volume0.ext4" "$work/volume0.verity" | awk '/Root hash/ {print $3}')"

markers=(
  "init: mounting /dev/mapper/verity-workload"
  "init: setting up dm-verity on /dev/vde with hash tree /dev/vdf (volume 0)"
  "init: 1 verified volume(s) mounted under /mnt/workload/volumes"
  "init: starting /sbin/init from /mnt/workload"
)
run_phase "phase 2" \
  "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash workload_roothash=$wl_roothash verified_volumes=$vol_roothash" \
  -drive "file=$work/workload.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/workload.verity,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/volume0.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/volume0.verity,format=raw,if=virtio,readonly=on"
echo "boot smoke phase 2 OK: workload and verified volume verity-mounted, workload init started" >&2
exit 0
