#!/usr/bin/env bash
# Boot smoke for the measured v-program image under plain QEMU (KVM when
# available, TCG otherwise), WITHOUT SEV-SNP. It proves the initrd still
# boots: busybox runs, the dm-verity modules load, the platform rootfs
# verifies and mounts, the nft firewall installs and /sbin/init is handed
# off. It is not a measurement check (see check-golden-measurements.sh) and
# the attest-agent is expected to fail without /dev/sev-guest. Phase 2
# additionally boots the fib workload with one verified data volume and
# proves the positional device binding (vde/vdf) and the /volumes mount.
# Phase 3 boots the workload with aleph_insecure_unattested=1 and proves the plain-HTTP
# agent path (see init-common.sh start_attest_agent) answers through a
# SLIRP port forward.
#
# `--gpu` instead boots the confidential-GPU image (gpuImage) on a host with
# no NVIDIA device, which is the flavor's own no-GPU path: init-gpu.sh must
# find no 0x10de PCI device, say so, and boot on exactly like the base image.
# It does not exercise the driver, the verifier or the ready state; those
# need real Blackwell hardware. CI runs it from the GPU golden job
# (.github/workflows/golden-measurements.yml), which has the image built.
#
# Usage: nix/boot-smoke.sh [--gpu] (curl and python3 are needed for phase 3)
# Runs in CI on a KVM runner (.github/workflows/boot-smoke.yml) and locally
# (needs KVM, or a slow TCG boot).
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

# run_phase NAME APPEND [extra -drive args...]
# Globals consumed: markers (required lines), forbidden (lines that must
# NOT appear), netdev_extra (appended to the -netdev user option string),
# probe (a function run once every marker is present; a non-zero return
# fails the phase). Every global resets to its default at the end.
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
    -netdev "user,id=n0${netdev_extra}" -device virtio-net-pci,netdev=n0 \
    > "$log" 2>&1 &
  qemu_pid=$!

  deadline=$((SECONDS + 120))
  while [ "$SECONDS" -lt "$deadline" ]; do
    all_present=1
    for marker in "${markers[@]}"; do
      grep -qF "$marker" "$log" || { all_present=0; break; }
    done
    if [ "$all_present" -eq 1 ]; then
      for line in "${forbidden[@]}"; do
        if grep -qF "$line" "$log"; then
          echo "boot smoke FAILED ($phase): forbidden line present: $line" >&2
          cat "$log" >&2
          exit 1
        fi
      done
      if ! "$probe"; then
        echo "boot smoke FAILED ($phase): probe failed; serial log follows:" >&2
        cat "$log" >&2
        exit 1
      fi
      kill "$qemu_pid" 2>/dev/null || true
      wait "$qemu_pid" 2>/dev/null || true
      markers=(); forbidden=(); netdev_extra=""; probe=true
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

# Defaults for the run_phase globals.
forbidden=()
netdev_extra=""
probe=true

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
  forbidden=("init: INSECURE UNATTESTED MODE:")
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
forbidden=("init: INSECURE UNATTESTED MODE:")
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
forbidden=("init: INSECURE UNATTESTED MODE:")
run_phase "phase 2" \
  "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash workload_roothash=$wl_roothash verified_volumes=$vol_roothash" \
  -drive "file=$work/workload.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/workload.verity,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/volume0.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/volume0.verity,format=raw,if=virtio,readonly=on"
echo "boot smoke phase 2 OK: workload and verified volume verity-mounted, workload init started" >&2

# Phase 3: unattested (non-confidential) mode. The `aleph_insecure_unattested=1` token makes
# init start the attest-agent in plain-HTTP mode; a SLIRP hostfwd to the
# agent port then reaches the fib workload's /health through the same
# agent-to-loopback proxy path production uses. This is the contract
# `aleph vprogram run` relies on.
for tool in curl python3; do
  command -v "$tool" >/dev/null || { echo "boot smoke: $tool not found on PATH (needed for phase 3)" >&2; exit 1; }
done
local_port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"

# shellcheck disable=SC2329  # invoked indirectly via probe=probe_local_health
probe_local_health() {
  local tries=0
  while [ "$tries" -lt 60 ]; do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${local_port}/health" || true)" = "200" ]; then
      return 0
    fi
    tries=$((tries + 1))
    sleep 1
  done
  echo "boot smoke: /health via the plain agent never returned 200 on port ${local_port}" >&2
  return 1
}

markers=(
  "init: mounting /dev/mapper/verity-workload"
  "init: INSECURE UNATTESTED MODE: attest agent serving plain HTTP without a TEE on tcp/8443"
  "init: starting /sbin/init from /mnt/workload"
)
netdev_extra=",hostfwd=tcp:127.0.0.1:${local_port}-:8443"
probe=probe_local_health
run_phase "phase 3" \
  "console=ttyS0 root=/dev/mapper/verity-root ro roothash=$roothash workload_roothash=$wl_roothash aleph_insecure_unattested=1" \
  -drive "file=$work/workload.ext4,format=raw,if=virtio,readonly=on" \
  -drive "file=$work/workload.verity,format=raw,if=virtio,readonly=on"
echo "boot smoke phase 3 OK: unattested mode booted, plain agent answered /health through the hostfwd" >&2
exit 0
