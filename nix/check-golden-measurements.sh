#!/usr/bin/env bash
# Golden SEV-SNP launch measurement check.
#
# Builds the flake's pinned measurement outputs and compares them to the
# committed golden file (nix/golden-measurements.json). A mismatch means the
# measured boot chain changed: OVMF, kernel, initrd contents (the regular
# files listed in initrd.nix, including the attest-agent binary; never a nix
# store path, see initrd.nix), or the kernel cmdline (dm-verity root hashes). That
# is either an intended change (regenerate the golden file in the same PR,
# and remember that anything pinning the old measurement must migrate) or an
# unintended reproducibility regression (investigate before merging).
#
# Usage:
#   nix/check-golden-measurements.sh              # verify every output
#   nix/check-golden-measurements.sh --base-only  # verify all but the GPU flavor
#   nix/check-golden-measurements.sh --gpu-only   # verify only the GPU flavor
#   nix/check-golden-measurements.sh --update     # regenerate the golden file
#
# The GPU flavor is split out because its chain shares almost nothing with the
# others: a second guest kernel, the NVIDIA open kernel modules, the raw driver
# userland and NVIDIA's verifier (nvat, a CMake + Rust build). Building it on
# every nix/** change would multiply this job's cost for changes that cannot
# move it. --update always rewrites the WHOLE file and therefore always builds
# everything: writing a subset would drop the other entries.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
golden="$repo_root/nix/golden-measurements.json"

# Every measurement package the flake exposes; keep in sync with the
# `packages` set in nix/flake.nix. instanceMeasurementSmoke pins the
# confidential-instance chain through its fixed placeholder owner address;
# real per-deployment instance measurements vary by owner but share every
# other measured input with it.
base_outputs=(
  measurement
  composeMeasurement
  workloadMeasurement
  instanceMeasurementSmoke
)
# The confidential-GPU flavor, built from gpuKernel + gpuInitrd + gpuVerity.
gpu_outputs=(
  gpuMeasurement
)

mode="all"
update=0
for arg in "$@"; do
  case "$arg" in
    --update) update=1 ;;
    --base-only) mode="base" ;;
    --gpu-only) mode="gpu" ;;
    *)
      echo "usage: $0 [--update] [--base-only|--gpu-only]" >&2
      exit 2
      ;;
  esac
done

# --update rewrites the whole golden file, so it must compute every output no
# matter which selection flag came with it.
if [ "$update" -eq 1 ]; then
  mode="all"
fi

case "$mode" in
  all) outputs=("${base_outputs[@]}" "${gpu_outputs[@]}") ;;
  base) outputs=("${base_outputs[@]}") ;;
  gpu) outputs=("${gpu_outputs[@]}") ;;
esac

echo "Building ${#outputs[@]} measurement output(s) (${mode}); a cold build compiles the whole measured boot chain and takes a while..." >&2

current="$(mktemp)"
expected="$(mktemp)"
trap 'rm -f "$current" "$expected"' EXIT
{
  echo "{"
  for i in "${!outputs[@]}"; do
    name="${outputs[$i]}"
    out_path="$(nix build "$repo_root/nix#$name" --no-link --print-out-paths)"
    sep=","
    if [ "$i" -eq $((${#outputs[@]} - 1)) ]; then
      sep=""
    fi
    printf '  "%s": "%s"%s\n' "$name" "$(cat "$out_path")" "$sep"
  done
  echo "}"
} > "$current"

if [ "$update" -eq 1 ]; then
  cp "$current" "$golden"
  echo "Updated $golden" >&2
  exit 0
fi

if [ ! -f "$golden" ]; then
  echo "Missing $golden; run $0 --update and commit the result." >&2
  exit 1
fi

if [ "$mode" = "all" ]; then
  # Compare the file itself, so an entry that is in the golden file but no
  # longer produced (or the other way round) still shows up as a diff.
  cp "$golden" "$expected"
else
  # Subset run: rebuild the golden's side of the comparison from just the
  # selected entries, in the same order and format.
  {
    echo "{"
    for i in "${!outputs[@]}"; do
      name="${outputs[$i]}"
      value="$(sed -n "s/^  \"${name}\": \"\([0-9a-f]*\)\".*\$/\1/p" "$golden")"
      if [ -z "$value" ]; then
        echo "No \"${name}\" entry in $golden; run $0 --update and commit the result." >&2
        exit 1
      fi
      sep=","
      if [ "$i" -eq $((${#outputs[@]} - 1)) ]; then
        sep=""
      fi
      printf '  "%s": "%s"%s\n' "$name" "$value" "$sep"
    done
    echo "}"
  } > "$expected"
fi

if diff -u "$expected" "$current"; then
  echo "Golden measurements match." >&2
else
  seeded_at="$(git -C "$repo_root" log -1 --format=%h -- nix/golden-measurements.json 2>/dev/null || echo unknown)"
  seeded_at="${seeded_at:-unknown}"
  head_rev="$(git -C "$repo_root" rev-parse --short HEAD 2>/dev/null || echo unknown)"
  cat >&2 <<EOF

Launch measurements diverged from nix/golden-measurements.json (last seeded
in commit ${seeded_at}; this tree is ${head_rev}).
If this change is intended, run nix/check-golden-measurements.sh --update
and commit the new golden file with the change that caused it. If nothing
in the measured chain was meant to change, this is a reproducibility
regression: do not update the golden file, find the drift instead.
EOF
  exit 1
fi
