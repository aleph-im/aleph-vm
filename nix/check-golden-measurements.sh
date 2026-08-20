#!/usr/bin/env bash
# Golden SEV-SNP launch measurement check.
#
# Builds the flake's pinned measurement outputs and compares them to the
# committed golden file (nix/golden-measurements.json). A mismatch means the
# measured boot chain changed: OVMF, kernel, initrd contents (including the
# attest-agent binary), or the kernel cmdline (dm-verity root hashes). That
# is either an intended change (regenerate the golden file in the same PR,
# and remember that anything pinning the old measurement must migrate) or an
# unintended reproducibility regression (investigate before merging).
#
# Usage:
#   nix/check-golden-measurements.sh           # verify (CI mode)
#   nix/check-golden-measurements.sh --update  # regenerate the golden file

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
golden="$repo_root/nix/golden-measurements.json"

# Every measurement package the flake exposes; keep in sync with the
# `packages` set in nix/flake.nix. instanceMeasurementSmoke pins the
# confidential-instance chain through its fixed placeholder owner address;
# real per-deployment instance measurements vary by owner but share every
# other measured input with it.
outputs=(
  measurement
  composeMeasurement
  workloadMeasurement
  instanceMeasurementSmoke
)

echo "Building ${#outputs[@]} measurement outputs (a cold build compiles the full measured boot chain and takes a while)..." >&2

current="$(mktemp)"
trap 'rm -f "$current"' EXIT
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

if [ "${1:-}" = "--update" ]; then
  cp "$current" "$golden"
  echo "Updated $golden" >&2
  exit 0
fi

if [ ! -f "$golden" ]; then
  echo "Missing $golden; run $0 --update and commit the result." >&2
  exit 1
fi

if diff -u "$golden" "$current"; then
  echo "Golden measurements match." >&2
else
  cat >&2 <<'EOF'

Launch measurements diverged from nix/golden-measurements.json.
If this change is intended, run nix/check-golden-measurements.sh --update
and commit the new golden file with the change that caused it. If nothing
in the measured chain was meant to change, this is a reproducibility
regression: do not update the golden file, find the drift instead.
EOF
  exit 1
fi
