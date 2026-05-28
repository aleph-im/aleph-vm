#!/usr/bin/env bash
# Re-run the proto generator and fail if the working tree changes.
# Used in CI to enforce: proto changes must be accompanied by
# regenerated _pb modules.

set -euo pipefail

cd "$(dirname "$0")/.."

python scripts/generate_proto.py

if ! git diff --quiet --exit-code -- src/aleph/vm/hypervisor/_pb proto/; then
    echo
    echo "ERROR: generated proto bindings are out of date." >&2
    echo "Run: python scripts/generate_proto.py" >&2
    echo "Then commit the changes." >&2
    git diff -- src/aleph/vm/hypervisor/_pb proto/
    exit 1
fi

echo "proto bindings are up to date."
