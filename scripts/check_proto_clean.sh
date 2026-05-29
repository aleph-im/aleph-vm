#!/usr/bin/env bash
# Re-run the proto generator and fail if the working tree changes.
# Used in CI to enforce: proto changes must be accompanied by
# regenerated _pb modules.
#
# The .pyi stub is INTENTIONALLY excluded from the check. mypy-protobuf
# emits Python-version-dependent boilerplate (different `TypeAlias`
# spellings between 3.10 and 3.12+), and we can't pin a single Python
# for the regen across all dev environments. The .pyi remains a
# best-effort convenience for editor type-checking; the source of truth
# is supervisor.proto + supervisor_pb2.py (binary descriptors are
# Python-version-stable).

set -euo pipefail

cd "$(dirname "$0")/.."

python scripts/generate_proto.py

if ! git diff --quiet --exit-code -- \
    src/aleph/vm/supervisor/_pb/supervisor_pb2.py \
    src/aleph/vm/supervisor/_pb/supervisor_pb2_grpc.py \
    proto/; then
    echo
    echo "ERROR: generated proto bindings are out of date." >&2
    echo "Run: python scripts/generate_proto.py" >&2
    echo "Then commit the changes." >&2
    git diff -- \
        src/aleph/vm/supervisor/_pb/supervisor_pb2.py \
        src/aleph/vm/supervisor/_pb/supervisor_pb2_grpc.py \
        proto/
    exit 1
fi

echo "proto bindings are up to date."
