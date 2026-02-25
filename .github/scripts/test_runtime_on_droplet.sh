#!/usr/bin/env bash
#
# Test a single runtime on a remote droplet.
#
# This script reconfigures the supervisor to use the given runtime,
# restarts it, runs the /status/check/fastapi health check (with one
# retry after a supervisor restart), and exercises the /control/allocations
# scheduling endpoint.
#
# Usage: test_runtime_on_droplet.sh <droplet_ip> <item_hash> [query_params]
#
#   droplet_ip   – public IPv4 of the droplet
#   item_hash    – aleph runtime item hash to test
#   query_params – optional query string appended to the check URL
#                  (e.g. "?retro-compatibility=true")

set -euo pipefail

DROPLET_IPV4="${1:?Usage: $0 <droplet_ip> <item_hash> [query_params]}"
ITEM_HASH="${2:?Usage: $0 <droplet_ip> <item_hash> [query_params]}"
QUERY_PARAMS="${3:-}"

echo "==> Configuring supervisor for runtime ${ITEM_HASH}"
ssh root@"${DROPLET_IPV4}" "sed -i '/^ALEPH_VM_CHECK_FASTAPI_VM_ID=/d' /etc/aleph-vm/supervisor.env && echo ALEPH_VM_CHECK_FASTAPI_VM_ID=${ITEM_HASH} >> /etc/aleph-vm/supervisor.env"
ssh root@"${DROPLET_IPV4}" "systemctl restart aleph-vm-supervisor"
sleep 5

echo "==> Running health check"
if ! curl --retry 5 --max-time 10 --fail "http://${DROPLET_IPV4}:4020/status/check/fastapi${QUERY_PARAMS}"; then
    echo "==> First attempt failed, restarting supervisor and retrying..."
    ssh root@"${DROPLET_IPV4}" "systemctl restart aleph-vm-supervisor"
    sleep 5
    curl --retry 5 --max-time 10 --fail "http://${DROPLET_IPV4}:4020/status/check/fastapi${QUERY_PARAMS}"
fi

echo "==> Scheduling an instance via /control/allocations"
curl --retry 5 --max-time 10 --fail -X POST -H "Content-Type: application/json" \
    -H "X-Auth-Signature: test" \
    -d "{\"persistent_vms\": [], \"instances\": [\"${ITEM_HASH}\"]}" \
    "http://${DROPLET_IPV4}:4020/control/allocations"

echo "==> Runtime ${ITEM_HASH} OK"
