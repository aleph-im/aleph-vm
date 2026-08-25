#!/usr/bin/env bash
# Extract the supervisor side of aleph-vm into its own repository,
# preserving history, using git filter-repo.
#
# NON-DESTRUCTIVE BY CONSTRUCTION:
#   - it never touches the repository it lives in: it operates ONLY on a
#     FRESH CLONE whose path you pass as the first argument;
#   - it refuses to run without an explicit --yes flag;
#   - it refuses to run on a clone that shares its toplevel with this repo,
#     on a dirty clone, or on a clone that still has push remotes
#     (filter-repo drops remotes itself, but we check first anyway).
#
# Usage:
#   git clone https://github.com/aleph-im/aleph-vm /tmp/aleph-vm-supervisor-split
#   bash scripts/split-repos.sh /tmp/aleph-vm-supervisor-split --yes
#
# Afterwards /tmp/aleph-vm-supervisor-split contains only the supervisor-side
# history, ready to be pushed to a NEW empty repository (operator action):
#   cd /tmp/aleph-vm-supervisor-split
#   git remote add origin git@github.com:aleph-im/aleph-vm-supervisor.git
#   git push -u origin --all && git push origin --tags
#
# The agent repo is NOT produced by deleting files from a clone with this
# script: the existing aleph-vm repository simply KEEPS its full history and
# removes the supervisor-side packages in an ordinary commit once the
# extracted repo is live. See docs/plans/2026-07-04-repo-extraction.md.
#
# Requires: git >= 2.36, git-filter-repo (https://github.com/newren/git-filter-repo)

set -euo pipefail

usage() {
    grep '^#' "$0" | sed -e '1d' -e 's/^# \{0,1\}//'
    exit 1
}

CLONE="${1:-}"
CONFIRM="${2:-}"

[ -n "$CLONE" ] || usage
if [ "$CONFIRM" != "--yes" ]; then
    echo "Refusing to run without --yes. This rewrites history in '$CLONE'." >&2
    echo "It must be a FRESH, DISPOSABLE clone. Re-run with --yes to proceed." >&2
    exit 2
fi

command -v git-filter-repo >/dev/null 2>&1 || python3 -c "import git_filter_repo" 2>/dev/null || {
    echo "git-filter-repo is not installed (pip install git-filter-repo)." >&2
    exit 3
}

CLONE="$(cd "$CLONE" && pwd)"
SELF_TOPLEVEL="$(cd "$(dirname "$0")/.." && git rev-parse --show-toplevel)"
CLONE_TOPLEVEL="$(git -C "$CLONE" rev-parse --show-toplevel)"

if [ "$CLONE_TOPLEVEL" = "$SELF_TOPLEVEL" ]; then
    echo "Refusing to run on the repository this script lives in ($SELF_TOPLEVEL)." >&2
    echo "Pass the path of a fresh clone instead." >&2
    exit 4
fi

if ! git -C "$CLONE" diff --quiet || ! git -C "$CLONE" diff --cached --quiet; then
    echo "Refusing to run on a dirty clone: $CLONE" >&2
    exit 5
fi

echo "Rewriting $CLONE to the supervisor-side history..."

# Path selection. Three eras of the tree are covered so that history follows
# the files through the big renames:
#   1. current layout (post supervisor split),
#   2. src/aleph/vm/{orchestrator,controllers,hypervisor,...} era,
#   3. the ancient top-level vm_supervisor/ + firecracker/ era.
# NOTE on shared early history: before the split, agent and supervisor code
# lived together in vm_supervisor/ and orchestrator/. The recipe keeps those
# directories' history because pool/models/network genuinely evolved there;
# the extracted repo therefore also carries some pre-split agent history.
# That is intentional (better too much provenance than truncated blame).
# Tests: tests/supervisor is a mixed directory; it is kept wholesale and the
# agent-only test files are removed by an ordinary follow-up commit in the
# new repo (list them with: grep -rl 'aleph.vm.agent' tests/supervisor).
git -C "$CLONE" filter-repo \
    --path src/aleph/vm/supervisor \
    --path src/aleph/vm/supervisor_interface \
    --path src/aleph/vm/pool.py \
    --path src/aleph/vm/models.py \
    --path src/aleph/vm/hypervisors \
    --path src/aleph/vm/network \
    --path src/aleph/vm/program_config.py \
    --path proto \
    --path scripts/generate_proto.py \
    --path scripts/check_proto_clean.sh \
    --path tests/supervisor \
    --path src/aleph/vm/conf.py \
    --path src/aleph/vm/utils \
    --path src/aleph/vm/chains.py \
    --path src/aleph/vm/agent/chain.py \
    --path src/aleph/vm/backup \
    --path src/aleph/vm/host_volumes.py \
    --path src/aleph/vm/guest_api \
    --path guest_api \
    --path src/aleph/vm/storage.py \
    --path src/aleph/vm/resources.py \
    --path src/aleph/vm/constants.py \
    --path src/aleph/vm/version.py \
    --path src/aleph/vm/sizes.py \
    --path src/aleph/vm/vm_type.py \
    --path src/aleph/vm/systemd.py \
    --path src/aleph/vm/sevclient.py \
    --path src/aleph/vm/hypervisor \
    --path src/aleph/vm/controllers \
    --path src/aleph/vm/orchestrator/pool.py \
    --path src/aleph/vm/orchestrator/models.py \
    --path src/aleph/vm/orchestrator/network \
    --path vm_supervisor/pool.py \
    --path vm_supervisor/models.py \
    --path vm_supervisor/network \
    --path vm_supervisor/conf.py \
    --path firecracker \
    --path packaging/aleph-vm/etc/systemd/system/aleph-vm-supervisor.service \
    --path packaging/aleph-vm/etc/aleph-vm/supervisor.env \
    --path LICENSE

echo
echo "Done. Review the result, then push it to a NEW empty repository:"
echo "  cd $CLONE"
echo "  git log --oneline | head"
echo "  git remote add origin <new-repo-url>"
echo "  git push -u origin --all && git push origin --tags"
