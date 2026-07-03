# Repo extraction: the two-repo end state

Companion to `scripts/split-repos.sh` and
`2026-07-04-package-split-design.md`. Nothing here is executed automatically;
creating and pushing repositories is an operator action.

## End state

Two repositories:

1. **aleph-vm-supervisor** (new, extracted with `scripts/split-repos.sh`)
   - Owns: `aleph.vm.supervisor` (daemon, gRPC server, controllers),
     `aleph.vm.pool`, `aleph.vm.models`, `aleph.vm.hypervisors`,
     `aleph.vm.network`, plus the supervisor-side shared modules it needs.
   - OWNS THE PROTO: `proto/supervisor.proto`, `scripts/generate_proto.py`,
     `scripts/check_proto_clean.sh`, and `aleph.vm.supervisor_interface`
     (ABC, DTOs, errors, `wire/` stubs, the `GrpcSupervisor` client).
     The server side is where wire changes originate, so the contract lives
     with it and is published FROM it.
   - Publishes two distributions: `aleph-vm-contract` and
     `aleph-vm-supervisor` (see the package split design for pyprojects).

2. **aleph-vm** (this repository, continuing)
   - Keeps: `aleph.vm.agent`, `aleph.vm.migration`, `aleph.vm.testing`, the
     agent-side shared modules, the deb packaging, the droplet/testnet CI.
   - Removes the supervisor-side packages in an ordinary commit once the
     extracted repo is live (full history stays in this repo's past; the
     extracted repo carries the filtered copy for blame/bisect).
   - Depends on the published `aleph-vm-contract` (and, for the deb and the
     single-process test harness, on `aleph-vm-supervisor`).

## Who owns the proto, and compatibility

- `proto/supervisor.proto` changes land in aleph-vm-supervisor, which
  regenerates the stubs (`check_proto_clean.sh` stays its CI gate) and
  releases a new `aleph-vm-contract`.
- Wire evolution rules (already the practice in-repo): fields are added,
  never renumbered or repurposed; enums (including `ErrorCode`) are closed
  vocabularies that only grow; unknown fields are ignored by both sides.
  Therefore any contract x.y client speaks to any contract x.z server within
  the same major version.
- Versioning: `aleph-vm-contract` uses semver. Additive proto/DTO changes
  bump minor; removing or changing the meaning of anything bumps major.
  The agent pins `aleph-vm-contract ~= X.Y` (compatible range); the
  supervisor dist pins the exact contract version it was generated with.
- Conformance: the gRPC roundtrip/conformance test suites
  (`tests/supervisor/test_grpc_roundtrip.py`, `test_supervisor_grpc.py`,
  `test_grpc_complete.py`, `test_proto_bindings.py`) move with the
  supervisor repo; the agent repo keeps a thin smoke suite that dials a
  supervisor daemon installed from the published wheel, so a contract
  regression is caught on both sides.

## Deb and deployment

Short term the single `aleph-vm` deb continues to be built from the aleph-vm
repo, installing both services into `/opt/aleph-vm` (the Makefile switches
from `cp -r ../src/aleph` to `pip install --target` of the published
`aleph-vm-agent` + `aleph-vm-supervisor` wheels). The systemd units,
`supervisor.env` and the Unix-socket wiring do not change. Long term each
repo can ship its own deb; nothing in the runtime layout prevents it since
the two services already communicate only over
`ALEPH_VM_SUPERVISOR_GRPC_SOCKET`.

## Operator runbook

```
# 1. Fresh clone, never the working checkout
git clone https://github.com/aleph-im/aleph-vm /tmp/aleph-vm-supervisor-split

# 2. Filter it (the script refuses without --yes and refuses the live repo)
bash scripts/split-repos.sh /tmp/aleph-vm-supervisor-split --yes

# 3. Inspect: history, blame on pool.py, the proto gate
cd /tmp/aleph-vm-supervisor-split && git log --oneline | head -30

# 4. Push to a NEW empty repository
git remote add origin git@github.com:aleph-im/aleph-vm-supervisor.git
git push -u origin --all && git push origin --tags

# 5. In the new repo: prune agent-only tests, add its pyproject(s), wire CI.
# 6. In aleph-vm: remove the supervisor-side packages, depend on the
#    published contract; keep the deb green before merging.
```
