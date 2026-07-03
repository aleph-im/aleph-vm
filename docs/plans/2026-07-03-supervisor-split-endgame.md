# Supervisor split endgame

Branch `od/supervisor-split-endgame` off `origin/dev` (b7688ace, post-#1010).
Goal: finish the agent/supervisor split entirely. Three phases, each leaving the
branch green (full pytest suite, mypy baseline, ruff/isort, import-linter, CI).

## Phase A: remove the last two import residuals

The import-linter contract "the supervisor does not import the agent" still
whitelists two edges:

1. `aleph.vm.models -> aleph.vm.agent.metrics` (`save_execution_data`).
   `VmExecution.record_usage` writes ExecutionRecord rows into the AGENT
   database from supervisor-side code: the last cross-actor DB write that
   #1009/#1010 did not remove. Investigate what consumes those records
   (agent logs auth, benefits/usage reporting) and move the persistence
   agent-side: the agent already observes every lifecycle transition it
   initiates (create/stop/delete through the Supervisor ABC), so it can
   record usage at those choke points; whatever only the supervisor knows
   (actual runtimes) must come over the wire via existing RPCs (get_vm /
   list_vms / events). No new proto field unless unavoidable.
2. `aleph.vm.pool -> aleph.vm.agent.utils` (`update_aggregate_settings`).
   Move the helper (and anything it drags in) to a neutral module
   (`aleph.vm.utils` or a conf-level module) imported by both sides.

Exit: both `ignore_imports` entries deleted, contract KEPT, behavior covered
by tests (usage records still written with the same content, from the agent).

## Phase B: gRPC-only mode

Already merged: #980 (agent decoupled from the pool), #981 (wire protocol +
two-service deb packaging, socket set in supervisor.env). Remaining:

1. Triage the LOCAL branch `od/grpc-only-supervisor-phase2` unmerged commits
   (git cherry vs dev; several were superseded by #966 etc.). Port the still
   relevant fixes, notably: port forwards after confidential secret injection
   (3f476a91), init-session on a VM awaiting init (114279a0, check vs #966),
   migration import ordering fixes from origin/od/grpc-only-supervisor
   (89543ece, a188990c) if not already on dev, SEV policy on both create
   paths (3e8ae66b, check vs dev).
2. Retire the in-process path: `build_supervisor` always returns
   `GrpcSupervisor`; `ALEPH_VM_SUPERVISOR_GRPC_SOCKET` gets a default value;
   the agent process stops constructing a `VmPool` (`_engine_pool`, agent-side
   reattach task hooks, stop_all_vms in-process branch all go); LocalSupervisor
   remains as the DAEMON's engine only. Update or repoint the in-process test
   suites (they still validly test LocalSupervisor as the daemon engine).
   `cli.py` benchmark/test-instance paths keep direct pool use (supervisor-side
   harness, documented as such) or spawn the daemon; choose what keeps the
   droplet fake-instance CI green.

Exit: no code path builds LocalSupervisor inside the agent process; deb and
droplet CI green in (now sole) split mode.

## Phase C: physical package split

1. Total import separation: agent imports only `aleph.vm.supervisor_interface`
   (contract) + the gRPC client. Move `grpc_client.py` (+ proto stubs and
   `proto_convert` split as needed) from `aleph.vm.supervisor` to the contract
   side (e.g. `aleph.vm.supervisor_interface.grpc`) so "agent -> supervisor.*"
   becomes an EMPTY set. Tighten import-linter to forbid agent->supervisor and
   supervisor->agent wholesale (no ignore lists except composition roots if
   truly needed; prefer zero).
2. Split the distribution: three packages in-repo (hatch): `aleph-vm-contract`
   (supervisor_interface + generated stubs), `aleph-vm-supervisor` (supervisor,
   pool, models, hypervisors, network host-side), `aleph-vm-agent` (agent).
   Keep the deb shipping both services from the same repo build. If namespace
   packaging or the deb build turns hostile overnight, fall back to: one
   distribution, two top-level packages with the total import separation
   enforced, plus a READY packaging commit on a side branch and notes.
3. Repo extraction: write `scripts/split-repos.sh` (git filter-repo recipe) +
   docs describing the two-repo end state. DO NOT create/push new repos
   (operator action).

Exit: import graph fully bipartite through the contract; CI green; extraction
script + doc committed.

## Validation

After CI is green on the branch: open a PR against dev, then point
aleph-testnets #27 `manifesto.yml` at `branch: "od/supervisor-split-endgame"`
and loop until the testnet integration suite passes; then restore the #27 pin
to dev.

## Process

Full test loop per phase (tests/supervisor + mypy + ruff + isort +
lint-imports), commit per logical change, no Co-Authored-By trailers, no
em-dashes. CI watched via gh; failures debugged root-cause-first.
