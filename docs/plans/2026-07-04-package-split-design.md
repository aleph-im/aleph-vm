# Package split design (aleph-vm-contract / -supervisor / -agent)

Status: DESIGNED, NOT APPLIED. The repo still builds a single `aleph-vm`
distribution. This document is the ready-to-apply recipe for splitting it
into installable distributions, written during Phase C of the supervisor
split endgame (see `2026-07-03-supervisor-split-endgame.md`).

## Why the split was not applied yet

The import boundary work (Phase C stage 1) made the *module* graph bipartite
through the contract: `aleph.vm.agent` imports no `aleph.vm.supervisor`,
`aleph.vm.pool` or `aleph.vm.network` module, and the wire client + generated
stubs live on the contract side (`aleph.vm.supervisor_interface.client` /
`.wire`). Two facts block a *distribution* split that would be worth its
churn today:

1. The agent still imports three supervisor-side / shared-domain modules:
   - `aleph.vm.models` (`VmExecution` in `agent/run.py` and
     `agent/custom_logs.py`, `MigrationState` in `agent/views/migration.py`)
   - `aleph.vm.hypervisors.firecracker.microvm` (`MicroVMFailedInitError` in
     `agent/run.py`, `RuntimeConfiguration` in `agent/vm/program_client.py`)
   - `aleph.vm.migration` (agent-side job plumbing that itself imports
     `agent.run` / `agent.messages` / `agent.translate` AND `aleph.vm.models`)

   With `models`/`hypervisors` assigned to `aleph-vm-supervisor` (as the plan
   requires), `aleph-vm-agent` would have to declare
   `Requires-Dist: aleph-vm-supervisor`. That makes the split cosmetic: you
   could not install the agent without the whole supervisor. The "model
   split" follow-up (dissolving `VmExecution` into contract DTOs plus
   supervisor-internal state) must land first; when it does, the dist
   contents below apply unchanged.

2. The shared pile is large and needs its own home. `conf.py`, `utils/`,
   `storage.py`, `resources.py`, `chains.py`, `version.py`, `constants.py`,
   `sizes.py`, `vm_type.py`, `systemd.py`, `haproxy.py`, `host_volumes.py`,
   `backup_staging.py`, `garbage_collector.py`, `guest_api/`,
   `program_config.py`, `sevclient.py` are imported by both sides. They do
   not belong in the contract dist (the contract must stay dependency-light:
   today `aleph.vm.supervisor_interface` imports NOTHING else from
   `aleph.vm`, and only needs grpcio/protobuf/msgpack/pydantic at runtime).
   They need a fourth "core" dist, and several of them are themselves not yet
   cleanly one-sided (`program_config.py` imports `hypervisors`,
   `resources.py` imports `utils.aggregate`).

Everything mechanical was validated and is recorded below, so applying this
design after the model split is bookkeeping, not research.

## Target distributions

| Distribution         | Packages                                                         | Depends on                          |
|----------------------|------------------------------------------------------------------|-------------------------------------|
| `aleph-vm-contract`  | `aleph.vm.supervisor_interface` (abc, types, errors, configuration, `wire/` with `_pb`, `client`) | grpcio, protobuf, msgpack, pydantic |
| `aleph-vm-core`      | `aleph.vm.conf`, `aleph.vm.utils`, `aleph.vm.chains`, `aleph.vm.storage`, `aleph.vm.version`, `aleph.vm.constants`, `aleph.vm.sizes`, `aleph.vm.vm_type`, `aleph.vm.systemd`, `aleph.vm.haproxy`, `aleph.vm.host_volumes`, `aleph.vm.backup_staging`, `aleph.vm.garbage_collector`, `aleph.vm.guest_api`, `aleph.vm.sevclient` | contract                            |
| `aleph-vm-supervisor`| `aleph.vm.supervisor`, `aleph.vm.pool`, `aleph.vm.models`, `aleph.vm.hypervisors`, `aleph.vm.network`, `aleph.vm.program_config` | core, contract                      |
| `aleph-vm-agent`     | `aleph.vm.agent`, `aleph.vm.migration`, `aleph.vm.testing` (extra: `harness`) | core, contract                      |
| `aleph-vm` (meta)    | no code; preserves `pip install aleph-vm` and the `aleph-vm` console script | agent + supervisor                  |

Notes:
- `aleph.vm.testing.harness` wires both sides in one process; ship it as an
  `aleph-vm-agent[harness]` extra depending on `aleph-vm-supervisor`, or move
  it into the meta package. The lazy import in `agent/cli.py` already
  guarantees the production agent path never loads it.
- Console entry points: `aleph-vm = aleph.vm.agent.cli:main` moves to
  `aleph-vm-agent`; add `aleph-vm-supervisor = aleph.vm.supervisor.__main__:main`
  to `aleph-vm-supervisor` (the systemd unit currently uses
  `python3 -m aleph.vm.supervisor`, which keeps working either way).

## Namespace packages (PEP 420)

`aleph.vm.*` spread over several dists requires implicit namespace packages:
NO dist may ship `aleph/__init__.py` or `aleph/vm/__init__.py`.

- Both files are EMPTY today (`src/aleph/__init__.py`,
  `src/aleph/vm/__init__.py`); deleting them loses nothing.
- `[tool.mypy] explicit_package_bases = true` is already set, so mypy copes.
- pytest with `pythonpath = ["src"]` handles namespace packages natively.
- CAVEAT to verify at apply time: import-linter/grimp with
  `root_package = "aleph"` where `aleph` is a namespace package. If grimp
  refuses, list `root_packages = ["aleph.vm.agent", "aleph.vm.supervisor", ...]`
  instead (import-linter supports multiple root packages).
- The deb is unaffected: `packaging/Makefile` copies `src/aleph` into
  `/opt/aleph-vm` wholesale and Python >= 3.3 imports the namespace package
  from that directory with or without the `__init__.py` files.

## In-repo layout (one src tree, N pyprojects)

Keep the unified `src/aleph/vm/` tree (test suite, mypy, CI, deb and the
`PYTHONPATH=src` workflow all depend on it). Add per-dist build projects that
reference it through symlinked package dirs:

```
packages/
  contract/
    pyproject.toml            # name = "aleph-vm-contract"
    src/aleph/vm/supervisor_interface -> ../../../../src/aleph/vm/supervisor_interface
  core/ ...
  supervisor/ ...
  agent/ ...
```

Each sub-pyproject:

```toml
[build-system]
build-backend = "hatchling.build"
requires = [ "hatch-vcs", "hatchling" ]

[project]
name = "aleph-vm-contract"
dynamic = [ "version" ]
dependencies = [ "grpcio>=1.70,<1.71", "protobuf==5.29.6", "msgpack==1.1.2", "pydantic>=2,<3" ]

[tool.hatch.version]
source = "vcs"
raw-options = { root = "../.." }      # version from the repo tags

[tool.hatch.build.targets.wheel]
packages = [ "src/aleph" ]            # PEP 420: no aleph/__init__.py anywhere
```

SPIKE EVIDENCE (2026-07-03, hatchling 1.x from the repo venv): a wheel built
from exactly this layout, with `src/aleph/vm/supervisor_interface` being a
symlink into the real tree, contains all 15 module files including
`wire/_pb/supervisor_pb2.py` and `client.py` and NO top-level `__init__.py`.
`pip wheel --no-build-isolation .` succeeds. Hatchling follows the symlink.

Development installs stay single-dist until the repo split: the root
`pyproject.toml` remains the only editable install (`pip install -e .`), and
the root dist must not be co-installed with the sub-dists (same files). The
sub-projects are BUILD-ONLY targets (CI: `for d in packages/*; do pip wheel
$d; done`); publish them once a consumer exists. After the repo extraction
(see `2026-07-04-repo-extraction.md`) each repo has one canonical pyproject
and the symlink farm disappears.

## Deb packaging

Now: unchanged. The deb does not pip-install the project; it copies
`src/aleph` into `/opt/aleph-vm/` and pip-installs only third-party
dependencies with `--target`. One repo, one copy, both services.

After the repo split: the aleph-vm deb build replaces `cp -r ../src/aleph`
with `pip install --target ./aleph-vm/opt/aleph-vm/ aleph-vm-agent
aleph-vm-supervisor` (which drags contract + core), or vendors the supervisor
repo as a build checkout. The /opt layout, the systemd units
(`aleph-vm-agent.service`, `aleph-vm-supervisor.service`) and
`supervisor.env` do not change.

## Ordered steps to apply

1. Land the model split: remove `aleph.vm.models` / `aleph.vm.hypervisors`
   imports from `aleph.vm.agent` and `aleph.vm.migration` (DTOs from the
   contract carry what the agent needs; `RuntimeConfiguration` and the
   MicroVM error move to contract types or agent-local definitions).
2. Sort the shared pile: confirm each `aleph-vm-core` module imports nothing
   supervisor- or agent-side (today `program_config.py` -> hypervisors keeps
   it supervisor-side); add an import-linter contract for core.
3. Delete `src/aleph/__init__.py` and `src/aleph/vm/__init__.py`; verify
   pytest, mypy and lint-imports (grimp namespace caveat above).
4. Add `packages/*/pyproject.toml` with symlinked package dirs; CI job builds
   all four wheels and pip-installs them together into a scratch venv, then
   runs the contract conformance tests against that install.
5. Turn the root `aleph-vm` pyproject into the meta-package at the same time
   as the repo extraction, not before.
