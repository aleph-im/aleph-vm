# Controller split by concern (PR-2: behavior-affecting)

**Status:** Design / approved scope
**Date:** 2026-06-19
**Owner:** Olivier Desenfans
**Repo:** `aleph-im/aleph-vm`
**Parent design:** `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (§4, A.6)
**Predecessor:** `docs/plans/2026-06-19-agent-supervisor-boundary-design.md` (PR-1)

## 1. Context

PR-1 establishes the `contract` layer and an import-enforced boundary, but it
leaves `controllers/` as a *shared* base layer because two pieces of it are used
on both sides. PR-1 records those as documented residuals:

- `orchestrator -> controllers` for the `Resources` classes, and
- `orchestrator -> controllers` for the controller exception types caught by the
  HTTP views.

PR-2 removes both residuals. It is the smaller half of what the parent design
called the §4 cleave, because the hardest piece (moving volume download out of
`controllers.setup()`) **already happened** during the spec work: `translate.py`
(agent) calls `resources.download_all()` and resolves every path before building
the `CreateVmSpec`; the running controller no longer downloads. What remains is
to stop the controller code from carrying a second, Aleph-aware personality, and
to finish the wire-error vocabulary so the views stop reaching into controller
internals.

PR-2 changes behavior (it splits a class and changes which exception types the
views catch), so it is gated on tests rather than on "moves only".

**Out of scope (still): the `VmExecution` / `VmPool` cleave.** PR-2 does not
split the god-objects. The controller split does not require it: download is
already agent-side and the spec path is in place. The `orchestrator ->
{pool, models}` residual from PR-1 stays until that separate, adjacent effort.

## 2. The two entanglements PR-2 removes

### 2.1 The `Resources` dual personality

`AlephQemuResources` (and the firecracker `AlephProgramResources` /
`AlephFirecrackerResources`, plus `AlephQemuConfidentialResources`) are
constructed two different ways:

- **Agent / download path**: `AlephQemuResources(message_content, namespace)`
  followed by `download_all()`. This reads the Aleph message, downloads runtime
  and volumes, creates writable qcow2 images, and feeds `translate.py`'s
  `CreateVmSpec`. It is Aleph-aware (holds `message_content`).
- **Supervisor / runtime path**: `AlephQemuResources.from_spec(spec, namespace)`.
  No download, `message_content=None`; it just exposes the attribute surface the
  running controller and pool read (`rootfs_path`, `volumes`, `gpus`,
  `kernel_image_path`). `from_spec` even does a local
  `from aleph.vm.supervisor.types import DiskRole` to read the spec.

One class, two lives. The download half is agent; the runtime half is supervisor.

**Target:** two types.

- An **agent-side downloader** owns `message_content`, `download_runtime`,
  `download_volumes`, `download_all`, and the writable-image creation. It lives
  agent-side and its product is the `CreateVmSpec` (resolved paths). It replaces
  the `AlephQemuResources(message)` use in `translate.py`.
- A **supervisor-side runtime holder** is the message-free
  `VmResources`/`from_spec` shape the controller reads. It stays controller-side
  (post-PR-3, supervisor-side). After PR-1 it reads `DiskRole` from `contract`,
  not via a local `supervisor.types` import.

The shared `controllers/resources.py::VmResources` attribute surface stays as the
common base for the runtime holder. The downloader composes or subclasses it;
choice deferred to the plan (see §5).

### 2.2 The wire-error vocabulary (parent A.6)

The views are in a hybrid state today: `orchestrator/views/__init__.py` imports
controller and hypervisor exception types (`ResourceDownloadError`,
`VmSetupError`, `FileTooLargeError`, `MicroVMFailedInitError`,
`HostNotFoundError`, `InsufficientResourcesError`) and lists them in the
`vm_creation_exceptions` catch tuples, *and* it already catches `SupervisorError`
/ `InternalSupervisorError` from the boundary. `operator.py` similarly imports
`controllers.qemu.backup` types.

The supervisor side already has the mapping: `supervisor/error_mapping.py` (split
out in PR-1) translates every internal backend exception to the closed
`SupervisorError` set via `translating_errors()`.

**Target:** every Supervisor boundary method wraps its work in
`translating_errors()` (audit that the create / operate / backup paths the views
exercise are covered), so the boundary only ever raises `SupervisorError`. The
views then:

- drop the `from aleph.vm.controllers...` and
  `from aleph.vm.hypervisors...` exception imports,
- catch `contract.errors.SupervisorError` (optionally branching on `.code` /
  `ErrorCode` for the few distinct HTTP statuses), and
- map `ErrorCode -> HTTP status` in one small helper.

`operator.py`'s direct use of `controllers.qemu.backup` / `QemuVmClient` is the
same shape: those operations move behind boundary methods that raise
`SupervisorError`, and the view stops importing controller types. (If any backup
RPC is not yet on the boundary, that surfaces as a plan task.)

## 3. Result

After PR-2:

- `controllers/` no longer carries Aleph-aware download personalities; it holds
  the runtime holder + the running controller + management (`QemuVmClient`,
  `backup`, `snapshots`) only.
- The agent imports its own downloader and catches only `SupervisorError`. The
  two `orchestrator -> controllers` residuals from PR-1 are deleted from the
  import-linter ignore list, and the linter is tightened to forbid them.
- `controllers/` is now unambiguously a supervisor-owned package (modulo
  `configuration.py`, the config-file contract). This is what makes PR-3's
  physical move mechanical.

The only remaining documented residual is `orchestrator -> {pool, models}`,
owned by the separate `VmExecution`/`VmPool` cleave.

## 4. Testing strategy

Behavior changes, so tests lead:

- **Error-mapping tests** (the riskiest surface): for each internal backend
  exception, assert `translate_exception` yields the right `SupervisorError` /
  `ErrorCode`, and that the view maps that code to the same HTTP status the
  current code returns. Lock the create-failure HTTP contract (503 for
  insufficient resources, the 4xx/5xx for setup/download/file-too-large) with
  view-level tests before changing the catch sites, so the refactor is provably
  status-preserving.
- **Downloader / runtime-holder split**: keep the existing
  `translate` and `test_qemu_instance` coverage green; the downloader must
  produce byte-identical spec paths, and `from_spec` must build the same runtime
  holder. Add a unit test that the runtime holder has no `message_content` /
  download surface.
- **Confidential**: `AlephQemuConfidentialResources` follows the same split;
  keep the SEV-path tests (and the testnet #27 SEV run before merge, as with the
  confidential-init work).
- Full supervisor suite green (known env-only exceptions excepted); `mypy`
  baseline unchanged; import-linter passes with the two residuals removed.

## 5. Open questions (resolved in the implementation plan)

- **Downloader vs runtime holder relationship**: does the agent downloader
  subclass `VmResources` (sharing the attribute surface) or compose a separate
  type that emits spec fields? Composition keeps the agent free of the
  controller base class; subclassing is less code.
- **`make_writable_volume` placement**: creating the writable qcow2 runs
  `qemu-img` on the host, which is arguably supervisor/infra work, but today it
  runs in the agent download phase. Keep it in the downloader (status quo,
  behavior-neutral) or move it behind the boundary (larger, defer)? Recommend
  keeping it in the downloader for PR-2 and noting it for the cleave.
- **Backup/QMP coverage on the boundary**: confirm `operator.py`'s backup and
  `QemuVmClient` uses already have boundary methods that raise `SupervisorError`;
  any gap is a prerequisite task inside PR-2 (or a thin precursor PR).

## 6. Next step

Implementation plan (writing-plans) covering the `Resources` split, the
boundary `translating_errors()` audit, the view error-mapping helper, the
residual-removal in the import-linter config, and the test checklist above.
