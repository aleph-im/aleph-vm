# Controller split by concern — implementation plan (PR-2)

**Status:** Plan, grounded in a code audit (2026-06-19)
**Design:** `docs/plans/2026-06-19-controller-split-by-concern-design.md`
**Branch:** `od/controller-split-by-concern` (stacked on PR-3 `od/agent-supervisor-code-move`)
**Paths are post-PR-3:** agent = `aleph.vm.agent`, controllers = `aleph.vm.supervisor.controllers`, contract = `aleph.vm.supervisor_interface`.

## 0. Audit findings that change the design's assumptions

A full read of the boundary (see session audit) resolved the design's §5 open
questions and surfaced one coupling the design under-specified:

- **Backup/QMP boundary coverage is already complete** (design §5 Q3). Every
  `BackupOps`/`ConfidentialOps` method is on `supervisor_interface.abc.Supervisor`
  and implemented in `supervisor/local.py` wrapped in `translating_errors()`
  (`get_measurement`, `inject_secret`, `start_backup`, `get_backup_status`,
  `list_backups`, `download_backup`, `delete_backup`, `restore_backup`,
  `restore_from_image`). `QemuVmClient` and the fsfreeze/fsthaw QMP calls are
  **supervisor-internal only** (`local.py` `_try_fsfreeze`/`_try_fsthaw`, inside
  `start_backup`). No agent code calls `QemuVmClient`. **No boundary gap.**
- **error_mapping is complete**: `translate_exception` maps every internal
  backend exception to the closed `SupervisorError` set; all 30+ boundary methods
  in `local.py` wrap their body in `translating_errors()`. So **the boundary only
  ever raises `SupervisorError`** today.
- **THE COUPLING (design under-specified):** the create path downloads
  **agent-side**, before the boundary. `agent/translate.py:100-101` builds
  `AlephQemuResources(message, namespace).download_all()` and
  `:188-189` builds `AlephProgramResources(message, namespace).download_all()`,
  resolving paths into the `CreateVmSpec`. The running controller no longer
  downloads. Therefore `ResourceDownloadError` / `FileTooLargeError` are raised
  **agent-side by controller code the agent imports** — they are NOT boundary
  errors. This is why `views/__init__.py` still imports controller exceptions
  (`vm_creation_exceptions`, lines 618-630 / 946-957). **Consequence:** Residual
  B (wire-error vocabulary) cannot be removed without Residual A (move the
  downloader agent-side and have it raise the neutral
  `supervisor_interface.errors` vocabulary). PR-2 is one coupled change.

### §5 open-question resolutions
- **Q1 downloader subclass vs compose:** **compose.** The agent downloader holds
  `message_content` and emits resolved spec fields; it does NOT subclass the
  controller `VmResources`. This is what actually removes the
  `agent -> supervisor.controllers` import (subclassing would keep it).
- **Q2 `make_writable_volume` placement:** **keep in the downloader** (status quo,
  behavior-neutral). Note for the future `VmExecution`/`VmPool` cleave.
- **Q3 backup boundary coverage:** no gap (above). The one loose thread is
  `operator.py:925` calling `controllers.qemu.backup.download_volume_by_ref`
  directly and `:33-36` importing `get_backup_directory` — agent code reaching a
  controller util. PR-2 relocates these (see step 4).

## 1. Inventory (file:line)

**Resources classes** (`supervisor/controllers/`):
- `resources.py:90` `VmResources` (base: `kernel_image_path`, `rootfs_path`,
  `volumes`, `namespace`, `download_kernel`), `:30` `HostVolume`.
- `qemu/instance.py:36` `AlephQemuResources(VmResources)` — DOWNLOAD:
  `download_runtime` `:61`, `download_volumes` `:69`, `download_all` `:74`,
  `make_writable_volume` `:80`; RUNTIME: `from_spec` `:125`, `gpus`,
  `get_disk_usage_delta` `:55`; holds optional `message_content` `:48`.
- `qemu_confidential/instance.py:25` `AlephQemuConfidentialResources(AlephQemuResources)`
  — `download_firmware` `:28`, `download_all` `:35`, `from_spec` `:43`,
  `firmware_path`.
- `firecracker/executable.py:92` `AlephFirecrackerResources(VmResources)` —
  `download_volumes` `:109`, `download_all` `:112`; required `message_content`.
- `firecracker/program.py:163` `AlephProgramResources(AlephFirecrackerResources)`
  — `download_code/runtime/data/all`, code fields.
- `firecracker/spec_program.py:47` `SpecProgramResources` — already message-free,
  `from_spec` `:57`. **This is the pattern to mirror for QEMU.**

**Construction sites:**
- Agent download: `agent/translate.py:100` (qemu), `:188` (program).
- Supervisor runtime (`from_spec`): `models.py:417` (spec program), `:419`
  (confidential), `:421` (qemu).

**Leak (supervisor -> agent):** `aleph/vm/resources.py:7`
`from aleph.vm.agent.utils import get_compatible_gpus` (used `:82`, `:91`).

**View error vocabulary:** `agent/views/__init__.py:67-73` import
`MicroVMFailedInitError` (hypervisors), `InsufficientResourcesError`
(`aleph.vm.resources`), `ResourceDownloadError`/`VmSetupError`
(controllers.firecracker.executable), `FileTooLargeError`
(controllers.firecracker.program); caught in `vm_creation_exceptions` `:618`,
`:946`. `operator.py:33-36` imports `download_volume_by_ref`,
`get_backup_directory` from `controllers.qemu.backup`; uses at `:925`.

## 2. Slice sequence (each committed only when green)

1. **Leak fix (independent, behavior-neutral).** Move `get_compatible_gpus` to a
   neutral home. It lives in `agent/utils.py` but is GPU-hardware logic with no
   agent dependency; move it to `aleph.vm.resources` (already the GPU util module)
   or a neutral `aleph.vm.hardware`. Update `agent/utils.py` to re-export (or
   update importers). Verify `resources.py` no longer imports `agent.*`;
   import-linter unaffected (this leak is not yet a contract, but fixing it
   unblocks a future supervisor-side contract).

2. **Lock HTTP-status contract (tests first, no code change).** Add view-level
   tests asserting `update_allocations`/`notify_allocation` aggregate status
   (200 all-ok, 207 partial, 503 all-fail) and that a download failure, setup
   failure, file-too-large, insufficient-resources each land a VM in `failing`
   with the right `repr`. These must pass on current code; they pin behavior
   across the refactor.

3. **Agent-side downloader (Residual A).** New `agent/vm/downloader.py` (or
   `agent/resources.py`): `QemuDownloader`, `ProgramDownloader`,
   `QemuConfidentialDownloader` — compose, hold `message_content`, own
   `download_runtime/volumes/code/data/firmware/all` + `make_writable_volume`,
   and emit the resolved fields `translate.py` needs. They raise
   `supervisor_interface.errors.ResourceDownloadError`/`FileTooLargeError`
   (neutral vocabulary). Rewire `translate.py:100,188` to use them. Keep
   `test_supervisor_translate*` green (mock the new downloader).

4. **Strip download from controller Resources.** Remove `download_*` /
   `make_writable_volume` from `AlephQemuResources`,
   `AlephQemuConfidentialResources`, `AlephFirecrackerResources`,
   `AlephProgramResources`, leaving the runtime holder (`from_spec` + attribute
   surface). `from_spec` reads `DiskRole` from `supervisor_interface` (already
   true post-PR-1). Add a test: the runtime holder has no `message_content` /
   download surface. Keep `test_supervisor_spec_resources` / `test_qemu_instance`
   green.

5. **Wire-error vocabulary (Residual B), now unblocked.** The agent now raises
   only neutral/contract errors (download from step 3; create from the boundary).
   Add an `ErrorCode -> HTTP status` helper. Replace the controller/hypervisor
   exception imports in `views/__init__.py` with `SupervisorError` (+ the
   download errors from `supervisor_interface.errors`). Update
   `vm_creation_exceptions`. Relocate `operator.py`'s `download_volume_by_ref` /
   `get_backup_directory`: either behind a boundary method or to a neutral
   staging util (recommend a thin boundary method `stage_restore_volume` if the
   restore path needs tenant isolation; else a neutral util). Step-2 tests must
   stay green.

6. **Tighten import-linter.** Delete the two `agent -> supervisor.controllers`
   residuals from the ignore list in `pyproject.toml`; the "controllers ... not
   the agent" / "agent does not reach ..." contracts now hold strictly. Run
   `lint-imports` (4 kept, 0 broken), full supervisor suite, mypy baseline.

## 3. Confidential / testnet

`AlephQemuConfidentialResources` follows the same split (download_firmware moves
to `QemuConfidentialDownloader`; `from_spec` runtime holder stays). The SEV
runtime path is exercised by unit tests with mocks; full validation needs the
testnet #27 SEV run before merge (same gate as the confidential-init work).

## 4. Risk / why this is gated on tests, not "moves only"

It splits a class and changes which exceptions the views catch. The step-2
HTTP-contract tests + the existing `translate`/`spec_resources`/`qemu_instance`
suites are the safety net. Commit each slice only when green; never weaken a test
to pass.
