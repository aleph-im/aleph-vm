# V-PROGRAM Workload Mechanism (fib-service) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver fib-service as a real, measured, message-referenced dm-verity workload volume that the SEV-SNP guest mounts and runs, replacing the baked `aleph.builtin/1` placeholder.

**Architecture:** The workload is a separate dm-verity ext4 volume the V-PROGRAM message references (`content.workload`). Its roothash is a **measured** kernel-cmdline parameter (`workload_roothash=`), so attestation binds the exact workload. Guest init mounts it (vdc/vdd) and execs its static entrypoint; the attest-agent proxies `:8443 → 127.0.0.1:8080` unchanged. All wiring is **conditional on a workload being present** so the workload-less path (`test_vm_snp`) is byte-identical.

**Tech Stack:** Rust (fib-service actix-web, supervisor-daemon), Nix (guest image + dm-verity), Python (agent launch path, manifest/measurement tooling, pytest), `sev-snp-measure` (pip 0.0.12), bash (aleph-testnets harness).

## Global Constraints

- Worktree: `/home/olivier/git/aleph/aleph-vm/.worktrees/vprogram-integration`, branch `od/vprogram-integration`. Do NOT switch branches.
- Frozen supervisor proto: NO new proto/spec fields. The daemon carries the workload roothash via a **sidecar file** (`{rootfs}.workload_roothash`), not the wire.
- Conditional wiring: when no workload sidecar / no `content.workload` is present, the derived **cmdline and disk set are byte-identical to today**. The platform *measurement* DOES change once `init.sh` is edited (init.sh lives in the measured initrd), so Task 7 re-pins the image and both `test_vm_snp` and the workload-less V-PROGRAM read the new measurement from the staged `measurement.hex` (never a hardcoded constant). The invariant is cmdline/disk parity for the no-workload path, not a frozen measurement value.
- Reproducible nix: fixed verity salt `0000…` (64 zeros) and UUID `0000…`, deterministic mkfs (fixed UUID/hash-seed, `SOURCE_DATE_EPOCH`, no journal), so the workload roothash is stable.
- Measured cmdline form (workload present), EXACT: `console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash} workload_roothash={workload_roothash}`. The daemon-emitted string and the manifest `cmdline_template` and the `sev-snp-measure --append` string must be byte-identical or attestation fails.
- Python test invocation (from the worktree): `PYTHONPATH="$PWD/src:/home/olivier/git/aleph/aleph-vm/.dev-stubs" ALEPH_VM_CACHE_ROOT=/tmp/vp-cache ALEPH_VM_EXECUTION_ROOT=/tmp/vp-exec /home/olivier/git/aleph/aleph-vm/venv/bin/python -m pytest <path> -p no:cacheprovider -q` (mkdir the two /tmp dirs first; venv has aleph-message@bc9c0f8).
- Rust gate: `cd rust && cargo clippy --workspace --all-targets --locked -- -D warnings` and `cargo test --workspace --locked`.
- fib-service reference: `GET /fib/{n}` returns the nth Fibonacci as text (saturating u64), `GET /health` returns ok; binds `127.0.0.1:8080`. `fib(10) == 55`.

---

## File Structure

- `nix/fib-service/` (new) — Rust actix-web app (Cargo.toml, src/main.rs), ported from the aleph-cvm donor.
- `nix/workload.nix` (new) — builds `workload.ext4` (fib entrypoint) + its dm-verity tree + roothash.
- `nix/flake.nix` (modify) — add fib-service + workload derivations; extend the measured-cmdline template to the workload form; expose a `workload` flake output.
- `nix/init.sh` (modify) — parse `workload_roothash=`, mount+verify the workload volume (vdc/vdd), exec its entrypoint.
- `rust/crates/supervisor-daemon/src/lifecycle.rs` (modify) — conditional `workload_roothash` sidecar → cmdline append.
- `src/aleph/vm/agent/vprogram_launch.py` (modify) — attach workload disks + write the workload sidecar.
- `src/aleph/vm/vprogram/manifest.py`, `bundle.py` (modify) — `{workload_roothash}` template variant + `aleph.exec/1` contract.
- `src/aleph/vm/vprogram/measurement.py` (new) — per-workload measurement via `sev-snp-measure`.
- aleph-testnets `tests/test_vm_vprogram.py`, `tests/conftest.py`, workflow (modify) — build/upload workload STOREs, compute measurement, publish, attest, assert fib output.

Task order: 4 (daemon) and 5 (python launch) are unit-testable and land first so the mechanism is exercised before the image is rebuilt; 1-3 + 6 build the workload image; 7 re-pins; 8-9 are tooling; 10 is the harness. Increments that change the measured image (1-3, flake) are grouped so a single re-pin covers them.

---

## Task 1: Daemon — conditional workload_roothash in the derived cmdline

**Files:**
- Modify: `rust/crates/supervisor-daemon/src/lifecycle.rs` (`snp_config_slice`, ~2067-2153)
- Test: same file's `#[cfg(test)]` module (mirror existing `snp_config_slice` tests)

**Interfaces:**
- Consumes: `SnpSlice`/`snp_config_slice(spec)` as they exist.
- Produces: cmdline `…roothash={p}` unchanged when no `{rootfs}.workload_roothash` sidecar; `…roothash={p} workload_roothash={w}` when present and bare-hex-valid; error (`InvalidBackend`) when the sidecar exists but is non-hex.

- [ ] **Step 1: Write the failing test.** In the lifecycle test module, add a test that stages a temp rootfs with a `.roothash` sidecar AND a `.workload_roothash` sidecar (bare hex), calls `snp_config_slice`, and asserts the derived `kernel_cmdline` ends with ` workload_roothash=<hex>`. Add a second test: no workload sidecar ⇒ cmdline is exactly `console=ttyS0 root=/dev/mapper/verity-root ro roothash={p}` (regression guard). Add a third: a non-hex workload sidecar ⇒ `snp_config_slice` returns an error.

- [ ] **Step 2: Run to verify failure.** `cd rust && cargo test -p supervisor-daemon snp_config_slice -- --nocapture` → the new workload assertion FAILS (cmdline lacks the suffix).

- [ ] **Step 3: Implement.** After the existing roothash read/validate + `let kernel_cmdline = format!(...)`, insert:

```rust
// Optional measured workload: if the launcher staged a
// {rootfs}.workload_roothash sidecar (from content.workload.roothash),
// bind the workload volume into the launch digest via the cmdline. Absent
// sidecar => byte-identical cmdline (workload-less parity).
let workload_sidecar = PathBuf::from(format!("{}.workload_roothash", rootfs_path.display()));
let kernel_cmdline = match std::fs::read_to_string(&workload_sidecar) {
    Ok(raw) => {
        let wh = raw.trim();
        if wh.is_empty() || !wh.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(InvalidBackendError(format!(
                "workload_roothash sidecar {workload_sidecar:?} is not bare hex"
            )).into());
        }
        format!("{kernel_cmdline} workload_roothash={wh}")
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => kernel_cmdline,
    Err(e) => return Err(InvalidBackendError(format!(
        "reading workload_roothash sidecar {workload_sidecar:?}: {e}"
    )).into()),
};
```
Bound the read like the existing roothash sidecar (4 KiB cap) — reuse the same read helper if one exists; otherwise read then check `raw.len() <= 4096`.

- [ ] **Step 4: Run to verify pass.** `cargo test -p supervisor-daemon snp_config_slice` → PASS. Then `cargo clippy --workspace --all-targets --locked -- -D warnings` → clean.

- [ ] **Step 5: Commit.**
```bash
git add rust/crates/supervisor-daemon/src/lifecycle.rs
git commit -m "feat(daemon): conditional workload_roothash in the SNP measured cmdline"
```

---

## Task 2: Python launch — attach the workload volume + write the sidecar

**Files:**
- Modify: `src/aleph/vm/agent/vprogram_launch.py` (`build_vprogram_spec`)
- Test: `tests/supervisor/test_vprogram_launch.py`

**Interfaces:**
- Consumes: `content.workload` (`VerifiedWorkload{ref, hash_tree, roothash}`), `get_existing_file`, the existing extract/sidecar staging.
- Produces: a `CreateVmSpec` with 4 disks when a workload is present (rootfs ROOTFS + platform hashtree EXTRA + workload data EXTRA + workload hashtree EXTRA), and a `{rootfs}.workload_roothash` sidecar file containing `content.workload.roothash`. Two disks + no workload sidecar when `content.workload` is absent.

- [ ] **Step 1: Write the failing test.** In `test_vprogram_launch.py`, add `test_workload_attached_and_sidecar_written`: build a `VerifiableProgramContent` with a `workload` block (roothash = 64 hex chars), monkeypatch `get_existing_file` to return staged temp files for the workload ref + hash_tree, call `build_vprogram_spec`, and assert (a) the spec has 4 disks with the workload data + hash tree as the 3rd/4th EXTRA disks in that order, (b) a `<rootfs>.workload_roothash` sidecar exists next to the rootfs with content == `content.workload.roothash`. Add `test_workload_roothash_non_hex_fails_closed` (garbage roothash ⇒ `VmSetupError`, nothing attached).

- [ ] **Step 2: Run to verify failure.** Run the pytest command on `tests/supervisor/test_vprogram_launch.py::test_workload_attached_and_sidecar_written` → FAIL (only 2 disks).

- [ ] **Step 3: Implement.** In `build_vprogram_spec`, after the platform rootfs + hashtree disks and after `_ensure_verity_sidecars`, add (guarded on `content.workload is not None`):

```python
HEX64 = re.compile(r"\A[0-9a-fA-F]+\Z")
...
if content.workload is not None:
    wl_roothash = content.workload.roothash
    if not HEX64.match(wl_roothash):
        raise VmSetupError(f"V-PROGRAM {vm_hash} workload roothash is not bare hex")
    workload_data = await get_existing_file(str(content.workload.ref))
    workload_hashtree = await get_existing_file(str(content.workload.hash_tree))
    # The daemon derives ' workload_roothash=' from this sidecar next to the
    # rootfs (proto has no cmdline field). Fail closed on a bad roothash.
    (rootfs_path.parent / f"{rootfs_path.name}.workload_roothash").write_text(wl_roothash)
    disks.append(DiskSpec(path=workload_data, readonly=True, format=DiskFormat.RAW, role=DiskRole.EXTRA))
    disks.append(DiskSpec(path=workload_hashtree, readonly=True, format=DiskFormat.RAW, role=DiskRole.EXTRA))
```
(`rootfs_path` is the extracted platform rootfs path already computed; ensure `import re` at top.)

- [ ] **Step 4: Run to verify pass.** Run both new tests + the existing suite: `pytest tests/supervisor/test_vprogram_launch.py tests/supervisor/test_vprogram.py -q` → all PASS. `ruff format --check` + `mypy src/aleph/vm/agent/vprogram_launch.py` clean.

- [ ] **Step 5: Commit.**
```bash
git add src/aleph/vm/agent/vprogram_launch.py tests/supervisor/test_vprogram_launch.py
git commit -m "feat(vprogram): attach the measured workload volume and stage its roothash sidecar"
```

---

## Task 3: Manifest + bundle — workload cmdline template and aleph.exec/1 contract

**Files:**
- Modify: `src/aleph/vm/vprogram/bundle.py` (`CMDLINE_TEMPLATE_V1`, `DEFAULT_WORKLOAD`, `make_manifest`)
- Test: `tests/vprogram/test_manifest.py`, `tests/vprogram/test_bundle.py`

**Interfaces:**
- Produces: `CMDLINE_TEMPLATE_EXEC_V1 = "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash} workload_roothash={workload_roothash}"`; a way to build a manifest whose workload contract is `aleph.exec/1` and whose template is the exec form. The existing platform-only template/contract remain for the no-workload runtime.

- [ ] **Step 1: Write the failing test.** In `test_bundle.py`, add `test_exec_manifest_uses_workload_template`: build a manifest with the exec runtime flavor and assert `manifest.boot.cmdline_template == CMDLINE_TEMPLATE_EXEC_V1` and `manifest.workload.contract == "aleph.exec/1"`, and that it validates (`RuntimeManifest.model_validate`). Confirm the template passes `BootSpec.check_cmdline_template` (it uses only reserved placeholders).

- [ ] **Step 2: Run to verify failure.** Run `pytest tests/vprogram/test_bundle.py::test_exec_manifest_uses_workload_template -q` → FAIL (constant/flavor missing).

- [ ] **Step 3: Implement.** Add the constant and a `workload_contract`/`cmdline_template` parameter path to `make_manifest` (default keeps the platform-only template; an `exec=True` or explicit template arg selects the exec form). Keep `DEFAULT_WORKLOAD` for the builtin case; add `EXEC_WORKLOAD = WorkloadSpec(contract="aleph.exec/1", upstream_port=8080)`.

- [ ] **Step 4: Run to verify pass.** `pytest tests/vprogram/ -q` → PASS. `ruff format --check`.

- [ ] **Step 5: Commit.**
```bash
git add src/aleph/vm/vprogram/bundle.py tests/vprogram/
git commit -m "feat(vprogram): aleph.exec/1 workload contract + workload_roothash cmdline template"
```

---

## Task 4: Measurement helper (sev-snp-measure)

**Files:**
- Create: `src/aleph/vm/vprogram/measurement.py`
- Test: `tests/vprogram/test_measurement.py`
- Modify: `pyproject.toml` (add `sev-snp-measure==0.0.12` as a tooling/test dependency, matching the nix pin)

**Interfaces:**
- Produces: `compute_snp_measurement(*, ovmf: Path, kernel: Path, initrd: Path, cmdline: str, vcpus: int, vcpu_type: str) -> str` returning the 96-hex SHA-384 launch digest. Thin wrapper over the `sev_snp_measure` library (or its CLI) so it can later be replaced by an aleph-rs implementation.

- [ ] **Step 1: Write the failing test.** `test_measurement.py`: `test_measurement_is_deterministic_and_96_hex` — call `compute_snp_measurement` twice on tiny fixture ovmf/kernel/initrd blobs (or skip-if `sev_snp_measure` import fails, marking the hardware-independent determinism check) and assert the result is 96 lowercase hex chars and stable across calls. `test_cmdline_changes_measurement` — two different cmdlines ⇒ different digests.

- [ ] **Step 2: Run to verify failure.** `pytest tests/vprogram/test_measurement.py -q` → FAIL (module missing).

- [ ] **Step 3: Implement.** `measurement.py`:

```python
"""Per-workload SEV-SNP launch measurement.

TRANSIENT: wraps the sev-snp-measure pip package (0.0.12, matching the nix
pin). The intended home for measurement computation is aleph-rs (the Rust
CLI); this module is the stopgop so the publisher can pin
verification.measurements[].digest for a message-delivered workload.
"""
from pathlib import Path
from sevsnpmeasure import guest, vmm_types
from sevsnpmeasure.sev_mode import SevMode

def compute_snp_measurement(*, ovmf: Path, kernel: Path, initrd: Path,
                            cmdline: str, vcpus: int, vcpu_type: str) -> str:
    ld = guest.calc_launch_digest(
        SevMode.SEV_SNP, vcpus, vcpu_type,
        str(ovmf), str(kernel), str(initrd), cmdline,
        vmm_type=vmm_types.VMMType.QEMU,
    )
    return ld.hex()
```
(Confirm the exact `sevsnpmeasure` API at 0.0.12 during implementation — `calc_launch_digest` signature/kwargs — and adjust; the nix flake calls the CLI form `sev-snp-measure --mode snp --vcpus N --vcpu-type T --ovmf … --kernel … --initrd … --append "<cmdline>"`, which is the fallback if the library API differs.)

- [ ] **Step 4: Run to verify pass.** `pip install sev-snp-measure==0.0.12` into the venv, then `pytest tests/vprogram/test_measurement.py -q` → PASS.

- [ ] **Step 5: Commit.**
```bash
git add src/aleph/vm/vprogram/measurement.py tests/vprogram/test_measurement.py pyproject.toml
git commit -m "feat(vprogram): sev-snp-measure measurement helper (transient; aleph-rs later)"
```

---

## Task 5: Nix — fib-service

**Files:**
- Create: `nix/fib-service/Cargo.toml`, `nix/fib-service/src/main.rs` (port from aleph-cvm `nix/fib-service/`)
- Modify: `nix/flake.nix` (add the `fib-service` static-musl crane derivation, mirroring `attest-agent`)

- [ ] **Step 1: Port the source.** Copy the donor's `nix/fib-service/src/main.rs` + `Cargo.toml` verbatim (actix-web 4, `GET /fib/{n}` saturating u64, `GET /health`, bind `127.0.0.1:8080`). Confirm no path-dependency on donor-only crates.

- [ ] **Step 2: Add the derivation.** In `flake.nix`, add `fib-service = craneToolchain.buildPackage { src = ./fib-service; CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl"; ... +crt-static }` (copy the attest-agent block's musl/static-openssl-free flags; fib-service has no openssl dep, so drop OpenSSL env if unused).

- [ ] **Step 3: Build to verify.** `cd nix && nix build .#fib-service` (or the flake's attr) → produces a static binary. `file result/bin/fib-service` → "statically linked". `./result/bin/fib-service &` then `curl 127.0.0.1:8080/fib/10` → `55`; `kill %1`.

- [ ] **Step 4: Commit.**
```bash
git add nix/fib-service nix/flake.nix
git commit -m "feat(nix): port fib-service (static-musl actix-web demo workload)"
```

---

## Task 6: Nix — workload volume + dm-verity

**Files:**
- Create: `nix/workload.nix`
- Modify: `nix/flake.nix` (call `workload.nix`; add a `workload` flake output shipping `workload.ext4`, `workload.ext4.verity`, `workload.ext4.roothash`)

- [ ] **Step 1: Build the ext4.** `workload.nix`: an ext4 whose `/sbin/init` is `#!/bin/sh\nexec /bin/fib-service` and `/bin/fib-service` is the Task-5 binary (+ a static busybox for `/bin/sh` if the entrypoint needs a shell; or make `/sbin/init` the fib binary directly). Reproducible mkfs (fixed UUID/hash-seed, `SOURCE_DATE_EPOCH=0`, `-O ^has_journal`), mirroring `rootfs.nix`.

- [ ] **Step 2: Build the verity tree.** Reuse the `verity` derivation pattern from `flake.nix` (`veritysetup format --salt=<64 zeros> --uuid=<zeros> --data-block-size --hash-block-size`) over `workload.ext4`, emitting `hashtree` + `roothash`.

- [ ] **Step 3: Expose the output.** Add a flake `workload` output (or fold into `image`) that stages `workload.ext4`, `workload.ext4.verity`, `workload.ext4.roothash`.

- [ ] **Step 4: Build to verify + capture the roothash.** `nix build .#workload`; assert `result/workload.ext4.roothash` is 64 hex chars; record it (this becomes the reference `workload_roothash`). Rebuild once and confirm the roothash is identical (reproducibility).

- [ ] **Step 5: Commit.**
```bash
git add nix/workload.nix nix/flake.nix
git commit -m "feat(nix): fib-service workload volume + dm-verity (reproducible roothash)"
```

---

## Task 7: Nix — guest init mounts and runs the workload

**Files:**
- Modify: `nix/init.sh`
- Modify: `nix/flake.nix` (extend the measured cmdline template to the workload form; the platform bundle's own `measurement.hex` stays the platform-only value for the workload-less path)

**Interfaces:**
- Guest boots with `workload_roothash=<w>` in cmdline ⇒ vdc/vdd verity-verified, mounted, entrypoint exec'd, fib listening on 127.0.0.1:8080; without it ⇒ platform-only boot as today.

- [ ] **Step 1: Parse the cmdline token.** After the existing `roothash=$(… \broothash= …)` line, add:
```sh
workload_roothash=$(/bin/busybox sed -n 's/.*\bworkload_roothash=\([0-9a-fA-F]*\).*/\1/p' /proc/cmdline)
```
Verify the platform `roothash` capture is unaffected (the `\b` boundary already excludes `workload_roothash`; confirm by grep-testing both tokens on a sample cmdline string in a scratch shell).

- [ ] **Step 2: Mount + verify the workload.** After the platform rootfs is mounted at `/mnt/root`, add a block: if `$workload_roothash` non-empty, wait for `/dev/vdc` + `/dev/vdd`, `veritysetup open /dev/vdc verity-workload /dev/vdd "$workload_roothash"` (poweroff on failure, same as platform), `mkdir -p /mnt/workload && mount -o ro /dev/mapper/verity-workload /mnt/workload`.

- [ ] **Step 3: Exec the workload entrypoint.** When a workload is mounted, exec its entrypoint instead of the baked `/mnt/root/sbin/init`. Simplest: `chroot /mnt/workload /sbin/init &` (the workload volume carries its own `/sbin/init` → fib). Keep the platform `/mnt/root/sbin/init` (baked httpd) as the fallback when no workload is present. Keep the attest-agent line unchanged (`--upstream http://127.0.0.1:8080`).

- [ ] **Step 4: Extend the measured cmdline template (flake).** Where the flake defines `kernelCmdline` (currently platform-only), add a workload-form template producing `…roothash={p} workload_roothash={w}` for use by the manifest/measurement path. The flake's baked `measurement.hex` remains the platform-only measurement (workload-less parity); per-workload measurements are computed by Task 4's helper, not baked.

- [ ] **Step 5: Rebuild the image + re-pin.** `nix build .#image`; note the new platform `measurement.hex` (should be UNCHANGED from `de933c37…` since the platform cmdline/inputs are unchanged — if it changed, the init edits altered the initrd, which is expected; capture the new value). Tar the image (`image/` layout) → new bundle `sha256`. Upload to Aleph mainnet storage (or the testnet directly) per the existing re-pin flow; record STORE hash + sha256 + platform_roothash. Update the harness `SNP_IMAGE_HASH`.

- [ ] **Step 6: Commit.**
```bash
git add nix/init.sh nix/flake.nix
git commit -m "feat(nix): guest init mounts and execs the measured workload volume"
```

---

## Task 8: Harness — build/upload workload STOREs, compute measurement, assert fib

**Files (aleph-testnets `.worktrees/od-aleph-vm-upgrade-checks`):**
- Modify: `.github/workflows/upgrade-checks.yml` (build-image stages `workload.ext4` + `.verity` + `.roothash` from the nix output into `.local/snp/workload/`)
- Modify: `tests/test_vm_vprogram.py`

**Interfaces:**
- Consumes: staged `workload.ext4`, `workload.ext4.verity`, `workload.ext4.roothash`; the platform bundle (OVMF/kernel/initrd) for the measurement; `compute_snp_measurement`.
- Produces: a V-PROGRAM whose `workload` block points at the two uploaded STOREs, `workload.roothash` = the volume roothash, and `verification.measurements[0].digest` = the computed per-workload measurement.

- [ ] **Step 1: Stage the workload artifacts.** In build-image, include `workload.ext4`, `workload.ext4.verity`, `workload.ext4.roothash` in the `snp-image` artifact (→ `.local/snp/workload/`). (If the pinned tarball already carries them, extract them there instead.)

- [ ] **Step 2: Upload the two workload STOREs.** In the `staged_refs` fixture, upload `workload.ext4` → `content.workload.ref` and `workload.ext4.verity` → `content.workload.hash_tree`; read `workload.ext4.roothash` → `content.workload.roothash`.

- [ ] **Step 3: Compute the per-workload measurement.** In the fixture, call `compute_snp_measurement(ovmf=.local/snp/image/OVMF.fd, kernel=…/bzImage, initrd=…/initrd, cmdline="console=ttyS0 root=/dev/mapper/verity-root ro roothash=<platform> workload_roothash=<workload>", vcpus=2, vcpu_type="EPYC-v4")`. Use this as the message `verification.measurements[0].digest` (replacing the static `ALEPH_TESTNET_SNP_MEASUREMENT`).

- [ ] **Step 4: Point the message at the workload.** `build_vprogram_content`: `workload = {ref: workload_ref, hash_tree: workload_hashtree_ref, roothash: workload_roothash}`; runtime.ref = the exec-flavor manifest (Task 3) whose bundle is the re-pinned image.

- [ ] **Step 5: Assert attested fib output.** After the boot assertion, on the SNP host run `aleph-attest-cli` to verify the (workload-bound) measurement, then `GET /fib/10` over the attested channel (attest-cli fetch, or curl through the verified endpoint) and assert the body is `55`. Reuse `test_vm_snp`'s attest-cli invocation pattern.

- [ ] **Step 6: Commit + run CI.**
```bash
git add .github/workflows/upgrade-checks.yml tests/test_vm_vprogram.py
git commit -m "test(vprogram): deliver + attest + run the fib workload end to end"
git push
```
Then iterate the upgrade-checks run until `test_vprogram_scheduled_to_snp_crn` asserts `fib(10)==55` over the attested channel.

---

## Self-Review

**Spec coverage:** design §Components 1 (fib port → Task 5), 2 (workload volume → Task 6), 3 (init → Task 7), 4 (daemon → Task 1), 5 (python launch → Task 2), 6 (manifest/measurement → Tasks 3+4), 7 (testnet test → Task 8). §Security-spine (measured workload_roothash) → Tasks 1/4/7/8. §Compatibility (conditional wiring) → Task 1 regression test + Task 2/7 guards. All covered.

**Placeholder scan:** the two "confirm the exact API during implementation" notes (Task 4 `sevsnpmeasure` signature, Task 7 measurement value) are genuine external-facts-to-verify, not hand-waves — each has a concrete fallback (the CLI form) and a verification step. No "add error handling"-style gaps.

**Type consistency:** `compute_snp_measurement(*, ovmf, kernel, initrd, cmdline, vcpus, vcpu_type) -> str` used identically in Tasks 4 and 8; the `{rootfs}.workload_roothash` sidecar written in Task 2 is exactly what Task 1's daemon reads; `CMDLINE_TEMPLATE_EXEC_V1` string in Task 3 is byte-identical to the daemon cmdline (Task 1) and the measurement cmdline (Task 8) — enforced by the Global Constraint.

**Ordering note:** Tasks 1-4 (unit-testable) are safe to land before the image rebuild (Task 7); the end-to-end only works once all of 1-8 are in and the image is re-pinned.
