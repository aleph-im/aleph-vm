# SNP instance pin runbook (2026-08-18)

Manual runbook for Olivier: republish the v-program bundle (its measurement
changed under the kernel-bump stack + init-common refactor) and publish the
two new confidential-instance artifacts, then re-pin the hashes the
aleph-testnets harness fetches. Task 14 (the confidential-instance E2E
scenario) is blocked on the three hashes recorded at the end of this
runbook.

This mirrors the working style of `.local/repin-20260818/CHECKLIST.md` (the
previous v-program-only republish): stage everything under a fresh, git-
ignored-in-spirit `.local/<date>/` directory in the repo root (this repo's
`.gitignore` does not special-case `.local/`, so treat it as scratch space
you do not `git add`), and record every hash as you go. The historical
convention of copying the staged tarball to the repo root as
`aleph-snp-image-*.tar.gz` before uploading is fine too; either location
works, `aleph file upload` just needs a local path.

## Prerequisites

- `nix` available (flakes enabled).
- `venv/bin/python` (or any Python with the repo's deps) for
  `scripts/vprogram_bundle.py`.
- `aleph` CLI configured with a funded account for `aleph file upload`.
- Working directory: repo root of this worktree
  (`.worktrees/snp-instances`), branch `od/snp-instances`.

## Step 1: build all three images locally

```bash
mkdir -p .local/snp-instance-repin-2026-08-18
nix build ./nix#image ./nix#instanceImage ./nix#instanceTestRootfs \
    --out-link .local/snp-instance-repin-2026-08-18/result
```

This produces three result symlinks (`.result`, `.result-1`, `.result-2` in
build order: `image`, `instanceImage`, `instanceTestRootfs`). Resolve which
is which with `readlink`, e.g.:

```bash
for l in .local/snp-instance-repin-2026-08-18/result*; do
  echo "$l -> $(readlink -f "$l")"
done
```

The v-program platform measurement is at `<image-result>/measurement.hex`;
the confidential-instance measurement is per-deployment (owner address is a
measured cmdline slot) and is computed with
`lib.${system}.instanceMeasurementFor { owner = "0x..."; }` or the
`compute_snp_measurement` helper the daemon/tests call, not baked into a
static file. `instanceMeasurementSmoke` gives that path build coverage but
its output is a placeholder-owner measurement, not one to record here.

## Step 2: build both bundle tarballs

Two bundles: the refreshed v-program bundle (`--flavor vprogram`, the
default) and the new instance bundle (`--flavor instance`). Point
`--image-dir` at the resolved `nix#image` / `nix#instanceImage` result paths
from Step 1 (or omit `--image-dir` and let the script build from Nix itself;
using the paths already built above avoids a second build).

```bash
python scripts/vprogram_bundle.py build \
    --image-dir "$(readlink -f .local/snp-instance-repin-2026-08-18/result)" \
    --out .local/snp-instance-repin-2026-08-18/vprogram

python scripts/vprogram_bundle.py build --flavor instance \
    --image-dir "$(readlink -f .local/snp-instance-repin-2026-08-18/result-1)" \
    --out .local/snp-instance-repin-2026-08-18/instance
```

Each `build` invocation writes `<out>/snp-image.tar.gz` (the bundle
tarball) and `<out>/bundle-info.json` (consumed by the `manifest`
subcommand later, when a new `runtime.ref` is needed — not required for
this runbook's harness re-pin, which only needs the tarball's own FILE
hash).

## Step 3: upload the two bundle tarballs and the test rootfs

```bash
aleph file upload .local/snp-instance-repin-2026-08-18/vprogram/snp-image.tar.gz
aleph file upload .local/snp-instance-repin-2026-08-18/instance/snp-image.tar.gz
aleph file upload "$(readlink -f .local/snp-instance-repin-2026-08-18/result-2)"
```

Aleph native storage is content-addressed: the FILE item's hash **is** the
uploaded file's sha256. Compute the same values locally first so you can
cross-check the CLI's printed hash against them (this is the invariant the
harness's fetch step relies on):

```bash
sha256sum .local/snp-instance-repin-2026-08-18/vprogram/snp-image.tar.gz
sha256sum .local/snp-instance-repin-2026-08-18/instance/snp-image.tar.gz
sha256sum "$(readlink -f .local/snp-instance-repin-2026-08-18/result-2)"
```

## Step 4: record the three pins

Record these three values (all sha256 of the uploaded file, per Step 3):

- `SNP_IMAGE_HASH` — sha256 of the refreshed v-program `snp-image.tar.gz`.
  This is a **re-pin of an existing value**: the v-program measurement
  changed (attest-agent atomic-write fix + kernel-bump base + init-common
  refactor all landed on `dev` since the last pin), so the old
  `SNP_IMAGE_HASH` in `aleph-testnets/.github/workflows/upgrade-checks.yml`
  is now stale and must be bumped alongside the two new ones below.
- `SNP_INSTANCE_IMAGE_HASH` — sha256 of the instance `snp-image.tar.gz`
  (new pin; Task 14 wires this into upgrade-checks.yml).
- `SNP_INSTANCE_TEST_ROOTFS_HASH` — sha256 of the uploaded
  `test-rootfs.ext4` (new pin; Task 14 wires this into upgrade-checks.yml).

Write them down (e.g. in a `.local/snp-instance-repin-2026-08-18/CHECKLIST.md`
following the prior CHECKLIST's format) together with the STORE item hash
`aleph file upload` prints for each, since that item hash is what a
manifest's `runtime.ref` would point at if one is regenerated. Task 14 is
blocked on the three FILE hashes above; hand them to whoever picks up that
task (or paste them directly into the PR that wires them into
`upgrade-checks.yml`).

## Step 5: re-run the v-program E2E after the re-pin

Because `SNP_IMAGE_HASH` moved, first revalidate the refreshed v-program
image on its own before layering the instance scenario on top of it: run
the existing v-program E2E (`aleph-testnets`' `upgrade-checks.yml`, the SNP
job covering `tests/test_vm_snp.py` / `tests/test_vm_vprogram.py`) against
the new `SNP_IMAGE_HASH` (and, if the fib-service workload volume also
changed, the corresponding `SNP_WORKLOAD_*` pins — check whether
`workload.nix`/`fib-service` changed since the last repin; if not, those
three stay as-is). Confirm the SNP scenario's launch measurement still
matches `<image-result>/measurement.hex` from Step 1 before proceeding to
wire up the confidential-instance scenario (Task 14) against
`SNP_INSTANCE_IMAGE_HASH` / `SNP_INSTANCE_TEST_ROOTFS_HASH`.

## Reference: what each artifact is for

- `nix#image` → `snp-image.tar.gz` (`--flavor vprogram`) → `SNP_IMAGE_HASH`:
  the measured v-program platform bundle (OVMF + kernel + initrd +
  dm-verity rootfs + `measurement.hex`), unchanged in shape from prior
  pins, just a fresh measurement.
- `nix#instanceImage` → `snp-image.tar.gz` (`--flavor instance`) →
  `SNP_INSTANCE_IMAGE_HASH`: OVMF + kernel + LUKS-mode initrd only, no
  rootfs and no baked `measurement.hex` (the instance measurement depends on
  the per-deployment owner address; see `lib.${system}.instanceMeasurementFor`
  in `nix/flake.nix`).
- `nix#instanceTestRootfs` → `test-rootfs.ext4` →
  `SNP_INSTANCE_TEST_ROOTFS_HASH`: the plain (unencrypted) dropbear-serving
  ext4 fixture (`nix/test-rootfs.nix`). The E2E harness downloads this,
  LUKS2-wraps it with a fresh per-run passphrase, writes the run's SSH
  public key into the opened container's `/root/.ssh/authorized_keys`, and
  publishes the wrapped result as the instance's `rootfs.parent`. It is
  never measured and is not bit-reproducible (build-time dropbear host key).
