# V-Program Runtime Bundle Tooling — Design

Date: 2026-07-09
Status: approved
Related: `docs/plans/2026-07-08-confidential-vm-protocol-design.md` (§11 runtime
manifest convention), aleph-message PR #158 (`VerifiableProgramRuntime.ref`
points at a manifest STORE).

## Goal

Automate the creation of V-Program runtime bundles from the Nix measured-image
build, and give the `aleph-vprogram-runtime` manifest format a strict,
type-safe Python model that later consumers (CRN agent launch path, pyaleph
phase 2, CLI tooling) can reuse.

Today the process is manual: CI runs
`nix build "git+file://$REPO?dir=nix#image"`, someone hand-tars the output
(the mainnet bundle `1db0d69c…` contains a stray `aleph-attest-cli` binary at
top level), uploads it with `aleph file upload`, and bumps a hash in a
workflow file. There is no manifest at all yet; `runtime.ref` in V-PROGRAM
messages has nothing to point to.

## Decisions (from brainstorming)

1. **Scope: build + manifest generation only; uploads stay manual.** The
   manifest's `bundle.ref` is the STORE item hash, which exists only after the
   bundle is uploaded, so full automation would need account keys and network
   in the script. Instead the tool has two steps around the manual upload, and
   prints the exact `aleph file upload` commands.
2. **Model home: `src/aleph/vm/vprogram/`.** Importable by the future agent
   launch path; promoted to aleph-message once the format is proven.
3. **Base branch: `od/controller-main-error-flow`** (the only line with
   `nix/`). New branch off it.
4. **Single-bundle model.** The runtime is ONE tar.gz pinned by ONE STORE
   message (57 MB today); per-artifact STOREs are overkill. The manifest
   spends its weight on what the tarball cannot say about itself: attestation
   protocols and port, boot recipe, cmdline template, workload contract.

## The manifest format: `aleph-vprogram-runtime/1`

Reference instance (real values for the existing mainnet bundle):

```json
{
  "format": "aleph-vprogram-runtime",
  "format_version": 1,
  "name": "aleph-snp-attest",
  "version": "2026.07.08",
  "platform": "sev_snp",
  "bundle": {
    "ref": "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977",
    "sha256": "1db0d69c96dc7ed6c8a6cbb8c63f8de516ef4ed668e95c468cc216e4c44d911b",
    "size": 57522386,
    "members": {
      "ovmf": "image/OVMF.fd",
      "kernel": "image/bzImage",
      "initrd": "image/initrd",
      "platform_rootfs": "image/rootfs.ext4",
      "platform_hash_tree": "image/rootfs.ext4.verity"
    }
  },
  "boot": {
    "method": "qemu-direct-kernel",
    "kernel_hashes": true,
    "cpu_models": ["EPYC-v4"],
    "platform_roothash": "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8",
    "cmdline_template": "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
  },
  "attestation": [
    { "protocol": "aleph.ra-tls", "version": "1",
      "transport": { "type": "tcp", "port": 8443 } }
  ],
  "workload": { "contract": "aleph.builtin/1", "upstream_port": 8080 },
  "source": {
    "repo": "https://github.com/aleph-im/aleph-vm",
    "rev": "4d90abaf",
    "build": "nix build \"git+file://$REPO?dir=nix#image\""
  }
}
```

Field rationale:

- `bundle.sha256` / `bundle.size` duplicate what the STORE message says, but
  make the manifest self-sufficiently content-addressed (fetch from
  `/api/v0/storage/raw/<sha256>`, verify, done — no message-DB round trip).
  There is no drift authority problem: a mismatch with the STORE means the
  manifest is invalid, full stop.
- `boot.platform_roothash` duplicates the tarball member
  `rootfs.ext4.roothash` so the CCN/CLI can build the measured cmdline without
  unpacking the bundle; cross-checkable the same way.
- `bundle.members` maps roles to tarball paths so agents never hardcode
  layout; new bundles can reorganize without code changes.
- `boot.cmdline_template` is the normative cmdline recipe. Only placeholders
  defined by the format version are legal — this is the "no smuggled cmdline"
  rule, enforced by the model.
- `attestation` is an ordered (preference) non-empty list of protocol
  descriptors; protocol identity lives ONLY here, never in messages
  (denormalization rejected in the protocol design). Port 8443 matches the
  hardcoded `aleph-attest-agent --port 8443` in `nix/init.sh`.
- Measurements do NOT belong in the manifest: a launch digest is a joint
  function of manifest artifacts AND message fields (vcpus, future workload
  roothash). `measurement.hex` inside the tarball is CI convenience only.
- `source` is informational but required: every published manifest states how
  to rebuild and audit it.

Honesty caveat: the current image's init parses only `roothash=` (the donor's
workload-volume branch was stripped in the Phase 3 backport), so its manifest
declares contract `aleph.builtin/1` and a template with no
`{workload_roothash}` slot. It is a format reference and plumbing test; the
manifest real V-Programs pin comes after the init grows workload support.

## Component 1: typed model — `src/aleph/vm/vprogram/manifest.py`

Pydantic v2, `model_config = ConfigDict(extra="forbid")` on every class.

- `BundleMembers`: `ovmf`, `kernel`, `initrd`, `platform_rootfs`,
  `platform_hash_tree` — each a relative path inside the tarball. Validators:
  must be relative, must not contain `..`, must not be empty.
- `RuntimeBundle`: `ref` (pattern `^[0-9a-f]{64}$`), `sha256` (same pattern),
  `size` (`gt=0`), `members: BundleMembers`.
- `BootSpec`: `method: Literal["qemu-direct-kernel"]`,
  `kernel_hashes: Literal[True]`, `cpu_models: list[str]` (`min_length=1`),
  `platform_roothash` (64-hex pattern), `cmdline_template: str`. Template
  validator: parse placeholders with `string.Formatter().parse()`; every
  placeholder must be in the closed set
  `{"platform_roothash", "workload_roothash", "verified_volumes"}` (format
  version 1), `{platform_roothash}` must be present, and no positional/empty
  placeholders are allowed.
- `AttestationTransport`: `type: Literal["tcp"]`, `port: int` (`ge=1`,
  `le=65535`).
- `AttestationProtocol`: `protocol` (pattern
  `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$`, e.g. `aleph.ra-tls`),
  `version: str` (non-empty), `transport: AttestationTransport`.
- `WorkloadSpec`: `contract` (pattern
  `^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+/[0-9]+$`, e.g.
  `aleph.builtin/1`), `upstream_port: int` (`ge=1`, `le=65535`).
- `SourceInfo`: `repo: str` (non-empty), `rev: str` (non-empty),
  `build: str` (non-empty).
- `RuntimeManifest`: `format: Literal["aleph-vprogram-runtime"]`,
  `format_version: Literal[1]`, `name: str` (non-empty), `version: str`
  (non-empty), `platform: Literal["sev_snp"]`, `bundle: RuntimeBundle`,
  `boot: BootSpec`, `attestation: list[AttestationProtocol]`
  (`min_length=1`), `workload: WorkloadSpec`, `source: SourceInfo`.
  Method `to_canonical_json() -> str`: `model_dump_json` is NOT used;
  instead `json.dumps(self.model_dump(mode="json"), separators=(",", ":"),
  sort_keys=True)` so published bytes are reproducible.

## Component 2: build script — `scripts/vprogram_bundle.py`

Stdlib CLI (argparse), imports the model. Two subcommands:

### `build`

```
python scripts/vprogram_bundle.py build [--repo PATH] [--image-dir PATH] --out DIR
```

1. Unless `--image-dir` is given, run
   `nix build "git+file://$REPO?dir=nix#image" --extra-experimental-features
   "nix-command flakes" -o <out>/image-result` (the exact invocation CI and
   `snp-artifacts.sh` use) and use the resulting store dir.
2. Package the image dir as `<out>/snp-image.tar.gz` with entries under
   `image/…`. Deterministic: entries sorted by name, `uid=gid=0`,
   `uname=gname=""`, mtime pinned to the source commit timestamp
   (`git -C REPO log -1 --format=%ct`; falls back to `SOURCE_DATE_EPOCH`,
   required when `--image-dir` is used outside a git repo), `gzip` stream
   with `mtime=0`. Bundle content = the nix image output only (no
   `aleph-attest-cli`).
3. Write `<out>/bundle-info.json`: sha256 + size of the tarball, member
   role→path map, `platform_roothash` (read from `rootfs.ext4.roothash`),
   `measurement` (from `measurement.hex`, informational), source repo/rev.
4. Print the upload command:
   `aleph file upload <out>/snp-image.tar.gz`.

### `manifest`

```
python scripts/vprogram_bundle.py manifest --bundle-info PATH --bundle-ref HASH \
    --name NAME --runtime-version VERSION [--out PATH]
```

1. Load `bundle-info.json`; if the tarball is present next to it, re-hash and
   cross-check sha256/size (hard error on mismatch).
2. Construct `RuntimeManifest` through the model — validation IS the
   constructor. Fixed v1 values: `method=qemu-direct-kernel`,
   `kernel_hashes=true`, `cpu_models=["EPYC-v4"]`, cmdline template
   `console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}`,
   attestation `[aleph.ra-tls v1, tcp 8443]`, workload
   `aleph.builtin/1` upstream 8080. These defaults describe what the current
   image implements; overriding them is a format evolution, not a flag.
3. Write `manifest.json` via `to_canonical_json()`.
4. Print the upload command: `aleph file upload <out>/manifest.json`.

## Tests

`tests/vprogram/test_manifest.py` (model):
- The reference manifest above (real mainnet values) validates and
  round-trips through `to_canonical_json()` → `model_validate_json`.
- Rejections, one test each: bad `platform_roothash` (wrong length, uppercase),
  unknown cmdline placeholder (`{foo}`), template missing
  `{platform_roothash}`, positional `{}` placeholder, extra field at every
  nesting level (parametrized), `port=0` / `port=65536`, empty `attestation`,
  member path absolute (`/etc/passwd`) or traversing (`../x`),
  bad protocol identifier (`RA-TLS`, `aleph`), bad contract (`aleph.builtin`,
  no `/1`), `format_version=2`, `size=0`.

`tests/vprogram/test_bundle_script.py` (script, no nix, no network):
- Fake image dir (tiny files incl. `rootfs.ext4.roothash`,
  `measurement.hex`); `build --image-dir` twice (fixed `SOURCE_DATE_EPOCH`)
  → byte-identical tarballs, `bundle-info.json` sha256 matches a re-hash.
- `manifest` on that bundle-info + a dummy 64-hex ref → output parses as
  `RuntimeManifest`, fields match bundle-info; tampered `bundle-info.json`
  sha256 → hard error.

## Out of scope

- Uploads (manual; the script prints the commands).
- A manifest-vs-remote-bundle verifier (pyaleph phase 2 territory).
- `workload_roothash` / `verified_volumes` support in the image init
  (separate follow-up; the model already accepts those template slots so the
  next runtime needs no schema change).
- Publishing the reference manifest to mainnet (done manually with this tool
  once it lands).
