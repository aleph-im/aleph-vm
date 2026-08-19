#!/usr/bin/env python3
"""Build V-Program runtime bundles from the Nix measured image and generate
the aleph-vprogram-runtime manifest.

Two steps around the manual upload (the manifest needs the bundle's STORE
item hash, which only exists after uploading):

  1. python scripts/vprogram_bundle.py build --out DIR [--image-dir PATH] [--flavor FLAVOR]
     -> DIR/snp-image.tar.gz + DIR/bundle-info.json; upload the tarball with
        the printed `aleph file upload` command and note the item hash.
  2. python scripts/vprogram_bundle.py manifest --bundle-info DIR/bundle-info.json \
         --bundle-ref ITEM_HASH --name NAME --runtime-version VERSION [--flavor FLAVOR] [--exec]
     -> DIR/manifest.json; upload it. Its STORE item hash is what V-PROGRAM
        messages pin as runtime.ref.

Design: docs/plans/2026-07-09-vprogram-runtime-bundle-design.md
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from aleph.vm.vprogram.bundle import (  # noqa: E402
    BUNDLE_NAME,
    MANIFEST_NAME,
    BundleInfo,
    InstanceBundleInfo,
    build_bundle,
    make_instance_manifest,
    make_manifest,
    verify_bundle_info,
)
from aleph.vm.vprogram.manifest import SourceInfo  # noqa: E402


def _build_command(flavor: str) -> str:
    """The `source.build` provenance recorded in the manifest: the exact nix
    target for this flavor, so an auditor rebuilds the same bundle (the
    instance flavor builds `nix#instanceImage` and the compose flavor
    `nix#composeImage`, not `nix#image`)."""
    return f'nix build "git+file://$REPO?dir=nix#{_nix_target(flavor)}"'


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],  # noqa: S603, S607
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def _source_epoch(repo: Path) -> int:
    from_env = os.environ.get("SOURCE_DATE_EPOCH")
    if from_env is not None:
        return int(from_env)
    return int(_git(repo, "log", "-1", "--format=%ct"))


def _nix_target(flavor: str) -> str:
    if flavor == "instance":
        return "instanceImage"
    if flavor == "compose":
        return "composeImage"
    return "image"


def cmd_build(args: argparse.Namespace) -> int:
    repo = args.repo.resolve()
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    if args.image_dir is not None:
        image_dir = args.image_dir.resolve()
    else:
        subprocess.run(
            [  # noqa: S603, S607
                "nix",
                "build",
                f"git+file://{repo}?dir=nix#{_nix_target(args.flavor)}",
                "--extra-experimental-features",
                "nix-command flakes",
                "-o",
                str(out / "image-result"),
            ],
            check=True,
        )
        image_dir = (out / "image-result").resolve()
    source = SourceInfo(
        repo="https://github.com/aleph-im/aleph-vm",
        rev=_git(repo, "rev-parse", "--short", "HEAD"),
        build=_build_command(args.flavor),
    )
    info = build_bundle(
        image_dir=image_dir, out_dir=out, source_epoch=_source_epoch(repo), source=source, flavor=args.flavor
    )
    print(f"bundle:   {out / BUNDLE_NAME}")  # noqa: T201
    print(f"sha256:   {info.sha256}")  # noqa: T201
    print(f"size:     {info.size}")  # noqa: T201
    if isinstance(info, BundleInfo):
        print(f"roothash: {info.platform_roothash}")  # noqa: T201
    print()  # noqa: T201
    print("Next: upload the bundle and note the STORE item hash it prints:")  # noqa: T201
    print(f"  aleph file upload {out / BUNDLE_NAME}")  # noqa: T201
    return 0


def cmd_manifest(args: argparse.Namespace) -> int:
    if args.flavor == "instance":
        info: BundleInfo | InstanceBundleInfo = InstanceBundleInfo.model_validate_json(args.bundle_info.read_text())
    else:
        info = BundleInfo.model_validate_json(args.bundle_info.read_text())
    tar_path = args.bundle_info.parent / BUNDLE_NAME
    if tar_path.is_file():
        verify_bundle_info(info, tar_path)
    else:
        print(f"note: {tar_path} not found, skipping bundle cross-check")  # noqa: T201
    if args.flavor == "instance":
        manifest = make_instance_manifest(
            info,
            bundle_ref=args.bundle_ref,
            name=args.name,
            version=args.runtime_version,
        )
    else:
        manifest = make_manifest(
            info=info,
            bundle_ref=args.bundle_ref,
            name=args.name,
            runtime_version=args.runtime_version,
            exec_runtime=args.exec_runtime,
            compose_runtime=args.flavor == "compose",
        )
    out: Path = args.out if args.out is not None else args.bundle_info.parent / MANIFEST_NAME
    out.write_text(manifest.to_canonical_json())
    print(f"manifest: {out}")  # noqa: T201
    print()  # noqa: T201
    print("Next: upload the manifest; its STORE item hash is what V-PROGRAM runtime.ref pins:")  # noqa: T201
    print(f"  aleph file upload {out}")  # noqa: T201
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_build = subparsers.add_parser("build", help="build the nix image and package the runtime bundle")
    p_build.add_argument("--repo", type=Path, default=REPO_ROOT, help="aleph-vm checkout (default: this one)")
    p_build.add_argument(
        "--image-dir",
        type=Path,
        default=None,
        help="package an existing nix image output instead of building",
    )
    p_build.add_argument("--out", type=Path, required=True, help="output directory")
    p_build.add_argument(
        "--flavor",
        choices=("vprogram", "instance", "compose"),
        default="vprogram",
        help="bundle flavor: vprogram (default, nix#image), instance (nix#instanceImage, "
        "no verity sidecars), or compose (nix#composeImage, same byte layout as vprogram)",
    )
    p_build.set_defaults(func=cmd_build)

    p_manifest = subparsers.add_parser("manifest", help="generate the runtime manifest for an uploaded bundle")
    p_manifest.add_argument("--bundle-info", type=Path, required=True, help="bundle-info.json from `build`")
    p_manifest.add_argument("--bundle-ref", required=True, help="item hash of the bundle STORE message")
    p_manifest.add_argument("--name", required=True, help="runtime name, e.g. aleph-snp-attest")
    p_manifest.add_argument("--runtime-version", required=True, help="runtime version string, e.g. 2026.07.08")
    p_manifest.add_argument("--out", type=Path, default=None, help="manifest path (default: next to bundle-info)")
    p_manifest.add_argument(
        "--flavor",
        choices=("vprogram", "instance", "compose"),
        default="vprogram",
        help="manifest flavor: vprogram (default, aleph-vprogram-runtime), "
        "instance (aleph-instance-runtime, luks cmdline template), or "
        "compose (aleph-vprogram-runtime with the aleph.compose/1 workload contract "
        "and the workload_roothash cmdline template)",
    )
    p_manifest.add_argument(
        "--exec",
        dest="exec_runtime",
        action="store_true",
        help="build the aleph.exec/1 workload-runtime manifest (workload_roothash in the "
        "cmdline template) instead of the builtin no-workload form; "
        "incompatible with --flavor instance/compose",
    )
    p_manifest.set_defaults(func=cmd_manifest)

    args = parser.parse_args(argv)
    # --exec builds the aleph.exec/1 workload-runtime manifest, which has no
    # meaning for an instance (LUKS) manifest and contradicts the compose
    # flavor's own contract; reject the combinations rather than silently
    # ignoring the flag.
    if getattr(args, "exec_runtime", False) and args.flavor != "vprogram":
        parser.error(f"--exec is incompatible with --flavor {args.flavor}")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
