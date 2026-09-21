"""The confidential-instance init (nix/init-instance.sh) validates the untrusted
host-supplied LUKS2 header before unlocking the rootfs: every "encryption" field
must be aes-xts-plain64 and there must be at least one crypt data segment,
otherwise it powers off (Trail of Bits 2025-10-30, the data-segment null-cipher
downgrade). This pins the header backup, that grep pipeline and the detached
`luksOpen --header` so a future edit that weakens any of them fails here.

The test does not re-implement the check: it lifts the real shell fragments out
of nix/init-instance.sh, so if they drift the assertions move with them. The
only rewrites are the initrd-absolute paths (/bin/busybox, /bin/cryptsetup), the
poweroff (turned into a non-zero exit so the verdict is observable) and, for the
open, --test-passphrase (mapping the volume needs root), all
substring-substitutions that leave the decision logic byte-for-byte.

The tamper + checksum-recompute mirrors the loopback PoC the fix was reproduced
with: patch segments.0.encryption (data-segment variant) or
keyslots.0.area.encryption (CVE-2025-59054 keyslot variant) to cipher_null-ecb,
then recompute the LUKS2 binary-header SHA256 checksum so cryptsetup accepts the
forged header as genuine -- exactly what a malicious host does.

Runs rootless (cryptsetup operates on a plain image file, no loop device) and is
skipped where cryptsetup is not installed.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
INIT_SCRIPT = REPO_ROOT / "nix" / "init-instance.sh"

CRYPTSETUP = shutil.which("cryptsetup") or "cryptsetup"
SH = shutil.which("sh") or "/bin/sh"
PASSPHRASE = b"correct horse battery staple"

# LUKS2 binary-header layout (see cryptsetup docs / the PoC): each metadata area
# is 16384 bytes = a 4096-byte binary header followed by 12288 bytes of JSON. The
# on-disk checksum is a SHA256 over the whole area with its own 64-byte csum field
# zeroed, stored at offset 448. There are two areas: primary at 0, secondary at
# one AREA in.
HDR_BIN = 4096
CSUM_OFF = 448
CSUM_LEN = 64
AREA = 16384

pytestmark = pytest.mark.skipif(
    shutil.which("cryptsetup") is None,
    reason="needs the cryptsetup binary (rootless, operates on an image file)",
)


def _initrd_to_host(fragment: str) -> str:
    """The initrd hard-codes absolute paths and powers off on refusal; rewrite
    both (substring substitution only) so a fragment runs on the test host with
    its decision logic byte-for-byte. A refusal becomes exit 1."""
    fragment = fragment.replace("exec /bin/busybox poweroff -f", "exit 1")
    fragment = fragment.replace("/bin/busybox ", "")
    return fragment.replace("/bin/cryptsetup", CRYPTSETUP)


def _extract_validation_fragment() -> str:
    """Lift the header backup + validation from nix/init-instance.sh, from the
    luksHeaderBackup copy through the "validated" line: verdict is the exit code
    (0 accept, 1 refuse). $1 is the device, $2 the RAM-copy path."""
    lines = INIT_SCRIPT.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("luks_header="))
    end = next(i for i, line in enumerate(lines) if 'echo "init: LUKS header validated' in line)
    fragment = _initrd_to_host("\n".join(lines[start + 1 : end + 1]))
    assert "luksHeaderBackup" in fragment, "extraction missed the header backup"
    assert "grep" in fragment and 'aes-xts-plain64"' in fragment, "extraction missed the check"
    return 'blkdev="$1"\nluks_header="$2"\n' + fragment + "\n"


def _extract_open_command() -> str:
    """Lift the real `luksOpen --header` line. It needs device-mapper (root) to
    map the volume, so --test-passphrase is added: cryptsetup then runs the same
    header + keyslot path and stops before creating the mapping."""
    line = next(
        line.strip()
        for line in INIT_SCRIPT.read_text().splitlines()
        if "cryptsetup luksOpen" in line and "--header" in line
    )
    command = line.removeprefix("if ").split(";")[0]
    command = command.replace("luksOpen", "luksOpen --test-passphrase", 1)
    command = command.replace("/tmp/secrets/luks_passphrase", '"$3"')
    return 'blkdev="$1"\nluks_header="$2"\n' + _initrd_to_host(command) + "\n"


def _run_validation(image: Path) -> bool:
    """Run the real backup + validation against `image`. True == ACCEPT."""
    header_copy = image.with_suffix(".header")
    result = subprocess.run(  # noqa: S603
        [SH, "-c", _extract_validation_fragment(), "sh", str(image), str(header_copy)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode in (0, 1), f"fragment errored: {result.returncode}\n{result.stderr}\n{result.stdout}"
    if result.returncode == 0:
        assert header_copy.is_file(), "accepted without taking the RAM header copy"
    return result.returncode == 0


def _luks_format(image: Path) -> None:
    image.write_bytes(b"\x00" * (32 * 1024 * 1024))
    argv = [
        "luksFormat",
        "--type",
        "luks2",
        "--cipher",
        "aes-xts-plain64",
        "--pbkdf",
        "pbkdf2",
        "--pbkdf-force-iterations",
        "1000",
        "--batch-mode",
        str(image),
        "-",
    ]
    subprocess.run(  # noqa: S603
        [CRYPTSETUP, *argv],
        input=PASSPHRASE,
        check=True,
        capture_output=True,
    )


def _read_area(buf: bytearray, base: int) -> tuple[dict, bytearray]:
    area = bytearray(buf[base : base + AREA])
    json_area = bytes(area[HDR_BIN:])
    end = json_area.find(b"\x00")
    return json.loads(json_area[: end if end >= 0 else len(json_area)]), area


def _recompute_csum(area: bytearray) -> bytes:
    tmp = bytearray(area)
    tmp[CSUM_OFF : CSUM_OFF + CSUM_LEN] = b"\x00" * CSUM_LEN
    return hashlib.sha256(bytes(tmp)).digest()


def _flip_cipher(image: Path, where: str) -> None:
    """Forge a malicious shape in both metadata areas and fix the checksum, so
    the header passes cryptsetup's own integrity check.

    where="segment": segments.0.encryption (Trail of Bits data-segment variant).
    where="keyslot": keyslots.0.area.encryption (CVE-2025-59054 keyslot variant).
    where="linear": segments.0.type -> "linear" (plaintext-region shape).
    """
    buf = bytearray(image.read_bytes())
    for base in (0, AREA):
        meta, area = _read_area(buf, base)
        if where == "segment":
            meta["segments"]["0"]["encryption"] = "cipher_null-ecb"
        elif where == "linear":
            meta["segments"]["0"]["type"] = "linear"
        else:
            meta["keyslots"]["0"]["area"]["encryption"] = "cipher_null-ecb"
        new_json = json.dumps(meta, separators=(",", ":")).encode()
        json_space = AREA - HDR_BIN
        assert len(new_json) + 1 <= json_space, "forged json overflows the area"
        newarea = bytearray(area[:HDR_BIN]) + bytearray(json_space)
        newarea[HDR_BIN : HDR_BIN + len(new_json)] = new_json
        csum = _recompute_csum(newarea)
        newarea[CSUM_OFF : CSUM_OFF + CSUM_LEN] = csum + b"\x00" * (CSUM_LEN - len(csum))
        buf[base : base + AREA] = newarea
    image.write_bytes(buf)


def _assert_cryptsetup_accepts_forgery(image: Path) -> None:
    """The forged header must parse cleanly in cryptsetup itself and carry the
    null cipher, so a refusal below comes from the init's check and not from a
    header cryptsetup would have rejected anyway (e.g. after a layout change
    that left our recomputed checksum wrong)."""
    result = subprocess.run(  # noqa: S603
        [CRYPTSETUP, "luksDump", "--dump-json-metadata", str(image)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"cryptsetup rejected the forged header:\n{result.stderr}"
    assert "cipher_null-ecb" in result.stdout, "forgery did not land in the parsed header"


def test_genuine_header_is_accepted(tmp_path):
    image = tmp_path / "genuine.img"
    _luks_format(image)
    assert _run_validation(image) is True


def test_data_segment_null_downgrade_is_refused(tmp_path):
    image = tmp_path / "data-null.img"
    _luks_format(image)
    _flip_cipher(image, "segment")
    _assert_cryptsetup_accepts_forgery(image)
    # The attack, not a corrupt disk: the genuine passphrase still unlocks the
    # forged header, because the digest does not bind the data-segment cipher.
    # (Only the segment variant: cryptsetup >= 2.8.1 refuses the keyslot one.)
    # This asserts the VULNERABILITY, so it doubles as a canary for the fix
    # landing upstream: if cryptsetup someday rejects data-segment null ciphers
    # the way >= 2.8.1 rejects the keyslot variant, this assert fails while the
    # init's behavior is still correct -- in that world the check in the init
    # can be relaxed, it is not a regression of ours.
    unlock = subprocess.run(  # noqa: S603
        [CRYPTSETUP, "luksOpen", "--test-passphrase", "--key-file", "-", str(image)],
        input=PASSPHRASE,
        capture_output=True,
        check=False,
    )
    assert unlock.returncode == 0, f"forgery is not unlockable:\n{unlock.stderr!r}"
    assert _run_validation(image) is False


def test_keyslot_null_downgrade_is_refused(tmp_path):
    image = tmp_path / "keyslot-null.img"
    _luks_format(image)
    _flip_cipher(image, "keyslot")
    _assert_cryptsetup_accepts_forgery(image)
    assert _run_validation(image) is False


def test_linear_segment_is_refused(tmp_path):
    """A linear segment is a plaintext region, so a header carrying one is
    refused no matter what else it says. Which layer refuses it is
    cryptsetup's choice: today's cryptsetup happens to reject hand-forged
    linear segments itself, but the init's seg_linear check must keep
    refusing the shape even if a future cryptsetup starts accepting it
    (e.g. as a mid-reencryption form), so the refusal is asserted either
    way."""
    image = tmp_path / "linear-segment.img"
    _luks_format(image)
    _flip_cipher(image, "linear")
    assert _run_validation(image) is False


def test_unreadable_header_is_refused(tmp_path):
    image = tmp_path / "blank.img"
    image.write_bytes(b"\x00" * (32 * 1024 * 1024))
    assert _run_validation(image) is False


def test_open_uses_the_validated_header_copy(tmp_path):
    """The init opens with --header <RAM copy>, so a header swapped on disk
    after validation is never read: the genuine passphrase still opens through
    the copy even once the on-disk header is destroyed."""
    image = tmp_path / "genuine.img"
    _luks_format(image)
    assert _run_validation(image) is True
    header_copy = image.with_suffix(".header")
    passphrase = tmp_path / "passphrase"
    passphrase.write_bytes(PASSPHRASE)

    with image.open("r+b") as disk:
        disk.write(b"\x00" * (2 * AREA))

    result = subprocess.run(  # noqa: S603
        [SH, "-c", _extract_open_command(), "sh", str(image), str(header_copy), str(passphrase)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"open through the header copy failed:\n{result.stderr}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
