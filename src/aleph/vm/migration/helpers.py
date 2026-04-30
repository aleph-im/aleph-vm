"""qemu-img and aiohttp helpers used by the migration runners."""

import asyncio
import hashlib
import logging
import shutil
import time
from pathlib import Path

import aiohttp

from aleph.vm.models import VmExecution

logger = logging.getLogger(__name__)

GRACEFUL_SHUTDOWN_TIMEOUT = 30


async def graceful_shutdown(execution: VmExecution, timeout: int = GRACEFUL_SHUTDOWN_TIMEOUT) -> None:
    """Gracefully shut down a QEMU VM via QMP system_powerdown, with fallback to systemd stop."""
    from aleph.vm.controllers.qemu.client import QemuVmClient

    vm = execution.vm
    if not vm:
        msg = "VM not initialized"
        raise RuntimeError(msg)

    try:
        client = QemuVmClient(vm)
        client.system_powerdown()
        client.close()
    except Exception as e:
        logger.warning("Failed to send system_powerdown for %s: %s", execution.vm_hash, e)

    start = time.monotonic()
    while time.monotonic() - start < timeout:
        if execution.systemd_manager and not execution.systemd_manager.is_service_active(execution.controller_service):
            logger.info("VM %s shut down gracefully", execution.vm_hash)
            return
        await asyncio.sleep(1)

    logger.warning("VM %s did not shut down within %ds, forcing stop", execution.vm_hash, timeout)
    if execution.systemd_manager:
        execution.systemd_manager.stop_and_disable(execution.controller_service)


async def compress_disk(source_path: Path, dest_path: Path) -> None:
    """Compress a QCOW2 disk using qemu-img convert."""
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "convert",
        "-c",
        "-O",
        "qcow2",
        str(source_path),
        str(dest_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img convert failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def rebase_overlay(overlay_path: Path, parent_path: Path, parent_format: str) -> None:
    """Rebase a QCOW2 overlay to point to a local backing file."""
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "rebase",
        "-u",
        "-b",
        str(parent_path),
        "-F",
        parent_format,
        str(overlay_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img rebase failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def detect_parent_format(parent_path: Path) -> str:
    """Detect the format of a parent image using qemu-img info."""
    import json as _json

    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "info",
        str(parent_path),
        "--output=json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img info failed: {stderr.decode()}"
        raise RuntimeError(msg)

    info = _json.loads(stdout)
    fmt = info.get("format")
    if not fmt:
        msg = f"Could not detect format for {parent_path}"
        raise RuntimeError(msg)
    return fmt


async def download_disk_from_source(
    session: aiohttp.ClientSession,
    url: str,
    dest_path: Path,
    token: str,
    *,
    expected_sha256: str,
    on_chunk=None,
) -> int:
    """Download a disk file from the source CRN and verify its SHA-256.

    The hash is computed while streaming (no extra read pass). If verification
    fails the partial file is unlinked and RuntimeError is raised, so callers
    never observe a corrupt file at dest_path.

    on_chunk: optional callback(bytes_downloaded_so_far) for progress reporting.
    """
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")
    part_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = 0
    hasher = hashlib.sha256()

    async with session.get(url, params={"token": token}) as resp:
        if resp.status != 200:
            body = await resp.text()
            msg = f"Failed to download {url}: HTTP {resp.status} - {body}"
            raise RuntimeError(msg)
        with open(part_path, "wb") as f:
            async for chunk in resp.content.iter_chunked(1024 * 1024):
                f.write(chunk)
                hasher.update(chunk)
                total_bytes += len(chunk)
                if on_chunk is not None:
                    on_chunk(total_bytes)

    actual_sha256 = hasher.hexdigest()
    if actual_sha256 != expected_sha256:
        part_path.unlink(missing_ok=True)
        msg = f"sha256 mismatch for {url}: expected {expected_sha256}, got {actual_sha256}"
        raise RuntimeError(msg)

    part_path.rename(dest_path)
    return total_bytes


async def compute_sha256(path: Path) -> str:
    """Stream-hash a file with SHA-256, off the event loop."""

    def _hash() -> str:
        hasher = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                hasher.update(chunk)
        return hasher.hexdigest()

    return await asyncio.get_running_loop().run_in_executor(None, _hash)
