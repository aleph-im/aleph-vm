import asyncio
import dataclasses
import functools
import hashlib
import json
import logging
import subprocess
from base64 import b16encode, b32decode
from collections.abc import Callable, Coroutine
from dataclasses import asdict as dataclass_as_dict
from dataclasses import is_dataclass
from pathlib import Path
from shutil import disk_usage
from typing import Any, Optional

import aiodns
import msgpack
from aiohttp_cors import ResourceOptions, custom_cors
from aleph_message.models import ExecutableContent, InstanceContent, ProgramContent
from eth_typing import HexAddress, HexStr
from eth_utils import hexstr_if_str, is_address, to_hex

logger = logging.getLogger(__name__)


def get_message_executable_content(message_dict: dict) -> ExecutableContent:
    try:
        return ProgramContent.model_validate(message_dict)
    except ValueError:
        return InstanceContent.model_validate(message_dict)


def cors_allow_all(function):
    default_config = {
        "*": ResourceOptions(
            allow_credentials=True,
            allow_headers="*",
            expose_headers="*",
        )
    }
    return custom_cors(config=default_config)(function)


class MsgpackSerializable:
    def __post_init__(self, *args, **kwargs):
        if not is_dataclass(self):
            msg = f"Decorated class must be a dataclass: {self}"
            raise TypeError(msg)
        super().__init_subclass__(*args, **kwargs)

    def as_msgpack(self) -> bytes:
        if is_dataclass(self):
            return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)  # type: ignore
        else:
            msg = f"Decorated class must be a dataclass: {self}"
            raise TypeError(msg)


def b32_to_b16(string: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = string.upper() + "=" * (56 - len(string))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def get_ref_from_dns(domain):
    resolver = aiodns.DNSResolver()
    record = await resolver.query(domain, "TXT")
    return record[0].text


def to_json(o: Any) -> dict | str:
    if hasattr(o, "to_dict"):  # default method
        return o.to_dict()
    elif hasattr(o, "dict"):  # Pydantic
        return o.dict()
    elif is_dataclass(o):
        return dataclass_as_dict(o)  # type: ignore
    else:
        return str(o)


def dumps_for_json(o: Any, indent: int | None = None):
    return json.dumps(o, default=to_json, indent=indent)


async def run_and_log_exception(coro: Coroutine):
    """Exceptions in coroutines may go unnoticed if they are not handled."""
    try:
        return await coro
    except Exception as error:
        logger.exception(error)
        raise


def create_task_log_exceptions(coro: Coroutine, *, name=None):
    """Ensure that exceptions running in coroutines are logged."""
    return asyncio.create_task(run_and_log_exception(coro), name=name)


async def run_in_subprocess(command: list[str], check: bool = True, stdin_input: bytes | None = None) -> bytes:
    """Run the specified command in a subprocess, returns the stdout of the process."""
    command = [str(arg) for arg in command]
    logger.debug(f"command: {' '.join(command)}")

    process = await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate(input=stdin_input)

    if check and process.returncode:
        logger.error(
            f"Command failed with error code {process.returncode}:\n"
            f"    stdin = {stdin_input!r}\n"
            f"    command = {command}\n"
            f"    stdout = {stderr!r}"
        )
        raise subprocess.CalledProcessError(process.returncode, str(command), stderr.decode())

    return stdout


def is_command_available(command):
    try:
        subprocess.check_output(["which", command], stderr=subprocess.STDOUT)
        return True
    except subprocess.CalledProcessError:
        return False


def check_system_module(module_path: str) -> str | None:
    p = Path("/sys/module") / module_path
    if not p.exists():
        return None
    return p.read_text().strip()


def check_amd_sev_supported() -> bool:
    """Check if AMD SEV is supported on the system.

    AMD Secure Encrypted Virtualization (SEV)
    Uses one key per virtual machine to isolate guests and the hypervisor from one another.
    """
    return (check_system_module("kvm_amd/parameters/sev") == "Y") and Path("/dev/sev").exists()


def check_amd_sev_es_supported() -> bool:
    """Check if AMD SEV-ES is supported on the system.

    AMD Secure Encrypted Virtualization-Encrypted State (SEV-ES)
    Encrypts all CPU register contents when a VM stops running.
    """
    return (check_system_module("kvm_amd/parameters/sev_es") == "Y") and Path("/dev/sev").exists()


def check_amd_sev_snp_supported() -> bool:
    """Check if AMD SEV-SNP is supported on the system.

    AMD Secure Encrypted Virtualization-Secure Nested Paging (SEV-SNP)
    Adds strong memory integrity protection to help prevent malicious hypervisor-based attacks like data replay,
    memory re-mapping, and more in order to create an isolated execution environment.
    """
    return check_system_module("kvm_amd/parameters/sev_snp") == "Y"


def fix_message_validation(message: dict) -> dict:
    """Patch a fake message program to pass validation."""
    message["item_content"] = json.dumps(message["content"])
    message["item_hash"] = hashlib.sha256(message["item_content"].encode("utf-8")).hexdigest()
    return message


class HostNotFoundError(Exception):
    pass


async def is_pinging(host: str, packets: int, timeout: int) -> bool:
    """
    Try to ping an ip, return true if host respond, fale otherwise
    """

    try:
        await run_in_subprocess(["ping", "-c", str(packets), "-W", str(timeout), host], check=True)
        return True
    except subprocess.CalledProcessError as err:
        return False


def check_disk_space(bytes_to_use: int) -> bool:
    host_disk_usage = disk_usage("/")
    return host_disk_usage.free >= bytes_to_use


class NotEnoughDiskSpaceError(OSError):
    pass


async def get_path_size(path: Path) -> int:
    """Get the size in bytes of a given path."""
    if path.is_dir():
        return sum([f.stat().st_size for f in path.glob("**/*")])
    elif path.is_block_device():
        return await get_block_device_size(str(path))
    elif path.is_file():
        return path.stat().st_size
    else:
        msg = f"Unknown path type for {path}"
        raise ValueError(msg)


async def get_block_device_size(device: str) -> int:
    """Get the size in bytes of a given device block."""
    output = await run_in_subprocess(
        ["lsblk", device, "--output", "SIZE", "--bytes", "--noheadings", "--nodeps"],
        check=True,
    )
    size = int(output.strip().decode())
    return size


def to_normalized_address(value: str) -> HexAddress:
    """
    Converts an address to its normalized hexadecimal representation.
    """
    try:
        hex_address = hexstr_if_str(to_hex, value).lower()
    except AttributeError:
        msg = f"Value must be any string, instead got type {type(value)}"
        raise TypeError(msg)
    if is_address(hex_address):
        return HexAddress(HexStr(hex_address))
    else:
        msg = f"Unknown format {value}, attempted to normalize to {hex_address}"
        raise ValueError(msg)


def md5sum(file_path: Path) -> str:
    """Calculate the MD5 hash of a file. Externalize to the `md5sum` command for better performance."""
    return subprocess.check_output(["md5sum", file_path], text=True).split()[0]


def file_hashes_differ(source: Path, destination: Path, checksum: Callable[[Path], str] = md5sum) -> bool:
    """Check if the MD5 hash of two files differ."""
    if not source.exists():
        msg = f"Source file does not exist: {source}"
        raise FileNotFoundError(msg)

    if not destination.exists():
        return True

    return checksum(source) != checksum(destination)


def async_cache(fn):
    """Simple async function cache decorator."""
    cache = {}

    @functools.wraps(fn)
    async def wrapper(*args, **kwargs):
        key = (args, frozenset(kwargs.items()))
        if key not in cache:
            cache[key] = await fn(*args, **kwargs)
        return cache[key]

    return wrapper
