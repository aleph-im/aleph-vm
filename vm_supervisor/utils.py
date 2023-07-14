import asyncio
import dataclasses
import hashlib
import json
import logging
import subprocess
import threading
from base64 import b16encode, b32decode
from dataclasses import asdict as dataclass_as_dict
from dataclasses import is_dataclass
from typing import Any, Coroutine, Dict, List, Optional

import aiodns
import msgpack

logger = logging.getLogger(__name__)


class MsgpackSerializable:
    def __post_init__(self, *args, **kwargs):
        if not is_dataclass(self):
            raise TypeError(f"Decorated class must be a dataclass: {self}")
        super().__init_subclass__(*args, **kwargs)

    def as_msgpack(self) -> bytes:
        if is_dataclass(self):
            return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)  # type: ignore
        else:
            raise TypeError(f"Decorated class must be a dataclass: {self}")


def b32_to_b16(hash: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = hash.upper() + "=" * (56 - len(hash))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def get_ref_from_dns(domain):
    resolver = aiodns.DNSResolver()
    record = await resolver.query(domain, "TXT")
    return record[0].text


def to_json(o: Any):
    if hasattr(o, "to_dict"):  # default method
        return o.to_dict()
    elif hasattr(o, "dict"):  # Pydantic
        return o.dict()
    elif is_dataclass(o):
        return dataclass_as_dict(o)
    else:
        return str(o)


def dumps_for_json(o: Any, indent: Optional[int] = None):
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


async def run_in_subprocess(
    command: List[str], check: bool = True, stdin_input: Optional[bytes] = None
) -> bytes:
    """Run the specified command in a subprocess, returns the stdout of the process."""
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
        raise subprocess.CalledProcessError(
            process.returncode, str(command), stderr.decode()
        )

    return stdout


def fix_message_validation(message: Dict) -> Dict:
    """Patch a fake message program to pass validation."""
    message["item_content"] = json.dumps(message["content"])
    message["item_hash"] = hashlib.sha256(
        message["item_content"].encode("utf-8")
    ).hexdigest()
    return message


class HostNotFoundError(Exception):
    pass


async def ping(host: str, packets: int, timeout: float):
    """
    Waits for a host to respond to a ping request.
    """

    try:
        await run_in_subprocess(
            ["ping", "-c", str(packets), "-W", str(timeout), host], check=True
        )
    except subprocess.CalledProcessError as err:
        raise HostNotFoundError() from err


def wrap_async_function(function):
    asyncio.run(function)


def run_threaded_async_function(function):
    job_thread = threading.Thread(target=wrap_async_function, args=(function,))
    job_thread.start()
