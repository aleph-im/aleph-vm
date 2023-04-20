"""
Used to check that the example_fastapi program works as expected
in a deployed supervisor.
"""
import logging
from typing import Any, Dict, List

from aiohttp import ClientResponseError, ClientSession

from .conf import settings

logger = logging.getLogger(__name__)

CHECK_VM_URL = f"http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}/vm/{settings.CHECK_FASTAPI_VM_ID}"


async def get_json_from_vm(session: ClientSession, suffix: str) -> Any:
    url = f"{CHECK_VM_URL}{suffix}"
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json()


async def check_index(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/")
        assert result["Example"] == "example_fastapi"
        return True
    except ClientResponseError:
        return False


async def check_lifespan(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/lifespan")
        return result["Lifetime"] is True
    except ClientResponseError:
        return False


async def check_environ(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/environ")
        assert "ALEPH_API_HOST" in result
        assert "ALEPH_API_UNIX_SOCKET" in result
        assert "ALEPH_REMOTE_CRYPTO_HOST" in result
        assert "ALEPH_REMOTE_CRYPTO_UNIX_SOCKET" in result
        assert "ALEPH_ADDRESS_TO_USE" in result
        return True
    except ClientResponseError:
        return False


async def check_messages(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/messages")
        assert "Messages" in result
        assert "messages" in result["Messages"]
        assert "item_hash" in result["Messages"]["messages"][0]
        return True
    except ClientResponseError:
        return False


async def check_dns(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/dns")
        assert result["ipv4"]
        assert result["ipv6"]
        return True
    except ClientResponseError:
        return False


async def check_ipv4(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/ip/4")
        assert result["result"] is True
        assert "headers" in result
        return True
    except ClientResponseError:
        return False


async def check_ipv6(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/ip/6")
        assert result["result"] is True
        assert "headers" in result
        return True
    except ClientResponseError:
        return False


async def check_internet(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/internet")
        assert result["result"] == 200
        assert "Server" in result["headers"]
        return True
    except ClientResponseError:
        return False


async def check_cache(session: ClientSession) -> bool:
    try:
        result1: bool = await get_json_from_vm(session, "/cache/set/a/42")
        assert result1 is True
        result2: int = await get_json_from_vm(session, "/cache/get/a")
        assert result2 == "42"
        keys: List[str] = await get_json_from_vm(session, "/cache/keys")
        print("KEYS", keys)
        assert "a" in keys
        return True
    except ClientResponseError:
        return False


async def check_persistent_storage(session: ClientSession) -> bool:
    try:
        result: Dict = await get_json_from_vm(session, "/state/increment")
        counter = result["counter"]
        result_2: Dict = await get_json_from_vm(session, "/state/increment")
        counter_2 = result_2["counter"]
        # Use >= to handle potential concurrency
        assert counter_2 >= counter + 1
        return True
    except ClientResponseError:
        return False


async def check_error_raised(session: ClientSession) -> bool:
    try:
        async with session.get(f"{CHECK_VM_URL}/raise") as resp:
            text = await resp.text()
            return resp.status == 500 and "Traceback" in text
    except ClientResponseError:
        return False


async def check_crash_and_restart(session: ClientSession) -> bool:
    # Crash the VM init.
    async with session.get(f"{CHECK_VM_URL}/crash") as resp:
        if resp.status != 502:
            return False

    # Try loading the index page. A new execution should be created.
    try:
        result: Dict = await get_json_from_vm(session, "/")
        assert result["Example"] == "example_fastapi"
        return True

    except ClientResponseError:
        return False
