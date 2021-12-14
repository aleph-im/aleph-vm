"""
Used to check that the example_fastapi program works as expected
in a deployed supervisor.
"""

from typing import Dict, Any, List

from aiohttp import ClientSession

from vm_supervisor.conf import settings

CHECK_VM_URL = f"http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}/vm/{settings.CHECK_FASTAPI_VM_ID}"


async def get_json_from_vm(session: ClientSession, suffix: str) -> Any:
    url = f"{CHECK_VM_URL}{suffix}"
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json()


async def check_index(session: ClientSession) -> bool:
    result: Dict = await get_json_from_vm(session, "/")
    assert result["Example"] == "example_fastapi"
    return True


async def check_environ(session: ClientSession) -> bool:
    result: Dict = await get_json_from_vm(session, "/environ")
    assert "ALEPH_API_HOST" in result
    assert "ALEPH_API_UNIX_SOCKET" in result
    assert "ALEPH_REMOTE_CRYPTO_HOST" in result
    assert "ALEPH_REMOTE_CRYPTO_UNIX_SOCKET" in result
    assert "ALEPH_ADDRESS_TO_USE" in result
    return True


async def check_messages(session: ClientSession) -> bool:
    result: Dict = await get_json_from_vm(session, "/messages")
    assert "Messages" in result
    assert "messages" in result["Messages"]
    assert "item_hash" in result["Messages"]["messages"][0]
    return True


async def check_internet(session: ClientSession) -> bool:
    result: Dict = await get_json_from_vm(session, "/internet")
    assert result["result"] == 200
    assert "Server" in result["headers"]
    return True


async def check_cache(session: ClientSession) -> bool:
    result1: bool = await get_json_from_vm(session, "/cache/set/a/42")
    assert result1 == True
    result2: int = await get_json_from_vm(session, "/cache/get/a")
    assert result2 == "42"
    keys: List[str] = await get_json_from_vm(session, "/cache/keys")
    print("KEYS", keys)
    assert "a" in keys
    return True


async def check_persistent_storage(session: ClientSession) -> bool:
    result: Dict = await get_json_from_vm(session, "/state/increment")
    counter = result["counter"]
    result_2: Dict = await get_json_from_vm(session, "/state/increment")
    counter_2 = result_2["counter"]
    assert counter_2 == counter + 1
    return True
