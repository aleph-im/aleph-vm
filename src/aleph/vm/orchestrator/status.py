"""
Used to check that the example_fastapi program works as expected
in a deployed supervisor.
"""
import logging
from typing import Any

from aiohttp import ClientResponseError, ClientSession
from aiohttp.web_exceptions import HTTPBadGateway, HTTPInternalServerError, HTTPOk
from aleph_message.models import ItemHash

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)


def make_check_vm_url(vm_id: ItemHash) -> str:
    return f"http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}/vm/{vm_id}"


async def get_json_from_vm(session: ClientSession, vm_id: ItemHash, suffix: str) -> Any:
    vm_url = make_check_vm_url(vm_id)
    url = f"{vm_url}{suffix}"
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json()


async def check_index(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/")
        assert result["Example"] == "example_fastapi"
        return True
    except ClientResponseError:
        return False


async def check_lifespan(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/lifespan")
        return result["Lifespan"] is True
    except ClientResponseError:
        return False


async def check_environ(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/environ")
        assert "ALEPH_API_HOST" in result
        assert "ALEPH_API_UNIX_SOCKET" in result
        assert "ALEPH_REMOTE_CRYPTO_HOST" in result
        assert "ALEPH_REMOTE_CRYPTO_UNIX_SOCKET" in result
        assert "ALEPH_ADDRESS_TO_USE" in result
        return True
    except ClientResponseError:
        return False


async def check_messages(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/messages")
        assert "Messages" in result
        assert "messages" in result["Messages"]
        assert "item_hash" in result["Messages"]["messages"][0]
        return True
    except ClientResponseError:
        return False


async def check_dns(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/dns")
        assert result["ipv4"]
        assert result["ipv6"]
        return True
    except ClientResponseError:
        return False


async def check_ipv4(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/ip/4")
        assert result["result"] is True
        return True
    except ClientResponseError:
        return False


async def check_ipv6(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/ip/6")
        assert result["result"] is True
        assert "headers" in result
        return True
    except ClientResponseError:
        return False


async def check_internet(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/internet")
        assert result["result"] == HTTPOk.status_code
        assert "Server" in result["headers"]
        return True
    except ClientResponseError:
        return False


async def check_cache(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result1: bool = await get_json_from_vm(session, vm_id, "/cache/set/a/42")
        assert result1 is True
        result2: int = await get_json_from_vm(session, vm_id, "/cache/get/a")
        assert result2 == "42"
        keys: list[str] = await get_json_from_vm(session, vm_id, "/cache/keys")
        assert "a" in keys
        return True
    except ClientResponseError:
        return False


async def check_persistent_storage(session: ClientSession, vm_id: ItemHash) -> bool:
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/state/increment")
        counter = result["counter"]
        result_2: dict = await get_json_from_vm(session, vm_id, "/state/increment")
        counter_2 = result_2["counter"]
        # Use >= to handle potential concurrency
        assert counter_2 >= counter + 1
        return True
    except ClientResponseError:
        return False


async def check_error_raised(session: ClientSession, vm_id: ItemHash) -> bool:
    vm_url = make_check_vm_url(vm_id)
    try:
        async with session.get(f"{vm_url}/raise") as resp:
            text = await resp.text()
            return resp.status == HTTPInternalServerError.status_code and "Traceback" in text
    except ClientResponseError:
        return False


async def check_crash_and_restart(session: ClientSession, vm_id: ItemHash) -> bool:
    # Crash the VM init.
    vm_url = make_check_vm_url(vm_id)
    async with session.get(f"{vm_url}/crash") as resp:
        if resp.status != HTTPBadGateway.status_code:
            return False

    # Try loading the index page. A new execution should be created.
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/")
        assert result["Example"] == "example_fastapi"
        return True

    except ClientResponseError:
        return False
