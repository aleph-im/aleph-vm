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


def assemble_vm_url(vm_id: ItemHash) -> str:
    """Assemble the URL for a VM based on the host and port that the orchestrator is running on and the VM ID."""
    return f"http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}/vm/{vm_id}"


async def get_json_from_vm(session: ClientSession, vm_id: ItemHash, suffix: str) -> Any:
    """Get JSON from a VM running locally."""
    vm_url = assemble_vm_url(vm_id)
    url = f"{vm_url}{suffix}"
    async with session.get(url) as resp:
        resp.raise_for_status()
        return await resp.json()


async def post_to_vm(session: ClientSession, vm_id: ItemHash, suffix: str, data: Any = None) -> Any:
    """Post data to a VM running locally."""
    vm_url = assemble_vm_url(vm_id)
    url = f"{vm_url}{suffix}"
    async with session.post(url, json=data) as resp:
        resp.raise_for_status()
        return await resp.json()


async def check_index(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the index page of the VM is working."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/")
        assert result["Example"] == "example_fastapi"
        return True
    except ClientResponseError:
        return False


async def check_lifespan(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the lifespan endpoint of the VM is working."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/lifespan")
        return result["Lifespan"] is True
    except ClientResponseError:
        return False


async def check_environ(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the environ endpoint of the VM returns the expected environment variables."""
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
    """Check that the messages endpoint of the VM returns a list of messages."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/messages")
        assert "Messages" in result
        assert "messages" in result["Messages"]
        assert "item_hash" in result["Messages"]["messages"][0]
        return True
    except ClientResponseError:
        return False


async def check_dns(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the DNS endpoint of the VM returns both IPv4 and IPv6 results."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/dns")
        assert result["ipv4"]
        assert result["ipv6"]
        return True
    except ClientResponseError:
        return False


async def check_ipv4(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM has IPv4 connectivity."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/ip/4")
        assert result["result"] is True
        return True
    except ClientResponseError:
        return False


async def check_ipv6(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM has IPv6 connectivity."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/ip/6")
        assert result["result"] is True
        assert "headers" in result
        return True
    except ClientResponseError:
        return False


async def check_internet(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM has internet connectivity. This requires DNS, IP, HTTP and TLS to work."""
    try:
        response: dict = await get_json_from_vm(session, vm_id, "/internet")

        if "headers" not in response:
            logger.error("The server cannot connect to Internet")
            return False

        # The HTTP Header "Server" must always be present in the result.
        if "Server" not in response["headers"]:
            raise ValueError("Server header not found in the result.")

        # The diagnostic VM returns HTTP 200 with {"result": False} when cannot connect to the internet.
        # else it forwards the return code if its own test endpoint.
        return response.get("result") == HTTPOk.status_code
    except ClientResponseError:
        return False


async def check_cache(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM can set and get a value in its cache."""
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
    """Check that the VM can set and get a value in its persistent storage."""
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
    """Check that the VM can raise an error and return a traceback instead of crashing."""
    vm_url = assemble_vm_url(vm_id)
    try:
        async with session.get(f"{vm_url}/raise") as resp:
            text = await resp.text()
            return resp.status == HTTPInternalServerError.status_code and "Traceback" in text
    except ClientResponseError:
        return False


async def check_crash_and_restart(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that a crash in the VM would cause it to restart and work as expected."""
    # Crash the VM init.
    vm_url = assemble_vm_url(vm_id)
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


async def check_get_a_message(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM can get a message from the aleph.im network."""
    try:
        result: dict = await get_json_from_vm(session, vm_id, "/get_a_message")
        return "item_hash" in result
    except ClientResponseError:
        return False


async def check_post_a_message(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM can post a message to the aleph.im network using a remote key present on the host."""
    try:
        result: dict = await post_to_vm(session, vm_id, "/post_a_message")
        return "item_hash" in result
    except ClientResponseError:
        return False


async def check_sign_a_message(session: ClientSession, vm_id: ItemHash) -> bool:
    """Check that the VM can sign a message using a key local to the VM."""
    try:
        result: dict = await post_to_vm(session, vm_id, "/sign_a_message")
        return "item_hash" in result
    except ClientResponseError:
        return False
