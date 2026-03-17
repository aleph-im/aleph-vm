#!/usr/bin/env python3
"""
Instance domain support.
aka HAProxy Dynamic Configuration Updater

HAProxy is a proxy server used to redirect the HTTP, HTTPS and SSL traffic
to the instances if they have it configured.

This module gets the instance domain-to-IP mapping from the aleph DNS API
and writes it to HAProxy map files. HAProxy uses set-dst with a placeholder
server to route traffic — no dynamic server management via socket is needed.

Map file format: domain_name vm_ip_address

For the control protocol and commands used, refer to
https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/management/
"""

import logging
import socket
from pathlib import Path

import aiohttp

from aleph.vm.conf import settings

# This should match the config in haproxy.cfg
HAPROXY_BACKENDS = [
    {
        "name": "bk_http",
        "port": 80,
        "map_file": "/etc/haproxy/http_domains.map",
    },
    {
        "name": "bk_ssl",
        "port": 443,
        "map_file": "/etc/haproxy/https_domains.map",
    },
    {
        "name": "bk_ssh",
        "port": 22,
        "map_file": "/etc/haproxy/ssh_domains.map",
    },
]

logger = logging.getLogger(__name__)


def send_socket_command(socket_path: Path | str, command: str) -> str | None:
    """Send a command to the HAProxy socket and return the response."""
    logger.debug("Send socket command: %s", command)
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(socket_path))
        sock.send(f"{command}\n".encode())

        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8")

        sock.close()
        logger.debug("Response: %r", response)
        return response
    except Exception as e:
        logger.exception("Socket command failed: %s", e)
        return None


def get_current_mappings(socket_path, map_file: str) -> dict[str, str]:
    """Get current in-memory map entries from HAProxy."""
    response = send_socket_command(socket_path, f"show map {map_file}")
    if not response:
        return {}
    mappings = {}
    for line in response.splitlines():
        if not line:
            continue
        parts = line.split()
        if len(parts) >= 3:
            mappings[parts[1]] = parts[2]
    return mappings


def _resolve_vm_ip(local_ip: str | None) -> str | None:
    """Convert a network address from the API to the VM's IP.

    The API returns the gateway address (ending in .1) or a CIDR range.
    The VM is always at .2 in the same subnet.
    """
    if not local_ip:
        return None
    addr = local_ip.split("/")[0]
    if addr.endswith(".1"):
        addr = addr.removesuffix(".1") + ".2"
    return addr


def _build_map_entries(instances: list[dict]) -> dict[str, str]:
    """Build domain->IP mapping from instance list."""
    entries = {}
    for instance in instances:
        ip = _resolve_vm_ip(instance["ipv4"]["local"])
        if ip:
            entries[instance["name"]] = ip
    return entries


def update_mapfile(entries: dict[str, str], map_file_path: str) -> bool:
    """Write domain->IP entries to the on-disk map file.

    Returns True if the file content changed.
    """
    mapfile = Path(map_file_path)
    previous = mapfile.read_text() if mapfile.exists() else ""
    current = "".join(f"{domain} {ip}\n" for domain, ip in sorted(entries.items()))
    if current == previous:
        return False
    mapfile.write_text(current)
    return True


def sync_runtime_map(socket_path, map_file_path: str, entries: dict[str, str]):
    """Sync HAProxy's in-memory map with the desired entries.

    Clears the current map and re-adds all entries. This is simpler
    and more reliable than diffing individual entries.
    """
    send_socket_command(socket_path, f"clear map {map_file_path}")
    for domain, ip in entries.items():
        send_socket_command(socket_path, f"add map {map_file_path} {domain} {ip}")


def update_backends(
    map_file_path: str,
    socket_path,
    instances: list[dict],
    force_update: bool = False,
):
    """Update map file and sync HAProxy's in-memory map."""
    entries = _build_map_entries(instances)
    file_updated = update_mapfile(entries, map_file_path)

    # Check if runtime map matches — after HAProxy restart the
    # in-memory map is reloaded from the file, but we sync anyway
    # to handle edge cases (file written but HAProxy not reloaded).
    current_mappings = get_current_mappings(socket_path, map_file_path)
    runtime_matches = all(current_mappings.get(domain) == ip for domain, ip in entries.items()) and len(
        current_mappings
    ) == len(entries)

    if force_update or file_updated or not runtime_matches:
        reason = "force" if force_update else "file changed" if file_updated else "runtime map out of sync"
        logger.info("Updating map (%s): %s", reason, map_file_path)
        sync_runtime_map(socket_path, map_file_path, entries)
    else:
        logger.debug("Map file and runtime in sync: %s", map_file_path)


async def fetch_list(domain: str | None = None) -> list[dict]:
    """Fetch domain mappings from the aleph DNS API."""
    async with aiohttp.ClientSession() as client:
        resp = await client.get(
            url=str(settings.DOMAIN_SERVICE_URL),
            params={"crn": domain} if domain else None,
        )
        resp.raise_for_status()
        instances = await resp.json()
        if len(instances) == 0:
            return []
        return instances


async def fetch_list_and_update(socket_path, local_vms: list[str], force_update):
    """Fetch domain mappings and update all HAProxy backends."""
    if settings.DOMAIN_NAME in ("localhost", "vm.example.org"):
        logger.info("Skipping domain update because DOMAIN_NAME is not set")
        return

    instances = await fetch_list(settings.DOMAIN_NAME)
    instances = [i for i in instances if i["item_hash"] in local_vms]

    for backend in HAPROXY_BACKENDS:
        update_backends(
            map_file_path=str(backend["map_file"]),
            socket_path=socket_path,
            instances=instances,
            force_update=force_update,
        )
