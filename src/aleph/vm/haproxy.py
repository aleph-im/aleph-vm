#!/usr/bin/env python3
"""
Instance domain support.
aka HAProxy Dynamic Configuration Updater

HAProxy is a proxy server used to redirect the HTTP, HTTPS and SSL traffic
to the instances if they have it configured.

This module gets the instance domain ip mapping and updates the HAProxy config
both live via its unix control socket and via the map file.


For the control protocol and commands used, refer to
https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/management/

"""

import dataclasses
import logging
import os
import re
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


def validate_domain(domain):
    """Validate domain name format."""
    domain_pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
    )
    return bool(domain_pattern.match(domain))


def validate_target(target):
    """Validate IP:port format."""
    ip_port_pattern = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})$")
    match = ip_port_pattern.match(target)
    if not match:
        return False

    # Validate IP address parts
    ip = match.group(1)
    port = int(match.group(2))

    ip_parts = ip.split(".")
    for part in ip_parts:
        if not 0 <= int(part) <= 255:
            return False

    # Validate port
    if not 1 <= port <= 65535:
        return False

    return True


def send_socket_command(socket_path: Path | str, command):
    """Send a command to the HAProxy socket and return the response."""
    logger.debug(f"Send socket command: {command}")

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(str(socket_path))
        sock.send(f"{command}\n".encode())

        # Read the response
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks).decode("utf-8")

        sock.close()
        logger.debug(f"Response: {response!r}")
        return response
    except Exception as e:
        logger.exception(f"Socket command failed: {e!s}")
        return None


def parse_map_file(map_file_path) -> list[tuple[str, str]]:
    """
    Parse the domain-to-IP map file.

    Format:
    domain.name target_ip:port
    """
    mappings: list[tuple[str, str]] = []

    if not os.path.exists(map_file_path):
        logger.error(f"Map file not found: {map_file_path}")
        return mappings

    try:
        with open(map_file_path) as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                parts = line.split()
                if len(parts) != 2:
                    logger.warning(f"Invalid format at line {line_num}: {line}")
                    continue

                domain, target = parts

                # Validate domain and target
                if not validate_domain(domain):
                    logger.warning(f"Invalid domain format at line {line_num}: {domain}")
                    continue

                if not validate_target(target):
                    logger.warning(f"Invalid target format at line {line_num}: {target}")
                    continue

                mappings.append((domain, target))

        return mappings
    except Exception as e:
        logger.error(f"Error reading map file: {e!s}")
        return []


@dataclasses.dataclass
class BackendServer:
    # see     # https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/management/#9.3-show%20servers%20state
    # for full field description
    be_id: str  # Backend id e.g 6
    be_name: str  # Backend name .e.g bk_ssl
    srv_id: str
    srv_name: str  # Server name e.g centurion.cybernetwork.me
    srv_addr: str  # e.g 172.16.35.0
    srv_op_state: str
    srv_admin_state: str
    srv_uweight: str
    srv_iweight: str
    srv_time_since_last_change: str
    srv_check_status: str
    srv_check_result: str
    # srv_name srv_addr srv_op_state srv_admin_state srv_uweight srv_iweight srv_time_since_last_change srv_check_status srv_check_result srv_check_health srv_check_state srv_agent_state bk_f_forced_id srv_f_forced_id srv_fqdn srv_port srvrecord srv_use_ssl srv_check_port srv_check_addr srv_agent_addr srv_agent_port


def get_current_backends(socket_path, backend_name):
    """Get a list of current servers for backend."""
    response = send_socket_command(socket_path, f"show servers state {backend_name}")
    if response == "Can't find backend.\n\n":
        logger.info("Server response: %s", response.strip())
        return []
    if not response:
        return []

    servers = {}
    # Parse the response to extract server names
    lines = response.strip().split("\n")
    # https://www.haproxy.com/documentation/haproxy-configuration-manual/2-8r1/management/#9.3-show%20servers%20state
    assert lines[0] == "1", "Format should be version 1"
    for line in lines[1:]:
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if parts:
            bs = BackendServer(
                be_id=parts[0],
                be_name=parts[1],
                srv_id=parts[2],
                srv_name=parts[3],
                srv_addr=parts[4],
                srv_op_state=parts[5],
                srv_admin_state=parts[6],
                srv_uweight=parts[7],
                srv_iweight=parts[8],
                srv_time_since_last_change=parts[9],
                srv_check_status=parts[10],
                srv_check_result=parts[11],
            )
            servers[bs.srv_name] = bs

    return servers


def get_current_mappings(socket_path, map_file) -> dict[str, str]:
    """Get a list of current mapping from HaProxy"""
    # show map /etc/haproxy/http_domains.map
    command = f"show map {map_file}"
    response = send_socket_command(socket_path, command)

    if not response:
        return {}
    try:
        mappings = {}
        lines = response.splitlines()
        for line in lines:
            if not line:
                continue
            mapping_id, mapping_name, mapping_target = line.split()
            mappings[mapping_name] = mapping_target

    except Exception as e:
        msg = f"Error retrieving current mapping: {e!s}"
        raise Exception(msg) from e
    return mappings


def update_haproxy_backend(socket_path, backend_name, instances, map_file_path, port, weight=1):
    """Update HAProxy backend servers config based on the map file.

    Sync the running config with the content of the map file.

     This allows us to update the config without needing to reload or restart HAProxy.

    It reads domain-to-IP mappings from a map file and uses HAProxy's
    socket commands to dynamically add/update backend servers allowing update without requiring a reload
    HAProxy.
    """

    mappings = get_current_mappings(socket_path, map_file_path)

    # Get current backend servers
    current_servers = get_current_backends(socket_path, backend_name)
    logger.info(f"Current servers in backend {backend_name}: {current_servers}")

    # Track which servers we've processed to identify removals later
    processed_servers = set()

    # Process each mapping
    for instance in instances:
        server_name = instance["name"]
        local_ip = instance["ipv4"]["local"]
        # custom domain name doesn't return the ip addr but the network range
        addr = local_ip.split("/")[0]
        if addr.endswith(".1"):
            addr = addr.rstrip(".1") + ".2"
        processed_servers.add(server_name)

        # Check if the server already exists
        if server_name in current_servers:
            # Update existing server
            command = f"set server {backend_name}/{server_name} addr {addr} port {port}"
            logger.info(f"Updating server: {command}")
            response = send_socket_command(socket_path, command)
            if response and "not found" in response:  # Fall back
                logger.warning(f"Server not found: {server_name}, trying to add it")
                # If server doesn't exist, add it
                command = f"add server {backend_name}/{server_name} {addr}:{port} weight {weight} maxconn 30"
                logger.info(f"Adding server: {command}")
                response = send_socket_command(socket_path, command)
                if response.strip() != "":
                    logger.info(f"Error adding server {response}")

        else:  # Add the new server
            command = f"add server {backend_name}/{server_name} {addr}:{port} weight {weight} maxconn 30"
            logger.info(f"Adding server: {command}")
            response = send_socket_command(socket_path, command)
            if response.strip() != "":
                logger.info(f"Error adding server {response}")
        # Enable the server
        command = f"enable server {backend_name}/{server_name}"
        logger.info(f"Enable server: {command}")
        response = send_socket_command(socket_path, command)
        if response.strip() != "":
            logger.info(f"Error enabling server {response}")

        # Add/set mapping
        if server_name not in mappings:
            response = send_socket_command(socket_path, f"add map {map_file_path} {server_name} {server_name}")
            logger.info(f"Added mapping: {server_name} {response=}")
        elif mappings[server_name] != server_name:
            response = send_socket_command(socket_path, f"set map {map_file_path} {server_name} {server_name}")
            logger.info(f"updated mapping: {server_name} {response=}")

    # Remove servers that are not in the map file
    servers_to_remove = set(current_servers) - processed_servers
    # Do not remove the fallback server
    servers_to_remove.discard("fallback_local")
    servers_to_remove.discard("web1")
    if servers_to_remove:
        logger.info(f"Removing {len(servers_to_remove)} servers no longer in map file")
        for server_name in servers_to_remove:
            logger.info(f"Removing server: {server_name}")
            command = f"set  server {backend_name}/{server_name} state maint"
            response = send_socket_command(socket_path, command)
            command = f"del server {backend_name}/{server_name}"
            response = send_socket_command(socket_path, command)
            logger.info(f"Response: {response}")

    return True


async def fetch_list(domain=None) -> list[dict]:
    async with aiohttp.ClientSession() as client:
        resp = await client.get(url=str(settings.DOMAIN_SERVICE_URL), params={"crn": domain} if domain else None)
        # print(resp.real_url)
        resp.raise_for_status()
        instances = await resp.json()
        if len(instances) == 0:
            return []
        return instances


async def fetch_list_and_update(socket_path, local_vms: list[str], force_update):
    if settings.DOMAIN_NAME in ("localhost", "vm.example.org"):
        logger.info("Skipping domain update because DOMAIN_NAME is not set")

    instances = await fetch_list(settings.DOMAIN_NAME)
    # filter on local hash
    instances = [i for i in instances if i["item_hash"] in local_vms]
    # This should match the config in haproxy.cfg
    for backend in HAPROXY_BACKENDS:
        update_backends(backend["name"], backend["map_file"], backend["port"], socket_path, instances, force_update)


def update_backends(backend_name, map_file_path, port, socket_path, instances, force_update=False):
    updated = update_mapfile(instances, map_file_path)
    if force_update:
        logger.info("Updating backends")
        update_haproxy_backend(socket_path, backend_name, instances, map_file_path, port, weight=1)
    elif updated:
        logger.info("Map file content changed, updating backends")
        update_haproxy_backend(socket_path, backend_name, instances, map_file_path, port, weight=1)

    else:
        logger.debug("Map file content no modification")


def update_mapfile(instances: list, map_file_path: str) -> bool:
    mapfile = Path(map_file_path)
    previous_mapfile = ""
    if mapfile.exists():
        content = mapfile.read_text()
        previous_mapfile = content
    current_content = ""

    for instance in instances:
        if instance["ipv4"]["local"]:
            current_content += f"{instance['name']} {instance['name']}\n"
    updated = current_content != previous_mapfile
    if updated:
        mapfile.write_text(current_content)
    return updated
