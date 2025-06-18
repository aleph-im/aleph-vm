#!/usr/bin/env python3
"""
Instance domain support.
aka HAProxy Dynamic Configuration Updater

This script reads domain-to-IP mappings from a map file and uses HAProxy's
socket commands to dynamically add/update backend servers without reloading
the HAProxy configuration.
"""

import argparse
import dataclasses
import logging
import os
import re
import socket
import sys
import time
from pathlib import Path

import aiohttp

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


def parse_map_file(map_file_path):
    """
    Parse the domain-to-IP map file.

    Format:
    domain.name target_ip:port
    """
    mappings = []

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


def update_haproxy_backends(socket_path, backend_name, map_file_path, weight=1):
    """
    Update HAProxy backend servers config based on the map file.

    Control HaProxy config via the unix socket

    This function:
    1. Reads domain-to-IP mappings from the map file
    2. For each mapping, adds or updates a server in the specified backend
    """
    mappings = parse_map_file(map_file_path)
    if not mappings:
        logger.error("No valid mappings found in the map file.")
        return False

    # Get current backend servers
    current_servers = get_current_backends(socket_path, backend_name)
    logger.info(f"Current servers in backend {backend_name}: {current_servers}")

    # Track which servers we've processed to identify removals later
    processed_servers = set()

    # Process each mapping
    for domain, target in mappings:
        server_name = domain
        processed_servers.add(server_name)

        # Check if server already exists in mapping
        if server_name in current_servers:
            # FIXME : In the future, don't update the address if it hasn't changed'
            # Update existing server
            addr, port = target.split(":")
            command = f"set server {backend_name}/{server_name} addr {addr} port {port}"
            logger.info(f"Updating server: {command}")
            response = send_socket_command(socket_path, command)
            if response and "not found" in response:
                logger.warning(f"Server not found: {server_name}, trying to add it")
                # If server doesn't exist, add it
                command = f"add server {backend_name}/{server_name} {target} weight {weight} maxconn 30"
                logger.info(f"Adding server: {command}")
                response = send_socket_command(socket_path, command)
        else:
            # Add new server
            command = f"add server {backend_name}/{server_name} {target} weight {weight} maxconn 30"
            logger.info(f"Adding server: {command}")
            response = send_socket_command(socket_path, command)

        # Check response
        if response and "not found" in response:
            logger.error(f"Error processing server {server_name}: {response}")
        else:
            command = f"enable server {backend_name}/{server_name}"
            logger.info(f"Enable server: {command}")
            response = send_socket_command(socket_path, command)
            if response.strip() != "":
                logger.info("Error enabling server Response")

    # Remove servers that are not in the map file
    servers_to_remove = set(current_servers) - processed_servers
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


def watch_and_update(socket_path, backend_name, map_file_path, interval=60, weight=1, port=80):
    """Watch the map file for changes and update HAProxy backends when needed."""
    while True:
        try:
            fetch_list_and_update(backend_name, map_file_path, port, socket_path, weight)
            time.sleep(interval)
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, exiting")
            break
        except Exception as e:
            logger.exception(f"Error in watch loop: {e!s}")
            time.sleep(interval)



async def fetch_list() -> list[dict]:
    return [
        {
            "name": "echo.agot.be",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.4.1/32"},
        }
    ]


async def fetch_list_() -> list[dict]:
    async with aiohttp.ClientSession() as client:
        resp = await client.get(url="https://api.dns.public.aleph.sh/instances/list")
        resp.raise_for_status()
        instances = await resp.json()
        if len(instances) == 0:
            return []
        return instances

async def fetch_list_and_update2(backend_name, map_file_path, port, socket_path, running_instances: list[str]):
    send_socket_command(socket_path, 'show backend')
    instances = await fetch_list()
    previous_mapfile = ""

    mapfile = Path(map_file_path)
    if mapfile.exists():
        content = mapfile.read_text()
        previous_mapfile = content

    current_content = ""
    for instance in instances:
        if instance["item_hash"] not in running_instances:
            continue
        local_ip = instance["ipv4"]["local"]
        if local_ip:
            local_ip = local_ip.split("/")[0]
            if local_ip.endswith(".1"):
                local_ip = local_ip.rstrip(".1") + ".2"
            current_content += f"{instance['name']} {local_ip}:{port}\n"
    if current_content != previous_mapfile:
        mapfile.write_text(current_content)
        logger.info("Map file content changed, updating backends")
        update_haproxy_backends(socket_path, backend_name, map_file_path, weight=1)


async def fetch_list_and_update(backend_name, map_file_path, port, socket_path, weight):
    with aiohttp.ClientSession() as client:
        resp = await client.get(url="https://api.dns.public.aleph.sh/instances/list")
        resp.raise_for_status()
        instances = resp.json()
        # Should filter the instance we actually have
        # instances = [i for i in instances if i['item_hash'] in pool.keys()]
        if len(instances) == 0:
            return
    previous_mapfile = ""
    if os.path.exists(map_file_path):
        with open(map_file_path) as f:
            previous_mapfile = f.read()

    current_content = ""
    for instance in instances:
        local_ip = instance["ipv4"]["local"]
        if local_ip:
            local_ip:str = local_ip.split("/")[0]
            if local_ip.endswith(".1"):
                local_ip = local_ip.rstrip(".1") +  ".2"
            current_content += f"{instance['name']} {local_ip}:{port}\n"
    if current_content != previous_mapfile:
        with open(map_file_path, "w") as file:
            file.write(current_content)
        logger.info("Map file content changed, updating backends")
        update_haproxy_backends(socket_path, backend_name, map_file_path, weight)


def main():
    parser = argparse.ArgumentParser(description="Update HAProxy backends from a map file")
    parser.add_argument("--socket", "-s", required=True, help="Path to HAProxy socket file")
    parser.add_argument("--backend", "-b", required=True, help="Name of the backend to update")
    parser.add_argument("--map-file", "-m", required=True, help="Path to domain-to-IP map file")
    parser.add_argument("--weight", "-w", type=int, default=1, help="Server weight (default: 1)")
    parser.add_argument("--watch", "-W", action="store_true", help="Watch map file for changes")
    parser.add_argument(
        "--interval",
        "-i",
        type=int,
        default=60,
        help="Watch interval in seconds (default: 60)",
    )

    parser.add_argument(
        "--port",
        "-p",
        type=int,
        default=80,
        help="Specify port number on watch mode (default: 80)",
    )

    args = parser.parse_args()

    # Validate socket path
    if not os.path.exists(args.socket):
        logger.error(f"HAProxy socket not found: {args.socket}")
        return 1

    # Validate map file
    if not args.watch and not os.path.exists(args.map_file):
        logger.error(f"Map file not found: {args.map_file}")
        return 1

    if args.watch:
        logger.info(f"Watching map file {args.map_file} for changes, updating backend {args.backend}")
        watch_and_update(
            args.socket,
            args.backend,
            args.map_file,
            args.interval,
            args.weight,
            args.port,
        )
    else:
        result = update_haproxy_backends(args.socket, args.backend, args.map_file, args.weight)
        return 0 if result else 1


if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler()],
    )

    sys.exit(main())
