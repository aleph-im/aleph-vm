"""Agent-side HAProxy domain-mapping sync.

The supervisor knows nothing about HAProxy. This module lives on the agent side
and drives HAProxy purely from the supervisor's `list_vms()` output: it derives
each local VM's IP from `VmInfo.ipv4.address` and combines it with the public
domain records served by the aleph DNS API to build the HAProxy map files.
"""

import logging
import pathlib

from aleph.vm.conf import settings
from aleph.vm.haproxy import (
    HAPROXY_BACKENDS,
    build_map_entries_from_vm_ips,
    fetch_list,
    write_entries_to_backend,
)

logger = logging.getLogger(__name__)

# DOMAIN_NAME values that mean "no real domain configured"; skip syncing.
PLACEHOLDER_DOMAINS = ("localhost", "vm.example.org")


def push_entries_to_haproxy(entries: dict[str, str], socket_path, force_update: bool = False) -> None:
    """Push domain->IP entries to every HAProxy backend (http, ssl, ssh)."""
    for backend in HAPROXY_BACKENDS:
        write_entries_to_backend(
            map_file_path=str(backend["map_file"]),
            socket_path=socket_path,
            entries=entries,
            force_update=force_update,
        )


async def sync_domain_mappings(supervisor, force_update: bool = False) -> bool:
    """Sync HAProxy domain mappings from the supervisor's running VMs.

    Returns True when a sync was performed, False when skipped (HAProxy not
    running or no real domain configured).
    """
    socket_path = settings.HAPROXY_SOCKET
    if not pathlib.Path(socket_path).exists():
        logger.info("HAProxy not running? socket not found, skip domain mapping update")
        return False

    if settings.DOMAIN_NAME in PLACEHOLDER_DOMAINS:
        logger.info("Skipping domain update because DOMAIN_NAME is not set")
        return False

    domain_records = await fetch_list(settings.DOMAIN_NAME)

    vm_ip_by_hash = {
        str(vm.vm_id): vm.ipv4.address for vm in await supervisor.list_vms() if vm.ipv4 and vm.ipv4.address
    }

    entries = build_map_entries_from_vm_ips(domain_records, vm_ip_by_hash)
    push_entries_to_haproxy(entries, socket_path, force_update=force_update)
    return True
