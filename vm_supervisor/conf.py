import ipaddress
import logging
import os
import re
from enum import Enum
from os.path import abspath, exists, isdir, isfile, join
from pathlib import Path
from subprocess import check_output
from typing import Any, Dict, Iterable, List, Literal, NewType, Optional, Union

from pydantic import BaseSettings, Field

logger = logging.getLogger(__name__)

Url = NewType("Url", str)

# This variable may not be set from an environment variable
ALLOW_DEVELOPER_SSH_KEYS = object()


class DnsResolver(str, Enum):
    resolv_conf = "resolv.conf"  # Simply copy from /etc/resolv.conf
    resolvectl = "resolvectl"  # Systemd-resolved, common on Ubuntu


class IPv6AllocationPolicy(str, Enum):
    static = "static"  # Compute the IP address based on the VM item hash.
    dynamic = "dynamic"  # Assign an available IP address.


def etc_resolv_conf_dns_servers():
    with open("/etc/resolv.conf", "r") as resolv_file:
        for line in resolv_file.readlines():
            ip = re.findall(r"^nameserver\s+([\w.]+)$", line)
            if ip:
                yield ip[0]


def resolvectl_dns_servers(interface: str) -> Iterable[str]:
    """
    Use resolvectl to list available DNS servers (IPv4 and IPv6).

    Note: we used to use systemd-resolve for Debian 11.
    This command is not available anymore on Ubuntu 22.04 and is actually a symlink
    to resolvectl.

    Example output for `resolvectl dns -i eth0`:
    Link 2 (eth0): 67.207.67.3 67.207.67.2 2a02:2788:fff0:5::140
    """
    output = check_output(["/usr/bin/resolvectl", "dns", "-i", interface], text=True)
    # Split on the first colon only to support IPv6 addresses.
    link, servers = output.split(":", maxsplit=1)
    for server in servers.split():
        yield server.strip()


def resolvectl_dns_servers_ipv4(interface: str) -> Iterable[str]:
    """
    Use resolvectl to list available IPv4 DNS servers.
    VMs only support IPv4 networking for now, we must exclude IPv6 DNS from their config.
    """
    for server in resolvectl_dns_servers(interface):
        ip_addr = ipaddress.ip_address(server)
        if isinstance(ip_addr, ipaddress.IPv4Address):
            yield server


class Settings(BaseSettings):
    SUPERVISOR_HOST = "127.0.0.1"
    SUPERVISOR_PORT: int = 4020

    # Public domain name
    DOMAIN_NAME: Optional[str] = Field(
        default="localhost",
        description="Default public domain name",
    )

    START_ID_INDEX: int = 4
    PREALLOC_VM_COUNT: int = 0
    REUSE_TIMEOUT: float = 60 * 60.0
    WATCH_FOR_MESSAGES = True
    WATCH_FOR_UPDATES = True

    API_SERVER = "https://official.aleph.cloud"
    USE_JAILER = True
    # System logs make boot ~2x slower
    PRINT_SYSTEM_LOGS = False
    DEBUG_ASYNCIO = False

    # Networking does not work inside Docker/Podman
    ALLOW_VM_NETWORKING = True
    NETWORK_INTERFACE = "eth0"
    IPV4_ADDRESS_POOL = Field(
        default="172.16.0.0/12",
        description="IPv4 address range used to provide networks to VMs.",
    )
    IPV4_NETWORK_PREFIX_LENGTH = Field(
        default=24,
        description="Individual VM network prefix length in bits",
    )
    IPV6_ADDRESS_POOL: str = Field(
        default="fc00:1:2:3::/64",
        description="IPv6 address range assigned to the host. Example: 1111:2222:3333:4444::/64. "
        "Defaults to a local address range for compatibility with hosts not yet configured for IPv6.",
    )
    IPV6_ALLOCATION_POLICY: IPv6AllocationPolicy = Field(
        default=IPv6AllocationPolicy.static
    )
    IPV6_SUBNET_PREFIX: int = Field(
        default=124,
        description="IPv6 subnet prefix for VMs. Made configurable for testing.",
    )
    IPV6_FORWARDING_ENABLED: bool = Field(
        default=True,
        description="Enable IPv6 forwarding on the host. Required for IPv6 connectivity in VMs."
    )
    NFTABLES_CHAIN_PREFIX = "aleph"
    USE_NDP_PROXY: bool = Field(
        default=True,
        description="Use the Neighbor Discovery Protocol Proxy to respond to Router Solicitation for instances on IPv6",
    )

    DNS_RESOLUTION: Optional[DnsResolver] = DnsResolver.resolv_conf
    DNS_NAMESERVERS: Optional[List[str]] = None

    FIRECRACKER_PATH = Path("/opt/firecracker/firecracker")
    JAILER_PATH = Path("/opt/firecracker/jailer")
    LINUX_PATH = Path("/opt/firecracker/vmlinux.bin")
    INIT_TIMEOUT: float = 20.0

    CONNECTOR_URL = Url("http://localhost:4021")

    CACHE_ROOT = Path("/var/cache/aleph/vm")
    MESSAGE_CACHE = CACHE_ROOT / "message"
    CODE_CACHE = CACHE_ROOT / "code"
    RUNTIME_CACHE = CACHE_ROOT / "runtime"
    DATA_CACHE = CACHE_ROOT / "data"

    EXECUTION_ROOT = Path("/var/lib/aleph/vm")
    EXECUTION_DATABASE = EXECUTION_ROOT / "executions.sqlite3"
    EXECUTION_LOG_ENABLED = False
    EXECUTION_LOG_DIRECTORY = EXECUTION_ROOT / "executions"

    PERSISTENT_VOLUMES_DIR = EXECUTION_ROOT / "volumes" / "persistent"

    MAX_PROGRAM_ARCHIVE_SIZE = 10_000_000  # 10 MB
    MAX_DATA_ARCHIVE_SIZE = 10_000_000  # 10 MB

    # hashlib.sha256(b"secret-token").hexdigest()
    ALLOCATION_TOKEN_HASH = (
        "151ba92f2eb90bce67e912af2f7a5c17d8654b3d29895b042107ea312a7eebda"
    )

    # Tests on programs

    FAKE_DATA_PROGRAM: Optional[Path] = None
    BENCHMARK_FAKE_DATA_PROGRAM = Path(
        abspath(join(__file__, "../../examples/example_fastapi"))
    )

    FAKE_DATA_MESSAGE = Path(
        abspath(join(__file__, "../../examples/program_message_from_aleph.json"))
    )
    FAKE_DATA_DATA: Optional[Path] = Path(
        abspath(join(__file__, "../../examples/data/"))
    )
    FAKE_DATA_RUNTIME = Path(
        abspath(join(__file__, "../../runtimes/aleph-debian-11-python/rootfs.squashfs"))
    )
    FAKE_DATA_VOLUME: Optional[Path] = Path(
        abspath(join(__file__, "../../examples/volumes/volume-venv.squashfs"))
    )

    # Tests on instances

    TEST_INSTANCE_ID: Optional[str] = Field(
        default=None,  # TODO: Use a valid item_hash here
        description="Identifier of the instance message used when testing the launch of an instance from the network",
    )

    USE_FAKE_INSTANCE_BASE = False
    FAKE_INSTANCE_BASE = Path(
        abspath(join(__file__, "../../runtimes/instance-debian-rootfs/rootfs.ext4"))
    )
    FAKE_INSTANCE_ID: str = Field(
        default="decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
        description="Identifier used for the 'fake instance' message defined in "
        "examples/instance_message_from_aleph.json",
    )
    FAKE_INSTANCE_MESSAGE = Path(
        abspath(join(__file__, "../../examples/instance_message_from_aleph.json"))
    )

    CHECK_FASTAPI_VM_ID = (
        "67705389842a0a1b95eaa408b009741027964edc805997475e95c505d642edd8"
    )

    # Developer options

    SENTRY_DSN: Optional[str] = None
    DEVELOPER_SSH_KEYS: Optional[List[str]] = []
    # Using an object here forces the value to come from Python code and not from an environment variable.
    USE_DEVELOPER_SSH_KEYS: Union[Literal[False], object] = False

    # Fields
    SENSITIVE_FIELDS: List[str] = Field(
        default=["SENTRY_DSN"],
        description="Sensitive fields, redacted from `--print-settings`.",
    )

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key != key.upper():
                logger.warning(f"Setting {key} is not uppercase")
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")

    def check(self):
        assert Path("/dev/kvm").exists(), "KVM not found on `/dev/kvm`."
        assert isfile(self.FIRECRACKER_PATH), f"File not found {self.FIRECRACKER_PATH}"
        assert isfile(self.JAILER_PATH), f"File not found {self.JAILER_PATH}"
        assert isfile(self.LINUX_PATH), f"File not found {self.LINUX_PATH}"
        assert self.CONNECTOR_URL.startswith(
            "http://"
        ) or self.CONNECTOR_URL.startswith("https://")
        if self.ALLOW_VM_NETWORKING:
            assert exists(
                f"/sys/class/net/{self.NETWORK_INTERFACE}"
            ), f"Network interface {self.NETWORK_INTERFACE} does not exist"

            _, ipv4_pool_length = settings.IPV4_ADDRESS_POOL.split("/")
            assert (
                int(ipv4_pool_length) <= settings.IPV4_NETWORK_PREFIX_LENGTH
            ), "The IPv4 address pool prefix must be shorter than an individual VM network prefix"

        if self.FAKE_DATA_PROGRAM:
            assert isdir(
                self.FAKE_DATA_PROGRAM
            ), "Local fake program directory is missing"
            assert isfile(self.FAKE_DATA_MESSAGE), "Local fake message is missing"
            assert isdir(self.FAKE_DATA_DATA), "Local fake data directory is missing"
            assert isfile(
                self.FAKE_DATA_RUNTIME
            ), "Local runtime .squashfs build is missing"
            assert isfile(
                self.FAKE_DATA_VOLUME
            ), "Local data volume .squashfs is missing"

    def setup(self):
        os.makedirs(self.MESSAGE_CACHE, exist_ok=True)
        os.makedirs(self.CODE_CACHE, exist_ok=True)
        os.makedirs(self.RUNTIME_CACHE, exist_ok=True)
        os.makedirs(self.DATA_CACHE, exist_ok=True)
        os.makedirs(self.EXECUTION_ROOT, exist_ok=True)
        os.makedirs(self.EXECUTION_LOG_DIRECTORY, exist_ok=True)
        os.makedirs(self.PERSISTENT_VOLUMES_DIR, exist_ok=True)

        if self.DNS_NAMESERVERS is None and self.DNS_RESOLUTION:
            if self.DNS_RESOLUTION == DnsResolver.resolv_conf:
                self.DNS_NAMESERVERS = list(etc_resolv_conf_dns_servers())

            elif self.DNS_RESOLUTION == DnsResolver.resolvectl:
                self.DNS_NAMESERVERS = list(
                    resolvectl_dns_servers_ipv4(interface=self.NETWORK_INTERFACE)
                )
            else:
                assert "This should never happen"

    def display(self) -> str:
        attributes: Dict[str, Any] = {}

        for attr in self.__dict__.keys():
            if attr != attr.upper():
                # Settings are expected to be ALL_UPPERCASE, other attributes snake_case or CamelCase
                continue

            if getattr(self, attr) and attr in self.SENSITIVE_FIELDS:
                attributes[attr] = "<REDACTED>"
            else:
                attributes[attr] = getattr(self, attr)

        return "\n".join(
            f"{attribute:<27} = {value}" for attribute, value in attributes.items()
        )

    class Config:
        env_prefix = "ALEPH_VM_"
        case_sensitive = False
        env_file = ".env"


def make_db_url():
    return f"sqlite:///{settings.EXECUTION_DATABASE}"


# Settings singleton
settings = Settings()
