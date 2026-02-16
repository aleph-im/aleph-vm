import ipaddress
import logging
import os
import re
import shutil
from collections.abc import Iterable
from decimal import Decimal
from enum import Enum
from os.path import abspath, exists, isdir, isfile, join
from pathlib import Path
from subprocess import CalledProcessError, check_output
from typing import Any, Literal, NewType

from aleph_message.models import Chain
from aleph_message.models.execution.environment import HypervisorType
from dotenv import load_dotenv
from pydantic import Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from aleph.vm.orchestrator.chain import STREAM_CHAINS
from aleph.vm.utils import (
    check_amd_sev_es_supported,
    check_amd_sev_supported,
    file_hashes_differ,
    is_command_available,
)

load_dotenv()

logger = logging.getLogger(__name__)

Url = NewType("Url", str)

# This variable may not be set from an environment variable
ALLOW_DEVELOPER_SSH_KEYS = object()


class DnsResolver(str, Enum):
    detect = "detect"  # Detect the resolver used by the system
    resolv_conf = "resolv.conf"  # Simply copy from /etc/resolv.conf
    resolvectl = "resolvectl"  # Systemd-resolved, common on Ubuntu


class IPv6AllocationPolicy(str, Enum):
    static = "static"  # Compute the IP address based on the VM item hash.
    dynamic = "dynamic"  # Assign an available IP address.


class SnapshotCompressionAlgorithm(str, Enum):
    gz = "gzip"


def etc_resolv_conf_dns_servers():
    with open("/etc/resolv.conf") as resolv_file:
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


def get_default_interface() -> str | None:
    """Returns the default network interface"""
    with open("/proc/net/route") as f:
        for line in f.readlines():
            parts = line.strip().split()
            if parts[1] == "00000000":  # Indicates default route
                return parts[0]
    return None


def obtain_dns_ips(dns_resolver: DnsResolver, network_interface: str) -> list[str]:
    # The match syntax is not yet available as of Python 3.9
    # match dns_resolver:
    if dns_resolver == DnsResolver.detect:
        # Use a try-except approach since resolvectl can be present but disabled and raise the following
        # "Failed to get global data: Unit dbus-org.freedesktop.resolve1.service not found."
        try:
            return list(resolvectl_dns_servers(interface=network_interface))
        except (FileNotFoundError, CalledProcessError) as error:
            if Path("/etc/resolv.conf").exists():
                return list(etc_resolv_conf_dns_servers())
            else:
                msg = "No DNS resolver found"
                raise FileNotFoundError(msg) from error

    elif dns_resolver == DnsResolver.resolv_conf:
        return list(etc_resolv_conf_dns_servers())

    elif dns_resolver == DnsResolver.resolvectl:
        return list(resolvectl_dns_servers(interface=network_interface))

    else:
        msg = "No DNS resolve defined, this should never happen."
        raise AssertionError(msg)


class Settings(BaseSettings):
    SUPERVISOR_HOST: str = "127.0.0.1"
    SUPERVISOR_PORT: int = 4020

    # Public domain name
    DOMAIN_NAME: str = Field(
        default="localhost",
        description="Default public domain name",
    )

    START_ID_INDEX: int = 4
    PREALLOC_VM_COUNT: int = 0
    REUSE_TIMEOUT: float = 60 * 60.0
    WATCH_FOR_MESSAGES: bool = True
    WATCH_FOR_UPDATES: bool = True

    API_SERVER: str = "https://official.aleph.cloud"
    # Connect to the Quad9 VPN provider using their IPv4 and IPv6 addresses.
    CONNECTIVITY_IPV4_URL: str = "https://9.9.9.9/"
    CONNECTIVITY_IPV6_URL: str = "https://[2620:fe::fe]/"
    CONNECTIVITY_DNS_HOSTNAME: str = "example.org"

    USE_JAILER: bool = True
    # Changelog: PRINT_SYSTEM_LOGS use to print the MicroVM logs with the supervisor output.
    # They are now in separate journald entries, disabling the settings disable the logs output of Firecracker VM (only)
    # via the serial console. This break the logs endpoint for program, as such disabling it in prod is not recommended.
    PRINT_SYSTEM_LOGS: bool = True
    IGNORE_TRACEBACK_FROM_DIAGNOSTICS: bool = True
    LOG_LEVEL: str = "INFO"
    DEBUG_ASYNCIO: bool = False

    # Networking does not work inside Docker/Podman
    ALLOW_VM_NETWORKING: bool = True
    NETWORK_INTERFACE: str | None = None
    IPV4_ADDRESS_POOL: str = Field(
        default="172.16.0.0/12",
        description="IPv4 address range used to provide networks to VMs.",
    )
    IPV4_NETWORK_PREFIX_LENGTH: int = Field(
        default=24,
        description="Individual VM network prefix length in bits",
    )
    IPV6_ADDRESS_POOL: str = Field(
        default="fc00:1:2:3::/64",
        description="IPv6 address range assigned to the host. Example: 1111:2222:3333:4444::/64. "
        "Defaults to a local address range for compatibility with hosts not yet configured for IPv6.",
    )
    IPV6_ALLOCATION_POLICY: IPv6AllocationPolicy = Field(default=IPv6AllocationPolicy.static)
    IPV6_SUBNET_PREFIX: int = Field(
        default=124,
        description="IPv6 subnet prefix for VMs. Made configurable for testing.",
    )
    IPV6_FORWARDING_ENABLED: bool = Field(
        default=True,
        description="Enable IPv6 forwarding on the host. Required for IPv6 connectivity in VMs.",
    )
    NFTABLES_CHAIN_PREFIX: str = "aleph"
    USE_NDP_PROXY: bool = Field(
        default=True,
        description="Use the Neighbor Discovery Protocol Proxy to respond to Router Solicitation for instances on IPv6",
    )

    DNS_RESOLUTION: DnsResolver | None = Field(
        default=DnsResolver.detect,
        description="Method used to resolve the dns server if DNS_NAMESERVERS is not present.",
    )
    DNS_NAMESERVERS: list[str] | None = None
    DNS_NAMESERVERS_IPV4: list[str] | None = None
    DNS_NAMESERVERS_IPV6: list[str] | None = None

    FIRECRACKER_PATH: Path = Path("/opt/firecracker/firecracker")
    JAILER_PATH: Path = Path("/opt/firecracker/jailer")
    SEV_CTL_PATH: Path = Path("/opt/sevctl")
    LINUX_PATH: Path = Path("/opt/firecracker/vmlinux.bin")
    INIT_TIMEOUT: float = 20.0

    CONNECTOR_URL: HttpUrl = HttpUrl("http://localhost:4021")
    # To fetch the list of domain mapping for the ipv4 domain features
    DOMAIN_SERVICE_URL: HttpUrl = HttpUrl("https://api.dns.public.aleph.sh/instances/list")

    CACHE_ROOT: Path = Path("/var/cache/aleph/vm")
    MESSAGE_CACHE: Path | None = Field(
        None,
        description="Default to CACHE_ROOT/message",
    )
    CODE_CACHE: Path | None = Field(None, description="Default to CACHE_ROOT/code")
    RUNTIME_CACHE: Path | None = Field(None, description="Default to CACHE_ROOT/runtime")
    DATA_CACHE: Path | None = Field(None, description="Default to CACHE_ROOT/data")

    EXECUTION_ROOT: Path = Path("/var/lib/aleph/vm")
    JAILER_BASE_DIRECTORY: Path | None = Field(None, description="Default to EXECUTION_ROOT/jailer")
    EXECUTION_DATABASE: Path | None = Field(
        None, description="Location of database file. Default to EXECUTION_ROOT/executions.sqlite3"
    )
    EXECUTION_LOG_ENABLED: bool = False
    EXECUTION_LOG_DIRECTORY: Path | None = Field(
        None, description="Location of executions log. Default to EXECUTION_ROOT/executions/"
    )

    PERSISTENT_VOLUMES_DIR: Path | None = Field(
        None, description="Persistent volumes location. Default to EXECUTION_ROOT/volumes/persistent/"
    )
    JAILER_BASE_DIR: Path | None = Field(None)

    MAX_PROGRAM_ARCHIVE_SIZE: int = 10_000_000  # 10 MB
    MAX_DATA_ARCHIVE_SIZE: int = 10_000_000  # 10 MB

    PAYMENT_MONITOR_INTERVAL: float = Field(
        default=60.0,
        description="Interval in seconds between payment checks",
    )
    PAYMENT_RECEIVER_ADDRESS: str = Field(
        default="",
        description="Address of the account receiving payments",
    )
    # This address is the ALEPH SuperToken on SuperFluid Testnet
    PAYMENT_PRICING_AGGREGATE: str = ""  # TODO: Missing

    # Use to check PAYG payment
    RPC_AVAX: HttpUrl = Field(
        default=STREAM_CHAINS[Chain.AVAX].rpc,
        description="RPC API Endpoint for AVAX chain",
    )

    RPC_BASE: HttpUrl = Field(
        default=STREAM_CHAINS[Chain.BASE].rpc,
        description="RPC API Endpoint for BASE chain",
    )

    PAYMENT_BUFFER: Decimal = Field(
        default=Decimal("0.0000000001"),
        description="Buffer to add to the required payment to prevent floating point errors",
    )

    CACHE_TTL_SECURITY_AGGREGATE: float = Field(
        default=120.0,
        description="TTL in seconds for cached security aggregates (delegation checks)",
    )
    CACHE_TTL_EXECUTION_PRICE: float = Field(
        default=300.0,
        description="TTL in seconds for cached execution prices",
    )
    CACHE_TTL_ADDRESS_BALANCE: float = Field(
        default=30.0,
        description="TTL in seconds for cached address balances",
    )
    CACHE_TTL_MESSAGE_STATUS: float = Field(
        default=30.0,
        description="TTL in seconds for cached message statuses",
    )

    SNAPSHOT_FREQUENCY: int = Field(
        default=0,
        description="Snapshot frequency interval in minutes. It will create a VM snapshot every X minutes. "
        "If set to zero, snapshots are disabled.",
    )

    SNAPSHOT_COMPRESSION_ALGORITHM: SnapshotCompressionAlgorithm = Field(
        default=SnapshotCompressionAlgorithm.gz,
        description="Snapshot compression algorithm.",
    )

    # hashlib.sha256(b"secret-token").hexdigest()
    ALLOCATION_TOKEN_HASH: str = "151ba92f2eb90bce67e912af2f7a5c17d8654b3d29895b042107ea312a7eebda"

    ENABLE_QEMU_SUPPORT: bool = Field(default=True)
    INSTANCE_DEFAULT_HYPERVISOR: HypervisorType | None = Field(
        default=HypervisorType.firecracker,  # User Firecracker
        description="Default hypervisor to use on running instances, can be Firecracker or QEmu",
    )

    ENABLE_CONFIDENTIAL_COMPUTING: bool = Field(
        default=False,
        description="Enable Confidential Computing using AMD-SEV. It will test if the host is compatible "
        "with SEV and SEV-ES",
    )

    CONFIDENTIAL_DIRECTORY: Path | None = Field(
        None,
        description="Confidential Computing default directory. Default to EXECUTION_ROOT/confidential",
    )

    CONFIDENTIAL_SESSION_DIRECTORY: Path | None = Field(None, description="Default to EXECUTION_ROOT/sessions")

    ENABLE_GPU_SUPPORT: bool = Field(
        default=False,
        description="Enable GPU pass-through support to VMs, only allowed for QEmu hypervisor",
    )

    # Settings to get from the network aggregates
    SETTINGS_AGGREGATE_ADDRESS: str = "0xFba561a84A537fCaa567bb7A2257e7142701ae2A"

    # Tests on programs
    FAKE_DATA_PROGRAM: Path | None = None
    BENCHMARK_FAKE_DATA_PROGRAM: Path = Path(abspath(join(__file__, "../../../../examples/example_fastapi")))

    FAKE_DATA_MESSAGE: Path = Path(abspath(join(__file__, "../../../../examples/program_message_from_aleph.json")))
    FAKE_DATA_DATA: Path | None = Path(abspath(join(__file__, "../../../../examples/data/")))
    FAKE_DATA_RUNTIME: Path = Path(
        abspath(join(__file__, "../../../../runtimes/aleph-debian-12-python/rootfs.squashfs"))
    )
    FAKE_DATA_VOLUME: Path | None = Path(abspath(join(__file__, "../../../../examples/volumes/volume-venv.squashfs")))

    # Tests on instances

    TEST_INSTANCE_ID: str | None = Field(
        default=None,  # TODO: Use a valid item_hash here
        description="Identifier of the instance message used when testing the launch of an instance from the network",
    )

    USE_FAKE_INSTANCE_BASE: bool = False
    FAKE_INSTANCE_BASE: Path = Path(abspath(join(__file__, "../../../../runtimes/instance-rootfs/debian-12.btrfs")))
    FAKE_QEMU_INSTANCE_BASE: Path = Path(abspath(join(__file__, "../../../../runtimes/instance-rootfs/rootfs.img")))
    FAKE_INSTANCE_ID: str = Field(
        default="decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
        description="Identifier used for the 'fake instance' message defined in "
        "examples/instance_message_from_aleph.json",
    )
    FAKE_INSTANCE_MESSAGE: Path = Path(abspath(join(__file__, "../../../../examples/instance_message_from_aleph.json")))
    FAKE_INSTANCE_QEMU_MESSAGE: Path = Path(
        abspath(join(__file__, "../../../../examples/qemu_message_from_aleph.json"))
    )

    CHECK_FASTAPI_VM_ID: str = "d2b74aa29898457bde0560e47f7cdd4e77287e9f1f7a1456161d2fd7d5c855d7"
    LEGACY_CHECK_FASTAPI_VM_ID: str = "ad67c6857d6319486794ec2a3d14b584ac7e6c27593f3172148e486dbd1e0e21"

    # Developer options

    SENTRY_DSN: str | None = None
    SENTRY_TRACES_SAMPLE_RATE: float = Field(ge=0, le=1.0, default=0.1)
    DEVELOPER_SSH_KEYS: list[str] | None = []
    # Using an object here forces the value to come from Python code and not from an environment variable.
    USE_DEVELOPER_SSH_KEYS: Literal[False] | object = False

    # Fields
    SENSITIVE_FIELDS: list[str] = Field(
        default=["SENTRY_DSN"],
        description="Sensitive fields, redacted from `--print-settings`.",
    )

    # Used to control HA Proxy
    HAPROXY_SOCKET: Path = Field(
        default=Path("/run/haproxy/admin.sock"), description="Control HAPROXY for domain mapping"
    )

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key != key.upper():
                logger.warning(f"Setting {key} is not uppercase")
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                msg = f"Unknown setting '{key}'"
                raise ValueError(msg)

    def check(self):
        """Check that the settings are valid. Call this method after self.setup()."""
        assert Path("/dev/kvm").exists(), "KVM not found on `/dev/kvm`."
        assert isfile(self.FIRECRACKER_PATH), f"File not found {self.FIRECRACKER_PATH}"
        assert isfile(self.JAILER_PATH), f"File not found {self.JAILER_PATH}"
        assert isfile(self.LINUX_PATH), f"File not found {self.LINUX_PATH}"
        assert self.NETWORK_INTERFACE, "Network interface is not specified"
        assert str(self.CONNECTOR_URL).startswith("http://") or str(self.CONNECTOR_URL).startswith("https://")
        if self.ALLOW_VM_NETWORKING:
            assert exists(
                f"/sys/class/net/{self.NETWORK_INTERFACE}"
            ), f"Network interface {self.NETWORK_INTERFACE} does not exist"

            _, ipv4_pool_length = settings.IPV4_ADDRESS_POOL.split("/")
            assert (
                int(ipv4_pool_length) <= settings.IPV4_NETWORK_PREFIX_LENGTH
            ), "The IPv4 address pool prefix must be shorter than an individual VM network prefix"

        if self.FAKE_DATA_PROGRAM:
            assert self.FAKE_DATA_PROGRAM, "Local fake program directory not specified"
            assert self.FAKE_DATA_MESSAGE, "Local fake message not specified"
            assert self.FAKE_DATA_DATA, "Local fake data directory not specified"
            assert self.FAKE_DATA_RUNTIME, "Local runtime .squashfs build not specified"
            assert self.FAKE_DATA_VOLUME, "Local data volume .squashfs not specified"

            assert isdir(
                self.FAKE_DATA_PROGRAM
            ), f"Local fake program directory is missing, no directory '{self.FAKE_DATA_PROGRAM}'"
            assert isfile(self.FAKE_DATA_MESSAGE), f"Local fake message '{self.FAKE_DATA_MESSAGE}' not found"
            assert isdir(self.FAKE_DATA_DATA), f"Local fake data directory '{self.FAKE_DATA_DATA}' is missing"
            assert isfile(
                self.FAKE_DATA_RUNTIME
            ), f"Local runtime '{self.FAKE_DATA_RUNTIME}' is missing, did you build it ?"
            assert isfile(
                self.FAKE_DATA_VOLUME
            ), f"Local data volume '{self.FAKE_DATA_VOLUME}' is missing, did you build it ?"

        assert is_command_available("setfacl"), "Command `setfacl` not found, run `apt install acl`"
        if self.USE_NDP_PROXY:
            assert is_command_available("ndppd"), "Command `ndppd` not found, run `apt install ndppd`"

        # Necessary for cloud-init customisation of instance
        assert is_command_available(
            "cloud-localds"
        ), "Command `cloud-localds` not found, run `apt install cloud-image-utils`"

        if self.ENABLE_QEMU_SUPPORT:
            # Qemu support
            assert is_command_available("qemu-img"), "Command `qemu-img` not found, run `apt install qemu-utils`"
            assert is_command_available(
                "qemu-system-x86_64"
            ), "Command `qemu-system-x86_64` not found, run `apt install qemu-system-x86`"

        if self.ENABLE_CONFIDENTIAL_COMPUTING:
            assert self.SEV_CTL_PATH.is_file(), f"File not found {self.SEV_CTL_PATH}"
            assert check_amd_sev_supported(), "SEV feature isn't enabled, enable it in BIOS"
            assert check_amd_sev_es_supported(), "SEV-ES feature isn't enabled, enable it in BIOS"
            # Not available on the test machine yet
            # assert check_amd_sev_snp_supported(), "SEV-SNP feature isn't enabled, enable it in BIOS"
            assert self.ENABLE_QEMU_SUPPORT, "Qemu Support is needed for confidential computing and it's disabled, "
            "enable it setting the env variable `ENABLE_QEMU_SUPPORT=True` in configuration"
        if self.ENABLE_GPU_SUPPORT:
            assert self.ENABLE_QEMU_SUPPORT, "Qemu Support is needed for GPU support and it's disabled, "

    def setup(self):
        """Setup the environment defined by the settings. Call this method after loading the settings."""

        # Update chain RPC
        STREAM_CHAINS[Chain.AVAX].rpc = str(self.RPC_AVAX)
        STREAM_CHAINS[Chain.BASE].rpc = str(self.RPC_BASE)

        if self.MESSAGE_CACHE:
            os.makedirs(self.MESSAGE_CACHE, exist_ok=True)
        if self.CODE_CACHE:
            os.makedirs(self.CODE_CACHE, exist_ok=True)
        if self.RUNTIME_CACHE:
            os.makedirs(self.RUNTIME_CACHE, exist_ok=True)
        if self.DATA_CACHE:
            os.makedirs(self.DATA_CACHE, exist_ok=True)

        os.makedirs(self.EXECUTION_ROOT, exist_ok=True)

        # If the Linux kernel provided is on another device than the execution root,
        # copy it to the execution root to allow hardlink creation within jailer directories.
        if os.stat(self.LINUX_PATH).st_dev != os.stat(self.EXECUTION_ROOT).st_dev:
            logger.info("The Linux kernel is on another device than the execution root. Creating a copy.")
            linux_path_on_device = self.EXECUTION_ROOT / "vmlinux.bin"

            # Only copy if the hash of the file differ.
            if file_hashes_differ(self.LINUX_PATH, linux_path_on_device):
                shutil.copy(self.LINUX_PATH, linux_path_on_device)

            self.LINUX_PATH = linux_path_on_device

        if self.EXECUTION_LOG_DIRECTORY:
            os.makedirs(self.EXECUTION_LOG_DIRECTORY, exist_ok=True)
        if self.PERSISTENT_VOLUMES_DIR:
            os.makedirs(self.PERSISTENT_VOLUMES_DIR, exist_ok=True)
        if self.CONFIDENTIAL_DIRECTORY:
            os.makedirs(self.CONFIDENTIAL_DIRECTORY, exist_ok=True)
        if self.CONFIDENTIAL_SESSION_DIRECTORY:
            os.makedirs(self.CONFIDENTIAL_SESSION_DIRECTORY, exist_ok=True)

        self.API_SERVER = self.API_SERVER.rstrip("/")

        if not self.NETWORK_INTERFACE:
            self.NETWORK_INTERFACE = get_default_interface()

        if self.DNS_NAMESERVERS is None and self.DNS_RESOLUTION and self.NETWORK_INTERFACE:
            self.DNS_NAMESERVERS = obtain_dns_ips(
                dns_resolver=self.DNS_RESOLUTION,
                network_interface=self.NETWORK_INTERFACE,
            )

        if not self.DNS_NAMESERVERS_IPV4:
            self.DNS_NAMESERVERS_IPV4 = []
        if not self.DNS_NAMESERVERS_IPV6:
            self.DNS_NAMESERVERS_IPV6 = []
        if self.DNS_NAMESERVERS:
            for server in self.DNS_NAMESERVERS:
                ip_addr = ipaddress.ip_address(server)
                if isinstance(ip_addr, ipaddress.IPv4Address):
                    self.DNS_NAMESERVERS_IPV4.append(server)
                if isinstance(ip_addr, ipaddress.IPv6Address):
                    self.DNS_NAMESERVERS_IPV6.append(server)

        if not settings.ENABLE_QEMU_SUPPORT:
            # If QEmu is not supported, ignore the setting and use Firecracker by default
            settings.INSTANCE_DEFAULT_HYPERVISOR = HypervisorType.firecracker

    def display(self) -> str:
        attributes: dict[str, Any] = {}

        for attr in self.__dict__.keys():
            if attr != attr.upper():
                # Settings are expected to be ALL_UPPERCASE, other attributes snake_case or CamelCase
                continue

            if getattr(self, attr) and attr in self.SENSITIVE_FIELDS:
                attributes[attr] = "<REDACTED>"
            else:
                attributes[attr] = getattr(self, attr)

        return "\n".join(
            f"{self.model_config['env_prefix']}{attribute} = {value}" for attribute, value in attributes.items()
        )

    def __init__(
        self,
        _env_file: str | None = None,
        _env_file_encoding: str | None = None,
        _env_nested_delimiter: str | None = None,
        _secrets_dir: Path | None = None,
        **values: Any,
    ) -> None:
        super().__init__(_env_file, _env_file_encoding, _env_nested_delimiter, _secrets_dir, **values)
        if not self.MESSAGE_CACHE:
            self.MESSAGE_CACHE = self.CACHE_ROOT / "message"
        if not self.CODE_CACHE:
            self.CODE_CACHE = self.CACHE_ROOT / "code"
        if not self.RUNTIME_CACHE:
            self.RUNTIME_CACHE = self.CACHE_ROOT / "runtime"
        if not self.DATA_CACHE:
            self.DATA_CACHE = self.CACHE_ROOT / "data"
        if not self.CONFIDENTIAL_DIRECTORY:
            self.CONFIDENTIAL_DIRECTORY = self.CACHE_ROOT / "confidential"
        if not self.JAILER_BASE_DIRECTORY:
            self.JAILER_BASE_DIRECTORY = self.EXECUTION_ROOT / "jailer"
        if not self.PERSISTENT_VOLUMES_DIR:
            self.PERSISTENT_VOLUMES_DIR = self.EXECUTION_ROOT / "volumes" / "persistent"
        if not self.EXECUTION_DATABASE:
            self.EXECUTION_DATABASE = self.EXECUTION_ROOT / "executions.sqlite3"
        if not self.EXECUTION_LOG_DIRECTORY:
            self.EXECUTION_LOG_DIRECTORY = self.EXECUTION_ROOT / "executions"
        if not self.JAILER_BASE_DIR:
            self.JAILER_BASE_DIR = self.EXECUTION_ROOT / "jailer"
        if not self.CONFIDENTIAL_SESSION_DIRECTORY:
            self.CONFIDENTIAL_SESSION_DIRECTORY = self.EXECUTION_ROOT / "sessions"

    model_config = SettingsConfigDict(env_prefix="ALEPH_VM_", case_sensitive=False, env_file=".env")


def make_db_url():
    return f"sqlite+aiosqlite:///{settings.EXECUTION_DATABASE}"


def make_sync_db_url():
    return f"sqlite:///{settings.EXECUTION_DATABASE}"


# Settings singleton
settings = Settings()
