import logging
import os
import re
from enum import Enum
from os.path import isfile, join, exists
from subprocess import check_output
from typing import NewType, Optional, List

from pydantic import BaseSettings
from .models import FilePath

logger = logging.getLogger(__name__)

Url = NewType("Url", str)


class DnsResolver(str, Enum):
    resolv_conf = "resolv.conf"  # Simply copy from /etc/resolv.conf
    resolvectl = "resolvectl"  # Systemd-resolved, common on Ubuntu


def etc_resolv_conf_dns_servers():
    with open("/etc/resolv.conf", "r") as resolv_file:
        for line in resolv_file.readlines():
            ip = re.findall(r"^nameserver\s+([\w.]+)$", line)
            if ip:
                yield ip[0]


def systemd_resolved_dns_servers(interface):
    ## Example output format from systemd-resolve --status {interface}:
    # Link 2 (enp7s0)
    #       Current Scopes: DNS
    # DefaultRoute setting: yes
    #        LLMNR setting: yes
    # MulticastDNS setting: no
    #   DNSOverTLS setting: no
    #       DNSSEC setting: no
    #     DNSSEC supported: no
    #   Current DNS Server: 213.133.100.100
    #          DNS Servers: 213.133.100.100
    #                       213.133.98.98
    #                       213.133.99.99
    #                       2a01:4f8:0:1::add:9898
    #                       2a01:4f8:0:1::add:1010
    #                       2a01:4f8:0:1::add:9999
    output = check_output(["/usr/bin/systemd-resolve", "--status", interface])
    nameserver_line = False
    for line in output.split(b"\n"):
        if b"DNS Servers" in line:
            nameserver_line = True
            _, ip = line.decode().split(":", 1)
            yield ip.strip()
        elif nameserver_line:
            ip = line.decode().strip()
            if ip:
                yield ip


class Settings(BaseSettings):
    START_ID_INDEX: int = 4
    PREALLOC_VM_COUNT: int = 0
    REUSE_TIMEOUT: float = 60 * 60.0
    NETWORK_INTERFACE: str = "eth0"
    DNS_RESOLUTION: Optional[DnsResolver] = DnsResolver.resolv_conf
    DNS_NAMESERVERS: Optional[List[str]] = None

    API_SERVER: str = "https://api2.aleph.im"
    USE_JAILER: bool = True
    # System logs make boot ~2x slower
    PRINT_SYSTEM_LOGS: bool = False
    # Networking does not work inside Docker/Podman
    ALLOW_VM_NETWORKING: bool = True
    FIRECRACKER_PATH: str = "/opt/firecracker/firecracker"
    JAILER_PATH: str = "/opt/firecracker/jailer"
    LINUX_PATH: str = os.path.abspath("./kernels/vmlinux.bin")

    CONNECTOR_URL: Url = Url("http://localhost:8000")

    CACHE_ROOT: FilePath = FilePath("/tmp/aleph/vm_supervisor")
    MESSAGE_CACHE: FilePath = FilePath(join(CACHE_ROOT, "message"))
    CODE_CACHE: FilePath = FilePath(join(CACHE_ROOT, "code"))
    RUNTIME_CACHE: FilePath = FilePath(join(CACHE_ROOT, "runtime"))
    DATA_CACHE: FilePath = FilePath(join(CACHE_ROOT, "data"))

    FAKE_DATA: bool = False

    def update(self, **kwargs):
        for key, value in kwargs.items():
            if key != key.upper():
                logger.warning(f"Setting {key} is not uppercase")
            if hasattr(self, key):
                setattr(self, key, value)
            else:
                raise ValueError(f"Unknown setting '{key}'")

    def check(self):
        assert isfile(self.FIRECRACKER_PATH)
        assert isfile(self.JAILER_PATH)
        assert isfile(self.LINUX_PATH)
        assert self.CONNECTOR_URL.startswith(
            "http://"
        ) or self.CONNECTOR_URL.startswith("https://")
        if self.ALLOW_VM_NETWORKING:
            assert exists(f"/sys/class/net/{self.NETWORK_INTERFACE}")

    def setup(self):
        os.makedirs(self.MESSAGE_CACHE, exist_ok=True)
        os.makedirs(self.CODE_CACHE, exist_ok=True)
        os.makedirs(self.RUNTIME_CACHE, exist_ok=True)
        os.makedirs(self.DATA_CACHE, exist_ok=True)

        if self.DNS_NAMESERVERS is None and self.DNS_RESOLUTION:
            if self.DNS_RESOLUTION == DnsResolver.resolv_conf:
                self.DNS_NAMESERVERS = list(etc_resolv_conf_dns_servers())


            elif self.DNS_RESOLUTION == DnsResolver.resolvectl:
                self.DNS_NAMESERVERS = list(systemd_resolved_dns_servers(
                    interface=self.NETWORK_INTERFACE))
            else:
                assert "This should never happen"


    def display(self) -> str:
        return "\n".join(
            f"{annotation:<17} = {getattr(self, annotation)}"
            for annotation, value in self.__annotations__.items()
        )

    class Config:
        env_prefix = "ALEPH_VM_"
        case_sensitive = False


# Settings singleton
settings = Settings()
