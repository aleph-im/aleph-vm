"""Agent-side program guest client: volume mapping + configuration build."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ProgramContent
from aleph_message.models.execution.base import Encoding

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.program import FileTooLargeError
from aleph.vm.orchestrator.vm.program_client import (
    build_code_and_volumes,
    build_program_configuration,
)
from aleph.vm.supervisor.types import Backend, IpAssignment, VmId, VmInfo, VmStatus

VM_HASH = "feed" * 16


def _resources(tmp_path: Path, *, encoding: Encoding, volumes: int = 2) -> SimpleNamespace:
    code_path = tmp_path / "code.bin"
    code_path.write_bytes(b"code!")
    return SimpleNamespace(
        code_encoding=encoding,
        code_entrypoint="main:app",
        code_interface="asgi",
        code_path=code_path,
        data_path=None,
        volumes=[
            SimpleNamespace(mount=f"/data{index}", read_only=index % 2 == 0, path_on_host=tmp_path / f"v{index}")
            for index in range(volumes)
        ],
    )


def _info(**overrides) -> VmInfo:
    defaults = dict(
        vm_id=VmId(VM_HASH),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(address="172.16.4.2", network_cidr="172.16.4.0/24", gateway="172.16.4.1"),
        ipv6=IpAssignment(address="fd00::42", network_cidr="fd00::/124", gateway="fd00::1"),
        uptime_secs=0,
        backend=Backend.FIRECRACKER,
        numa_node=None,
        status_message="",
        guest_channel_path="/tmp/v.sock",
        guest_ready_payload=b"",
    )
    defaults.update(overrides)
    return VmInfo(**defaults)


def _content() -> MagicMock:
    content = MagicMock()
    content.__class__ = ProgramContent
    content.variables = {"KEY": "VALUE"}
    content.authorized_keys = ["ssh-ed25519 AAAA user@host"]
    return content


def test_volumes_with_squashfs_code(tmp_path):
    code, volumes = build_code_and_volumes(_resources(tmp_path, encoding=Encoding.squashfs))
    # The CODE drive takes vdb; volumes follow.
    assert code == b""
    assert [(volume.mount, volume.device) for volume in volumes] == [
        ("/opt/code", "vdb"),
        ("/data0", "vdc"),
        ("/data1", "vdd"),
    ]


def test_volumes_with_inline_code(tmp_path):
    code, volumes = build_code_and_volumes(_resources(tmp_path, encoding=Encoding.zip))
    assert code == b"code!"
    assert [(volume.mount, volume.device) for volume in volumes] == [("/data0", "vdb"), ("/data1", "vdc")]


def test_inline_code_too_large(tmp_path, mocker):
    mocker.patch.object(settings, "MAX_PROGRAM_ARCHIVE_SIZE", 1)
    with pytest.raises(FileTooLargeError):
        build_code_and_volumes(_resources(tmp_path, encoding=Encoding.zip))


def test_configuration_network_fields(tmp_path, mocker):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", True)
    mocker.patch.object(settings, "DNS_NAMESERVERS", ["1.1.1.1"])
    mocker.patch.object(settings, "DNS_NAMESERVERS_IPV4", ["1.1.1.1"])
    mocker.patch.object(settings, "DNS_NAMESERVERS_IPV6", ["2606:4700::1111"])
    mocker.patch.object(settings, "USE_DEVELOPER_SSH_KEYS", False)

    config = build_program_configuration(_info(), _content(), _resources(tmp_path, encoding=Encoding.zip))

    assert config.ip == "172.16.4.2"
    assert config.route == "172.16.4.1"
    # Guest IPv6 is recomposed with the tap network's prefix length.
    assert config.ipv6 == "fd00::42/124"
    assert config.ipv6_gateway == "fd00::1"
    assert config.dns_servers == ["1.1.1.1", "2606:4700::1111"]
    assert config.vm_hash == VM_HASH
    assert config.entrypoint == "main:app"
    assert config.variables == {"KEY": "VALUE"}
    assert config.authorized_keys == ["ssh-ed25519 AAAA user@host"]


def test_configuration_without_networking(tmp_path, mocker):
    mocker.patch.object(settings, "USE_DEVELOPER_SSH_KEYS", False)
    info = _info(ipv4=IpAssignment(), ipv6=IpAssignment())

    config = build_program_configuration(info, _content(), _resources(tmp_path, encoding=Encoding.zip))

    assert config.ip is None
    assert config.ipv6 is None
    assert config.route is None
    assert config.dns_servers == []


def test_configuration_requires_dns_when_networked(tmp_path, mocker):
    mocker.patch.object(settings, "ALLOW_VM_NETWORKING", True)
    mocker.patch.object(settings, "DNS_NAMESERVERS", None)

    with pytest.raises(ValueError, match="DNS nameservers missing"):
        build_program_configuration(_info(), _content(), _resources(tmp_path, encoding=Encoding.zip))


def test_ready_payload_parsing():
    import msgpack

    from aleph.vm.orchestrator.vm.program_client import (
        runtime_config_from_ready_payload,
    )

    # The Aleph runtime sends a msgpack version handshake with its ready signal.
    config = runtime_config_from_ready_payload(msgpack.dumps({"version": "2.0.0"}))
    assert config.version == "2.0.0"
    # Older runtimes send nothing: 1.0.0, same defaulting the hypervisor-side
    # parser applied before the payload became opaque pass-through.
    assert runtime_config_from_ready_payload(b"").version == "1.0.0"
