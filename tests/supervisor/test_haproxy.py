import pytest

from aleph.vm import haproxy

# Sample response for https://api.dns.public.aleph.sh/instances/list
sample_domain_instance_list = [
    {
        "name": "api-dev.thronetools.com",
        "item_hash": "747b52c712e16642b498f16c4c6e68d5fb00ddbaf8d2a0dc7bd298d33abb9124",
        "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.15.1/32"},
    },
    {
        "name": "centurion.cybernetwork.me",
        "item_hash": "cefb9373558927d70365746900a410f01e1340ecff0dda93deb672f55bb70ac8",
        "ipv6": "2a01:240:ad00:2502:3:cefb:9373:5581",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.52.1/32"},
    },
    {
        "name": "cms-dev.thronetools.com",
        "item_hash": "747b52c712e16642b498f16c4c6e68d5fb00ddbaf8d2a0dc7bd298d33abb9124",
        "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.15.1/32"},
    },
    {
        "name": "platform-api.3mera.dev",
        "item_hash": "d78e81d99e7468302bdaf82b5ca338b486629cf813384bdc3282e2b8fa7f478f",
        "ipv6": "2a01:240:ad00:2502:3:d78e:81d9:9e71",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.30.1/32"},
    },
    {
        "name": "platform-variants.3mera.dev",
        "item_hash": "d78e81d99e7468302bdaf82b5ca338b486629cf813384bdc3282e2b8fa7f478f",
        "ipv6": "2a01:240:ad00:2502:3:d78e:81d9:9e71",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.30.1/32"},
    },
    {
        "name": "platform.3mera.dev",
        "item_hash": "d78e81d99e7468302bdaf82b5ca338b486629cf813384bdc3282e2b8fa7f478f",
        "ipv6": "2a01:240:ad00:2502:3:d78e:81d9:9e71",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.30.1/32"},
    },
    {
        "name": "praetorian.cybernetwork.me",
        "item_hash": "ec18fa850f6a530a8c0e6a616b0df5def3ab3662eb6feeba8ece580780a86dc6",
        "ipv6": "2a01:240:ad00:2502:3:ec18:fa85:f61",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.19.1/32"},
    },
    {
        "name": "template-frontend.3mera.dev",
        "item_hash": "d78e81d99e7468302bdaf82b5ca338b486629cf813384bdc3282e2b8fa7f478f",
        "ipv6": "2a01:240:ad00:2502:3:d78e:81d9:9e71",
        "ipv4": {"public": "46.247.131.211", "local": "172.16.30.1/32"},
    },
    {
        "name": "test-twentysix-cloud.gerardmolina.com",
        "item_hash": "31826cf53c655bd25d50f7e371242baf240d4f854372c798a37bb9eb6c562682",
        "ipv6": "2a01:240:ad00:2501:3:3182:6cf5:3c61",
        "ipv4": {"public": "46.255.204.201", "local": "172.16.5.1/32"},
    },
]


@pytest.fixture
def mock_sample_domain_instance_list(mocker):
    mocker.patch("aleph.vm.haproxy.fetch_list", mocker.AsyncMock(return_value=sample_domain_instance_list))


@pytest.mark.asyncio
async def test_fetch_list(mock_sample_domain_instance_list):
    instance_list = await haproxy.fetch_list()
    assert len(instance_list) == 9


def test_resolve_vm_ip():
    assert haproxy._resolve_vm_ip("172.16.4.1/32") == "172.16.4.2"
    assert haproxy._resolve_vm_ip("172.16.11.1/32") == "172.16.11.2"
    assert haproxy._resolve_vm_ip("172.16.4.2") == "172.16.4.2"
    assert haproxy._resolve_vm_ip(None) is None


def test_build_map_entries():
    instances = [
        {
            "name": "echo.agot.be",
            "ipv4": {"local": "172.16.4.1/32"},
        },
        {
            "name": "skip.example.com",
            "ipv4": {"local": None},
        },
    ]
    entries = haproxy._build_map_entries(instances)
    assert entries == {"echo.agot.be": "172.16.4.2"}


def test_update_mapfile(tmp_path):
    map_file = tmp_path / "test.map"
    entries = {"echo.agot.be": "172.16.4.2", "api.example.com": "172.16.5.2"}

    # First write — should update
    assert haproxy.update_mapfile(entries, str(map_file)) is True
    content = map_file.read_text()
    assert "api.example.com 172.16.5.2\n" in content
    assert "echo.agot.be 172.16.4.2\n" in content

    # Second write — same content, no update
    assert haproxy.update_mapfile(entries, str(map_file)) is False


@pytest.fixture
def mock_haproxy_socket(mocker):
    """Mock HAProxy socket commands, tracking all sent commands."""
    commands = []
    runtime_mappings: dict[str, str] = {}

    def mock_response(socket_path, command):  # noqa: ARG001
        commands.append(command)
        if "show map" in command:
            lines = [f"0x{i:012x} {k} {v}" for i, (k, v) in enumerate(runtime_mappings.items())]
            return "\n".join(lines) + "\n" if lines else ""
        if "clear map" in command:
            runtime_mappings.clear()
            return ""
        if "add map" in command:
            parts = command.split()
            if len(parts) >= 5:
                runtime_mappings[parts[3]] = parts[4]
            return ""
        return ""

    mock = mocker.patch("aleph.vm.haproxy.send_socket_command", mock_response)
    mock.commands = commands
    mock.runtime_mappings = runtime_mappings
    mock.socket_path = "/fakepath/to/haproxy.sock"
    return mock


def test_sync_runtime_map(mock_haproxy_socket):
    entries = {"echo.agot.be": "172.16.4.2", "api.example.com": "172.16.5.2"}
    haproxy.sync_runtime_map(mock_haproxy_socket.socket_path, "/etc/haproxy/test.map", entries)

    assert "clear map /etc/haproxy/test.map" in mock_haproxy_socket.commands
    assert "add map /etc/haproxy/test.map echo.agot.be 172.16.4.2" in mock_haproxy_socket.commands
    assert "add map /etc/haproxy/test.map api.example.com 172.16.5.2" in mock_haproxy_socket.commands


def test_update_backends_syncs_when_runtime_empty(mock_haproxy_socket, tmp_path):
    """After HAProxy restart, map file is correct but runtime is empty."""
    map_file = tmp_path / "test.map"
    # Pre-populate file so file_updated=False
    map_file.write_text("echo.agot.be 172.16.4.2\n")

    instances = [
        {
            "name": "echo.agot.be",
            "item_hash": "deca" * 16,
            "ipv4": {"local": "172.16.4.1/32"},
        }
    ]

    haproxy.update_backends(
        map_file_path=str(map_file),
        socket_path=mock_haproxy_socket.socket_path,
        instances=instances,
    )

    # Runtime was empty, so sync should have happened
    assert "clear map" in " ".join(mock_haproxy_socket.commands)
    assert "add map" in " ".join(mock_haproxy_socket.commands)


def test_update_backends_skips_when_in_sync(mock_haproxy_socket, tmp_path):
    """When file and runtime match, no update needed."""
    map_file = tmp_path / "test.map"
    map_file.write_text("echo.agot.be 172.16.4.2\n")

    # Pre-populate runtime
    mock_haproxy_socket.runtime_mappings["echo.agot.be"] = "172.16.4.2"

    instances = [
        {
            "name": "echo.agot.be",
            "item_hash": "deca" * 16,
            "ipv4": {"local": "172.16.4.1/32"},
        }
    ]

    haproxy.update_backends(
        map_file_path=str(map_file),
        socket_path=mock_haproxy_socket.socket_path,
        instances=instances,
    )

    # Only show map for checking, no clear/add
    assert "clear map" not in " ".join(mock_haproxy_socket.commands)


def test_update_backends_with_multidigit_octets(mock_haproxy_socket, tmp_path):
    """Regression: IP 172.16.11.1 should become 172.16.11.2, not 172.16.2."""
    map_file = tmp_path / "test.map"

    instances = [
        {
            "name": "n8n.aleph.im",
            "item_hash": "deca" * 16,
            "ipv4": {"local": "172.16.11.1/32"},
        }
    ]

    haproxy.update_backends(
        map_file_path=str(map_file),
        socket_path=mock_haproxy_socket.socket_path,
        instances=instances,
    )

    content = map_file.read_text()
    assert "n8n.aleph.im 172.16.11.2\n" in content
    assert "add map" in " ".join(mock_haproxy_socket.commands)
    assert "172.16.11.2" in " ".join(mock_haproxy_socket.commands)
