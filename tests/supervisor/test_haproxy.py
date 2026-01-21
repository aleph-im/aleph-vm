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
    istance_list = await haproxy.fetch_list()
    assert len(istance_list) == 9


@pytest.fixture
def mock_small_domain_list(mocker):
    small_list = [
        {
            "name": "echo.agot.be",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.4.1/32"},
        }
    ]
    mocker.patch("aleph.vm.haproxy.fetch_list", mocker.AsyncMock(return_value=small_list))


@pytest.mark.asyncio
async def test_update_map_file(mock_small_domain_list, tmp_path):
    map_file_path = tmp_path / "backend.map"
    instance_list = await haproxy.fetch_list()
    assert instance_list

    haproxy.update_mapfile(instance_list, str(map_file_path))
    content = map_file_path.read_text()
    assert content == "echo.agot.be echo.agot.be\n"


@pytest.fixture
def mock_haproxy_server(mocker):
    """Mock a haproxy proxy server by patching haproxy.send_socket_command

    Update the backend server response via:
        mock_socket_command.existing_servers = [
        "8 test_backend 1 existing_bk 127.0.0.1 2 0 1 1 683294 1 0 2 0 0 0 0 - 4020 - 0 0 - - 0"
    ]
    Idem existing mappings
    """
    commands = []

    existing_servers: list[str] = []
    existing_mappings: list[str] = []

    def mock_response(socket_path, command):  # noqa: ARG001
        commands.append(command)
        if "show servers state" in command:
            return "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state\n" + "\n".join(mock.existing_servers)
        if "show map" in command:
            return "\n" + "\n".join(mock.existing_mappings)
        elif "disable server" in command:
            return ""
        elif "set server" in command:
            return ""
        elif "enable server" in command:
            return ""
        return ""

    mock = mocker.patch("aleph.vm.haproxy.send_socket_command", mock_response)
    mock.existing_servers = existing_servers
    mock.existing_mappings = existing_mappings
    mock.socket_path = "/fakepath/to/haproxy.sock"
    mock.commands = commands
    return mock


@pytest.mark.asyncio
async def test_update_backend_add_server(mock_haproxy_server):
    instances = [
        {
            "name": "echo.agot.be",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.4.1/32"},
        }
    ]
    map_file_path = "fakyfake"

    # Run test
    haproxy.update_haproxy_backend(
        mock_haproxy_server.socket_path, "test_backend", instances, map_file_path, 22, weight=1
    )

    # Verify commands
    assert mock_haproxy_server.commands == [
        "show map fakyfake",
        "show servers state test_backend",
        "add server test_backend/echo.agot.be 172.16.4.2:22 weight 1 maxconn 30",
        "enable server test_backend/echo.agot.be",
        "add map fakyfake echo.agot.be echo.agot.be",
    ]


@pytest.mark.asyncio
def test_update_backend_add_server_remove_server(mock_haproxy_server):
    instances = [
        {
            "name": "echo.agot.be",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.4.1/32"},
        }
    ]

    map_file_path = "backend.map"

    mock_haproxy_server.existing_servers = [
        "8 test_backend 1 toremove.agot.be 127.0.0.1 2 0 1 1 683294 1 0 2 0 0 0 0 - 4020 - 0 0 - - 0"
    ]
    mock_haproxy_server.existing_mappings = ["0x563a8ebca6b0 toremove.agot.be toremove.agot.be"]
    haproxy.update_haproxy_backend(
        mock_haproxy_server.socket_path, "test_backend", instances, map_file_path, 22, weight=1
    )

    # Verify commands
    assert mock_haproxy_server.commands == [
        "show map backend.map",
        "show servers state test_backend",
        "add server test_backend/echo.agot.be 172.16.4.2:22 weight 1 maxconn 30",
        "enable server test_backend/echo.agot.be",
        "add map backend.map echo.agot.be echo.agot.be",
        "set  server test_backend/toremove.agot.be state maint",
        "del server test_backend/toremove.agot.be",
    ]


@pytest.mark.asyncio
def test_update_backend_do_no_remove_fallback(mock_haproxy_server):
    instances = [
        {
            "name": "echo.agot.be",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.4.1/32"},
        }
    ]

    map_file_path = "backend.map"

    mock_haproxy_server.existing_servers = [
        "8 test_backend 1 fallback_local 127.0.0.1 2 0 1 1 683294 1 0 2 0 0 0 0 - 4020 - 0 0 - - 0"
    ]
    haproxy.update_haproxy_backend(
        mock_haproxy_server.socket_path, "test_backend", instances, map_file_path, 80, weight=1
    )

    # Verify commands
    assert mock_haproxy_server.commands == [
        "show map backend.map",
        "show servers state test_backend",
        "add server test_backend/echo.agot.be 172.16.4.2:80 weight 1 maxconn 30",
        "enable server test_backend/echo.agot.be",
        "add map backend.map echo.agot.be echo.agot.be",
    ]


@pytest.mark.asyncio
def test_update_backend_with_multidigit_octets(mock_haproxy_server):
    """Test that IP addresses with multi-digit octets ending in .1 are handled correctly.

    This is a regression test for a bug where rstrip(".1") was used instead of
    removesuffix(".1"), causing IPs like 172.16.11.1 to be incorrectly converted
    to 172.16.2 instead of 172.16.11.2.
    """
    instances = [
        {
            "name": "n8n.aleph.im",
            "item_hash": "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca",
            "ipv6": "2a01:240:ad00:2502:3:747b:52c7:12e1",
            "ipv4": {"public": "46.247.131.211", "local": "172.16.11.1/32"},
        }
    ]

    map_file_path = "backend.map"

    haproxy.update_haproxy_backend(
        mock_haproxy_server.socket_path, "test_backend", instances, map_file_path, 80, weight=1
    )

    # Verify the IP address is correctly converted to 172.16.11.2, NOT 172.16.2
    assert mock_haproxy_server.commands == [
        "show map backend.map",
        "show servers state test_backend",
        "add server test_backend/n8n.aleph.im 172.16.11.2:80 weight 1 maxconn 30",
        "enable server test_backend/n8n.aleph.im",
        "add map backend.map n8n.aleph.im n8n.aleph.im",
    ]
