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
    list = await haproxy.fetch_list()
    assert len(list) == 9


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

    haproxy.update_mapfile(instance_list, str(map_file_path), 22)
    content = map_file_path.read_text()
    assert content == "echo.agot.be 172.16.4.2:22\n"


@pytest.fixture
def mock_socket_command(mocker):
    commands = []
    existing_servers: list[str] = []

    def mock_response(socket_path, command):  # noqa: ARG001
        commands.append(command)
        if "show servers state" in command:
            return "1\n# be_id be_name srv_id srv_name srv_addr srv_op_state\n" + "\n".join(mock.existing_servers)
        elif "disable server" in command:
            return ""
        elif "set server" in command:
            return ""
        elif "enable server" in command:
            return ""
        return ""

    mock = mocker.patch("aleph.vm.haproxy.send_socket_command", mock_response)
    mock.existing_servers = existing_servers
    mock.commands = commands
    return mock


@pytest.mark.asyncio
async def test_update_backend_add_server(mock_socket_command, tmp_path):
    map_file_path = tmp_path / "backend.map"
    map_file_path.write_text("echo.agot.be 172.16.4.2:22\n")
    socket_path = "fakyfake"

    # Run test
    haproxy.update_haproxy_backends(socket_path, "test_backend", map_file_path, weight=1)

    # Verify commands
    assert mock_socket_command.commands == [
        "show servers state test_backend",
        # "disable server test_backend echo.agot.be",
        "add server test_backend/echo.agot.be 172.16.4.2:22 weight 1 maxconn 30",
        # "set server test_backend echo.agot.be addr 172.16.4.2 port 22",
        # "set server test_backend echo.agot.be weight 1",
        "enable server test_backend/echo.agot.be",
    ]


@pytest.mark.asyncio
def test_update_backend_add_server_remove_server(mock_socket_command, tmp_path):
    map_file_path = tmp_path / "backend.map"
    map_file_path.write_text("echo.agot.be 172.16.4.2:22\n")
    socket_path = "fakyfake"

    mock_socket_command.existing_servers = [
        "8 test_backend 1 existing_bk 127.0.0.1 2 0 1 1 683294 1 0 2 0 0 0 0 - 4020 - 0 0 - - 0"
    ]
    haproxy.update_haproxy_backends(socket_path, "test_backend", map_file_path, weight=1)

    # Verify commands
    assert mock_socket_command.commands == [
        "show servers state test_backend",
        "add server test_backend/echo.agot.be 172.16.4.2:22 weight 1 maxconn 30",
        "enable server test_backend/echo.agot.be",
        "set  server test_backend/existing_bk state maint",
        "del server test_backend/existing_bk",
    ]


@pytest.mark.asyncio
def test_update_backend_do_no_remove_fallback(mock_socket_command, tmp_path):
    map_file_path = tmp_path / "backend.map"
    map_file_path.write_text("echo.agot.be 172.16.4.2:22\n")
    socket_path = "fakyfake"

    mock_socket_command.existing_servers = [
        "8 test_backend 1 fallback_local 127.0.0.1 2 0 1 1 683294 1 0 2 0 0 0 0 - 4020 - 0 0 - - 0"
    ]
    haproxy.update_haproxy_backends(socket_path, "test_backend", map_file_path, weight=1)

    # Verify commands
    assert mock_socket_command.commands == [
        "show servers state test_backend",
        "add server test_backend/echo.agot.be 172.16.4.2:22 weight 1 maxconn 30",
        "enable server test_backend/echo.agot.be",
    ]
