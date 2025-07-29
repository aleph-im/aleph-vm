import socket

from aleph.vm.network.firewall import check_nftables_redirections

MIN_DYNAMIC_PORT = 24000
MAX_PORT = 65535


def get_available_host_port(start_port: int | None = None) -> int:
    """Find an available port on the host system.

    Args:
        start_port: Optional starting port number. If not provided, starts from MIN_DYNAMIC_PORT

    Returns:
        An available port number

    Raises:
        RuntimeError: If no ports are available in the valid range
    """
    start_port = start_port if start_port and start_port >= MIN_DYNAMIC_PORT else MIN_DYNAMIC_PORT
    for port in range(start_port, MAX_PORT):
        try:
            # check if there is already a redirect to that port
            if check_nftables_redirections(port):
                continue
            # Try both TCP and UDP on all interfaces
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp_sock:
                tcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                tcp_sock.bind(("0.0.0.0", port))
                tcp_sock.listen(1)

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_sock:
                udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                udp_sock.bind(("0.0.0.0", port))

            return port

        except OSError:
            pass

    raise RuntimeError(f"No available ports found in range {MIN_DYNAMIC_PORT}-{MAX_PORT}")


LAST_ASSIGNED_HOST_PORT = MIN_DYNAMIC_PORT


def fast_get_available_host_port() -> int:
    """Find an available port on the host system.
    Use a global state to not start as each check may take several seconds and return a resulta faster

    Args:
        start_port: Optional starting port number. If not provided, starts from MIN_DYNAMIC_PORT

    Returns:
        An available port number

    Raises:
        RuntimeError: If no ports are available in the valid range
    """
    global LAST_ASSIGNED_HOST_PORT  # noqa: PLW0603
    host_port = get_available_host_port(start_port=LAST_ASSIGNED_HOST_PORT)
    LAST_ASSIGNED_HOST_PORT = host_port
    if LAST_ASSIGNED_HOST_PORT > MAX_PORT:
        LAST_ASSIGNED_HOST_PORT = MIN_DYNAMIC_PORT
    return host_port
