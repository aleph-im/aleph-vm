from collections.abc import Iterator
from ipaddress import IPv4Interface, IPv4Network


class IPv4NetworkWithInterfaces(IPv4Network):
    def hosts(self) -> Iterator[IPv4Interface]:
        network = int(self.network_address)
        broadcast = int(self.broadcast_address)
        for x in range(network + 1, broadcast):
            yield IPv4Interface((x, self.prefixlen))

    def __getitem__(self, n) -> IPv4Interface:
        network = int(self.network_address)
        broadcast = int(self.broadcast_address)
        if n >= 0:
            if network + n > broadcast:
                msg = "address out of range"
                raise IndexError(msg)
            return IPv4Interface((network + n, self.prefixlen))
        else:
            n += 1
            if broadcast + n < network:
                msg = "address out of range"
                raise IndexError(msg)
            return IPv4Interface((broadcast + n, self.prefixlen))
