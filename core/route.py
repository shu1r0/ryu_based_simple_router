from enum import Enum


class RouteCodes(Enum):

    CONNECTED = 0
    STATIC = 1


class Route:
    """Route

    Attributes:
        ip_dst (IPv4Network) :
        out_port (int) :
        route_code (RouteCodes) :
        ad (int) : administrative distance
        next_hop (IPv4Address) :
    """

    def __init__(self, ip_dst, out_port, route_code, ad=-1, next_hop=None):
        self.ip_dst = ip_dst
        self.out_port = out_port
        self.route_code = route_code
        self.ad = ad if ad != -1 else route_code.value
        self.next_hop = next_hop

    @property
    def ip_dst_network(self):
        return str(self.ip_dst.network_address)

    @property
    def ip_dst_mask(self):
        return self.ip_dst.netmask

    @property
    def ip_dst_prefixlen(self):
        return self.ip_dst.prefixlen

    @property
    def priority(self):
        """return value combining the prefix and the AD value

        Returns:
            int : priority
        """
        return (self.ip_dst_prefixlen << 8) + (255 - self.ad)