from abc import ABCMeta, abstractmethod
import ipaddress
import yaml

from core.route import RouteCodes, Route
from util.router_log import get_logger

logger = get_logger(__name__)


class DatapathesConfig:
    """datapathes config"""

    def __init__(self):
        self.config = None
        with open('config/config.yaml', 'r') as f:
            dict_config = yaml.safe_load(f)
            logger.debug("read config : {}".format(dict_config))
            self.read(dict_config)

    def __getattr__(self, item):
        return getattr(self.config, item)

    def read(self, param):
        self.config = dict2obj(param)
        self._parse_ip_address()
        self._parse_routes()

    def _parse_ip_address(self):
        for datapath_config in props(self.config.datapathes).values():
            ints = datapath_config.interfaces
            for i in range(len(ints)):
                ints[i].ip_address = ipaddress.ip_interface(ints[i].ip_address)
            routes = datapath_config.routes
            for i in range(len(routes)):
                routes[i].ip_dst = ipaddress.ip_network(routes[i].ip_dst)
                routes[i].next_hop = ipaddress.ip_address(routes[i].next_hop)

    def _parse_routes(self):
        for datapath_config in props(self.config.datapathes).values():
            routes = datapath_config.routes
            for i in range(len(routes)):
                route = Route(routes[i].ip_dst, routes[i].out_port, RouteCodes.STATIC, next_hop=routes[i].next_hop)
                routes[i] = route

    def get_datapath(self, datapath_id):
        for dp in props(self.config.datapathes).values():
            if dp.datapath_id == datapath_id:
                return dp
        raise KeyError("unknown datapath id")

    def get_ports(self, datapath_id):
        return self.get_datapath(datapath_id).interfaces

    def get_port(self, datapath_id, port_no):
        for interface in self.get_ports(datapath_id):
            if interface.number == port_no:
                return interface
        return None

    def get_ip(self, datapath_id, port):
        return self.get_port(datapath_id, port).ip_address.ip

    def get_hw(self, datapath_id, port):
        return self.get_port(datapath_id, port).hw_addr

    def set_port(self, datapath_id, port_stats):
        port_no = port_stats.port_no
        port = self.get_port(datapath_id, port_no)
        if port:
            setattr(port, 'hw_addr', port_stats.hw_addr)

    def get_static_routes(self, datapath_id):
        return self.get_datapath(datapath_id).routes


def dict2obj(target_dict):
    top = type('props', (object,), {})
    seqs = (tuple, list, set, frozenset)
    for key, value in target_dict.items():
        if isinstance(key, int):
            key = str(key)

        if isinstance(value, dict):
            setattr(top, key, dict2obj(value))
        elif isinstance(value, seqs):
            setattr(top, key, type(value)(dict2obj(v) if isinstance(v, dict) else v for v in value))
        else:
            setattr(top, key, value)
    return top


def props(obj):
    pr = {}
    for name, value in vars(obj).items():
        if not name.startswith('__'):
            pr[name] = value
    return pr


dp_config = DatapathesConfig()

if __name__ == '__main__':
    config = DatapathesConfig()
    # config.print_config()
