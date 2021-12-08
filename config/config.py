from abc import ABCMeta, abstractmethod
import ipaddress
import yaml

from core.route import RouteCodes, Route
from util.router_log import get_logger

logger = get_logger(__name__)


class DatapathesConfig:
    """datapathes config"""

    def __init__(self):
        self._config = None
        self._dict_config = None
        with open('config/config.yaml', 'r') as f:
            dict_config = yaml.safe_load(f)
            logger.debug("read config : {}".format(dict_config))
            self.read(dict_config)

    def __getattr__(self, item):
        return getattr(self._config, item)

    def read(self, param):
        """read config

        Args:
            param (dict) : config param
        """
        self._config = dict2obj(param)
        self._dict_config = param
        self._parse_ip_address()
        self._parse_routes()

    def _parse_ip_address(self):
        """
        ip address to ``IPInterface``
        """
        for datapath_config in props(self._config.datapathes).values():
            # parse interfaces
            ints = datapath_config.interfaces
            for i in range(len(ints)):
                ints[i].ip_address = ipaddress.ip_interface(ints[i].ip_address)
            # parse routes
            routes = datapath_config.routes
            for i in range(len(routes)):
                routes[i].ip_dst = ipaddress.ip_network(routes[i].ip_dst)
                routes[i].next_hop = ipaddress.ip_address(routes[i].next_hop)

    def _parse_routes(self):
        """
        routes to ``Route``
        """
        for datapath_config in props(self._config.datapathes).values():
            routes = datapath_config.routes
            for i in range(len(routes)):
                route = Route(routes[i].ip_dst, routes[i].out_port, RouteCodes.STATIC, next_hop=routes[i].next_hop)
                routes[i] = route

    def get_datapath(self, datapath_id):
        """get datapath

        Args:
            datapath_id (int) : datapath id

        Returns:
            Datapath
        """
        for dp in props(self._config.datapathes).values():
            if dp.datapath_id == datapath_id:
                return dp
        raise KeyError("unknown datapath id")

    def get_ports(self, datapath_id):
        """get ports

        Args:
            datapath_id (int) :

        Returns:
            list[Interface]
        """
        return self.get_datapath(datapath_id).interfaces

    def get_port(self, datapath_id, port_no):
        """get port

        Args:
            datapath_id (int) :
            port_no (int) :

        Returns:
            Interface
        """
        for interface in self.get_ports(datapath_id):
            if interface.number == port_no:
                return interface
        return None

    def get_ip(self, datapath_id, port):
        """get ip address

        Args:
            datapath_id (int) : datapath id
            port (int) :  port

        Returns:
            IPv4Address
        """
        return self.get_port(datapath_id, port).ip_address.ip

    def get_hw(self, datapath_id, port):
        """get hw address (set by port stats)

        Args:
            datapath_id (int) :
            port (int) :

        Returns:
            str
        """
        return self.get_port(datapath_id, port).hw_addr

    def set_port(self, datapath_id, port_stats):
        port_no = port_stats.port_no
        port = self.get_port(datapath_id, port_no)
        if port:
            setattr(port, 'hw_addr', port_stats.hw_addr)

    def get_static_routes(self, datapath_id):
        """get route

        Args:
            datapath_id (int) :

        Returns:
            list[Route]
        """
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
    """obj to props dict

    Args:
        obj:

    Returns:
        dict
    """
    pr = {}
    for name, value in vars(obj).items():
        if not name.startswith('__'):
            pr[name] = value
    return pr


dp_config = DatapathesConfig()

if __name__ == '__main__':
    config = DatapathesConfig()
    # config.print_config()
