from enum import Enum

from .route import Route, RouteCodes
from config.config import dp_config
from ipaddress import IPv4Network, IPv4Address, ip_address


class RoutingTable:

    def __init__(self):
        self.routes = {}

    def read_config(self, datapath_id):
        """load configuration file

        Args:
            datapath_id (int) :
        """
        self.set_local_route_from_config(datapath_id)
        routes = dp_config.get_static_routes(datapath_id)
        for route in routes:
            self.insert(datapath_id, route)

    def set_local_route_from_config(self, datapath_id):
        """set connected route

        Args:
            datapath_id (Datapath): datapath
        """
        ports = dp_config.get_ports(datapath_id)
        for port in ports:
            ip_dst = port.ip_address.network
            route = Route(ip_dst, port.number, RouteCodes.CONNECTED)
            self.insert(datapath_id, route)

    def insert(self, datapath_id, route):
        """add to be in priority order

        Args:
            datapath_id (int) :
            route (Route) :
        """
        self.routes.setdefault(datapath_id, [])
        inserted = False
        for i in range(len(self.routes[datapath_id])):
            if route.priority >= self.routes[datapath_id][i].priority:
                inserted = True
                self.routes[datapath_id].insert(i, route)
                break
        if not inserted:
            self.routes[datapath_id].append(route)

    def lookup(self, datapath_id, destination_ip_address):
        """return the route

        Args:
            datapath_id (int) :
            destination_ip_address (str or IPv4Address) :
        """
        if isinstance(destination_ip_address, str):
            destination_ip_address = ip_address(destination_ip_address)
        routes = self.routes[datapath_id]
        for route in routes:
            if destination_ip_address in route.ip_dst:
                if route.route_code == RouteCodes.CONNECTED:
                    route.next_hop = destination_ip_address
                return route
        return None

    def get(self, datapath_id):
        return self.routes[datapath_id]

    def get_next_hop(self, datapath_id, dst_ip):
        """get next hop

        Args:
            datapath_id (int) :
            dst_ip (str or IPv4address) :

        Returns:
            str : next hop adress
        """
        route = self.lookup(datapath_id, dst_ip)
        if route.route_code == RouteCodes.CONNECTED:
            return str(dst_ip)
        elif route.route_code == RouteCodes.STATIC:
            return route.next_hop


class ArpTable:

    def __init__(self):
        self.ip_to_mac = {}

    def add(self, datapath_id, ip, mac):
        self.ip_to_mac.setdefault(datapath_id, {})
        self.ip_to_mac[datapath_id][ip] = mac

    def remove(self, datapath_id, ip):
        self.ip_to_mac[datapath_id].pop(ip)

    def get_mac(self, datapath_id, ip):
        mac = None
        if datapath_id in self.ip_to_mac.keys():
            ipmac = self.get(datapath_id)
            if ip in ipmac.keys():
                mac = ipmac[ip]
        return mac

    def get(self, datapath_id):
        return self.ip_to_mac[datapath_id]

