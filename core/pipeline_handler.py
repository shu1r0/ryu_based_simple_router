import ipaddress
from abc import ABCMeta, abstractmethod

from ryu.controller.controller import Datapath
from ryu.ofproto import ofproto_v1_3, ofproto_v1_3_parser
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet.ether_types import ETH_TYPE_ARP, ETH_TYPE_IP

# from core.pipeline import PIPELINE
from config.config import dp_config
from router import RouterCore, NEXT_HOP_METADATA_MASK
from .tables import RoutingTable, ArpTable
from .buffer import ArpTableBuffer
from .route import RouteCodes
from util.router_log import get_logger

logger = get_logger(__name__)


class PipelineHandler(metaclass=ABCMeta):
    """The base of handler for the pipeline table

    Attributes:
        table_id (int) : flow table id
        pipeline (PIPELINE) : PIPELINE class
    """

    def __init__(self, pipeline, table_id):
        self.table_id = table_id
        self.pipeline = pipeline

    @abstractmethod
    def add_default_flows(self, datapath):
        """add default flow when the datapath ready

        Args:
            datapath (Datapath) : datapath
        """
        raise NotImplementedError

    @abstractmethod
    def packet_in_handler(self, event):
        """Processing of packets-in that occurred in this table

        Args:
            event: Packet In event
        """
        raise NotImplementedError

    def flow_removed_handler(self, event):
        """このテーブルのフローが削除されたときの処理

        Args:
            event: Flow Removed event
        """
        pass

    def flow_mod(self, datapath, priority, match, inst):
        """flow modify with self table id

        Args:
            datapath (Datapath) : datapth
            priority (int) : priority
            match (OFPMatch) : match obj
            inst (list) : instruction list
        """
        RouterCore.flow_mod(datapath, self.table_id, priority, match, inst)


class IngressHandler(PipelineHandler):
    """Entry point for packet"""

    DEFAULT_FLOW_PRIORITY = 0x0000

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)

    def add_default_flows(self, datapath):
        """add default flows
         * goto Protocol Classifier

        Args:
            datapath (Datapath) : datapath
        """
        of_parser = datapath.ofproto_parser
        match = of_parser.OFPMatch()
        next_table = self.pipeline.PROTOCOL_CLASSIFIER.table_id
        instructions = [of_parser.OFPInstructionGotoTable(next_table)]
        self.flow_mod(datapath, self.DEFAULT_FLOW_PRIORITY, match, instructions)

    def packet_in_handler(self, event):
        raise NotImplementedError


class ProtocolClassifierHandler(PipelineHandler):
    """This assigns packets to subsequent tables by eth_type"""

    DEFAULT_CLASSIFIER_FLOW_PRIORITY = 0x0001

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)

    def add_default_flows(self, datapath):
        """add default flows

        Args:
            datapath (Datapath) : datapath
        """
        self.add_protocol_classifier_flow(datapath, ETH_TYPE_ARP, self.pipeline.ARP_RESPONDER.table_id)
        self.add_protocol_classifier_flow(datapath, ETH_TYPE_IP, self.pipeline.ROUTING_TABLE.table_id)

    def packet_in_handler(self, event):
        raise NotImplementedError

    def add_protocol_classifier_flow(self, datapath, eth_type, next_table_id):
        of_parser = datapath.ofproto_parser
        match = of_parser.OFPMatch(eth_type=eth_type)
        instructions = [of_parser.OFPInstructionGotoTable(next_table_id)]
        self.flow_mod(datapath, self.DEFAULT_CLASSIFIER_FLOW_PRIORITY, match, instructions)


class ArpResponderHandler(PipelineHandler):
    """This receives arp packet"""

    DEFAULT_ARP_FLOW_PRIORITY = 0x0001
    CACHE_FLOW_PRIORITY = 0x0010

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)

    def add_default_flows(self, datapath):
        """add default flows
         * Packet In when ARP directed at the datapath
        
        Args:
            datapath (Datapath) : datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        for port in dp_config.get_ports(datapath.id):
            match = parser.OFPMatch(eth_type=ETH_TYPE_ARP,
                                    arp_op=arp.ARP_REQUEST,
                                    in_port=port.number,
                                    arp_tpa=port.ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.flow_mod(datapath, self.DEFAULT_ARP_FLOW_PRIORITY, match, instructions)

            match = parser.OFPMatch(eth_type=ETH_TYPE_ARP,
                                    arp_op=arp.ARP_REPLY,
                                    in_port=port.number,
                                    arp_tpa=port.ip_address)
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            self.flow_mod(datapath, self.DEFAULT_ARP_FLOW_PRIORITY, match, instructions)

    def packet_in_handler(self, event):
        """Packet In when ARP directed at the datapath

         * ARP reply when ARP request is received
         * Save in ARP table when ARP reply is received
        
        Args:
            event:
        """
        msg = event.msg
        datapath = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            if pkt_arp.opcode == arp.ARP_REQUEST:
                self.arp_request_handler(datapath, in_port, pkt_eth, pkt_arp)
            elif pkt_arp.opcode == arp.ARP_REPLY:
                self.arp_reply_handler(datapath, in_port, pkt_arp)

    def arp_request_handler(self, datapath, in_port, pkt_eth, pkt_arp):
        """Reply to ARP request

        Args:
            datapath (Datapath) : datapath
            in_port (int) : in port
            pkt_eth (ethernet.ethernet) : request ethernet
            pkt_arp (arp.arp) : arp request
        """
        logger.debug("send arp reply (dst={})".format(pkt_arp.dst_ip))
        port_hw = dp_config.get_hw(datapath.id, in_port)
        port_ip = str(dp_config.get_ip(datapath.id, in_port))
        arp_reply = self.get_arp_reply_packet(pkt_eth, pkt_arp, port_hw, port_ip)
        RouterCore.send_packet(datapath, in_port, arp_reply)

    def arp_reply_handler(self, datapath, in_port, pkt_arp):
        """ave in ARP table

        Args:
            datapath (Datapath) : datapath
            pkt_arp (arp.arp) : arp reply packet
        """
        logger.debug("received arp reply (dst={})".format(pkt_arp.dst_ip))
        src_ip = pkt_arp.src_ip
        src_mac = pkt_arp.src_mac
        port_hw = dp_config.get_hw(datapath.id, in_port)
        self.add_flows_to_arp_table(datapath, port_hw, src_ip, src_mac)

    def get_arp_reply_packet(self, pkt_ethernet, pkt_arp_request, port_hw, port_ip):
        """generate arp reply packet

        Args:
            pkt_ethernet (ethernet.ethernet) :
            pkt_arp_request (arp.arp) :
            port_hw (str) :
            port_ip (str) :

        Returns:
            arp.arp : arp reply packet
        """
        pkt = packet.Packet()
        eth_proto = ethernet.ethernet(ethertype=ETH_TYPE_ARP,
                                      dst=pkt_ethernet.src,
                                      src=port_hw)
        pkt.add_protocol(eth_proto)
        arp_proto = arp.arp(opcode=arp.ARP_REPLY,
                            src_mac=port_hw,
                            src_ip=port_ip,
                            dst_mac=pkt_arp_request.src_mac,
                            dst_ip=pkt_arp_request.src_ip)
        pkt.add_protocol(arp_proto)
        return pkt

    def add_flows_to_arp_table(self, datapath, port_hw, ip, mac):
        """add ip and mac to ARP Table

        Args:
            datapath (Datapath) :
            port_hw (str) :
            ip (str) :
            mac (str) :
        """
        self.pipeline.ARP_TABLE.handler.add_arp_table_entry(datapath, port_hw, ip, mac)

    def add_cache_flow(self, datapath, ip, mac):
        """ARP Caching

        Args:
            datapath:
            ip:
            mac:
        """
        raise NotImplementedError


class RoutingTableHandler(PipelineHandler):
    """Routing Table

     * Determine the out port
     * Write the next hop address to the metadata
     * Send Packet In when connected route or no route
    """

    DEFAULT_FLOW_PRIORITY = 0x0000
    # base (1bit) address prefix (5bit) 255-AD (8bit) control (2bit)
    MIN_ROUTING_ENTRY_PRIORITY = 0x8000

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)
        self.routing_tables = RoutingTable()

    def add_default_flows(self, datapath):
        """add routing flow from config
        
        Args:
            datapath (Datapath) :
        """
        self.routing_tables.read_config(datapath.id)

        # no route
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.flow_mod(datapath, self.DEFAULT_FLOW_PRIORITY, match, instructions)

        for route in self.routing_tables.get(datapath.id):
            self.add_routing_flow(datapath, route)

    def packet_in_handler(self, event):
        """when connected route or no route

        Args:
            event:
        """
        msg = event.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        if msg.reason == ofproto.OFPR_ACTION:
            pkt = packet.Packet(msg.data)
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                route = self.get_route(datapath.id, pkt_ipv4.dst)
                handler = self.pipeline.ARP_TABLE.handler
                handler.address_resolve_and_send(datapath, pkt, route.next_hop, route.out_port)

    def add_routing_flow(self, datapath, route):
        """add routing flow

        Args:
            datapath (Datapath) :
            route (Route) :
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_TYPE_IP,
                                ipv4_dst=(route.ip_dst_network, route.ip_dst_mask))
        next_table = self.pipeline.ARP_TABLE.table_id

        if route.route_code == RouteCodes.CONNECTED:
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            instructions = [parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
            priority = self.MIN_ROUTING_ENTRY_PRIORITY + (route.priority << 2)
            self.flow_mod(datapath, priority, match, instructions)
        elif route.route_code == RouteCodes.STATIC:
            actions = [parser.OFPActionOutput(route.out_port)]
            next_hop = route.next_hop
            instructions = [parser.OFPInstructionActions(ofproto_v1_3.OFPIT_WRITE_ACTIONS, actions),
                            parser.OFPInstructionWriteMetadata(metadata=int(next_hop),
                                                               metadata_mask=NEXT_HOP_METADATA_MASK),
                            parser.OFPInstructionGotoTable(next_table)]
            priority = self.MIN_ROUTING_ENTRY_PRIORITY + (route.priority << 2)
            self.flow_mod(datapath, priority, match, instructions)

    def get_next_hop(self, datapath_id, dst_ip):
        """get next hop from routing table

        Args:
            datapath_id (int) :
            dst_ip (str) :

        Returns:
            IPv4Address: next hop
        """
        return self.routing_tables.get_next_hop(datapath_id, dst_ip)

    def get_route(self, datapath_id, dst_ip):
        """get route

        Args:
            datapath_id (int) :
            dst_ip (str) :

        Returns:
            Route or None: route
        """
        return self.routing_tables.lookup(datapath_id, dst_ip)


class ArpTableHandler(PipelineHandler):
    """ARP Table

     * Resolve Address
     * Change Ethernet address
     * Add entry to change Ethernet address
    """

    DEFAULT_FLOW_PRIORITY = 0x0000
    ARP_ENTRY_PRIORITY = 0x0010

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)
        self.arp_table = ArpTable()
        self.buffer = ArpTableBuffer(self.pipeline)

    def add_default_flows(self, datapath):
        """packet in by default

        Args:
            datapath (Datapath) : datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_TYPE_IP)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, []),
                        parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        self.flow_mod(datapath, self.DEFAULT_FLOW_PRIORITY, match, instructions)

    def packet_in_handler(self, event):
        """send arp request

        * This method is called when there is no ARP entry

        Args:
            event:
        """
        msg = event.msg
        datapath = msg.datapath
        pkt = packet.Packet(msg.data)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        if pkt_ipv4:
            handler = self.pipeline.ROUTING_TABLE.handler
            route = handler.get_route(datapath.id, pkt_ipv4.dst)
            self.buffer.add(datapath.id, pkt)
            RouterCore.send_arp_request(datapath, route.out_port, route.next_hop)

    def flow_removed_handler(self, event):
        """

        Args:
            event: Flow remved event
        """
        raise NotImplementedError

    def address_resolve_and_send(self, datapath, pkt, next_hop, out_port):
        """address resolve and send packets

        Args:
            datapath (Datapath) :
            pkt (Packet) :
            next_hop (str) :
            out_port (int) :
        """
        mac = self.arp_table.get_mac(datapath.id, next_hop)
        if mac is None:
            self.buffer.add(datapath.id, pkt)
            RouterCore.send_arp_request(datapath, out_port, next_hop)
        else:
            pkt_eth = pkt.get_protocol(ethernet.ethernet)
            pkt_eth.dst = mac
            RouterCore.change_src_mac_and_send_packet(datapath, out_port, pkt)

    def add_arp_table_entry(self, datapath, port_hw, ip, mac):
        """add address into controller's arp table and insert flow entry to rewrite ethernet address
         
        Args:
            datapath (Datapath) : datapath
            port_hw (str) : ethernet source address
            ip (str) : ip address
            mac (str) : mac address
        """
        logger.debug("add arp table (ip={}, mac={})".format(ip, mac))
        self.arp_table.add(datapath.id, ip, mac)
        self.send_packets_from_buffer(datapath, ip, mac)

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        target_ip = self._str_ip_to_int(ip)
        next_table = self.pipeline.EGRESS.table_id
        match = parser.OFPMatch(eth_type=ETH_TYPE_IP,
                                metadata=(target_ip, NEXT_HOP_METADATA_MASK))
        actions = [parser.OFPActionSetField(eth_src=port_hw),
                   parser.OFPActionSetField(eth_dst=mac)]
        instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions),
                        parser.OFPInstructionGotoTable(next_table)]
        self.flow_mod(datapath, self.ARP_ENTRY_PRIORITY, match, instructions)

    def send_packets_from_buffer(self, datapath, ip, mac):
        """send all packets matching the ip

        Args:
            datapath (Datapath) : datapath
            ip (str) : resolved ip address
            mac (str) : mac address
        """
        packets = self.buffer.pop_all(datapath.id, ip)
        for pkt in packets:
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            pkt_eth = pkt.get_protocol(ethernet.ethernet)
            pkt_eth.dst = mac
            routing_handler = self.pipeline.ROUTING_TABLE.handler
            route = routing_handler.get_route(datapath.id, pkt_ipv4.dst)
            RouterCore.change_src_mac_and_send_packet(datapath, route.out_port, pkt)

    def remove_arp_table_entry(self, datapath_id, ip):
        """Delete arp entry when a timeout occurs.
        
        Args:
            datapath_id (int) : datapath id
            ip (str) : ip address
        """
        self.arp_table.remove(datapath_id, ip)

    def _str_ip_to_int(self, ip):
        """ip address to int

        Args:
            ip (str) : ip address

        Returns:
            int : ip address int
        """
        return int.from_bytes(ipaddress.ip_address(ip).packed, 'big')


class EgressHandler(PipelineHandler):
    """egress of packet"""

    DEFAULT_FLOW_PRIORITY = 0x0000

    def __init__(self, pipeline, table_id):
        super().__init__(pipeline, table_id)

    def add_default_flows(self, datapath):
        of_parser = datapath.ofproto_parser
        match = of_parser.OFPMatch()
        instructions = [ofproto_v1_3_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, [])]
        self.flow_mod(datapath, self.DEFAULT_FLOW_PRIORITY, match, instructions)

    def packet_in_handler(self, event):
        raise NotImplementedError
