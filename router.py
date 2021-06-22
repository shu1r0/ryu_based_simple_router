from ryu.base import app_manager
from ryu.controller import ofp_event, dpset
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet.ether_types import ETH_TYPE_ARP
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, arp
from ryu.lib.packet import ethernet

from config.config import dp_config
from util.router_log import get_logger


logger = get_logger(__name__)

NEXT_HOP_METADATA_MASK = 0x00000000ffffffff


class RouterCore(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # _CONTEXTS = {
    #     'dpset': dpset.DPSet,
    # }

    def __init__(self, *args, **kwargs):
        super(RouterCore, self).__init__(*args, **kwargs)
        # self.dpset = kwargs['dpset']

    @set_ev_cls(ofp_event.EventOFPStateChange, MAIN_DISPATCHER)
    def on_switch_ready(self, event):
        """add default flow

        Args:
            event: Packet In Event
        """
        from core.pipeline import PIPELINE
        datapath = event.datapath
        for table in PIPELINE:
            self.logger.debug("add default flow on ({})".format(table.table_id))
            table.handler.add_default_flows(datapath)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, CONFIG_DISPATCHER)
    def port_desc_stats_reply_handler(self, event):
        """set port stats in config

        Args:
            event: PortDescStatsReply Event
        """
        datapath = event.msg.datapath
        for port_stats in event.msg.body:
            dp_config.set_port(datapath.id, port_stats)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def pakcet_in_handler(self, event):
        """Send the event to event's table_id handler

        Args:
            event: Packet In Event
        """
        from core.pipeline import get_handler
        msg = event.msg
        table_id = msg.table_id
        self.logger.info("get packet in event (datapath={}, table_id={})".format(msg.datapath.id, table_id))
        handler = get_handler(table_id)
        handler.packet_in_handler(event)

    @classmethod
    def flow_mod(cls, datapath, table_id, priority, match, inst):
        logger.debug("flow mod (datapath={}, table_id={}, priority={}, match={}, inst={})"
                     .format(datapath, table_id, priority, match, inst))
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(datapath=datapath, table_id=table_id, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    @classmethod
    def send_packet(cls, datapath, out_port, pkt):
        logger.debug("send pkt (datapath={}, out_port={}, pkt={})".format(datapath.id, out_port, pkt))
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=out_port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

    @classmethod
    def change_src_mac_and_send_packet(cls, datapath, out_port, pkt):
        pkt_eth = pkt.get_protocol(ethernet.ethernet)
        if pkt_eth:
            pkt_eth.src = dp_config.get_hw(datapath.id, out_port)
            cls.send_packet(datapath, out_port, pkt)


    @classmethod
    def send_arp_request(cls, datapath, out_port, target_ip):
        logger.debug("send arp request (datapath={}, out_port={}, target_ip={})".format(datapath.id, out_port, target_ip))
        port_hw = dp_config.get_hw(datapath.id, out_port)
        port_ip = dp_config.get_ip(datapath.id, out_port)
        if not isinstance(target_ip, str):
            target_ip = str(target_ip)
        if not isinstance(port_ip, str):
            port_ip = str(port_ip.ip)
        pkt = packet.Packet()
        eth_proto = ethernet.ethernet(ethertype=ETH_TYPE_ARP,
                                      dst='ff:ff:ff:ff:ff:ff',
                                      src=port_hw)
        pkt.add_protocol(eth_proto)
        arp_proto = arp.arp(opcode=arp.ARP_REQUEST,
                            src_mac=port_hw,
                            src_ip=port_ip,
                            dst_mac='00:00:00:00:00:00',
                            dst_ip=target_ip)
        pkt.add_protocol(arp_proto)
        logger.debug(pkt)
        cls.send_packet(datapath, out_port, pkt)
