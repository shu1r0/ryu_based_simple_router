from abc import ABCMeta, abstractmethod

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4

class Buffer(metaclass=ABCMeta):

    def __init__(self):
        self.buffer = {}

    @abstractmethod
    def add(self, datapath_id, pkt):
        self.buffer.setdefault(datapath_id, [])
        self.buffer.add(pkt)

    @abstractmethod
    def pop_all(self, datapath_id, ip):
        raise NotImplementedError

class ArpTableBuffer(Buffer):

    def __init__(self, pipeline):
        super(ArpTableBuffer, self).__init__()
        self.pipeline = pipeline

    def add(self, datapath_id, pkt):
        self.buffer.setdefault(datapath_id, [])
        self._get(datapath_id).append(pkt)

    def pop_all(self, datapath_id, resolved_ip):
        packets = []
        for i in range(len(self._get(datapath_id))):
            pkt = self._get(datapath_id)[i]
            pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
            if pkt_ipv4:
                handler = self.pipeline.ROUTING_TABLE.handler
                next_hop = handler.get_next_hop(datapath_id, pkt_ipv4.dst)
                if str(next_hop) == str(resolved_ip):
                    popped = self._get(datapath_id).pop(i)
                    packets.append(popped)
        return packets

    def _get(self, datapath_id):
        return self.buffer[datapath_id]