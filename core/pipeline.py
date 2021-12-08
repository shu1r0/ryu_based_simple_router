from enum import Enum

from util.router_log import get_logger
from core.pipeline_handler import IngressHandler, ProtocolClassifierHandler, ArpResponderHandler, RoutingTableHandler, ArpTableHandler, EgressHandler

logger = get_logger(__name__)


class PIPELINE(bytes, Enum):

    def __new__(cls, value, cls_handler):
        logger.debug("pipeline new with attr({}, {})".format(value, cls_handler))
        obj = bytes.__new__(cls)
        obj._value_ = value
        obj.handler = cls_handler(cls, value)
        return obj

    INGRESS = (0, IngressHandler)
    PROTOCOL_CLASSIFIER = (5, ProtocolClassifierHandler)
    ARP_RESPONDER = (10, ArpResponderHandler)
    ROUTING_TABLE = (20, RoutingTableHandler)
    ARP_TABLE = (30, ArpTableHandler)
    EGRESS = (100, EgressHandler)

    @property
    def table_id(self):
        return self.value


def get_handler(id):
    """get pipeline table handler

    Args:
        id (int) : table id

    Returns:
        PipelineHandler
    """
    return PIPELINE(id).handler

