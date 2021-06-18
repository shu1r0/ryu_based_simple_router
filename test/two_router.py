# coding: utf-8

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI

from functools import partial

class Three_switches_topo(Topo):
    def build(self, n=5):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h1 = self.addHost('h1', ip="192.168.1.2/24")
        h2 = self.addHost('h2', ip="192.168.3.2/24")

        self.addLink(s1, h1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


def setup():
    topo = Three_switches_topo()
    net = Mininet(topo=topo, controller=partial(RemoteController, ip='127.0.0.1', port=6653))
    net.start()
    net.hosts[0].cmd("route add default gw 192.168.1.1")
    net.hosts[1].cmd("route add default gw 192.168.3.1")
    dumpNodeConnections(net.hosts)
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    setup()