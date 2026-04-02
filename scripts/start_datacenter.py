# File: scripts/start_datacenter.py
import sys
from functools import partial

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# Import the topology
sys.path.append(".")
from topology.datacenter_topo import DatacenterTopo


def start_prod():
    setLogLevel("info")
    info("*** Starting the datacenter (production environment)...\n")

    topo = DatacenterTopo()
    switch_of13 = partial(OVSKernelSwitch, protocols="OpenFlow13")

    # Create the network with QoS-capable links.
    net = Mininet(topo=topo, link=TCLink, controller=None)
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6633)
    c0.start()
    net.start()

    # Force OpenFlow 1.3 on all switches.
    for switch in net.switches:
        switch.cmd("ovs-vsctl set bridge", switch, "protocols=OpenFlow13")

    info("\n" + "=" * 60 + "\n")
    info("DATACENTER IS ONLINE AND OPERATIONAL!\n")
    info("The network is running and waiting for CI/CD pipeline rules.\n")
    info("Type 'exit' only when you are done with the environment.\n")
    info("=" * 60 + "\n")

    # Keep the network alive and open the interactive console.
    CLI(net)

    net.stop()


if __name__ == "__main__":
    start_prod()
