import os
import sys
import time
from functools import partial

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from topology.datacenter_topo import DatacenterTopo

CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653


def main():
    setLogLevel("info")
    info("*** Starting persistent datacenter topology...\n")

    topo = DatacenterTopo()

    # Keep OpenFlow 1.3 consistent with the Ryu controller
    # AJOUTE stp=True ICI ABSOLUMENT
    switch_of13 = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(
        topo=topo,
        switch=switch_of13,
        link=TCLink,
        controller=None,
        autoSetMacs=True
    )

    net.addController(
        "c0",
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )

    net.start()

    # Allow switches to connect and the controller to install initial flows
    time.sleep(60)

    info("*** Persistent lab topology is running.\n")
    info("*** Controller connected at %s:%s\n" % (CONTROLLER_IP, CONTROLLER_PORT))

    CLI(net)

    info("*** Stopping persistent lab topology...\n")
    net.stop()


if __name__ == "__main__":
    main()