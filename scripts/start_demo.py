# File: scripts/start_demo.py
import time
import sys
import subprocess
from functools import partial

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

# Import the topology
sys.path.append(".")
from topology.datacenter_topo import DatacenterTopo


def start_interactive_demo():
    setLogLevel("info")
    info("*** Starting the NetDevOps demo environment...\n")

    topo = DatacenterTopo()
    switch_of13 = partial(OVSKernelSwitch, protocols="OpenFlow13")

    net = Mininet(topo=topo, switch=switch_of13, link=TCLink, controller=None)
    c0 = net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)

    c0.start()
    time.sleep(3)
    net.start()

    info("*** Waiting 5 seconds for network learning...\n")
    time.sleep(5)

    info("*** Deploying policies (Firewall & QoS) via Policy as Code...\n")
    subprocess.run(["python3", "scripts/deploy_policies.py"])

    info("\n" + "=" * 60 + "\n")
    info("NETWORK IS UP AND MONITORING IS ACTIVE!\n")
    info("Open Grafana at http://localhost:3000 to view the dashboards.\n")
    info("Generate traffic here with: h1 ping h2 or iperf h1 h2\n")
    info("Type 'exit' to shut the network down cleanly.\n")
    info("=" * 60 + "\n")

    # Start the interactive CLI. The script pauses here until the user exits.
    CLI(net)

    # Cleanup resumes here after "exit" is entered in the CLI.
    info("\n*** Stopping the demo network...\n")
    net.stop()


if __name__ == "__main__":
    start_interactive_demo()
