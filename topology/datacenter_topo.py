from mininet.topo import Topo

class DatacenterTopo(Topo):
    def build(self):
        spine1 = self.addSwitch('s1')
        spine2 = self.addSwitch('s2')
        leaf1 = self.addSwitch('s3')
        leaf2 = self.addSwitch('s4')

        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # QoS sur h1
        self.addLink(h1, leaf1)

        self.addLink(h2, leaf1)
        self.addLink(h3, leaf2)
        self.addLink(h4, leaf2)

        self.addLink(leaf1, spine1)
        self.addLink(leaf1, spine2)
        self.addLink(leaf2, spine1)
        self.addLink(leaf2, spine2)