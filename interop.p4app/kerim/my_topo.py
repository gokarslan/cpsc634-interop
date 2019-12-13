from mininet.topo import Topo


class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switch = self.addSwitch('s1')

        for i in xrange(1, n + 1):
            host = self.addHost('h%d' % i,
                                ip="10.0.0.%d" % i,
                                mac='00:00:00:00:00:%02x' % i)
            self.addLink(host, switch, port2=i)


# Takes number of switches (n) and optional number of hosts (excluding CP) per switch (default m=1)
class LinearTopo(Topo):
    def __init__(self, n, m=None, **opts):
        Topo.__init__(self, **opts)
        if not m:
            m = 1

        switches = []
        for i in xrange(1, n + 1):
            switch = self.addSwitch('s%d' % i)
            host = self.addHost('c%d' % i,
                                ip="10.0.%d.%d/24" % (i, 1),
                                # mask='255.255.255.0',
                                mac='00:00:00:%02x:00:%02x' % (i, 1))
            self.addLink(host, switch, port2=1)
            host = self.addHost('h%d' % i,
                                ip="10.0.%d.%d/24" % (i, 2),
                                mac='00:00:00:%02x:00:%02x' % (i, 2))
            self.addLink(host, switch, port2=2)
            switches.append(switch)

        iface_ports = [3] * n
        for i in xrange(n - 1):
            s1 = switches[i]
            s2 = switches[i + 1]
            self.addLink(s1, s2, port1=iface_ports[i], port2=iface_ports[i + 1])
            iface_ports[i] += 1
            iface_ports[i + 1] += 1


class RingLinearTopo(Topo):
    def __init__(self, n, m=None, **opts):
        Topo.__init__(self, **opts)
        if not m:
            m = 1

        switches = []
        for i in xrange(1, n + 1):
            switch = self.addSwitch('s%d' % i)
            host = self.addHost('c%d' % i,
                                ip="10.0.%d.%d/24" % (i, 1),
                                # mask='255.255.255.0',
                                mac='00:00:00:%02x:00:%02x' % (i, 1))
            self.addLink(host, switch, port2=1)
            host = self.addHost('h%d' % i,
                                ip="10.0.%d.%d/24" % (i, 2),
                                mac='00:00:00:%02x:00:%02x' % (i, 2))
            self.addLink(host, switch, port2=2)
            switches.append(switch)

        iface_ports = [3] * n
        for i in xrange(n - 1):
            s1 = switches[i]
            s2 = switches[i + 1]
            self.addLink(s1, s2, port1=iface_ports[i], port2=iface_ports[i + 1])
            iface_ports[i] += 1
            iface_ports[i + 1] += 1
        self.addLink(switches[0], switches[-1], port1=4, port2=4)


class RingTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        switches = []
        for i in xrange(1, n + 1):
            switch = self.addSwitch('s%d' % i)
            host = self.addHost('c%d' % i,
                                ip="10.0.%d.%d/24" % (i, 1),
                                # mask='255.255.255.0',
                                mac='00:00:00:%02x:00:%02x' % (i, 1))
            self.addLink(host, switch, port2=1)
            host = self.addHost('h%d' % i,
                                ip="10.0.%d.%d/24" % (i, 2),
                                mac='00:00:00:%02x:00:%02x' % (i, 2))
            self.addLink(host, switch, port2=2)
            switches.append(switch)
        for i in xrange(n):
            # self.addLink(switches[(i - 1) % n], switches[i], port2=3)
            j = (i + 1) % n
            s1 = switches[i]
            s2 = switches[j]
            # s1_ipv4 = '192.168.%d.%d' % (i, (j << 1) + 1)
            # s2_ipv4 = '192.168.%d.%d' % (i, (j << 1) + 2)

            self.addLink(s1, s2, port1=3, port2=4)
            # self.get('s%d' % i).cmd('ifconfig s%d-eth%d %s netmask 255.255.255.254' % (i, 3, s1_ipv4))
            # s2.cmd('ifconfig s%d-eth%d %s netmask 255.255.255.254' % (j, 4, s2_ipv4))
