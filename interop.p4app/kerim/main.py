#!/usr/bin/env python
# Kerim Gokarslan <kerim.gokarslan@yale.edu>
from time import sleep

from p4app import P4Mininet
from my_topo import SingleSwitchTopo, LinearTopo, RingTopo, RingLinearTopo
from controller import MacLearningController

from internet_router import InternetRouter


def main(N=6):
    topo = RingTopo(N)
    num_hosts_per_router = 3
    net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)
    net.start()

    switches = []
    routers = []
    for i in range(1, N + 1):
        switch = net.get('s%d' % i)
        switches.append(switch)

        # Add a mcast group for all ports (except for the CPU port)
        bcast_mgid = i
        switch.addMulticastGroup(mgid=bcast_mgid, ports=range(2, 2 + num_hosts_per_router))
        #
        # Send MAC bcast packets to the bcast multicast group
        switch.insertTableEntry(table_name='MyIngress.fwd_l2',
                                match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
                                action_name='MyIngress.set_mgid',
                                action_params={'mgid': bcast_mgid})

        switch.insertTableEntry(table_name='MyIngress.routing_table',
                                match_fields={'hdr.ipv4.dstAddr': ['10.0.%d.0' % i, 24]},
                                action_name='MyIngress.route',
                                action_params={'nextHop': '10.0.%d.2' % i,
                                               'port': 2})

        # PWOSFP Hello!
        switch.insertTableEntry(table_name='MyIngress.routing_table',
                                match_fields={'hdr.ipv4.dstAddr': ['224.0.0.5', 32]},
                                action_name='MyIngress.route',
                                action_params={'nextHop': '224.0.0.5',
                                               'port': 3})

        switch.insertTableEntry(table_name='MyIngress.arp_table',
                                match_fields={'meta.nextHop': '224.0.0.5'},
                                action_name='MyIngress.arp_lookup',
                                action_params={'nextHopMac': '00:00:00:11:22:33'})

    # Assign IP address to each link for ring topology.
    links = []
    for i in range(N):
        links.append(dict())

    for i in range(N):
        j = (i + 1) % N
        s1_port = 3
        s2_port = 4
        tmp = i
        if i > j:
            tmp = i
            i = j
            j = tmp
            s1_port = 4
            s2_port = 3
        # s1 = switches[i]
        # s2 = switches[j]
        i += 1
        j += 1
        s1_ipv4 = '192.168.%d.%d/31' % (i, (j << 2) + 0)
        s2_ipv4 = '192.168.%d.%d/31' % (i, (j << 2) + 1)

        # net.get('s%d' % i).cmd('ifconfig s%d-eth2 10.0.%d.10 netmask 255.255.255.0' % (i, i))
        # net.get('s%d' % i).cmd(
        #     'ifconfig s%d-eth%d %s netmask 255.255.255.254' % (i, s1_port, s1_ipv4))
        # net.get('s%d' % j).cmd(
        #     'ifconfig s%d-eth%d %s netmask 255.255.255.254' % (j, s2_port, s2_ipv4))
        # links[tmp][1] = '172.14.%d.10/24' % (tmp + 1)
        links[tmp][2] = '10.0.%d.10/24' % (tmp + 1)
        links[i - 1][s1_port] = s1_ipv4
        links[j - 1][s2_port] = s2_ipv4

    s1, s2, s3 = net.get('s1'), net.get('s2'), net.get('s3')
    c1, c2 = net.get('c1'), net.get('c2')
    hosts = []
    for i in range(1, N + 1):
        hosts.append(net.get('h%d' % i))
        hosts[-1].cmd('route add default gw 10.0.%d.10 eth0' % i)
    # Start CPs
    for i, switch in enumerate(switches):
        routers.append(InternetRouter(switch, links=links[i]))
    for router in routers:
        router.start()

    sleep_time = 30
    print 'All routers are started, the main program is sleeping for %d seconds...' % sleep_time
    # Wait for network to be stabilized
    sleep(sleep_time)

    print 'Executing test...'
    # Run some ping tests

    print 'Expected ttl %d' % 61
    print hosts[3 - 1].cmd('ping -c1 10.0.5.2')
    print 'Expected ttl %d' % 60
    print hosts[1 - 1].cmd('ping -c1 10.0.4.2')

    print 'Expected ttl %d (pinging router)' % 60
    print hosts[1 - 1].cmd('ping -c1 10.0.4.10')

    # Print topology on router 1
    print 'Topology in the 2nd router', routers[1].pwospf._router.links

    routers[2].switch.printTableEntries()

    # print net.iperf([hosts[1], hosts[3]])
    # for router in routers:
    #     r = router.pwospf._router
    #     print '%s' % r.routerID
    #     for id in r.interfaces:
    #         print '\t ', r.interfaces[id].ipv4, r.interfaces[id]
    #     print '\n'
    # s1.printTableEntries()
    # print('')
    # s2.printTableEntries()
    # print('')
    # s3.printTableEntries()

    # s1.printTableEntries()
    # print('')
    # s2.printTableEntries()
    # print('')
    # s3.printTableEntries()

    # print h2.cmd('ifconfig && netstat -nr')
    # print h2.cmd('ping -c1 10.0.1.2')

    # print s1.cmd('ifconfig && netstat -nr')
    # return

    # print net.get('c1').cmd('ifconfig')
    # print h1.cmd('ifconfig')
    # print h2.cmd('ifconfig')

    # print sw.cmd('ifconfig')
    # print h2.cmd('ifconfig && netstat -nr && arp')

    # print h1.cmd('arping -c1 10.0.2.2')
    #
    # print h2.cmd('ifconfig && netstat -nr')
    # print h2.cmd('ping -c1 10.0.1.2')

    # These table entries were added by the CPU:
    # sw.printTableEntries()

    # sleep(4)

    # cpu.send_pwospf_hello()
    # cpu.send_pwospf_lsu()


if __name__ == "__main__":
    main()
