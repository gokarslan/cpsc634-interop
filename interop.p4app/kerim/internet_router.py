#!/usr/bin/env python

from threading import Thread, Event, Timer
from time import sleep

from scapy.all import sendp
from scapy.all import Ether, IP, ARP, ICMP, Raw

from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import PWOSPF, PWOSPFHeader, PWOSPFHello, PWOSPFLSU
from tools import apply_mask

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002


class PacketQueue:
    def __init__(self):
        self._queue = dict()

    def enqueue(self, pkt, ipv4):
        if ipv4 in self._queue:
            self._queue[ipv4].append(pkt)
        else:
            self._queue[ipv4] = [pkt]

    def dequeue(self, ipv4):
        pkts = []
        if ipv4 in self._queue:
            pkts = self._queue[ipv4]
            del self._queue[ipv4]
        return pkts


class ARPTable:
    def __init__(self, switch):
        self._switch = switch
        self._table = dict()

    def addEntry(self, mac, ipv4):
        if ipv4 in self._table:
            return

        # print '%sCalled addArpTableEntry %s %s' % (self._switch.name, mac, ipv4)
        self._switch.insertTableEntry(table_name='MyIngress.arp_table',
                                      match_fields={'meta.nextHop': ipv4},
                                      action_name='MyIngress.arp_lookup',
                                      action_params={'nextHopMac': mac})
        self._table[ipv4] = mac
        Timer(120, self._entry_timeout, (ipv4,)).start()

    def getEntry(self, ipv4):
        return self._table.get(ipv4, '00:00:00:00:00:00')

    def _entry_timeout(self, ipv4):
        del self._table[ipv4]
        # TODO expire arp entry
        # self._switch.deleteTableEntry(table_name='MyIngress.arp_table',
        #                               match_fields={'meta.nextHop': ipv4}
        #                               )


class InternetRouter(Thread):
    def __init__(self, switch, links):
        super(InternetRouter, self).__init__()
        self.switch = switch
        self.arp_queue = PacketQueue()
        self.control_iface = switch.intfs[1].name
        self.arp_table = ARPTable(switch)
        self.stop_event = Event()

        self.port_for_mac = dict()
        for interface in self.switch.intfList():
            if interface.name != 'lo':
                linkid = interface.name.split('eth')[1]
                if linkid in links:
                    interface.setIP(str(links[linkid]))
            # print interface.name, interface.ip, interface.mac
        self.pwospf = PWOSPF(controller=self, routerID=self.switch.intfList()[2].ip, areaID=1,
                             lsuint=30)
        switch.insertTableEntry(table_name='MyIngress.local_ipv4_table',
                                match_fields={'hdr.ipv4.dstAddr': self.switch.intfList()[2].ip},
                                action_name='MyIngress.local_ipv4_match',
                                action_params={})
        # Do not add loopback and interface for cpu.
        # for i, interface in enumerate(self.switch.intfList()[1:2]):
        #     if interface.name != 'lo' and interface.ip:
        #         self.pwospf.add_subnet(subnet=interface.ip, mask='255.255.255.0')
        offset = 2
        for i, interface in enumerate(self.switch.intfList()[offset:]):
            mask = '255.255.255.254' if i != 0 else '255.255.255.0'
            if interface.name != 'lo' and interface.ip:
                self.pwospf.add_interface(id=i + offset, mac=interface.mac, ipv4=interface.ip,
                                          mask=mask,
                                          helloint=15)
            # else:
            #     print interface, interface.ip

    # Overloading Threading functionality

    def run(self):
        sniff(iface=self.control_iface, prn=self.handlePacket, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(InternetRouter, self).start(*args, **kwargs)
        sleep(0.3)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(InternetRouter, self).join(*args, **kwargs)

    # ARP cache update functions
    # This is for ETH packets, L3 will use routing egrr.
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac:
            return
        # print 'Add mac called %s %s' % (mac, port)

        self.switch.insertTableEntry(table_name='MyIngress.fwd_l2',
                                     match_fields={'hdr.ethernet.dstAddr': [mac]},
                                     action_name='MyIngress.set_egr',
                                     action_params={'port': port})

        self.port_for_mac[mac] = port

    # Packet Handlers

    def handlePacket(self, pkt):
        pkt.show2()
        assert CPUMetadata in pkt, 'Should only receive packets from switch with special header'
        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1:
            return

        # if IP in pkt and ICMP not in pkt:
        #     print pkt.summary(), PWOSPFHeader in pkt, PWOSPFHello in pkt
        #     pkt.show()
        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.receive_arp_request(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.receive_arp_reply(pkt)
        # If switch sends this packet to resolve ARP
        elif pkt[CPUMetadata].arpDst != '0.0.0.0':
            self.send_arp_request(dst=pkt[CPUMetadata].arpDst)
            self.arp_queue.enqueue(pkt, pkt[CPUMetadata].arpDst)
        # PWOSPF Hello message
        elif PWOSPFHello in pkt:
            self.pwospf.receive_hello_msg(pkt)
        elif PWOSPFLSU in pkt:
            self.pwospf.receive_lsu_msg(pkt)
        elif ICMP in pkt:
            # handle server icmp pkts
            self.receive_icmp(pkt)

    # ARP Handlers

    def receive_arp_reply(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.arp_table.addEntry(pkt[ARP].hwsrc, pkt[ARP].psrc)
        self.arp_table.addEntry(pkt[ARP].hwdst, pkt[ARP].pdst)
        self.send(pkt)
        pkts = self.arp_queue.dequeue(pkt[ARP].psrc)
        for pkt in pkts:
            self.send(pkt)

    def receive_arp_request(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.arp_table.addEntry(pkt[ARP].hwsrc, pkt[ARP].psrc)
        self.send_arp_reply(pkt)

    # ICMP Handlers

    def receive_icmp(self, pkt):
        print
        'CP has received an ICMP pkt: ', self.pwospf._router.routerID, pkt.summary()
        # pkt.show()

        reply_pkt = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) / CPUMetadata(
            fromCpu=1, origEtherType=0x800, srcPort=1)
        reply_pkt /= IP(src=pkt[IP].dst, dst=pkt[IP].src, proto=pkt[IP].proto)
        reply_pkt /= ICMP(type=0, code=0, seq=pkt[ICMP].seq, id=pkt[ICMP].id) / pkt[Raw]
        self.send(reply_pkt)

    # Packet Senders

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.control_iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def send_arp_request(self, dst):
        hwdst = 'ff:ff:ff:ff:ff:ff'
        # iface_addr = int(dst.split('.')[-1])
        # if iface_addr % 2 == 0:
        #     iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr + 1)
        # else:
        #     iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr - 1)
        # hwsrc = self.getHwAddress(iface_addr, type=2)
        for interface in self.pwospf._router.interfaces.values():
            if apply_mask(interface.ipv4, interface.mask) == apply_mask(dst, interface.mask):
                # if self.pwospf._router.routerID == '10.0.6.10':
                #     print 'Sending arp req from ', interface.mac
                req_pkt = Ether(src=interface.mac, dst=hwdst) / CPUMetadata(
                    fromCpu=1, origEtherType=0x0806, srcPort=1) / ARP(op=ARP_OP_REQ,
                                                                      hwsrc=interface.mac,
                                                                      psrc=interface.ipv4,
                                                                      hwdst=hwdst,
                                                                      pdst=dst)

                self.send(req_pkt)

    def send_arp_reply(self, pkt):
        # if self.pwospf._router.routerID == '10.0.1.10':
        #     print pkt.show()
        # TODO avoid static ip addr handling
        if '10.' in pkt[ARP].psrc:
            if pkt[ARP].psrc.split('.')[-1] == '10':
                # print 'I shouldn\'t reply myself!'
                return
            iface_addr = '.'.join(pkt[ARP].psrc.split('.')[:3]) + '.10'
            hwsrc = self.switch.intfList()[1].mac
            # if self.pwospf._router.routerID == '10.0.6.10':
            #     print hwsrc
        else:
            hwsrc = self.getHwAddress(pkt[ARP].psrc, type=1)
            dst = pkt[ARP].psrc
            iface_addr = int(dst.split('.')[-1])
            if iface_addr % 2 == 0:
                iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr + 1)
            else:
                iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr - 1)
        reply_pkt = Ether(src=hwsrc, dst=pkt[ARP].hwsrc) / CPUMetadata(
            fromCpu=1, origEtherType=0x0806, srcPort=1) / ARP(op=ARP_OP_REPLY, hwsrc=hwsrc,
                                                              psrc=iface_addr, hwdst=pkt[ARP].hwsrc,
                                                              pdst=pkt[ARP].psrc)

        self.send(reply_pkt)

    def add_routing_rule(self, destination, cidr, nextHop, port):
        # if self.pwospf._router.routerID == '10.0.4.10':
        #     print ('%s: Adding routing rule %s/%d' % (
        #         self.pwospf._router.routerID, destination, cidr)), cidr, nextHop, port
        self.switch.insertTableEntry(table_name='MyIngress.routing_table',
                                     match_fields={'hdr.ipv4.dstAddr': [destination, cidr]},
                                     action_name='MyIngress.route',
                                     action_params={'nextHop': nextHop,
                                                    'port': port})

    # Private functions
    def getHwAddress(self, ipv4, type):
        for interface in self.switch.intfList():
            # print interface.ip
            if interface.ip and ipv4.split('.')[:-1] == interface.ip.split('.')[:-1]:
                return interface.mac

        mac = self.arp_table.getEntry(ipv4)
        if mac == "00:00:00:00:00:00":
            print
            'Interface not found for %s %s %d' % (
                ipv4, self.arp_table._table, type)  # str(self.switch.intfList()))
        return mac
        # # if self.pwospf._router.routerID == '10.0.4.10':
        # #     for interface in self.switch.intfList():
        # #         # print interface.ip
        # #         if interface.ip:
        # #             print ipv4.split('.')[:-1], interface.ip.split('.')[:-1]
        # # # for interface in self.switch.intfList():
        # # #     # print interface.ip
        # # #     if interface.ip and
        # # #         print ipv4[:-3], interface.ip:
        # return '00:00:00:00:00:00'
