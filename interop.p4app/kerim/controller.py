from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
import time

ARP_OP_REQ = 0x0001
ARP_OP_REPLY = 0x0002

from pwospf import PWOSPFHeader, PWOSPFHello, PWOSPFLSU, PWOSPF_TYPE_HELLO, PWOSPF_TYPE_LSU


class MacLearningController(Thread):
    def __init__(self, sw, start_wait=0.3):
        super(MacLearningController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait  # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.port_for_mac = {}
        self.arp_table = {}
        self.stop_event = Event()
        self.arp_queue = dict()

    # This is for ETH packets, L3 will use routing egrr.
    def addMacAddr(self, mac, port):
        # Don't re-add the mac-port mapping if we already have it:
        if mac in self.port_for_mac:
            return
        print 'Add mac called %s %s' % (mac, port)

        self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
                                 match_fields={'hdr.ethernet.dstAddr': [mac]},
                                 action_name='MyIngress.set_egr',
                                 action_params={'port': port})

        self.port_for_mac[mac] = port

    def addArpTableEntry(self, mac, ipv4):  # '10.0.0.%d' % port
        if ipv4 in self.arp_table:
            return
        print 'Called addArpTableEntry %s %s' % (mac, ipv4)
        self.sw.insertTableEntry(table_name='MyIngress.arp_table',
                                 match_fields={'meta.nextHop': ipv4},
                                 action_name='MyIngress.arp_lookup',
                                 action_params={'nextHopMac': mac})
        self.arp_table[ipv4] = mac

    def handleArpReply(self, pkt):
        # self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpTableEntry(pkt[ARP].hwsrc, pkt[ARP].psrc)
        self.send(pkt)
        pkts = self.arp_dequeue(pkt[ARP].psrc)
        for pkt in pkts:
            self.send(pkt)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addArpTableEntry(pkt[ARP].hwsrc, pkt[ARP].psrc)
        self.sendArpReply(pkt)
        # hwsrc = '00:00:00:10:00:00'
        # iface_addr = '.'.join(pkt[ARP].psrc.split('.')[:3]) + '.10'
        # reply_pkt = Ether(src=hwsrc, dst=pkt[ARP].hwsrc) / CPUMetadata(
        #     fromCpu=1, origEtherType=0x0806, srcPort=1) / ARP(op=ARP_OP_REPLY, hwsrc=hwsrc,
        #                                                       psrc=iface_addr, hwdst=pkt[ARP].hwsrc,
        #                                                       pdst=pkt[ARP].psrc)
        #
        # self.send(reply_pkt)

    def arp_enqueue(self, pkt, arpDst):
        if arpDst in self.arp_queue:
            self.arp_queue[arpDst].append(pkt)
        else:
            self.arp_queue[arpDst] = [pkt]

    def arp_dequeue(self, arpDst):
        pkts = []
        if arpDst in self.arp_queue:
            pkts = self.arp_queue[arpDst]
            del self.arp_queue[arpDst]
        return pkts

    def handlePkt(self, pkt):
        # pkt.show2()
        # assert CPUMetadata in pkt, "Should only receive packets from switch with special header"
        if CPUMetadata not in pkt:
            pkt.show()

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1:
            return

        if ARP in pkt:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        else:
            print 'Recvd'
            pkt.show()
            self.sendArpRequest(dst=pkt[CPUMetadata].arpDst)
            self.arp_enqueue(pkt, pkt[CPUMetadata].arpDst)

    def sendArpRequest(self, dst):
        hwsrc = '00:00:00:00:00:00'
        hwdst = 'ff:ff:ff:ff:ff:ff'
        iface_addr = int(dst.split('.')[-1])
        if iface_addr % 2 == 0:
            iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr + 1)
        else:
            iface_addr = '.'.join(dst.split('.')[:3]) + '.' + str(iface_addr - 1)
        req_pkt = Ether(src=hwsrc, dst=hwdst) / CPUMetadata(
            fromCpu=1, origEtherType=0x0806, srcPort=1) / ARP(op=ARP_OP_REQ, hwsrc=hwsrc,
                                                              psrc=iface_addr, hwdst=hwdst,
                                                              pdst=dst)

        self.send(req_pkt)

    def sendArpReply(self, pkt):
        hwsrc = '00:00:00:00:00:00'
        if '10.' in pkt[ARP].psrc:
            iface_addr = '.'.join(pkt[ARP].psrc.split('.')[:3]) + '.10'
        else:
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

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, "Controller must send packets with special header"
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

    def start(self, *args, **kwargs):
        super(MacLearningController, self).start(*args, **kwargs)
        time.sleep(self.start_wait)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(MacLearningController, self).join(*args, **kwargs)

    # TEst
    def get_pwospf_header(self, type, dst='224.0.0.5'):
        return Ether() / CPUMetadata(
            fromCpu=1, origEtherType=0x800, srcPort=1) / IP(proto=0x59,
                                                            dst=dst) / PWOSPFHeader(type=type)

    def send_pwospf_lsu(self):
        lsu_packet = self.get_pwospf_header(dst='10.0.0.3', type=PWOSPF_TYPE_LSU) / PWOSPFLSU(
            lsuAdvertisements=[1, 2, 3, 4, 5, 6])
        lsu_packet.show()
        self.send(lsu_packet)

    def send_pwospf_hello(self):
        hello_packet = self.get_pwospf_header(type=PWOSPF_TYPE_HELLO) / PWOSPFHello()
        hello_packet.show()
        self.send(hello_packet)

    def test_send(self, *args, **override_kwargs):
        pkt = args[0]
        # assert CPUMetadata in pkt, "Controller must send packets with special header"
        # pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)
