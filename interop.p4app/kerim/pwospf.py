#!/usr/bin/env python
from threading import Timer
from time import time

from scapy.all import bind_layers
from scapy.all import Ether, IP
from scapy.all import Packet, XShortField, XByteField, XIntField, XLongField, FieldListField, \
    IPField

from cpu_metadata import CPUMetadata
from tools import apply_mask

PWOSPF_TYPE_HELLO = 0x1
PWOSPF_TYPE_LSU = 0x4
PWOSPF_PROTO = 0x59


class PWOSPFHeader(Packet):
    name = 'PWOSPFHeader '
    fields_desc = [
        XByteField('version', 2),
        XByteField('type', 0),
        XShortField('packetLen', 0),
        IPField('routerID', 0),
        XIntField('areaID', 0),
        XShortField('checksum', 0),
        XShortField('autype', 0),
        XLongField('authentication', 0),

    ]


class PWOSPFHello(Packet):
    name = 'PWOSPFHello '
    fields_desc = [
        IPField('networkMask', 0),
        XShortField('helloInt', 0),
        XShortField('padding', 0),
    ]


# class LSUAdvertisement(Packet):
#     name = "Simple group of two fields"
#
#     fields_desc = [IPField('subnet', 0),
#                    IPField('mask', 0),
#                    IPField('routerID', 0)
#                    ]


class PWOSPFLSU(Packet):
    name = 'PWOSPFLSU '
    fields_desc = [
        # TODO is it 15-17 or 16-16?
        XShortField('sequence', 0),
        XShortField('ttl', 0),
        XIntField('numAdvertisements', 0),
        FieldListField("lsuAdvertisements", None, IPField('intfield', 0)),
    ]


# Bind layers on scapy
bind_layers(IP, PWOSPFHeader, proto=PWOSPF_PROTO)
bind_layers(PWOSPFHeader, PWOSPFHello, type=PWOSPF_TYPE_HELLO)
bind_layers(PWOSPFHeader, PWOSPFLSU, type=PWOSPF_TYPE_LSU)


class Interface:
    def __init__(self, pwospf, id, mac, ipv4, mask, helloint):
        self.pwospf = pwospf
        self.id = id
        self.mac = mac
        self.ipv4 = ipv4
        self.mask = mask
        self.helloint = helloint
        self.neighbor_ips = dict()
        self.neighbor_timestamps = dict()

    def add_neighbor(self, neighbor_id, neighbor_ip):
        self.neighbor_timestamps[neighbor_id] = time()
        if neighbor_id not in self.neighbor_ips:
            # self.pwospf._controller.add_routing_rule(destination=neighbor_ip, mask=self.mask,
            #                                          nextHop=neighbor_ip, port=self.id)
            self.neighbor_ips[neighbor_id] = neighbor_ip
            self.pwospf.trigger_lsu()

    def del_neighbor(self, neighbor_id):
        if neighbor_id in self.neighbor_ips:
            del self.neighbor_ips[neighbor_id]
            self.pwospf.trigger_lsu()

    def __str__(self):
        neighbors = ""
        for neighbor_id in self.neighbor_ips:
            neighbors += "%s: %s %s\n" % (
                neighbor_id, self.neighbor_ips[neighbor_id], self.neighbor_timestamps[neighbor_id])
        return neighbors


class Router:
    def __init__(self, pwospf, routerID, areaID, lsuint):
        self.pwospf = pwospf
        self.routerID = routerID
        self.areaID = areaID
        self.lsuint = lsuint
        self.interfaces = dict()
        self.subnets = dict()
        self.links = dict()
        self.routing_table = dict()
        self.topology = dict()
        self.topology[self.routerID] = self.routerID
        # self.topology['0.0.0.0'] = self.routerID
        self._neigbor_nodes = set()

    def add_interface(self, interface):
        self.interfaces[interface.id] = interface

    def get_interface_with_id(self, neighbor_id):
        for interface in self.interfaces.values():
            if neighbor_id in interface.neighbor_ips.keys():
                return interface
        return None

    def get_interface_with_ip(self, neighbor_ip):
        for interface in self.interfaces.values():
            if neighbor_ip == interface.ipv4:
                return interface
            if neighbor_ip in interface.neighbor_ips.values():
                return interface
            # print interface.ipv4
        print 'No iface with neighbor ip: ', neighbor_ip
        return None

    def add_neighbor(self, neighbor_id):
        self._neigbor_nodes.add(neighbor_id)

    def del_neighbor(self, neighbor_id):
        self._neigbor_nodes.remove(neighbor_id)

    def add_subnet(self, subnet, mask, router_id='0.0.0.0'):
        self.subnets[(subnet, mask)] = router_id
        # self._dijkstra()
        self._update_routing_table()
        # print self.routerID, self.nodes

    def add_link(self, router1_id, router2_id):
        if router1_id not in self.links:
            self.links[router1_id] = set()
        if router2_id not in self.links:
            self.links[router2_id] = set()
        self.links[router1_id].add(router2_id)
        self.links[router2_id].add(router1_id)
        self._dijkstra()
        # if self.routerID == '10.0.4.10':
        #     print self.links

    def _dijkstra(self, target=None):
        start = self.routerID
        visited = {start: 0}
        path = dict()

        nodes = set(self.links.keys())

        while nodes:
            min_node = None
            for node in nodes:
                if node in visited:
                    if min_node is None:
                        min_node = node
                    elif visited[node] < visited[min_node]:
                        min_node = node

            if min_node is None:
                break

            nodes.remove(min_node)
            current_weight = visited[min_node]

            for edge in self.links[min_node]:
                weight = current_weight + 1
                if edge not in visited or weight < visited[edge]:
                    visited[edge] = weight
                    path[edge] = min_node
            if target == min_node:
                break

        # return visited, path
        self._update_routing_table(path)

    def _update_routing_table(self, path=None):

        # If djkstra's algorithm is executed
        if path:
            self.topology = dict()
            # self.routing_table = dict()
            for destination, gateway in path.iteritems():
                if gateway == self.routerID:
                    gateway = destination
                else:
                    while gateway not in self._neigbor_nodes and gateway != self.routerID:
                        if gateway in path:
                            if path[gateway] == self.routerID:
                                break
                            gateway = path[gateway]
                        else:
                            print 'NF ', gateway, ' at ', path
                            return
                self.topology[destination] = gateway
            self.topology[self.routerID] = self.routerID
            # self.topology['0.0.0.0'] = self.routerID

        for (subnet, mask), router_id in self.subnets.iteritems():
            ipv4, cidr = apply_mask(subnet, mask)
            # if self.pwospf._router.routerID == '10.0.4.10':
            #     print 'Checking... ', subnet, mask, router_id, ipv4, cidr
            if router_id == '0.0.0.0':
                continue
            if router_id in self.topology:
                if (ipv4, cidr) not in self.routing_table:
                    if self.routerID == router_id:
                        # if self.pwospf._router.routerID == '10.0.4.10':
                        #    print 'overlap', ipv4, cidr, router_id, self.routerID
                        continue
                    if self.routerID == self.topology[router_id]:
                        interface = self.get_interface_with_ip(ipv4)
                    else:
                        interface = self.get_interface_with_id(self.topology[router_id])
                    if interface:
                        # print 'Adding routing rule', ipv4, cidr, self.topology[router_id], interface.id
                        self.pwospf._controller.add_routing_rule(destination=ipv4, cidr=cidr,
                                                                 nextHop=self.topology[router_id],
                                                                 port=interface.id)
                        self.routing_table[(ipv4, cidr)] = self.topology[router_id]
                    else:
                        print 'Not found: ', self.routerID, self.topology[router_id], ipv4, cidr
                elif self.routing_table[(ipv4, cidr)] != self.topology[router_id]:
                    # TODO update routing rule!
                    pass

            else:
                pass
                # if self.pwospf._router.routerID == '10.0.4.10':
                #     print 'Router is not in topology...', router_id, self.topology


class PWOSPF:
    def __init__(self, controller, routerID, areaID, lsuint=30):
        self._router = Router(self, routerID, areaID, lsuint)
        self._hello_scheds = []
        self._controller = controller
        self._lsu_sequence = 0
        self._lsu_ttl = 64
        self._lsu_received_sequences = dict()
        self._last_hello = dict()

    def _next_lsu_sequence(self):
        current = self._lsu_sequence
        self._lsu_sequence += 1
        return current

    def add_interface(self, id, mac, ipv4, mask, helloint=30):
        interface = Interface(self, id, mac, ipv4, mask, helloint)
        self._router.add_interface(interface)
        Timer(helloint, self._trigger_hello, (interface,)).start()
        self._router.add_subnet(subnet=ipv4, mask=mask)
        self.trigger_lsu()

    # def add_subnet(self, subnet, mask):
    #     self.trigger_single_lsu(subnet=subnet, mask=mask,
    #                             router_id=self._router.routerID)
    #     self._router.add_node(subnet=subnet, mask=mask, router_id=self._router.routerID)

    def _trigger_hello(self, interface):
        # print '%s:Sending hello to the interface %s %s\n' % (self._router.routerID, interface.id, interface.ipv4)

        self._send_hello_msg(src_port=interface.id, src=interface.ipv4, mask='255.255.255.254',
                             helloint=interface.helloint)
        Timer(interface.helloint, self._trigger_hello, (interface,)).start()

    def trigger_lsu(self):
        lsu_advertisements = []
        for interface in self._router.interfaces.values():
            # apply mask to ipv4
            for neighbor_id in interface.neighbor_ips:
                lsu_advertisements.extend([interface.ipv4, interface.mask, neighbor_id])
            if not interface.neighbor_ips:
                lsu_advertisements = [interface.ipv4, interface.mask, '0.0.0.0']

        for interface in self._router.interfaces.values():
            self._send_lsu_msg(src_port=interface.id, src=interface.ipv4, dst=interface.ipv4,
                               sequence=self._next_lsu_sequence(), ttl=self._lsu_ttl,
                               num_advertisements=len(lsu_advertisements) / 3,
                               lsu_advertisements=lsu_advertisements)

        # def trigger_single_lsu(self, subnet, mask, router_id):
        #     lsu_advertisements = [subnet, mask, router_id]
        #     for interface in self._router.interfaces.values():
        #         self._send_lsu_msg(src_port=interface.id, src=interface.ipv4, dst=subnet,
        #                            sequence=self._next_lsu_sequence(), ttl=self._lsu_ttl,
        #                            num_advertisements=1, lsu_advertisements=lsu_advertisements)
        """    name = 'PWOSPFLSU '
    fields_desc = [
        # TODO is it 15-17 or 16-16?
        XShortField('sequence', 0),
        XShortField('ttl', 0),
        XIntField('numAdvertisements', 0),
        FieldListField("lsuAdvertisements", None, XIntField('intfield', 0)),
    ]"""

    # Senders
    def _get_pwospf_header(self, src, type, packet_len, src_port=1, dst='224.0.0.5'):
        return Ether() / CPUMetadata(
            fromCpu=1, origEtherType=0x800, srcPort=src_port) / IP(src=src, proto=PWOSPF_PROTO,
                                                                   dst=dst) / PWOSPFHeader(
            type=type, packetLen=packet_len, routerID=self._router.routerID,
            areaID=self._router.areaID)

    def _send_lsu_msg(self, src_port, src, dst, sequence, ttl, num_advertisements,
                      lsu_advertisements):
        # print 'Num adv: ', num_advertisements
        lsu_packet = self._get_pwospf_header(src=src, dst=dst, packet_len=60,
                                             type=PWOSPF_TYPE_LSU, src_port=src_port) / PWOSPFLSU(
            sequence=sequence, ttl=ttl, numAdvertisements=num_advertisements,
            lsuAdvertisements=lsu_advertisements)

        # lsu_packet.show()
        self._controller.send(lsu_packet)

    def _send_hello_msg(self, src_port, src, mask, helloint):
        hello_packet = self._get_pwospf_header(src=src, type=PWOSPF_TYPE_HELLO,
                                               packet_len=66, src_port=src_port) / PWOSPFHello(
            networkMask=mask, helloInt=helloint)
        # hello_packet.show()
        self._controller.send(hello_packet)

    # Receivers

    def receive_hello_msg(self, pkt):
        header = pkt[PWOSPFHeader]
        hello = pkt[PWOSPFHello]
        if header.type != PWOSPF_TYPE_HELLO:
            print 'Received corrupted PWOSPFHello msg'
            return
        if header.areaID != self._router.areaID:
            print 'Received hello message from area %s but this router (%s) has area %s' % (
                header.areaID, self._router.routerID, self._router.areaID)

        neighbor_id = header.routerID
        neighbor_ip = pkt[IP].src
        mask = hello.networkMask
        hello_interval = hello.helloInt

        # print 'Received hello from %s (%s) at %s\n\t %s %s' % (
        #     neighbor_id, neighbor_ip, self._router.routerID, mask, hello_interval)
        if pkt[CPUMetadata].srcPort in self._router.interfaces:
            received_interface = self._router.interfaces[pkt[CPUMetadata].srcPort]
            received_interface.add_neighbor(neighbor_id, neighbor_ip)
            self._router.add_neighbor(neighbor_id)
            self._last_hello[neighbor_id] = (time(), hello_interval * 3, received_interface)
            # set timer with hello interval to check whether next hello received.
            Timer(hello_interval * 3, self._check_hello, (neighbor_id,)).start()
        else:
            print 'Received interface is not in the interface list', self._router.routerID, pkt[
                CPUMetadata].srcPort, self._router.interfaces

    def _check_hello(self, neighbor_id):
        if neighbor_id not in self._last_hello:
            return
        recvd, timeout, interface = self._last_hello[neighbor_id]
        if time() > recvd + timeout:
            del self._last_hello[neighbor_id]
            interface.del_neighbor(neighbor_id)
            self._router.del_neighbor(neighbor_id)

    def receive_lsu_msg(self, pkt):

        # sequence control
        source_router = pkt[PWOSPFHeader].routerID
        if source_router not in self._lsu_received_sequences or self._lsu_received_sequences[
            source_router] < pkt[PWOSPFLSU].sequence:
            self._lsu_received_sequences[source_router] = pkt[PWOSPFLSU].sequence
        else:
            return

        # Add each advertisement as a node to the routing DB
        for i in range(pkt[PWOSPFLSU].numAdvertisements):
            index = 3 * i
            lsvad = pkt[PWOSPFLSU].lsuAdvertisements
            if lsvad[index + 2] != '0.0.0.0':
                self._router.add_link(router1_id=lsvad[index + 2], router2_id=source_router)
                self._router.add_subnet(subnet=lsvad[index], mask=lsvad[index + 1],
                                        router_id=lsvad[index + 2])
            else:
                self._router.add_subnet(subnet=lsvad[index], mask=lsvad[index + 1],
                                        router_id=source_router)

        # flood the message if ttl > 1
        pkt[PWOSPFLSU].ttl -= 1
        if pkt[PWOSPFLSU].ttl == 0:
            return
        pkt[CPUMetadata].fromCpu = 1
        for interface in self._router.interfaces.values():
            if interface.id != pkt[CPUMetadata].srcPort:
                for neighbor_ip in interface.neighbor_ips.values():
                    pkt[CPUMetadata].srcPort = interface.id
                    pkt[IP].src = interface.ipv4
                    pkt[IP].dst = neighbor_ip
                    self._controller.send(pkt)


if __name__ == "__main__":
    print 'This file should not be executed.'
