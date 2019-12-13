/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

// Eth types
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IPV4         = 0x800;
// IP protos
const bit<8>  TYPE_ICMP         = 0x1;
const bit<8>  TYPE_PWOSPF       = 0x59;
// PWOSPF types
const bit<8>  TYPE_PWOSPF_HELLO = 0x1;
const bit<8>  TYPE_PWOSPF_LSU   = 0x4;

// Provide counters for the following: IP, ARP, packets-to-cp
const bit<32> COUNTER_IP = 0x0;
const bit<32> COUNTER_ARP = 0x1;
const bit<32> COUNTER_CP = 0x2;

counter(3, CounterType.packets) ct;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8>      fromCpu;
    bit<16>     origEtherType;
    bit<16>     srcPort;
    ip4Addr_t   arpDst;
}

header arp_t {
    bit<16>     hwType;
    bit<16>     protoType;
    bit<8>      hwAddrLen;
    bit<8>      protoAddrLen;
    bit<16>     opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t   srcEth;
    ip4Addr_t   srcIP;
    macAddr_t   dstEth;
    ip4Addr_t   dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header pwospf_t {
    bit<8>    version;
    bit<8>    type;
    bit<16>   packetLen;
    bit<32>   routerID;
    bit<32>   areaID;
    bit<16>   checksum;
    bit<16>   autype;
    bit<64>   authentication;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ipv4;
    pwospf_t          pwospf;
}

struct metadata {
    ip4Addr_t       nextHop;
    bit<1>          matchedLocalIP;
    port_t          srcPort;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            TYPE_PWOSPF: parse_pwospf;
            default: accept;
        }
    }

    state parse_pwospf {
        packet.extract(hdr.pwospf);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.arpDst = meta.nextHop;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        meta.srcPort = (bit<9>)hdr.cpu_metadata.srcPort;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
        // increment counter for packets-to-cp
        ct.count(COUNTER_CP);
    }

    action route(ip4Addr_t nextHop, egressSpec_t port){
        standard_metadata.egress_spec = port;
        meta.nextHop = nextHop;
        //hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        // not here...
        // hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        //hdr.ethernet.dstAddr = dstAddr;

    }

    action arp_lookup(macAddr_t nextHopMac){
        // set the src MAC address based on the port the packet is departing from
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr; //0x000000000100 + (bit<48>)standard_metadata.egress_spec;
        hdr.ethernet.dstAddr = nextHopMac;

        // decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action local_ipv4_match(){
        meta.matchedLocalIP = 0x1;
    }

    action drop_local_match(){
    }

    action send_pwospf_hello(){
        standard_metadata.egress_spec = meta.srcPort;

    }
    table routing_table {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            drop_local_match;
            route;
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table arp_table {
        key = {
           meta.nextHop: exact;
        }
        actions = {
            arp_lookup;
            // if there is a entry in the routing table but there is no entry in the arp table.
            send_to_cpu;
            drop;
            NoAction;
        }
        size = 64;
        default_action = send_to_cpu();
    }

    table local_ipv4_table {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            local_ipv4_match;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    // TODO is initial value always 0?
    action init_matchedlocalip(){
        meta.matchedLocalIP = 0x0;
    }
    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (hdr.arp.isValid()) {
            // increment counter for ARP
            ct.count(COUNTER_ARP);
            if(standard_metadata.ingress_port != CPU_PORT){
                send_to_cpu();
            }else{
                fwd_l2.apply();

            }
        }
        else if (hdr.ethernet.isValid()) {
            if (hdr.ipv4.isValid()){
                // is initial value always 0?
                // init_matchedlocalip();
                // increment counter for IP
                ct.count(COUNTER_IP);

                if (hdr.pwospf.isValid()){
                    if(standard_metadata.ingress_port == CPU_PORT){
                        if(hdr.pwospf.type == TYPE_PWOSPF_HELLO){
                            send_pwospf_hello();
                        }else{
                            routing_table.apply();
                            arp_table.apply();
                        }

                    // PWOSPF packets should be sent to the software
                    }else{
                        send_to_cpu();
                    }

                } else{
                    // local IP packets (destined for the router) should be sent to the software
                    local_ipv4_table.apply();
                    if (meta.matchedLocalIP == 0x1){
                        send_to_cpu();
                    }
                    else{
                        // look up the next-hop port and IP address in the route table
                        routing_table.apply();
                        // look up the MAC address of the next-hop in the ARP table
                        arp_table.apply();
                    }
                }
            } else{
                // any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
                send_to_cpu();
            }
        } else{
            // any packets that the hardware cannot deal with should be forwarded to the CPU. (e.g. not Version 4 IP)
            send_to_cpu();
        }

    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    // calculate a new IP checksum
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.pwospf);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
