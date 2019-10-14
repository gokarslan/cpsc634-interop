#!/usr/bin/env python

import argparse

from mininet.net import Mininet
from mininet.node import Node

def initParser():
    parser = argparse.ArgumentParser(description="Start a mininet for interoperability")
    parser.add_argument('-t', '--topo', help="choose a JSON file defining the topology",
                        type=argparse.FileType('r'), default='topo.json')
    return parser.parse_args()

def interopNet(topo):
    net = Mininet()
    for sw_name in sorted(topo['switches'].keys()):
        sw_info = topo['switches'][sw_name]
        sw_cls = Node
        if 'class' in sw_info.keys():
            names = sw_info['class'].split('.')
            cls_module_name = '.'.join(names[:-1])
            cls_module = __import__(cls_module_name)
            cls_name = names[-1]
            sw_cls = getattr(cls_module, cls_name)
        net.addSwitch(sw_name, cls=sw_cls, **sw_info)
    for h_name in sorted(topo['hosts'].keys()):
        h_info = topo['hosts'][h_name]
        net.addHost(h_name, **h_info)
    for link in topo['links']:
        node1 = link[0]
        node2 = link[1]
        link_args = link[2] if len(link) > 2 else {}
        net.addLink(node1, node2, **link_args)
    return net

def interopTest(net):
    # TODO: add test cases for interop
    pass

def main():
    args = initParser()
    import json
    topo = json.load(args.topo)
    net = interopNet(topo)
    net.start()
    interopTest(net)
    net.stop()

if __name__ == '__main__':
    main()