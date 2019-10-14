#!/usr/bin/env python

import argparse

from p4app import P4Mininet

def initParser():
    parser = argparse.ArgumentParser(description="Start a mininet for interoperability")
    parser.add_argument('-t', '--topo', help="choose a JSON file defining the topology",
                        type=argparse.FileType('r'), default='topo.json')
    return parser.parse_args()

def interop(topo):
    net = P4Mininet()

def main():
    args = initParser()
    import json
    topo = json.load(args.topo)
    interop(topo)

if __name__ == '__main__':
    main()