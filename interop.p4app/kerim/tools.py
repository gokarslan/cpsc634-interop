#!/usr/bin/env python

def IP2Int(ip):
    o = map(int, ip.split('.'))
    res = (16777216 * o[0]) + (65536 * o[1]) + (256 * o[2]) + o[3]
    return res


def Int2IP(ipnum):
    o1 = int(ipnum / 16777216) % 256
    o2 = int(ipnum / 65536) % 256
    o3 = int(ipnum / 256) % 256
    o4 = int(ipnum) % 256
    return '%(o1)s.%(o2)s.%(o3)s.%(o4)s' % locals()


def apply_mask(ip, mask):
    cidr = sum(bin(int(x)).count('1') for x in mask.split('.'))
    destination = IP2Int(ip)
    destination >>= (32 - cidr)
    destination <<= (32 - cidr)
    destination = Int2IP(destination)
    return destination, cidr
