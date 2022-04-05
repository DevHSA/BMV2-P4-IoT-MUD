#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print 'pass 1 arguments: <destination> "<tos>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt = Ether(src='94:16:3e:3b:41:cf', dst='00:01:0a:00:01:02', type=0x0800)
    pkt = pkt / IP(proto=6 , src='10.0.1.1', dst='10.0.1.2')
    pkt = pkt / TCP(sport=5445, dport=443)
    #sendp(pkt, iface=iface, verbose=False)
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
