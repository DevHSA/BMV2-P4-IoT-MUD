#!/usr/bin/env python3
import sys
import socket
import random
import time
from scapy.all import *



def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def send_packet(iface):
    input("Press the return key to send a packet:")
    pkt = Ether(src='94:16:3e:3b:41:cf', dst='00:01:0a:00:01:01')
    pkt = pkt / IP(proto=6, src='10.0.1.1', dst='35.203.134.252')
    pkt = pkt / TCP(sport=53, dport=443)
    sendp(pkt, iface=iface, verbose=False)


def main():
    iface = get_if()

    try:
        while True:
            send_packet(iface)
            time.sleep(0.5)

    except KeyboardInterrupt:
        print("Enter Pressed")


if __name__ == '__main__':
    main()
