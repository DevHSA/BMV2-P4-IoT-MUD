#!/usr/bin/env python3
import sys
import socket
import random
import time
import pandas as pd

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


def send_packet(iface, listView):

    #convert to match types
    typeEth = int(listView[2], 16)
    print(type(typeEth))


    proto = int(listView[3])
    sport = int(listView[4])
    dport = int(listView[5])
    sIP = listView[6]
    dIP = listView[7]#'2.2.2.2'
    # print(type(type))
    # print(type(typeEthNew))
    pkt = []

    if listView[3] == "17":
        pkt = Ether(src=listView[0], dst=listView[1], type=typeEth)
        pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
        pkt = pkt / UDP(sport=sport, dport=dport)
    else:
        pkt = Ether(src=listView[0], dst=listView[1], type=typeEth)
        pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
        pkt = pkt / TCP(sport=sport, dport=dport)

    print(listView)
    # input("Press the return key to send the packet:")

    sendp(pkt, iface=iface, verbose=False)


def main():

    iface = get_if()
# time.sleep(0.1)


    #Read packet generator

    packetGen = pd.read_csv('./GeneratedPackets.csv', dtype=str)

    # print(packetGen)

    try:
        # while True:

        for index,row in packetGen.iterrows():
            listView = row.tolist()
            send_packet(iface,listView)
            time.sleep(0.01)

    except KeyboardInterrupt:
        print("Enter Pressed")


if __name__ == '__main__':
    main()
