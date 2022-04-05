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


def send_DHCP(iface):

    pkt = Ether(src="00:0b:82:01:fc:42", dst="ff:ff:ff:ff:ff:ff", type=0x0800)
    pkt = pkt / IP(proto=17 , src="0.0.0.0", dst="255.255.255.255")
    pkt = pkt / UDP(sport=68, dport=67)
    # pkt = pkt /
    #MSG TYPE to hops
    data = b'\x01\x01\x06\x00'
    #transaction ID
    data = data + b'\x00\x00\x3d\x1d'
    #seconds elapsed
    data = data + b'\x00\x00'
    #bootp flags
    data = data + b'\x00\x00'
    #Client IP
    data = data + b'\x00\x00\x00\x00'
    #Y IP
    data = data + b'\x00\x00\x00\x00'
    #Next Server
    data = data + b'\x00\x00\x00\x00'
    #Relay Agent
    data = data + b'\x00\x00\x00\x00'
    #Client MAC
    data = data + b'\x00\x0b\x82\x01\xfc\x42'
    #Client Hardware
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    #Server Hostname
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    data = data + b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    #Magic Cookie
    data = data + b'\x63\x82\x53\x63'
    #Option DHCP Message Type
    data = data + b'\x35\x01\x01'
    #Option Client Identifier
    data = data + b'\x3d\x07\x01\x00\x0b\x82\x01\xfc\x42'
    #Requested IP address
    data = data + b'\x32\x04\x00\x00\x00\x00'
    #Parameter Request List
    data = data + b'\x37\x04\x01\x03\x06\x2a'
    #Host name
    str = "http://127.0.0.1:443/awairairqualitymud"
    strlen = len(str)
    print(strlen)
    strlen_bytes = strlen.to_bytes(1,'big')
    str_bytes = str.encode('utf_8')
    print(strlen_bytes)

    data = data + b'\x0c' +strlen_bytes + str_bytes

    #END
    data = data + b'\xff'



    pkt = pkt / Raw(load=data)

    sendp(pkt, iface=iface, verbose=True)


def main():

    iface = get_if()
    send_DHCP(iface)

    #Read packet generator

    # packetGen = pd.read_csv('./GeneratedPackets.csv', dtype=str)

    # print(packetGen)

    # try:
    #     # while True:
    #
    #     for index,row in packetGen.iterrows():
    #         listView = row.tolist()
    #         send_packet(iface,listView)
    #         time.sleep(0.01)
    #
    # except KeyboardInterrupt:
    #     print("Enter Pressed")


if __name__ == '__main__':
    main()
