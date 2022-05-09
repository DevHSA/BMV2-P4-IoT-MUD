#!/usr/bin/env python3
import sys
import socket
import random
import time
import pandas as pd
from datetime import datetime


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
    str = "http://127.0.0.1:443/huebulb"
    strlen = len(str)
    print(strlen)
    strlen_bytes = strlen.to_bytes(1,'big')
    str_bytes = str.encode('utf_8')
    print(strlen_bytes)

    data = data + b'\x0c' +strlen_bytes + str_bytes

    #END
    data = data + b'\xff'



    pkt = pkt / Raw(load=data)

    now = datetime.now()
    mic = now.microsecond
    print(mic)

    milliseconds = int(time.time() * 1000)

    sendp(pkt, iface=iface, verbose=True)
    print("Timestamp at Packet generation", milliseconds)

def send_test(iface):

    pkt = Ether(src="00:0b:82:01:fc:42", dst="00:0b:82:01:fc:46", type=0x0800)
    pkt = pkt / IP(proto=6 , src="224.239.227.216", dst="104.114.84.137")
    pkt = pkt / TCP(sport=3322, dport=443)

    sendp(pkt, iface=iface, verbose=True)

def correctness_sendPacket(iface, listView):


    print(listView)

    # convert to match types
    #0 = smac, 1 = dmac, 2 = typeth, 3 = srcip, 4 = dstip, 5 = proto, 6 = sport, 7 = dport

    if(listView[0] == '*'):
        src = "00:00:5e:00:53:af"
    else:
        src = listView[0]

    if(listView[1] == '*'):
        dst = "00:00:5e:00:53:af"
    else:
        dst = listView[1]

    if(listView[2] == '*'):
        typeEth = 0x0800
    else :
        typeEth = int(listView[2], 16)
    # print(type(typeEth))

    if(listView[3] == '*'):
        sIP = "0.0.0.1"
    else:
        sIP = listView[3]

    if(listView[4] == '*'):
        dIP = "0.0.0.4"
    else:
        dIP = listView[4]

    if(listView[5] == '*'):
        proto = 17
    else :
        proto = int(listView[5])

    if(listView[6] == '*'):
        sport = 443
    else:
        sport = int(listView[6])

    if(listView[7] == '*'):
        dport = 443
    else:
        dport = int(listView[7])

    # sport = int(listView[4])
    # dport = int(listView[5])
    # sIP = listView[6]
    # dIP = listView[7]#'2.2.2.2'
    # print(type(type))
    # print(type(typeEthNew))
    pkt = []

    if proto == 17:
        pkt = Ether(src=src, dst=dst, type=typeEth)
        pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
        pkt = pkt / UDP(sport=sport, dport=dport)
    else:
        pkt = Ether(src=src, dst=dst, type=typeEth)
        pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
        pkt = pkt / TCP(sport=sport, dport=dport)

    # print(listView)
    # input("Press the return key to send the packet:")

    sendp(pkt, iface=iface, verbose=False)

    # print(listView)

    # # convert to match types

    # typeEth = int(listView[2], 16)
    # print(type(typeEth))


    # proto = int(listView[3])
    # sport = int(listView[4])
    # dport = int(listView[5])
    # sIP = listView[6]
    # dIP = listView[7]#'2.2.2.2'
    # # print(type(type))
    # # print(type(typeEthNew))
    # pkt = []

    # if listView[3] == "17":
    #     pkt = Ether(src=listView[0], dst=listView[1], type=typeEth)
    #     pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
    #     pkt = pkt / UDP(sport=sport, dport=dport)
    # else:
    #     pkt = Ether(src=listView[0], dst=listView[1], type=typeEth)
    #     pkt = pkt / IP(proto=proto , src=sIP, dst=dIP)
    #     pkt = pkt / TCP(sport=sport, dport=dport)

    # print(listView)
    # # input("Press the return key to send the packet:")

    # sendp(pkt, iface=iface, verbose=False)


def correctness_openFile(iface):

    packetGen = pd.read_csv('./template.csv', dtype=str)

    for index,row in packetGen.iterrows():
        listView = row.tolist()
        correctness_sendPacket(iface,listView)
        time.sleep(0.01)

    print("Stub")

def main():

    iface = get_if()
    # send_DHCP(iface)
    # time.sleep(2)
    # send_test(iface)
    correctness_openFile(iface)

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
