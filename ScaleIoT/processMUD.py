import json
import pandas as pd
import os
import numpy as np
import csv
import random

##*****ENABLE WHEN NOT EXECUTING FROM JUPYTER*********##
#***Get current directory path for future use
# currPath = os.getcwd()
# currPath = currPath.replace('\\','/')
# reqPath = currPath + "/JSON/"
##****************************************************##


## UNFORTUNATELY FORCED TO USE ABSOULTE PATHS DUE TO INTERACTIVE SHELL.

#Utility Function 1
def getSourceDestination(data):
    if 'dnsname' in str(data):
        src_net_key = 'ietf-acldns:src-dnsname'
        dest_net_key = 'ietf-acldns:dst-dnsname'
    elif 'network' in str(data):
        src_net_key = 'source-ipv4-network'
        dest_net_key = 'destination-ipv4-network'
    else:
        src_net_key = '*'
        dest_net_key = '*'
    return data.get(src_net_key, '*'), data.get(dest_net_key, '*'), data.get('protocol', '*')

#Main Function
def readMUDFile(pathName):
    print("INSIDE READMUDFILE")
    os.chdir("/home/p4/IoTMUD/ScaleIoT/MUDFiles/")
    files=os.listdir("/home/p4/IoTMUD/ScaleIoT/MUDFiles/")
    data = []
    df = None

    print(pathName)

    print(files)

    with open(pathName) as f:
        df = json.load(f)
        data.append(df)

    # print(df)
    # print(data)
    # print(type(data))

    print("Reached End")

    final_list = []
    for i in range(len(data)):
        print("Inside")
        access_json=data[i].get('ietf-access-control-list:access-lists').get('acl')
        for acl in access_json:
            aces = acl['aces']['ace']
            for ace in aces:
                final_row = {
                'sMAC': '*',
                'dMAC': '*',
                'typEth': '*',
                }
                if 'ethertype' in str(ace['matches']):
                    final_row['sMAC'] = ace['matches']['eth'].get('source-mac-address', '*')
                    final_row['dMAC'] = ace['matches']['eth'].get('destination-mac-address', '*')
                    final_row['typEth'] = ace['matches']['eth'].get('ethertype', '*')
                    # print("Inside if")
                    # print(ace['matches']['eth'])

                if 'ipv4' in str(ace['matches']):
                    source, dest, proto = getSourceDestination(ace['matches']['ipv4'])
                    final_row['srcIP'] = source
                    final_row['dstIP'] = dest
                    final_row['proto'] = proto
                elif 'ipv6' in str(ace['matches']):
                    source, dest, proto = getSourceDestination(ace['matches']['ipv6'])
                    final_row['srcIP'] = source
                    final_row['dstIP'] = dest
                    final_row['proto'] = proto
                else:
                    final_row['srcIP'] = '*'
                    final_row['dstIP'] = '*'
                    final_row['proto'] = '*'
                if 'ipv4' in str(ace['matches']):
                    source, dest, proto = getSourceDestination(ace['matches']['ipv4'])
                    if proto in [1,6,17] :
                        final_row['typEth']='0x0800'
                if 'icmp' in str(ace['matches']):
                    final_row['type'] = ace['matches']['icmp'].get('type', '*')
                    final_row['code'] = ace['matches']['icmp'].get('code', '*')
                else:
                    final_row['type'] = '*'
                    final_row['code'] = '*'
                if 'source-port' in str(ace['matches']):
                    final_row['sPort'] = ace['matches']['udp']['source-port'].get('port', '*') if 'udp' in str(ace['matches']) else ace['matches']['tcp']['source-port'].get('port', '*')
                else:
                    final_row['sPort'] = '*'
                if 'destination-port' in str(ace['matches']):
                    final_row['dPort'] = ace['matches']['udp']['destination-port'].get('port', '*') if 'udp' in str(ace['matches']) else ace['matches']['tcp']['destination-port'].get('port', '*')
                else:
                    final_row['dPort'] = '*'
                final_row['priority'] = '*'
                final_row['action'] = 'forward' if ace['actions'].get('forwarding', '') == 'accept' else '*'
                if final_row['srcIP'] == '*' and final_row['dstIP'] != '*':
                    final_row['sMAC'] = '9e:8d:de:80:29:28'
                if final_row['dstIP'] == '*' and final_row['srcIP'] != '*':
                    final_row['dMAC'] = '9e:8d:de:80:29:28'
                final_list.append(final_row)

    df = pd.DataFrame(final_list)
    df.head()
    print(df)


    print("Reached End")
    print(df.shape)
    columns = ['sMAC','dMAC','typEth','srcIP','dstIP','proto','sPort','dPort','action']
    df1 = df[columns]

    df2 =df1.drop_duplicates()

    for column in columns:
        df2[column] = df2[column].fillna('*')


    print(df2)
    return df2

    # df2.to_csv('ACLWithoutDuplicates.csv')






#
# df.shape
# df.to_csv('D:/PHD/RESEARCH/IOT-MUD-New/modules/1.MUDtoACL/ACLWithDuplicates.csv')
# column = ['sEth','dEth','typEth','Source','Destination','proto','sPort','dPort','priority','action']
#
# df2 = df[column]
# df1 =df2.drop_duplicates()
#
# df1.shape
#
# df1.to_csv('D:/PHD/RESEARCH/IOT-MUD-New/modules/1.MUDtoACL/ACLWithoutDuplicates.csv')
