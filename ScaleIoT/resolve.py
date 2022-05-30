'''
Here, the domain names are resolved to IP addresses using the gethostbyname() function. 
Subsequently, the resolved ACL rules are sent to decisiontree.py.
'''

import csv
import pandas as pd
import ipaddress
import socket
import random

from socket import gaierror
from random import randint
import time
from datetime import datetime

'''
ENABLE WHEN NOT EXECUTING FROM JUPYTER --

Get current directory path for future use
currPath = os.getcwd()
currPath = currPath.replace('\\','/')
reqPath = currPath + "/JSON/"

'''

#Dictionary to hold all resolved IP addresses
resolvedDomains = {} #Empty Dictionary

#Function to resolve Domains to IP addresss and store it in a local cache

def domainResolver(domainName):
    try:
        return resolvedDomains[domainName] #Return the IP address if domain already resolved

    except KeyError:
        '''
        We find that the domainName is not present in the dictionary as a key,
        so we resolve the domain using gethostbyname function
        '''

        try: #Check if it already is an IP address. If so, return the same
            ip = ipaddress.ip_address(domainName)
            return domainName
        except ValueError: #If not an IP address, then resolve. Store and return the same
            
            try: #If successfully resolved
                resolvedDomains[domainName] = socket.gethostbyname(domainName)
                return resolvedDomains[domainName]
            except gaierror: #If not successfully resolved, generate random IP
                randIp = ".".join(str(randint(1, 254)) for _ in range(4))
                resolvedDomains[domainName] = randIp
                return resolvedDomains[domainName]

# MAIN FUNCTION
def resolve(pureACL):

    print(pureACL)
    # print(pureACL.iterrows())

    for index,row in pureACL.iterrows():
        
        # print("count = ", count)
        # count+=1
        #print(index)
        #0 (Convert All MACs to generic ones)
        # if row['sMAC'] != '*' and row['sMAC']!= 'ff:ff:ff:ff:ff:ff':
        #     row['sMAC'] = "<sMAC>"
        #     pureACL.at[index,'sMAC'] = row['sMAC']
        # if row['dMAC'] != '*' and row['dMAC']!= 'ff:ff:ff:ff:ff:ff':
        #     row['dMAC'] = "<dMAC>"
        #     pureACL.at[index,'dMAC'] = row['dMAC']

        #1 (Remove all '/' notations)

        if row['srcIP'] != '*' and row['srcIP'].find('/')!=-1:
            row['srcIP'] = row['srcIP'].split('/')[0]
            pureACL.at[index,'srcIP'] = row['srcIP']

        if row['dstIP'] != '*' and row['dstIP'].find('/')!=-1:
            row['dstIP'] = row['dstIP'].split('/')[0]
            pureACL.at[index,'dstIP'] = row['dstIP']

        #2 Convert all the Domain Names to IP Addresses
        if row['srcIP'] != '*':
            pureACL.at[index,'srcIP'] = domainResolver(row['srcIP'])

        if row['dstIP'] != '*':
            pureACL.at[index,'dstIP'] = domainResolver(row['dstIP'])

    return pureACL

# ##INPUT: separate ACL lists of IoT Devices derived from MUD profiles
# ##OUTPUT: file named GeneratedDatasetACL.csv in the same folder
#
# ##Conf Variables. (to be changed in different environment)
# pathPrefix = "D:/PHD/RESEARCH/IOT-MUD-New/modules/2.ACLScaling/" #Change to base path of script
# pathSuffix = ".csv" #file type
#
#
# macList = [] #Contains list of generated Mac Addresses
#
# #Contains the ordering of columns. Change the order but not the columns name itself.
# columnOrder = ['sMAC', 'dMAC', 'typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'action']
#
# #Dictionary to hold all resolved IP addresses
# resolvedDomains = {} #Empty Dictionary
#
# #Final DataFrame List
# accumulateList = pd.DataFrame(columns=columnOrder)
#
# ##Function to check if the same MAC has been generated before
# def checkUniqueMAC(macAddr):
#     for mac in macList:
#         if mac == macAddr:
#             return True
#     return False
#
# ##Function to resolve Domains to IP addresss and store it in a local cache
# def domainResolver(domainName):
#     try:
#         return resolvedDomains[domainName] #Return the IP address if domain already resolved
#     except KeyError:
#         #resolve the domain
#         try: #Check if it already is an IP address. If so, return the same
#             ip = ipaddress.ip_address(domainName)
#             return domainName
#         except ValueError: #If not an IP address, then resolve. Store and return the same
#             print(domainName)
#             try: #If successfully resolved
#                 resolvedDomains[domainName] = socket.gethostbyname(row['dstIP'])
#                 return resolvedDomains[domainName]
#             except gaierror: #If not successfully resolved, generate random IP
#                 randIp = ".".join(str(randint(1, 254)) for _ in range(4))
#                 resolvedDomains[domainName] = randIp
#                 return resolvedDomains[domainName]
#
#
# scalingFactor = 160 #Scale the dataset by this factor
#
# distributionArray = [0]*28
# noOfDevicesCalc = 140
#
# for i in range(noOfDevicesCalc) :
#      distributionArray[randint(0, 28) % 28] += 1;
#
#
#
# ##If a new device is added, please append the same to this array
# ##Change the number beside it to simulate appropriate number of devices
# deviceList=[["air_quality", 1],
#            ["amazon_echo", 1],
#            ["august_doorbell", 1],
#            ["babymonitor", 1],
#            ["barbie", 1],
#            ["belkin_camera", 1],
#            ["blipcarebpmeter", 1],
#            ["canarycamera", 1],
#            ["cultra", 1],
#            ["dropcam", 1],
#            ["hpprinter", 1],
#            ["huebulb", 1],
#            ["ihomeplug", 1],
#            ["lifxbulb", 1],
#            ["nestsmo", 1],
#            ["netacamera", 1],
#            ["netaWS", 1],
#            ["pixphotoframe", 1],
#            ["ringdoorbell", 1],
#            ["samsungsmartcam", 1],
#            ["sleepsensor", 1],
#            ["smartthings", 1],
#            ["tplinkcamera", 1],
#            ["tplinkplug", 1],
#            ["tribyspeaker", 1],
#            ["wemoswitch", 1],
#            ["wemotion", 1],
#            ["withcardio", 1]]


# ##Scale Each device by the scaling Factor
# noOfDevices = 0
#
# for i in range(0,28):
#     deviceList[i][1] = deviceList[i][1] * distributionArray[i]
#     noOfDevices = noOfDevices + distributionArray[i];
#
# # for device in deviceList:
# #     device[1] = device[1] * scalingFactor
# #     noOfDevices = noOfDevices + device[1]
#
# print(deviceList)
#
# ##Process each device one by one
# for device in deviceList:
#
#     #Read data from each file
#     data = pd.read_csv(pathPrefix + "aclrules/" + device[0] + pathSuffix, dtype=str)
#
#     #Drop some columns
#     newData = data[['sEth', 'dEth', 'typEth', 'proto', 'sPort', 'dPort', 'Source', 'Destination', 'action']]
#
#     #Rename some columns
#     newData.columns = ['sMAC', 'dMAC', 'typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'action']
#
#
#
#     ##Cleaning the dataset##
#     for index, row in newData.iterrows():
#
#         #0 (Convert All MACs to generic ones)
#         if row['sMAC'] != '*' and row['sMAC']!= 'ff:ff:ff:ff:ff:ff':
#             row['sMAC'] = "<sMAC>"
#             newData.at[index,'sMAC'] = row['sMAC']
#         if row['dMAC'] != '*' and row['dMAC']!= 'ff:ff:ff:ff:ff:ff':
#             row['dMAC'] = "<dMAC>"
#             newData.at[index,'dMAC'] = row['dMAC']
#
#         #1 (Remove all '/' notations)
#         if row['srcIP'] != '*' and row['srcIP'].find('/')!=-1:
#             row['srcIP'] = row['srcIP'].split('/')[0]
#             newData.at[index,'srcIP'] = row['srcIP']
#         if row['dstIP'] != '*' and row['dstIP'].find('/')!=-1:
#             row['dstIP'] = row['dstIP'].split('/')[0]
#             newData.at[index,'dstIP'] = row['dstIP']
#
#         #2 Convert all the Domain Names to IP Addresses
#         if row['srcIP'] != '*':
#             newData.at[index,'srcIP'] = domainResolver(row['srcIP'])
#         if row['dstIP'] != '*':
#             newData.at[index,'dstIP'] = domainResolver(row['dstIP'])
#
#         # Convert Protocol column to all strings
# #         if type(row['proto']) == int:
# #             print(row['proto'], type(row['proto']), sep='-----')
# #             row['proto'] = str(row['proto'])
# #             temp = str(row['proto'])
# #             print(temp, type(temp), sep='-----')
# #             newData.at[index,'proto'] = temp
#
#
#
#     ##Now the dataset per device is ready. Replicating it n times with unique mac addresses
#     for i in range(0,device[1]):
#
#         #Creating a copy
#         copyFrame = newData.copy()
#
#         #Generate a random MAC address. First three bytes are fixed.
#         mac = [ 0x94, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
#         genMAC = ':'.join(map(lambda x: "%02x" % x, mac))
#
#         #Check for Duplicate MAC addresses
#         while checkUniqueMAC(genMAC):
#             mac = [ 0x94, 0x16, 0x3e, random.randint(0x00, 0x7f), random.randint(0x00, 0xff), random.randint(0x00, 0xff) ]
#             genMAC = ':'.join(map(lambda x: "%02x" % x, mac))
#
#         #If found Unique, then add to the list of all MACs
#         macList.append(genMAC)
#
#         #Replace the MAC Address with the randomly generated unique MAC Address
#         for index,row in copyFrame.iterrows():
#             if row['sMAC'] == '<sMAC>':
#                 row['sMAC'] = genMAC
#                 copyFrame.at[index,'sMAC'] = row['sMAC']
#             if row['dMAC'] == '<dMAC>':
#                 row['dMAC'] = genMAC
#                 copyFrame.at[index,'dMAC'] = row['dMAC']
#
#         #Add the dataset to the bigger list
#         accumulateList = accumulateList.append(copyFrame, ignore_index=True)
#
# accumulateList.loc[len(accumulateList)] = ["*","*","*","*","*","*","*","*","drop"]
#
# ##Drop Duplicates and export the final DataSet
# finalList = pd.DataFrame(columns=columnOrder)
# finalList = accumulateList.drop_duplicates(keep='first', ignore_index=True)
# finalList.to_csv('GeneratedDatasetACL.csv', index=False)
# print("No.of ACL Rules (With duplicates): ",accumulateList.shape[0])
# print("No.of ACL Rules (Without duplicates): ",finalList.shape)
# print("No.of Devices: ", noOfDevices)
# # print(resolvedDomains)
# # print(len(resolvedDomains))
#
# # print(finalList)
#
# ##Now to extract statistics from the generated dataset.
#
# #Create 9 different arrays and store only unique values
#
# sMAC = []
# dMAC = []
# typEth = []
# proto = []
# sPort = []
# dPort = []
# srcIP = []
# dstIP = []
# action = []
#
#
# #Store all unique values of the levels
# def checkUniqueAndStore(array, value):
#
#     for val in array:
#         if val == value:
#             return
#     array.append(value)
#     return
#
# # print(finalList)
# #Iterate and check for unique values
# for index, row in finalList.iterrows():
#     checkUniqueAndStore(sMAC, row['sMAC'])
#     checkUniqueAndStore(dMAC, row['dMAC'])
#     checkUniqueAndStore(typEth, row['typEth'])
#     checkUniqueAndStore(proto, row['proto'])
#     checkUniqueAndStore(sPort, row['sPort'])
#     checkUniqueAndStore(dPort, row['dPort'])
#     checkUniqueAndStore(srcIP, row['srcIP'])
#     checkUniqueAndStore(dstIP, row['dstIP'])
#     checkUniqueAndStore(action, row['action'])
#
# print("Completed")
#
# #Extract data from the arrays
#
# print("sMAC", str(len(sMAC)), sep="---")
# print("dMAC", str(len(dMAC)), sep="---")
# print("typEth", str(len(typEth)), sep="---")
# print("proto", str(len(proto)), sep="---")
# print("sPort", str(len(sPort)), sep="---")
# print("dPort", str(len(dPort)), sep="---")
# print("srcIP", str(len(srcIP)), sep="---")
# print("dstIP", str(len(dstIP)), sep="---")
# print("action", str(len(action)), sep="---")
#
# print(typEth)
# print(proto)
# print(sPort)
# print(action)
#
#
# #calculate the size of each level
# sizeTemplate = [6,6,2,1,2,2,4,4]  # 27
# # size = [0,0,0,0,0,0,0,0]
#
# val = finalList.shape
#
# print("Total memory occupied in the TCAM: ", val[0] * 27 , "Bytes")


# ## For later
# newcolumnOrder = ['sMAC', 'dMAC', 'typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP']
# #Dataset Dataframe
# dataSet = pd.DataFrame(columns=newcolumnOrder, dtype=str)

# droppedDataset = finalList[newcolumnOrder].copy()

# print("Something1")
# # print(droppedDataset)
# #Now generate a random dataset from the unique values
# for index, row in droppedDataset.iterrows():
#     print(index)
#     #convert row to list
#     listView = row.tolist()
# #     print("Something12")
#     #Case of device emissiontype
#     if(row['sMAC'] !='*' and row['dMAC'] =='*'):
#         listView[1] = "00:00:00:00:00"
#         if listView[2] == "*":
#             listView[2] = "0x0000"
#         if listView[3] == "*":
#             listView[3] = "99"
#         if listView[4] == "*":
#             listView[4] = "0"
#         if listView[5] == "*":
#             listView[5] = "0"
#         if listView[6] == "*":
#             listView[6] = "0.0.0.0"
#         if listView[7] == "*":
#             listView[7] = "0.0.0.0"

# #         print("Something21")
#         dataSet.loc[len(dataSet)] = listView
# #         print("Something22")
#     #Case of 2
#     if(row['sMAC'] =='*' and row['dMAC'] =='*'):

#         if listView[0] == "*":
#             listView[0] = "00:00:00:00:00"
#         if listView[1] == "*":
#             listView[1] = "00:00:00:00:00"
#         if listView[2] == "*":
#             listView[2] = "0x0000"
#         if listView[3] == "*":
#             listView[3] = "99"
#         if listView[4] == "*":
#             listView[4] = "0"
#         if listView[5] == "*":
#             listView[5] = "0"
#         if listView[6] == "*":
#             listView[6] = "0.0.0.0"
#         if listView[7] == "*":
#             listView[7] = "0.0.0.0"
# #         print("Something31")
#         dataSet.loc[len(dataSet)] = listView
# #         print("Something32")

# dataSet.to_csv('GeneratedPackets.csv', index=False)

# #Dataset Dataframe
# aclRules = pd.DataFrame(columns=columnOrder, dtype=str)


# #Open the commands file where all the commands are accumulated
# commandsACL = open("commandsACL.txt", 'w')

# # print(finalList)
# #Now generate a random dataset from the unique values
# for index, row in finalList.iterrows():

#     #convert row to list
#     listView = row.tolist()

#     command = 'table_add data forward '

#     if listView[0] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         octet = listView[0].split(':')
#         convertedValue = '0x'+octet[0]+octet[1]+octet[2]+octet[3]+octet[4]+octet[5]
#         command = command + convertedValue + '&&&0xff '

#     if listView[1] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         octet = listView[1].split(':')
#         convertedValue = '0x'+octet[0]+octet[1]+octet[2]+octet[3]+octet[4]+octet[5]
#         command = command + convertedValue + '&&&0xff '

#     if listView[2] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         command = command + listView[2] + '&&&0xff '

#     if listView[3] == "*":
#         command = command + '0x99&&&0xff '
#     else:
#         value = hex(int(listView[3]))
#         command = command + value + '&&&0xff '

#     if listView[4] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         value = hex(int(listView[4]))
#         command = command + value + '&&&0xff '

#     if listView[5] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         value = hex(int(listView[5]))
#         command = command + value + '&&&0xff '

#     if listView[6] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         octet = listView[6].split('.')
#         convertedValue = '0x'+''.join((hex(int(i))[2:] for i in octet))
#         command = command + convertedValue + '&&&0xff '

#     if listView[7] == "*":
#         command = command + '0x00&&&0xff '
#     else:
#         octet = listView[7].split('.')
#         convertedValue = '0x'+''.join((hex(int(i))[2:] for i in octet))
#         command = command + convertedValue + '&&&0xff '

#     command = command + '=> 00:01:0a:00:01:02 2 ' + str(index+1)


#     #Whatever the command is, it needs to be outputed on a file stream
#     commandsACL.write("%s\n" % command)

# val = 'table_add data drop 0x00&&&0xff 0x00&&&0xff 0x99&&&0xff 0x00&&&0xff 0x00&&&0xff 0x00&&&0xff 0x00&&&0xff '
# commandsACL.write("%s\n" % val)
# commandsACL.close()
