'''
The decisiontree.py has two tasks: converting resolved ACL rules to a decision tree
and adding corresponding table rules to the switch.
'''

import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import time
from datetime import datetime

'''
#*****ENABLE WHEN NOT EXECUTING FROM JUPYTER --
***Get current directory path for future use
currPath = os.getcwd()
currPath = currPath.replace('\\','/')
reqPath = currPath + "/JSON/"
#INPUT: GeneratedDatasetACL.csv in the same path of the executing script
#OUTPUT: Varied... Will be listed
'''

'''
Initialized Corresponding LevelCounters, and the decision tree and added
the first node which is NULL
'''

levelCounters = [1,1,1,1,1,1,1,1,1];
G = nx.DiGraph();
G.add_node('Null')

'''

#calculate the size of each level
sizeTemplateBits = [72,96,64,56,64,64,80,80,9]
sizeTemplateBytes = [9,12,8,7,8,8,10,10,1.125]

calculatedSizeBits = [0,0,0,0,0,0,0,0,0]
calculatedSizeBytes = [0,0,0,0,0,0,0,0,0]
noOfNodes = [0,0,0,0,0,0,0,0,0]
noOfNodesSep = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

'''

#Function to check if a particular node is present in the list of its neighbors
def checkIfPresent(valueToCheck, neighborList):

    for node in neighborList:
        values = node.split('=')
        if(values[2] == valueToCheck):
            return True

    return False

def checkIfPresentAndReturn(valueToCheck, neighborList):
    # print(valueToCheck)
    # print(type(valueToCheck))
    # print(neighborList)

    for node in neighborList:
        values = node.split('=')
        if(values[2] == valueToCheck):
            # print("present")
            return node
    # print("not present")
    return False

#FUNCTION TO ADD RULES and SEND CORRESPONDING SWITCH COMMANDS
def addSwitchCommand(addedNodeArray, addedStateArray, levelHeaders, p4info_helper, s1, readTableRules):

    # print("Adding Switch Command")
    print(addSwitchCommand.cntr)
    print(addedNodeArray)
    print(addedStateArray)

    addSwitchCommand.cntr = addSwitchCommand.cntr + 1
    #for every addition, generate a corresponding switch command
    for i in range(0,8):


        #Check if the node is to be added with the help of stub values X and -1
        if addedNodeArray[i]!='X' and addedStateArray[i]!='-1':

            command = ''
            convertedValue = ''

            tableName = ''
            matchFields = {}
            actionName = ""
            actionParams = {}

            #Logic to convert to Hex values
            if addedNodeArray[i] == '*': #if * then dont touch it. it is taken care of below
                convertedValue = addedNodeArray[i]
            elif levelHeaders[i] == 'sMAC' or levelHeaders[i] == 'dMAC':
#                 octet = addedNodeArray[i].split(':')
#                 convertedValue = '0x'+octet[0]+octet[1]+octet[2]+octet[3]+octet[4]+octet[5]
                convertedValue = str(addedNodeArray[i])
            elif levelHeaders[i] == 'srcIP' or levelHeaders[i] == 'dstIP':
#                 octet = addedNodeArray[i].split('.')
#                 convertedValue = '0x'+''.join((hex(int(i))[2:] for i in octet))
                convertedValue = str(addedNodeArray[i])
            else:
                convertedValue = addedNodeArray[i]

            #Handle First Level addition (Add only val,nxtState)

            '''
            We are using dictionaries here so that code could be compressed for levels
            2 to 7(which are numbered 1 to  6).
            '''

            tablesmap = {1 : "MyIngress.dMAC_exact" ,
                        2 : "MyIngress.typEth_exact",
                        3 : "MyIngress.proto_exact",
                        4 : "MyIngress.sPort_exact",
                        5 : "MyIngress.dPort_exact",
                        6 : "MyIngress.srcIP_exact"}
            tablesdefaultmap = {1 : "MyIngress.dMAC_default",
                                2 : "MyIngress.typEth_default",
                                3: "MyIngress.proto_default",
                                4: "MyIngress.sPort_default",
                                5: "MyIngress.dPort_default",
                                6: "MyIngress.srcIP_default"}
            matchesmap = {  1 : "hdr.ethernet.dEth",
                            2 : "hdr.ethernet.typeEth",
                            3 : "hdr.ipv4.protocol",
                            4 : "meta.sport",
                            5 : "meta.dport",
                            6 : "hdr.ipv4.srcAddr"
                            }
            '''
            this is the first level which is used for adding table entry
            to match source MAC address
            '''

            if i==0:
#                 print("Entered 0")
                #if it is to be added in the exact table
                if addedNodeArray[i]!="*":
                    tableName = levelHeaders[i] + '_exact'
                    actionName = 'store_state_'+levelHeaders[i]
                    matchFields = convertedValue
                    actionParams = addedStateArray[i+1]
                    nxtState = int(addedStateArray[i+1])
                    command='table_add '+levelHeaders[i]+'_exact'+' store_state_'+levelHeaders[i]+' '+convertedValue+' => '+addedStateArray[i+1]

                    ##sETH TABLE ENTRY
                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.sMAC_exact",
                        match_fields={
                            "hdr.ethernet.sEth": matchFields
                        },
                        action_name="MyIngress.ns_exact",
                        action_params={
                            "next_state": nxtState,
                        })
                    s1.WriteTableEntry(table_entry)

                #if it is to be added in the default table
                elif addedNodeArray[i]=="*":

                    nxtState = int(addedStateArray[i+1])
                    command='table_add '+levelHeaders[i]+'_default'+' store_state_'+levelHeaders[i]+'_default1'+' 0 => '+addedStateArray[i+1]

                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.sMAC_default",
                        match_fields={
                            "meta.stub_current_state_value": 0
                        },
                        action_name="MyIngress.ns_default",
                        action_params={
                            "next_state": nxtState,
                        })
                    s1.WriteTableEntry(table_entry)

            #handling level 1 to 6 for adding table entries
            elif i < 7:

                #print("Entered 0")
                #if it is to be added in the exact table
                if addedNodeArray[i]!="*":
                    matchFields = convertedValue
                    currState = int(addedStateArray[i])
                    nxtState = int(addedStateArray[i+1])

                    if i == 2:
                        matchfields = int(matchFields , 16)
                    elif i in (3,4,5) :
                        matchfields = int(matchFields)
                    else :
                        matchfields = matchFields

                    ##dETH TABLE ENTRY
                    table_entry = p4info_helper.buildTableEntry(
                        table_name= tablesmap[i],
                        match_fields={
                            "meta.current_state": currState,
                            matchesmap[i] : matchfields
                        },
                        action_name="MyIngress.ns_exact",
                        action_params={
                            "next_state": nxtState,
                        })
                    s1.WriteTableEntry(table_entry)

                #if it is to be added in the default table
                else:

                    currState = int(addedStateArray[i])
                    nxtState = int(addedStateArray[i+1])
                    # print(currState)
                    # print(nxtState)

                    table_entry = p4info_helper.buildTableEntry(
                        table_name = tablesdefaultmap[i],
                        match_fields={
                            "meta.current_state": currState
                        },
                        action_name="MyIngress.ns_default",
                        action_params={
                            "next_state": nxtState,
                        })
                    s1.WriteTableEntry(table_entry)

            else:
                #print("Entered 8")
                #if the action is forward, then push
                if addedNodeArray[i] == "forward":
                    command = 'table_add final '+convertedValue+' '+addedStateArray[i] + ' => 08:00:00:00:02:22 2'
                elif addedNodeArray[i] == "drop":
                    command = 'table_add final '+convertedValue+' '+addedStateArray[i] + ' =>'

                matchFields = convertedValue
                currState = int(addedStateArray[i])
                nxtState = int(addedStateArray[i+1])

                if addedNodeArray[i]!="*":

                    ##dIP TABLE ENTRY
                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.dstIP_exact",
                        match_fields={
                            "meta.current_state": currState,
                            "hdr.ipv4.dstAddr": convertedValue
                        },
                        action_name="MyIngress.forward",
                        action_params={
                            "dstAddr": "08:00:00:00:02:22",
                            "switchPort": 2
                        })
                    s1.WriteTableEntry(table_entry)

                elif addedNodeArray[i]=="*":
                    currState = int(addedStateArray[i])
                    nxtState = int(addedStateArray[i+1])

                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.dstIP_default",
                        match_fields={
                            "meta.current_state": currState
                        },
                        action_name="MyIngress.forward",
                        action_params={
                            "dstAddr": "08:00:00:00:02:22",
                            "switchPort": 2
                        })
                    s1.WriteTableEntry(table_entry)
            '''

            IGNORE THE BELOW COMMENTED PART WHICH PREVIOUSLY ADDED TABLE ENTRIES
            FOR EACH LEVEL ONE BY ONE.
            The final level is already dealt separately



            # #Handle level 2 - this is the optimized code start
            # elif i == 1:

            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])

            #         if i == 2:
            #             matchfields = int(matchFields , 16)
            #         elif i in (3,4,5) :
            #             matchfields = int(matchFields)
            #         else :
            #             matchfields = matchFields

            #         ##dETH TABLE ENTRY
            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name= "MyIngress.dMAC_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "hdr.ethernet.dEth" : matchfields
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)


            #     #if it is to be added in the default table
            #     else:

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name = "MyIngress.dMAC_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)

            # #Handle level 3
            # elif i==2:
            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         intconv = int(matchFields, 16)

            #         ##dETH TABLE ENTRY
            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.typEth_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "hdr.ethernet.typeEth": intconv
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)
            #     elif addedNodeArray[i]=="*":

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.typEth_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)


            # #Handle level 4
            # elif i==3:
            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         # print("Inside TYPE ETH")
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         intconv = int(matchFields,10)
            #         # print(matchFields)
            #         # print(type(matchFields))
            #         # print(intconv)

            #         # print(addedNodeArray)
            #         # print(addedStateArray)

            #         # intconv = 17


            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.proto_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "hdr.ipv4.protocol": intconv
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)


            #         # readTableRules(p4info_helper, s1)


            #     #if it is to be added in the default table
            #     elif addedNodeArray[i]=="*":

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print("Inside default")
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.proto_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)

            # #Handle level 5
            # elif i==4:
            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         intconv = int(matchFields)
            #         # print(matchFields)
            #         # print(intconv)


            #         # print(bytearray.fromhex(matchFields[2]))

            #         ##dETH TABLE ENTRY
            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.sPort_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "meta.sport": intconv
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)
            #     elif addedNodeArray[i]=="*":

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.sPort_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)

            # #Handle level 6
            # elif i==5:
            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         intconv = int(matchFields)
            #         # print(matchFields)
            #         # print(intconv)


            #         # print(bytearray.fromhex(matchFields[2]))

            #         ##dETH TABLE ENTRY
            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.dPort_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "meta.dport": intconv
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)
            #     elif addedNodeArray[i]=="*":

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.dPort_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)

            # #Handle level 7
            # elif i==6:
            #     #print("Entered 0")
            #     #if it is to be added in the exact table
            #     if addedNodeArray[i]!="*":
            #         matchFields = convertedValue
            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(matchFields)
            #         # print(intconv)


            #         # print(bytearray.fromhex(matchFields[2]))

            #         ##dETH TABLE ENTRY
            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.srcIP_exact",
            #             match_fields={
            #                 "meta.current_state": currState,
            #                 "hdr.ipv4.srcAddr": convertedValue
            #             },
            #             action_name="MyIngress.ns_exact",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)
            #     elif addedNodeArray[i]=="*":

            #         currState = int(addedStateArray[i])
            #         nxtState = int(addedStateArray[i+1])
            #         # print(currState)
            #         # print(nxtState)

            #         table_entry = p4info_helper.buildTableEntry(
            #             table_name="MyIngress.srcIP_default",
            #             match_fields={
            #                 "meta.current_state": currState
            #             },
            #             action_name="MyIngress.ns_default",
            #             action_params={
            #                 "next_state": nxtState,
            #             })
            #         s1.WriteTableEntry(table_entry)

            ##LAST STAGE WHERE WE FORWARD
            '''


            # print("Reached end");
            #Handle other levels other than the first and last
#             else:
# #                 print("Entered ANY")
#                 tableName = levelHeaders[i] + '_exact'
#                 actionName = 'store_state_'+levelHeaders[i]
#                 matchFields = convertedValue
#                 actionParams = addedStateArray[i+1]
#                 nxtState = int(addedStateArray[i+1])
#
#
#                 #if it is to be added in the exact table
#                 if addedNodeArray[i]!="*":
#                     command='table_add '+levelHeaders[i]+'_exact'+' store_state_'+levelHeaders[i]+' '+ addedStateArray[i]+' '+convertedValue+' => '+addedStateArray[i+1]
#
#
#
#                 #if it is to be added in the default table
#                 elif addedNodeArray[i]=="*":
#                     command='table_add '+levelHeaders[i]+'_default'+' store_state_'+levelHeaders[i]+'_default '+ addedStateArray[i]+' => '+addedStateArray[i+1]

            #Whatever the command is, it needs to be outputed on a file stream


def convertDT(data, p4info_helper, s1, readTableRules):

    addSwitchCommand.cntr = 0;
    print("Decision Tree Converter")

    #Read the ACL Add Dataset
    # data = pd.read_csv(pathPrefix + "GeneratedDatasetACL" + pathSuffix, dtype=str)

    levelHeaders = data.columns
    # print(data.columns)

    #newDf = data[['typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'sMAC', 'dMAC', 'action']]
    #levelHeaders = ['typEth', 'proto', 'sPort', 'dPort', 'sMAC', 'dMAC', 'srcIP', 'dstIP', 'action']
    ##Redundant conversion. Can be changed

    newDf = data[['sMAC', 'dMAC', 'typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP',  'action']]
    levelHeaders = ['sMAC', 'dMAC', 'typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP',  'action']

    # print(newDf)
    for index,row in newDf.iterrows():

        #Graph Variables to keep track
        currentNode = 'Null'
        neighborList = []

        #convert row to list
        listView = row.tolist()

        # print("LIST VIEW")
        # print(listView)


        #Variables to convert to switch commands
        addedNodeArray = ['X'] * 9
        addedStateArray = ['-1'] * 9

        # print(listView);
        for iter in range(0,len(listView)):

            #Preambles
            neighborList = list(G.neighbors(currentNode))
            isPresent = checkIfPresent(str(listView[iter]), neighborList)
            state = str(levelCounters[iter])

            #In case of fresh insertion
            if len(neighborList) == 0 and currentNode !='Null': #For the rest of the Levels
                levelCounters[iter] = levelCounters[iter] + 1
            #Optimization: and isPresent == False to be added. Test and add
            elif len(neighborList) != 0 and currentNode !='Null': #No increment of state when that level is populated
                state = neighborList[0].split('=')[0]
            elif currentNode == 'Null' and isPresent == False: #For First Level
                levelCounters[iter] = levelCounters[iter] + 1

            #if Node is already present, then iterate through to the next
            if isPresent == True:
                #Store the matched node
                matchedNode = checkIfPresentAndReturn(str(listView[iter]), neighborList)
    #             [string for string in neighborList if str(listView[iter]) in string]
                #[string for string in neighborList if str(listView[iter]) in string]
                currentNode = matchedNode

            #If node is absent, then create node and then iterate through to the next
            else:
                #Construct Label
                label = str(state) + "=" + str(levelHeaders[iter]) + "=" +  str(listView[iter])

                #Add Node and create edge between the previous and current
                G.add_node(label)
                G.add_edge(currentNode, label)

                #iterate to the next node (it is the node that was added)
                currentNode = label

                #Add to the switch commad convertion variable
                addedNodeArray[iter] = str(listView[iter])
                addedStateArray[iter] = str(state)


        # table_entry = p4info_helper.buildTableEntry(
        #     table_name="MyIngress.ipv4_lpm",
        #     match_fields={
        #         "hdr.ipv4.srcAddr": ("0.0.0.1", 32)
        #     },
        #     action_name="MyIngress.dhcp_forward",
        #     action_params={
        #         "port": 510,
        #     })
        # s1.WriteTableEntry(table_entry)

        addSwitchCommand(addedNodeArray, addedStateArray, levelHeaders, p4info_helper, s1, readTableRules)



    # now = datetime.now()
    # mic = now.microsecond
    # print(mic)

    # print(addedNodeArray)
        # print(addedStateArray)


    #             #Keep track of the size
    #             calculatedSizeBits[iter] = calculatedSizeBits[iter] + sizeTemplateBits[iter];
    #             calculatedSizeBytes[iter] = calculatedSizeBytes[iter] + sizeTemplateBytes[iter];
    #             noOfNodes[iter] = noOfNodes[iter] + 1;
    #
    #
    #             nodeVal = listView[iter]
    #
    #
    #             exact = iter*2
    #             default = iter*2+1
    #
    #
    # #             print(exact, " ", default)
    #             if nodeVal  == '*':
    #                 noOfNodesSep[default] = noOfNodesSep[default] + 1;
    #             else:
    #                 noOfNodesSep[exact] = noOfNodesSep[exact] + 1;

# ##Conf Variables. (to be changed in different environment)
# pathPrefix = "D:/PHD/RESEARCH/IOT-MUD-New/modules/3.ControlPlane/" #Change to base path of script
# pathSuffix = ".csv" #file type

# #Initialized Corresponding LevelCounters
# levelCounters = [1,1,1,1,1,1,1,1,1];
#
# #Initialize the Desision Tree
# G = nx.DiGraph();
#
# #Add the first node which is labeled Null
# G.add_node('Null')
#
# #Open the commands file where all the commands are accumulated
# file = open("commands.txt", 'w')
#
# #calculate the size of each level
# sizeTemplateBits = [72,96,64,56,64,64,80,80,9]
# sizeTemplateBytes = [9,12,8,7,8,8,10,10,1.125]
#
# calculatedSizeBits = [0,0,0,0,0,0,0,0,0]
# calculatedSizeBytes = [0,0,0,0,0,0,0,0,0]
# noOfNodes = [0,0,0,0,0,0,0,0,0]
# noOfNodesSep = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]

# #FUNCTION TO ADD RULES and SEND CORRESPONDING SWITCH COMMANDS
# def addSwitchCommand(addedNodeArray, addedStateArray, levelHeaders):
#
#     #for every addition, generate a corresponding switch command
#     for i in range(0,9):
#
#         #Check if the node is to be added with the help of stub values X and -1
#         if addedNodeArray[i]!='X' and addedStateArray[i]!='-1':
#
#             command = ''
#             convertedValue = ''
#
#             #Logic to convert to Hex values
#             if addedNodeArray[i] == '*': #if * then dont touch it. it is taken care of below
#                 convertedValue = addedNodeArray[i]
#             elif levelHeaders[i] == 'sMAC' or levelHeaders[i] == 'dMAC':
# #                 octet = addedNodeArray[i].split(':')
# #                 convertedValue = '0x'+octet[0]+octet[1]+octet[2]+octet[3]+octet[4]+octet[5]
#                 convertedValue = str(addedNodeArray[i])
#             elif levelHeaders[i] == 'srcIP' or levelHeaders[i] == 'dstIP':
# #                 octet = addedNodeArray[i].split('.')
# #                 convertedValue = '0x'+''.join((hex(int(i))[2:] for i in octet))
#                 convertedValue = str(addedNodeArray[i])
#             else:
#                 convertedValue = addedNodeArray[i]
#
#             #Handle First Level addition (Add only val,nxtState)
#             if i==0:
# #                 print("Entered 0")
#                 #if it is to be added in the exact table
#                 if addedNodeArray[i]!="*":
#                     command='table_add '+levelHeaders[i]+'_exact'+' store_state_'+levelHeaders[i]+' '+convertedValue+' => '+addedStateArray[i+1]
#
#                 #if it is to be added in the default table
#                 elif addedNodeArray[i]=="*":
#                     command='table_add '+levelHeaders[i]+'_default'+' store_state_'+levelHeaders[i]+'_default1'+' 0 => '+addedStateArray[i+1]
#
#             #Handle Last Level addition (Add only currState,val)
#             elif i==8:
# #                 print("Entered 8")
#                 #if the action is forward, then push
#                 if addedNodeArray[i] == "forward":
#                     command = 'table_add final '+convertedValue+' '+addedStateArray[i] + ' => 00:01:0a:00:01:02 2'
#                 elif addedNodeArray[i] == "drop":
#                     command = 'table_add final '+convertedValue+' '+addedStateArray[i] + ' =>'
#
#
#             #Handle other levels other than the first and last
#             else:
# #                 print("Entered ANY")
#                 #if it is to be added in the exact table
#                 if addedNodeArray[i]!="*":
#                     command='table_add '+levelHeaders[i]+'_exact'+' store_state_'+levelHeaders[i]+' '+ addedStateArray[i]+' '+convertedValue+' => '+addedStateArray[i+1]
#
#                 #if it is to be added in the default table
#                 elif addedNodeArray[i]=="*":
#                     command='table_add '+levelHeaders[i]+'_default'+' store_state_'+levelHeaders[i]+'_default '+ addedStateArray[i]+' => '+addedStateArray[i+1]
#
#             #Whatever the command is, it needs to be outputed on a file stream
#             file.write("%s\n" % command)
#
# #FUNCTION TO DELETE RULES and SEND CORRESPONDING SWITCH COMMANDS
# def deleteSwitchCommand(nodeValue, i, levelHeaders):
#
#
#     #Extract values from the node label
#     splitValues = nodeValue.split('=')
#
#     state = splitValues[0]
#     header = splitValues[1]
#     value = splitValues[2]
#
#     command = ''
#     convertedValue = ''
#     headerCopy = levelHeaders.tolist()
#     headerCopy.reverse()
#
#
#     #Logic to convert to Hex values
#     if value == '*': #if * then dont touch it. it is taken care of below
#         convertedValue = value
#     elif headerCopy[i] == 'sMAC' or headerCopy[i] == 'dMAC':
#         octet = value.split(':')
#         convertedValue = '0x'+octet[0]+octet[1]+octet[2]+octet[3]+octet[4]+octet[5]
#     elif headerCopy[i] == 'srcIP' or headerCopy[i] == 'dstIP':
#         octet = value.split('.')
#         convertedValue = '0x'+''.join((hex(int(i))[2:] for i in octet))
#     else:
#         convertedValue = value
#
#
#
#     #Handle First Level deletion ()
#     if i==8:
#         print("Entered 0")
#         #if it is to be removed from the exact table
#         if value!="*":
#             command='table_delete '+header+'_exact'+' '+convertedValue
#         #if it is to be removed from the default table
#         elif value=="*":
#             command='table_delete '+header+'_default'+' 0'
#
#     #Handle Last Level Deletion ()
#     elif i==0:
#         print("Entered 8")
#         #Just delete the entry
#         if value!="*":
#             command = 'table_delete final '+ state
#
#     #Handle other levels other than the first and last
#     else:
#         print("Entered ANY")
#         #if it is to be added in the exact table
#         if value!="*":
#             command='table_delete '+header+'_exact'+' '+state+ ' ' + convertedValue
#         #if it is to be added in the default table
#         elif value=="*":
#             command='table_delete '+header+'_default'+' '+state
#
#     #Whatever the command is, it needs to be outputed on a file stream
#     file.write("%s\n" % command)

# #Function to check if a particular node is present in the list of its neighbors
#
# def checkIfPresent(valueToCheck, neighborList):
#
#     for node in neighborList:
#         values = node.split('=')
#         if(values[2] == valueToCheck):
#             return True
#
#     return False
#
# def checkIfPresentAndReturn(valueToCheck, neighborList):
#
#     for node in neighborList:
#         values = node.split('=')
#         if(values[2] == valueToCheck):
#             return node
#
#     return False
#
#
# #Read the ACL Add Dataset
# data = pd.read_csv(pathPrefix + "GeneratedDatasetACL" + pathSuffix, dtype=str)
# levelHeaders = data.columns
#
#
# #[['typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'sMAC', 'dMAC', 'action']]
# #['typEth', 'proto', 'sPort', 'dPort', 'sMAC', 'dMAC', 'srcIP', 'dstIP', 'action']
#
# newDf = data[['typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'sMAC', 'dMAC', 'action']]
# levelHeaders = ['typEth', 'proto', 'sPort', 'dPort', 'srcIP', 'dstIP', 'sMAC', 'dMAC', 'action']
#
#
# #Store the level names in a variable
#
# start_time= time.time()

# ###********************ADDITION*********************###
# #Main loop to start adding the nodes. Goes through each row of the ACL file
# for index,row in newDf.iterrows():
#
#     #Graph Variables to keep track
#     currentNode = 'Null'
#     neighborList = []
#
#     #convert row to list
#     listView = row.tolist()
#
#     #Variables to convert to switch commands
#     addedNodeArray = ['X'] * 9
#     addedStateArray = ['-1'] * 9
#
#
#     for iter in range(0,len(listView)):
#
#         #Preambles
#         neighborList = list(G.neighbors(currentNode))
#         isPresent = checkIfPresent(listView[iter], neighborList)
#         state = str(levelCounters[iter])
#
#         #In case of fresh insertion
#         if len(neighborList) == 0 and currentNode !='Null': #For the rest of the Levels
#             levelCounters[iter] = levelCounters[iter] + 1
#         elif len(neighborList) != 0 and currentNode !='Null': #No increment of state when that level is populated
#             state = neighborList[0].split('=')[0]
#         elif currentNode == 'Null' and isPresent == False: #For First Level
#             levelCounters[iter] = levelCounters[iter] + 1
#
#         #if Node is already present, then iterate through to the next
#         if isPresent == True:
#             #Store the matched node
#             matchedNode = checkIfPresentAndReturn(listView[iter], neighborList)
# #             [string for string in neighborList if str(listView[iter]) in string]
#             #[string for string in neighborList if str(listView[iter]) in string]
#             currentNode = matchedNode
#
#         #If node is absent, then create node and then iterate through to the next
#         else:
#             #Construct Label
#             label = str(state) + "=" + str(levelHeaders[iter]) + "=" +  str(listView[iter])
#
#             #Add Node and create edge between the previous and current
#             G.add_node(label)
#             G.add_edge(currentNode, label)
#
#             #iterate to the next node (it is the node that was added)
#             currentNode = label
#
#
#
#
#             #Keep track of the size
#             calculatedSizeBits[iter] = calculatedSizeBits[iter] + sizeTemplateBits[iter];
#             calculatedSizeBytes[iter] = calculatedSizeBytes[iter] + sizeTemplateBytes[iter];
#             noOfNodes[iter] = noOfNodes[iter] + 1;
#
#
#             nodeVal = listView[iter]
#
#
#             exact = iter*2
#             default = iter*2+1
#
#
# #             print(exact, " ", default)
#             if nodeVal  == '*':
#                 noOfNodesSep[default] = noOfNodesSep[default] + 1;
#             else:
#                 noOfNodesSep[exact] = noOfNodesSep[exact] + 1;
#
#
#
#             #Add to the switch commad convertion variable
#             addedNodeArray[iter] = str(listView[iter])
#
#
#             addedStateArray[iter] = str(state)
#
# #     print(addedNodeArray)
# #     print(addedStateArray)
# #     addSwitchCommand(addedNodeArray, addedStateArray, levelHeaders)
#
#
# end_time=time.time()
#
# totalTimeMS = end_time - start_time
# totalTimeSEC = totalTimeMS / 1000
#
# temp = data.shape[0]
# print(type(temp))
# print(temp)
# noOfRules = float(temp)
#
#
# ruleMS = totalTimeMS / noOfRules
# ruleSEC = totalTimeSEC / noOfRules
#
#
#
#
#
# totalBits = sum(calculatedSizeBits)
# totalBytes = sum(calculatedSizeBytes)
# totalNodes = sum(noOfNodes)
# totalNodesSep = sum(noOfNodesSep)
# exactSum =0
# defaultSum=0
#
# for i in range(0,len(noOfNodesSep)):
#     if i % 2 == 0:
#         exactSum = exactSum + noOfNodesSep[i]
#     else:
#         defaultSum = defaultSum + noOfNodesSep[i]
#
# print("In Bits: ", calculatedSizeBits," Total: " , totalBits)
# print("In Bytes: ", calculatedSizeBytes, " Total: ", totalBytes)
# print("Number of Nodes: ", noOfNodes, " Total: ", totalNodes)
# print("Number of Sep Nodes: ", noOfNodesSep, " Total: ", totalNodes)
# print("Exact Total: ",exactSum, " Default Total: ", defaultSum)
#
# print("Total Time(ms): ", totalTimeMS, "Total Time(sec): ", totalTimeSEC)
# print("Per Rule(ms): ", ruleMS, "Per Rule(sec): ", ruleSEC)
# print("Level Counter: ", levelCounters)
#
#
# # pos = nx.spring_layout(G, k=0.3*1/np.sqrt(len(G.nodes())), iterations=30)
# # plt.figure(3, figsize=(25, 25))
# # nx.draw(G, node_size = 600, with_labels=True, pos=pos)
# # nx.draw_networkx_labels(G, pos=pos)
# # plt.show()
#
# ###********************DELETION*********************###
# #Main loop to start adding the nodes. Goes through each row of the ACL file
# #Assumption -----> We only give as input those ACL rules that are existing in the graph.
# #Read the ACL Add Dataset
# data = pd.read_csv(pathPrefix + "DeleteRules" + pathSuffix)
#
#
#
# for index,row in data.iterrows():
#
#     #Graph Variables to keep track
#     currentNode = 'Null' #The iterator
#     neighborList = [] #Stores neighbours of the iterator
#     deleteFlag = 1
#
#     pathArray=["x","x","x","x","x","x","x","x","x"] #For deletion purposes Keeping track of traversed nodes
#     nodePathArray=[0,0,0,0,0,0,0,0,0] #Neighbour nodes are also recorded.
#
#     #convert row to list
#     listView = row.tolist()
#
#     for iter in range(0,len(listView)):
#
#         #Preambles
#         neighborList = list(G.neighbors(currentNode))
#         isPresent = any(str(listView[iter]) in string for string in neighborList)
#
#
#         #if Node is already present, then iterate through to the next
#         if isPresent == True:
#             #Store the matched node
#             matchedNode = [string for string in neighborList if str(listView[iter]) in string]
# #             print(matchedNode[0])
#
#             pathArray[iter] = matchedNode[0]
#             nodePathArray[iter] = len(neighborList)
#             currentNode = matchedNode[0]
#
#         #If node is absent, then create node and then iterate through to the next
#         else:
#             #Cannot Delete. The rule does not exist
#             print("Rule Does not Exist")
#             deleteFlag = 0
#             break
#
#
#     #Now we delete the traversed path
#     if deleteFlag:
#
# #         print(pathArray)
# #         print(nodePathArray)
#
#         #Small shift operation
#         for i in range(0,8):
#             nodePathArray[i] = nodePathArray[i+1]
#         nodePathArray[8] = 0
#
#         pathArray.reverse()
#         nodePathArray.reverse()
#
# #         print(pathArray)
# #         print(nodePathArray)
#
#         #Final Deletion Loop
#         for i in range(0,9):
#
#             #Delete if there are no outgoing edges from this node
#             if(nodePathArray[i] < 2):
#                 G.remove_node(pathArray[i])
# #                 print(pathArray[i])
#
#                 #Construct and send the delete command
#                 deleteSwitchCommand(pathArray[i], i, levelHeaders)
#
#             else:
#                 break
#
#
#
# # pos = nx.spring_layout(G, k=0.3*1/np.sqrt(len(G.nodes())), iterations=30)
# # plt.figure(3, figsize=(25, 25))
# # nx.draw(G, with_labels=True, pos=pos)
# # nx.draw_networkx_labels(G, pos=pos)
# # plt.show()
#
# file.close()
