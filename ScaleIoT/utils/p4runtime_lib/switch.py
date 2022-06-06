'''

Copyright 2017-present Open Networking Foundation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

'''

from abc import abstractmethod
from datetime import datetime
from queue import Queue
import time


#Our MUD imports
import requests
import subprocess
import os
import sys


##Not at all a good practice
sys.path.append("/home/p4/BMV2-P4-IoT-MUD/ScaleIoT/")

#Our Solution Imports
from processMUD import readMUDFile
from resolve import resolve
from decisiontree import convertDT


import grpc
from p4.tmp import p4config_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

MSG_LOG_MAX_LEN = 1024

# List containing all active connections
connections = []

#function to shutdown all switch connections
def ShutdownAllSwitchConnections():
    for c in connections:
        c.shutdown()

class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(self.requests_stream))
        self.proto_dump_file = proto_dump_file
        connections.append(self)

    @abstractmethod
    def buildDeviceConfig(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()


    '''

    Packet-in refers to the packets that are directly forwarded by the switch to the controller

    Here, we have a custom function that extracts the MUD URL from the packet payload. Subsequently, the
    conversion of MUD Rules to table rules ensue.

    '''

    def PacketIn(self, p4info_helper, s1, readTableRules, **kwargs):

        print("Installed ingress tunnel rule on %s" % s1.name)
        readTableRules(p4info_helper, s1)

        for item in self.stream_msg_resp:


            packetpayload = item.packet.payload
            packetString = packetpayload.hex()
            convertedAddress = packetString[12:24]
            IoTmacAddress = ':'.join(convertedAddress[i:i+2] for i in range(0, len(convertedAddress), 2))

            #now converting payload from bytes to string
            packetstring = packetpayload.decode("utf-8",'backslashreplace')
            ind = packetstring.find("http") #finding index of http in the packet

            cleanURL = packetstring[ind:-4]#URL after removing the trailing characters

            #extracting the words from cleanURL, where the last word in the list is the MUDfile name
            wordList = cleanURL.split("/")
            MUDfilename = wordList[-1]

            #In case of router solicitation messages we ignore and listen to the stream again
            if len(MUDfilename) == 0 :
                continue

            rootpath = "/home/p4/BMV2-P4-IoT-MUD/ScaleIoT/MUDFiles/"

            '''

            Now we are downloading the MUD file, signed file and the public key file
            using the MUD file name

            '''
            #saving Raw MUD file
            rawMUDurl = 'http://127.0.0.1:443/' + MUDfilename
            rawRequest = requests.get(rawMUDurl, allow_redirects=True)
            rawMUDfile = rootpath + MUDfilename + '_file.json'
            open(rawMUDfile , 'wb').write(rawRequest.content)

            #saving Signed MUD file
            signedMUDurl = 'http://127.0.0.1:443/sign' + MUDfilename
            signatureRequest = requests.get(signedMUDurl, allow_redirects=True)
            signedMUDfile = rootpath + MUDfilename + '_signfile.json'
            open(signedMUDfile, 'wb').write(signatureRequest.content)

            #saving public key
            publickeyurl = 'http://127.0.0.1:443/pub-key.pem'
            publickeyRequest = requests.get(publickeyurl, allow_redirects=True)
            publickeyfile = rootpath + 'pub-key.pem'
            open(publickeyfile, 'wb').write(publickeyRequest.content)

            try:

                #verifying the signed file and raw file using the public key
            	subprocess.check_output(["openssl", "dgst" ,"-sha256", "-verify" ,"/home/p4/BMV2-P4-IoT-MUD/ScaleIoT/MUDFiles/pub-key.pem", "-signature" , signedMUDfile, rawMUDfile]).decode("utf-8")

            except subprocess.CalledProcessError as error:

            	print((error.output).decode("utf-8"))
                #removing the downloaded MUD files as the signature is not verified
            	os.remove(rawMUDfile)
            	os.remove(signedMUDfile)
            	os.remove('pub-key.pem')

            '''

            now we are converting the MUD file to table rules and also calculating
            the time needed for each operation

            '''

            milliseconds1 = int(time.time() * 1000)

            pureACL = readMUDFile(rawMUDfile, IoTmacAddress)
            milliseconds2 = int(time.time() * 1000) - milliseconds1

            resolvedACL = resolve(pureACL)
            milliseconds3 = int(time.time() * 1000) - milliseconds1

            ##Save Resolved ACL
            resolvedACL.to_csv('template.csv', index=False);


            # milliseconds3 = int(time.time() * 1000)

            convertDT(resolvedACL, p4info_helper, s1, readTableRules)
            milliseconds4 = int(time.time() * 1000) - milliseconds1

            '''

            printing the table rules for debugging purpose
            print("All table rules are here")
            readTableRules(p4info_helper, s1)

            '''


            print("Time in milliseconds after MUD file download", milliseconds1)
            print("Time in milliseconds after processMUD (Convert MUD file to ACL Rules)", milliseconds2)
            print("Time in milliseconds to resolve domain names", milliseconds3)
            print("Time in milliseconds after Convertion to Decision Tree ---> Send Table rules", milliseconds4)
            

    #DeleteTableEntry is useful for deleting the table rules when device is removed

    def DeleteTableEntry(self, table_entry, dry_run=False):

        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if table_entry.is_default_action:
            update.type = p4runtime_pb2.Update.DELETE
        else:
            update.type = p4runtime_pb2.Update.DELETE
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    '''
    The P4Runtime interface allows multiple controllers to be connected to the P4Runtime server
    running on the device at the same time: one master controller - the only one with write
    access to the device - and potentially several stand-by controllers.

    In case the master goes offline, one of the stand-by controllers is available to take its place,
    based on next highest election ID
    '''

    def MasterArbitrationUpdate(self, dry_run=False, **kwargs):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1

        if dry_run:
            print("P4Runtime MasterArbitrationUpdate: ", request)
        else:
            self.requests_stream.put(request)
            for item in self.stream_msg_resp:
                return item # just one
    '''
    A P4Runtime client may configure the P4Runtime target with a new P4 pipeline
    by invoking the SetForwardingPipelineConfig RPC.
    '''

    def SetForwardingPipelineConfig(self, p4info, dry_run=False, **kwargs):
        device_config = self.buildDeviceConfig(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT
        if dry_run:
            print("P4Runtime SetForwardingPipelineConfig:", request)
        else:
            self.client_stub.SetForwardingPipelineConfig(request)


    ''' to write table entries '''
    def WriteTableEntry(self, table_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        if table_entry.is_default_action:
            update.type = p4runtime_pb2.Update.MODIFY
        else:
            update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

    ''' to read table entries '''
    def ReadTableEntries(self, table_id=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response

    def ReadCounters(self, counter_id=None, index=None, dry_run=False):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        if dry_run:
            print("P4Runtime Read:", request)
        else:
            for response in self.client_stub.Read(request):
                yield response


    def WritePREEntry(self, pre_entry, dry_run=False):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)
        if dry_run:
            print("P4Runtime Write:", request)
        else:
            self.client_stub.Write(request)

class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write("Message too long (%d bytes)! Skipping log...\n" % len(msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details, request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
