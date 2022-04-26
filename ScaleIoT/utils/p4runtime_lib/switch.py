# Copyright 2017-present Open Networking Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from abc import abstractmethod
from datetime import datetime
from queue import Queue



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


    #Custom function to handle packet-in
    def PacketIn(self, p4info_helper, s1, readTableRules, **kwargs):

        print("Installed ingress tunnel rule on %s" % s1.name)
        readTableRules(p4info_helper, s1)

        for item in self.stream_msg_resp:

            packetpayload = item.packet.payload
            #now converting payload from bytes to string
            packetstring = packetpayload.decode("utf-8",'backslashreplace')
            ind = packetstring.find("http") #finding index of http in the packet

            cleanURL = packetstring[ind:-4]#URL after removing the trailing characters

            #extracting the words from cleanURL, where the last word in the list is the MUDfile name
            wordList = cleanURL.split("/")
            MUDfilename = wordList[-1]

            if len(MUDfilename) == 0 :
                continue

            rootpath = "/home/p4/BMV2-P4-IoT-MUD/ScaleIoT/MUDFiles/"
            #
            # print(">>>>>>>>>>>>>>>>>>>>>IoT Device Name")
            # print(MUDfilename)
            #for Raw MUD file
            rawMUDurl = 'http://127.0.0.1:443/' + MUDfilename
            rawRequest = requests.get(rawMUDurl, allow_redirects=True)
            rawMUDfile = rootpath + MUDfilename + '_file.json'
            open(rawMUDfile , 'wb').write(rawRequest.content)

            #for Signed MUD file
            signedMUDurl = 'http://127.0.0.1:443/sign' + MUDfilename
            signatureRequest = requests.get(signedMUDurl, allow_redirects=True)
            signedMUDfile = rootpath + MUDfilename + '_signfile.json'
            open(signedMUDfile, 'wb').write(signatureRequest.content)

            #for public key
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

            pureACL = readMUDFile(rawMUDfile)
            resolvedACL = resolve(pureACL)


            ##sETH TABLE ENTRY
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.sMAC_exact",
                match_fields={
                    "hdr.ethernet.sEth": "11:44:20:00:00:11"
                },
                action_name="MyIngress.ns_exact",
                action_params={
                    "next_state": 4,
                })
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.sMAC_default",
                match_fields={
                    "meta.stub_current_state_value": 1
                },
                action_name="MyIngress.ns_default",
                action_params={
                    "next_state": 4,
                })
            s1.WriteTableEntry(table_entry)

            ##dETH TABLE ENTRY
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.dMAC_exact",
                match_fields={
                    "meta.current_state": 1,
                    "hdr.ethernet.dEth": "11:44:20:00:00:11"
                },
                action_name="MyIngress.ns_exact",
                action_params={
                    "next_state": 8,
                })
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.dMAC_default",
                match_fields={
                    "meta.current_state": 1
                },
                action_name="MyIngress.ns_default",
                action_params={
                    "next_state": 9,
                })
            s1.WriteTableEntry(table_entry)

            ##typEth TABLE ENTRY
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.typEth_exact",
                match_fields={
                    "meta.current_state": 1,
                    "hdr.ethernet.typeEth": 0x0800
                },
                action_name="MyIngress.ns_exact",
                action_params={
                    "next_state": 10,
                })
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.typEth_default",
                match_fields={
                    "meta.current_state": 1
                },
                action_name="MyIngress.ns_default",
                action_params={
                    "next_state": 11,
                })
            s1.WriteTableEntry(table_entry)

            ##protocol TABLE ENTRY
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.proto_exact",
                match_fields={
                    "meta.current_state": 1,
                    "hdr.ipv4.protocol": 17
                },
                action_name="MyIngress.ns_exact",
                action_params={
                    "next_state": 13,
                })
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.proto_default",
                match_fields={
                    "meta.current_state": 1
                },
                action_name="MyIngress.ns_default",
                action_params={
                    "next_state": 14,
                })
            s1.WriteTableEntry(table_entry)

            ##sPORT TABLE ENTRY
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.sPort_exact",
                match_fields={
                    "meta.current_state": 1,
                    "meta.sport": 443
                },
                action_name="MyIngress.ns_exact",
                action_params={
                    "next_state": 16,
                })
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.sPort_default",
                match_fields={
                    "meta.current_state": 1
                },
                action_name="MyIngress.ns_default",
                action_params={
                    "next_state": 17,
                })
            s1.WriteTableEntry(table_entry)

            # ##sPORT TABLE ENTRY
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.dPort_exact",
            #     match_fields={
            #         "meta.current_state": 1,
            #         "meta.dport": 443
            #     },
            #     action_name="MyIngress.ns_exact",
            #     action_params={
            #         "next_state": 16,
            #     })
            # s1.WriteTableEntry(table_entry)
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.dPort_default",
            #     match_fields={
            #         "meta.current_state": 1
            #     },
            #     action_name="MyIngress.ns_default",
            #     action_params={
            #         "next_state": 17,
            #     })
            # s1.WriteTableEntry(table_entry)
            #
            # ##sIP TABLE ENTRY
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.srcIP_exact",
            #     match_fields={
            #         "meta.current_state": 1,
            #         "hdr.ipv4.srcAddr": "55.65.55.33"
            #     },
            #     action_name="MyIngress.ns_exact",
            #     action_params={
            #         "next_state": 120,
            #     })
            # s1.WriteTableEntry(table_entry)
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.srcIP_default",
            #     match_fields={
            #         "meta.current_state": 1
            #     },
            #     action_name="MyIngress.ns_default",
            #     action_params={
            #         "next_state": 290,
            #     })
            # s1.WriteTableEntry(table_entry)
            #
            # ##dIP TABLE ENTRY
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.dstIP_exact",
            #     match_fields={
            #         "meta.current_state": 1,
            #         "hdr.ipv4.dstAddr": "55.65.55.11"
            #     },
            #     action_name="MyIngress.forward",
            #     action_params={
            #         "dstAddr": "08:00:00:00:02:22",
            #         "switchPort": 2
            #     })
            # s1.WriteTableEntry(table_entry)
            # table_entry = p4info_helper.buildTableEntry(
            #     table_name="MyIngress.dstIP_default",
            #     match_fields={
            #         "meta.current_state": 1
            #     },
            #     action_name="MyIngress.forward",
            #     action_params={
            #         "dstAddr": "08:00:00:00:02:22",
            #         "switchPort": 2
            #     })
            # s1.WriteTableEntry(table_entry)



            readTableRules(p4info_helper, s1)

            convertDT(resolvedACL, p4info_helper, s1, readTableRules)

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
