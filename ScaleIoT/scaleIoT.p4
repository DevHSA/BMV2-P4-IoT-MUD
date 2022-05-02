/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

//Type Declarations for Parser TypeEth
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_EAP  = 0x888e;
const bit<16> TYPE_UNKNOWN = 0x0006;
const bit<16> TYPE_STUB = 0x00;

//Type Declarations for Parser IPv4 packets
const bit<8>  TYPE_TCP  = 6;
const bit<8>  TYPE_UDP  = 17;
const bit<8>  TYPE_ICMP  = 1;
const bit<8>  TYPE_IGMP  = 2;
const bit<8>  TYPE_IPV6frag  = 44;
const bit<8>  TYPE_IPV6icmp  = 58;
const bit<8>  TYPE_HOPORT  = 0;
const bit<8>  TYPE_STUB_PROTO  = 99;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dEth;
    macAddr_t sEth;
    bit<16>   typeEth;
}

//Standard IPv4 Header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

//Standard TCP Header
header tcp_t{

    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;

}

//Standard UDP Header
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

//Header Amalgamation
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

//Metadata variables that get reset for every packet. Need to define the roles ASAP
struct metadata {

    bit<24> current_state; //contains the current state to match with
    bit<24> stub_current_state_value; //Just for the first level
    bit<8>  flag; //used as a toggle for the match action pipeline
    bit<8>  dropFlag; //used as a drop toggle

    //used to store port numbers of both UDP and TCP
    bit<16> sport;
    bit<16> dport;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    //Transition based on EtherType
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.typeEth) {
            TYPE_IPV4: parse_ipv4;
            TYPE_EAP: parse_ipv4;
            TYPE_UNKNOWN: parse_ipv4;
            TYPE_STUB: parse_ipv4;
            default: accept;
        }
    }

    //Transition based on Protocol Field
    state parse_ipv4 {

        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol){

            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            TYPE_ICMP: parse_tcp;
            TYPE_IGMP: parse_tcp;
            TYPE_IPV6frag: parse_tcp;
            TYPE_IPV6icmp: parse_tcp;
            TYPE_HOPORT: parse_tcp;
            TYPE_STUB_PROTO: parse_tcp;
            default: accept;

        }

    }

    //Parse the TCP Header
    state parse_tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }

    //Parse the UDP Header
    state parse_udp {
       packet.extract(hdr.udp);
       transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    //Just an example Declaration
    register<bit<32>>(100) flow_duration;


    //******** ACTION DECLARATIONS **********//

    //Drop action declared for further use
    action drop() {
        //Use the predefined primitive
        meta.dropFlag = 1;
        mark_to_drop(standard_metadata);
    }

    //Send Packet to ControlPlane
    action dhcp_forward(egressSpec_t port) {

        //Example Register wrire. Ignore
        flow_duration.write(1, standard_metadata.enq_timestamp);

        //send via the CPU port defined in Switch.py (510)
        standard_metadata.egress_spec = port;
    }

    //Normal Forward to the normal port
    action forward(macAddr_t dstAddr, egressSpec_t switchPort) {

           //Standard Operations
          meta.flag = 1;
          hdr.ethernet.sEth = hdr.ethernet.dEth;
          hdr.ethernet.dEth = dstAddr;
          standard_metadata.egress_spec = switchPort;
          hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    //***LEVEL 1 Special Action
    action default_action_one()
    {
        // Just store a stub state value
        //Hardcoded to 0 for the time being
        meta.stub_current_state_value = 0;
    }

    //***Generic match actions LEVELS(2-7)
    //exact table match
    action ns_exact(bit<24> next_state)
    {
      meta.flag = 1;
      meta.current_state = next_state;
    }
    //default table match
    action ns_default(bit<24> next_state)
    {
    	meta.flag = 0;
    	meta.current_state = next_state;
    }

    //***LEVEL 8 Special Actions
    //exact table match
    // action ns_exact_last(macAddr_t dstAddr, egressSpec_t switchPort)
    // {
    //
    //         //Standard Operations
    //         hdr.ethernet.sEth = hdr.ethernet.dEth;
    //         hdr.ethernet.dEth = dstAddr;
    //         standard_metadata.egress_spec = switchPort;
    //         hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    //
    // }
    // //default table match
    // action ns_default_last(macAddr_t dstAddr, egressSpec_t switchPort)
    // {
    //         //Standard Operations
    //         hdr.ethernet.sEth = hdr.ethernet.dEth;
    //         hdr.ethernet.dEth = dstAddr;
    //         standard_metadata.egress_spec = switchPort;
    //         hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    // }



    //******** TABLE DECLARATIONS **********//

    //**DHCP packet flow**//
    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            dhcp_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //**LEVEL 1**//
    //sMAC_exact table
    table sMAC_exact{
        key= {
            hdr.ethernet.sEth:exact;
        }
        actions = {
                ns_exact;
                default_action_one;
        }
        size = 1024;
        default_action = default_action_one();
    }

    table sMAC_default{
        key= {
            meta.stub_current_state_value:exact;
        }
        actions = {
                ns_default;
                drop;
        }
        size = 1024;
        default_action = drop();

    }

    //**LEVEL 2**//
    table dMAC_exact{
        key= {
            meta.current_state:exact;
            hdr.ethernet.dEth:exact;
        }
        actions = {
              ns_exact;
              NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table dMAC_default{
        key= {
            meta.current_state:exact;
        }
        actions = {
            ns_default;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    //**LEVEL 3**//
    table typEth_exact{
        key = {
            meta.current_state:exact;
            hdr.ethernet.typeEth:exact;
        }
        actions = {
            ns_exact;
            NoAction;
        }

        size = 1024;
        default_action = NoAction();
    }

    table typEth_default{
       key= {
           meta.current_state:exact;
       }
       actions = {
           ns_default;
           drop;
       }
       size = 1024;
       default_action =drop();
    }

    //**LEVEL 4**//
    table proto_exact{
      key={

        meta.current_state:exact;
        hdr.ipv4.protocol:exact;
      }

    actions = {
        ns_exact;
        NoAction;
    }
    size = 1024;
    default_action = NoAction();
    }

    table proto_default{
      key={
        meta.current_state:exact;
      }

    actions = {
        ns_default;
        drop;
    }

    size = 1024;
    default_action = drop();
    }

    //**LEVEL 5**//
    table sPort_exact{
      key={
        meta.current_state:exact;
        meta.sport:exact;
      }
      actions = {
        ns_exact;
        NoAction;
      }
      size = 1024;
      default_action =NoAction();
    }

    table sPort_default{
      key={
        meta.current_state:exact;

      }
      actions = {
        ns_default;
        drop;
      }
      size = 1024;
      default_action =drop();
    }

    //**LEVEL 6**//
    table dPort_exact{
      key={
        meta.current_state:exact;
        meta.dport:exact;
      }
      actions = {
        ns_exact;
        NoAction;
      }
      size = 1024;
      default_action = NoAction();
    }

    table dPort_default{
      key={
        meta.current_state:exact;

      }
      actions = {
        ns_default;
        drop;
      }
      size = 1024;
      default_action =drop();
    }

    //**LEVEL 7**//
    table srcIP_exact{
      key={
        meta.current_state:exact;
        hdr.ipv4.srcAddr:exact;
      }
      actions = {
        ns_exact;
        NoAction;
      }
      size = 1024;
      default_action = NoAction();
    }

    table srcIP_default{
      key={
        meta.current_state:exact;

      }
      actions = {
        ns_default;
        drop;
      }
      size = 1024;
      default_action =drop();
    }

    //**LEVEL 8**//
    table dstIP_exact{
      key={
        meta.current_state:exact;
        hdr.ipv4.dstAddr:exact;
      }
      actions = {
        forward;
        NoAction;
      }
      size = 1024;
      default_action = NoAction();
    }

    table dstIP_default{
      key={
        meta.current_state:exact;

      }
      actions = {
        forward;
        drop;
      }
      size = 1024;
      default_action =drop();
    }



    //******** APPLY BLOCK (Steer The Packet) **********//

    apply {

        //For DHCP packets
        // if (hdr.ipv4.isValid()) {

        // }
        if(ipv4_lpm.apply().miss){

        //Getting the port numbers
        if (hdr.tcp.isValid()){
            meta.sport= hdr.tcp.srcPort;
            meta.dport= hdr.tcp.dstPort;
        }
        else if (hdr.udp.isValid()){
            meta.sport= hdr.udp.srcPort;
            meta.dport= hdr.udp.dstPort;
        }

        //Match Action pipeline definition
        sMAC_exact.apply();
        if(meta.flag==0){
            sMAC_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        dMAC_exact.apply();
        if(meta.flag==0){
            dMAC_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        typEth_exact.apply();
        if(meta.flag==0){
            typEth_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        proto_exact.apply();
        if(meta.flag==0){
            proto_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        sPort_exact.apply();
        if(meta.flag==0){
            sPort_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        dPort_exact.apply();
        if(meta.flag==0){
            dPort_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        srcIP_exact.apply();
        if(meta.flag==0){
            srcIP_default.apply();
        }
        if(meta.dropFlag == 1) return;

        meta.flag=0;
        dstIP_exact.apply();
        if(meta.flag==0){
            dstIP_default.apply();
        }
        if(meta.dropFlag == 1) return;
        

        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
