/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>


//Type Declarations for Parser
const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_EAP  = 0x888e;
const bit<16> TYPE_UNKNOWN = 0x0006;
const bit<16> TYPE_STUB = 0x00;
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
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

    //God knows what what these variables were declared
    bit<24> state_smac;
    bit<24> state_dmac;
    bit<24> state_type;
    bit<24> state_sip;
    bit<24> state_dip;
    bit<24> state_proto;
    bit<24> state_sport;
    bit<24> state_dport;
    bit<24> state_default;
    bit<16> sport;
    bit<16> dport;
    bit<8> protocol;
    bit<32> sip;
    bit<32> dip;

    //bit<16> state_smac_default;
    bit<8> flag_smac;
    bit<8> flag_dmac;
    bit<8> flag_type;
    bit<8> flag_sip;
    bit<8> flag_dip;
    bit<8> flag_proto;
    bit<8> flag_sport;
    bit<8> flag_dport;

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
        transition select(hdr.ethernet.etherType) {
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
        mark_to_drop(standard_metadata);
    }

    //Send Packet to Control ControlPlane
    action dhcp_forward(egressSpec_t port) {

        //Example Register wrire. Ignore
        flow_duration.write(1, standard_metadata.enq_timestamp);

        //send via the CPU port defined in Switch.py (510)
        standard_metadata.egress_spec = port;
    }

    //Normal Forward to the normal port
    action forward(macAddr_t dstAddr, egressSpec_t port) {

           //Standard Operations
           hdr.ethernet.sEth = hdr.ethernet.dEth;
           hdr.ethernet.dEth = dstAddr;
           standard_metadata.egress_spec = port;
           hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    //OUR SOLUTION TABLES
    action store_state_sMAC(bit<24> val)
    {
      meta.flag_smac = 1;
      meta.state_smac = val;
    }
    action store_state_sMAC_default(bit<24> val)
    {
      meta.state_default = val;
    }
    action store_state_sMAC_default1(bit<24> val)
    {
    	meta.flag_smac=0;
    	meta.state_smac=val;
    }
    action store_state_dMAC(bit<24> val)
    {
      meta.flag_dmac = 1;
      meta.state_dmac = val;
    }
    action store_state_dMAC_default(bit<24> val)
    {
    	meta.flag_dmac=0;
    	meta.state_dmac=val;
    }
    action store_state_typEth(bit<24> val)
    {
      meta.flag_type = 1;
      meta.state_type = val;
    }
    action store_state_typEth_default(bit<24> val)
    {
    	meta.flag_type=0;
    	meta.state_type=val;
    }
    action store_state_proto(bit<24> val)
    {
      meta.flag_proto = 1;
      meta.state_proto = val;
    }
    action store_state_proto_default(bit<24> val)
    {
    	meta.flag_proto=0;
    	meta.state_proto=val;
    }
    action store_state_sPort(bit<24> val)
    {
      meta.flag_sport = 1;
      meta.state_sport = val;
    }
    action store_state_sPort_default(bit<24> val)
    {
    	meta.flag_sport=0;
    	meta.state_sport=val;
    }
    action store_state_dPort(bit<24> val)
    {
      meta.flag_dport = 1;
      meta.state_dport = val;
    }
    action store_state_dPort_default(bit<24> val)
    {
    	meta.flag_dport=0;
    	meta.state_dport=val;
    }
    action store_state_srcIP(bit<24> val)
    {
      meta.flag_sip = 1;
      meta.state_sip = val;
    }
    action store_state_srcIP_default(bit<24> val)
    {
    	meta.flag_sip=0;
    	meta.state_sip=val;
    }
    action store_state_dstIP(bit<24> val)
    {
      meta.flag_dip = 1;
      meta.state_dip = val;
    }
    action store_state_dstIP_default(bit<24> val)
    {
    	meta.flag_dip=0;
    	meta.state_dip=val;
    }


    //******** TABLE DECLARATIONS **********//

    table ipv4_lpm {
        key = {
            hdr.ipv4.srcAddr: lpm;
        }
        actions = {
            dhcp_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }


    //sMAC_exact table
    table sMAC_exact{
        key= {

            hdr.ethernet.sEth:exact;
        }
        actions = {
                store_state_sMAC;
                store_state_sMAC_default;
        }
        size = 1024;
        default_action = store_state_sMAC_default(0);

    }

    table sMAC_default{
        key= {
            meta.state_default:exact;
        }
        actions = {
                store_state_sMAC_default1;
                NoAction;
        }
         size = 1024;
       default_action =NoAction();

    }

    table dMAC_exact{
        key= {
            meta.state_smac:exact;
            hdr.ethernet.dEth:exact;
        }

    actions = {

              store_state_dMAC;
                drop;
                NoAction;
        }

        size = 1024;
        default_action =NoAction();
    }

    table dMAC_default{
        key= {
            meta.state_smac:exact;

        }

    actions = {

              store_state_dMAC_default;
                drop;
                NoAction;
        }

        size = 1024;
        default_action =drop();
    }

    table typEth_exact{
        key= {
            meta.state_dmac:exact;
            hdr.ethernet.typeEth:exact;

        }

    actions = {

              store_state_typEth;
               // drop;
                NoAction;
        }

        size = 1024;
        default_action =NoAction();
        //default_action = register_action_ethernet_type(1010);
    }

    table typEth_default{
       key= {
           meta.state_dmac:exact;

       }

   actions = {

             store_state_typEth_default;
             drop;
               //NoAction;
       }

       size = 1024;
       default_action =drop();//NoAction();
       }

    table proto_exact{
      key={

        meta.state_type:exact;
        //hdr.ipv4.protocol:exact;
        meta.protocol:exact;
      }

    actions = {

                store_state_proto;
                //drop;
                NoAction;
        }

        size = 1024;
        default_action =NoAction();
    }

    table proto_default{
      key={

        meta.state_type:exact;
      }

    actions = {

                store_state_proto_default;
                drop;
                //NoAction;
        }

        size = 1024;
        default_action =drop();//NoAction();
    }

    table sPort_exact{
      key={
        meta.state_proto:exact;
        //hdr.tcp.srcPort:exact;
        //hdr.udp.srcPort:exact;
        meta.sport:exact;
      }
      actions = {
        store_state_sPort;
        //drop;
        NoAction;
      }
      size = 1024;
      default_action =NoAction();
      //default_action =NoAction();
    }

    table sPort_default{
      key={
        meta.state_proto:exact;

      }
      actions = {
        store_state_sPort_default;
        drop;
        //NoAction;
      }
      size = 1024;
      default_action =drop();//NoAction();
    }

    table dPort_exact{
      key={
        meta.state_sport:exact;
        //hdr.tcp.dstPort:exact;
        //hdr.udp.dstPort:exact;
        meta.dport:exact;
      }
      actions = {
        store_state_dPort;
        //drop;
        NoAction;
      }
      size = 1024;
      default_action =NoAction();
      //default_action =NoAction();
    }

    //******** APPLY BLOCK (Steer The Packet) **********//

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
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
