#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */

//const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x888e;
const bit<16> TYPE_DDCMP = 0x0006;
const bit<16> TYPE_STUB = 0x0000;

const bit<8>  TYPE_HOPORT  = 0x00; //Hop by Hop
const bit<8>  TYPE_ICMP  = 0x01; //ICMP
const bit<8>  TYPE_IGMP  = 0x02; //IGMP
const bit<8>  TYPE_TCP  = 0x06; //TCP
const bit<8>  TYPE_UDP  = 0x11; //UDP
const bit<8>  TYPE_IPV6frag  = 0x2c; //IPv6Frag
const bit<8>  TYPE_IPV6icmp  = 0x3a; //ICMPv6

const bit<8>  TYPE_STUB_PROTO = 0x63; //For local scenario


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
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
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

header tcp_t{
	//bit reduction
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

header udp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
    udp_t        udp;
}

struct metadata {
    /* empty */
    bit<8> protocol;
    bit<16> sport;
    bit<16> dport;
    bit<32> sip;
    bit<32> dip;

}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {

        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.typeEth){

            TYPE_IPV4: ipv4;
            TYPE_DDCMP: ipv4;
            TYPE_STUB: ipv4;
            TYPE_IPV6: ipv4;
            default: accept;
        }
    }

    state ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){

            //Only differentiate between TCP and UDP
            TYPE_TCP: tcp;
            TYPE_UDP: udp;
            TYPE_ICMP:tcp;
            TYPE_IGMP:tcp;
            TYPE_IPV6frag:tcp;
            TYPE_IPV6icmp:tcp;
            TYPE_HOPORT:tcp;
            TYPE_STUB_PROTO:tcp;
            default: accept;
        }
    }

    state tcp {
       packet.extract(hdr.tcp);
       transition accept;
    }
    state udp {
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
//meta.flag=0;


 action forward(macAddr_t dstAddr, egressSpec_t port) {

        //set the src mac address as the previous dst, this is not correct right?
        hdr.ethernet.sEth = hdr.ethernet.dEth;

       //set the destination mac address that we got from the match in the table
        hdr.ethernet.dEth = dstAddr;

        //set the output port that we also get from the table
        standard_metadata.egress_spec = port;

        //decrease ttl by 1
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;

    }

action drop() {
        mark_to_drop(standard_metadata);
    }
table data{
    key= {
        hdr.ethernet.sEth:ternary;
        hdr.ethernet.dEth:ternary;
        hdr.ethernet.typeEth:ternary;
        //hdr.ipv4.protocol:ternary;
        meta.protocol:ternary;
        //hdr.tcp.srcPort:ternary;
        meta.sport:ternary;
        //hdr.tcp.dstPort:ternary;
        meta.dport:ternary;
        //hdr.ipv4.srcAddr:ternary;
        meta.sip:ternary;
        //hdr.ipv4.dstAddr:ternary;
        meta.dip:ternary;
    }

    actions = {
            forward;
            drop;
            NoAction;

    }

    size = 1024;
    default_action = NoAction();
}

apply {
          //if (hdr.ipv4.isValid()){
             /*ipv4_exact_src.apply();
             ipv4_exact_dst.apply();
             ipv4_exact_proto.apply();*/
          //}
          //else if (hdr.ethernet.isValid()){
            //if(hdr.ethernet.sMAC!=*)
            if (hdr.ipv4.isValid())
            {
                meta.protocol=hdr.ipv4.protocol;
                meta.sip=hdr.ipv4.srcAddr;
                meta.dip=hdr.ipv4.dstAddr;
            }
             if(hdr.tcp.isValid()){
              meta.sport= hdr.tcp.srcPort;
              meta.dport= hdr.tcp.dstPort;
            }
            if(hdr.udp.isValid()){
            meta.sport= hdr.udp.srcPort;
            meta.dport= hdr.udp.dstPort;
            //proto_exact.apply();
            }

            data.apply();
                     //else if (hdr.tcp.isValid()){
            /* tcp_exact_s.apply();
             tcp_exact_d.apply();
             tcp_exact_prior.apply();*/
          //}
          //meta.result_and =(meta.result_ethernet_source)&(meta.result_ipv4_src)&(meta.result_tcp_s)&(meta.result_ethernet_destination)&(meta.result_ethernet_type)&(meta.result_ipv4_dst)&(meta.result_ipv4_proto)&(meta.result_tcp_d)&(meta.result_tcp_prior);
          // ipv4_exact.apply();)
           //tcp_exact.apply();
   }
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
    }
}
/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
    update_checksum(
      hdr.ipv4.isValid(),
            { hdr.ipv4.version,
        hdr.ipv4.ihl,
              hdr.ipv4.tos,
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

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/
//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
