#ifndef _IPHDR_H_
#define _IPHDR_H_

#include <pshpack1.h>
#include <ws2tcpip.h>
#include <mstcpip.h>
#include <inaddr.h>
//
// IPv4 Header (without any IP options)
//
typedef struct ip_hdr
{
    unsigned char  ip_verlen;        // 4-bit IPv4 version
                                     // 4-bit header length (in 32-bit words)
    unsigned char  ip_tos;           // IP type of service
    unsigned short ip_totallength;   // Total length
    unsigned short ip_id;            // Unique identifier 
    unsigned short ip_offset;        // Fragment offset field
    unsigned char  ip_ttl;           // Time to live
    unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
    unsigned short ip_checksum;      // IP checksum
    unsigned int   ip_srcaddr;       // Source address
    unsigned int   ip_dstaddr;		 // Source address
} IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR;

//
// IPv6 Header
//
typedef struct ipv6_hdr
{
    unsigned long   ipv6_vertcflow;        // 4-bit IPv6 version
                                           // 8-bit traffic class
                                           // 20-bit flow label
    unsigned short  ipv6_payloadlen;       // payload length
    unsigned char   ipv6_nexthdr;          // next header protocol value
    unsigned char   ipv6_hoplimit;         // TTL 
    struct in6_addr ipv6_srcaddr;          // Source address
    struct in6_addr ipv6_destaddr;         // Destination address
} IPV6_HDR, *PIPV6_HDR, FAR * LPIPV6_HDR;

//
// IPv6 Fragmentation Header
//
typedef struct ipv6_fragment_hdr
{
    unsigned char   ipv6_frag_nexthdr;      // Next protocol header
    unsigned char   ipv6_frag_reserved;     // Reserved: zero
    unsigned short  ipv6_frag_offset;       // Offset of fragment
    unsigned long   ipv6_frag_id;           // Unique fragment ID
} IPV6_FRAGMENT_HDR, *PIPV6_FRAGMENT_HDR, FAR * LPIPV6_FRAGMENT_HDR;

//
// Define the UDP header 
//
typedef struct udp_hdr
{
    unsigned short src_portno;       // Source port no.
    unsigned short dest_portno;      // Dest. port no.
    unsigned short udp_length;       // Udp packet length
    unsigned short udp_checksum;     // Udp checksum
} UDP_HDR, *PUDP_HDR;

//
// Define the TCP header
//
typedef struct tpc_hdr
{
    unsigned short src_port;         // Source port no.
    unsigned short dst_port;         // Dest. port no.
    unsigned long  seq_num;          // Sequence number
    unsigned long  ack_num;          // Acknowledgement number;
    unsigned short lenflags;         // Header length and flags
    unsigned short window_size;      // Window size
    unsigned short tcp_checksum;     // Checksum
    unsigned short tcp_urgentptr;    // Urgent data?
} TCP_HDR, *PTCP_HDR;

//
// Stucture to extract port numbers that overlays the UDP and TCP header
//
typedef struct port_hdr
{
    unsigned short src_portno;
    unsigned short dest_portno;
} PORT_HDR, *PPORT_HDR;

//
// IGMP header
//
typedef struct igmp_hdr
{
    unsigned char   version_type;
    unsigned char   max_resp_time;
    unsigned short  checksum;
    unsigned long   group_addr;
} IGMP_HDR, *PIGMP_HDR;

typedef struct igmp_hdr_query_v3
{
    unsigned char   type;
    unsigned char   max_resp_time;
    unsigned short  checksum;
    unsigned long   group_addr;
    unsigned char   resv_suppr_robust;
    unsigned char   qqi;
    unsigned short  num_sources;
    unsigned long   sources[1];
} IGMP_HDR_QUERY_V3, *PIGMP_HDR_QUERY_V3;

typedef struct igmp_group_record_v3
{
    unsigned char   type;
    unsigned char   aux_data_len;
    unsigned short  num_sources;
    unsigned long   group_addr;
    unsigned long   source_addr[1];
} IGMP_GROUP_RECORD_V3,  *PIGMP_GROUP_RECORD_V3;

typedef struct igmp_hdr_report_v3
{
    unsigned char   type;
    unsigned char   reserved1;
    unsigned short  checksum;
    unsigned short  reserved2;
    unsigned short  num_records;
} IGMP_HDR_REPORT_V3, *PIGMP_HDR_REPORT_V3;

typedef	unsigned int tcp_seq;
/*
* TCP header
*/
struct tcphdr
{
	unsigned short	th_sport;		/* source port */
	unsigned short	th_dport;		/* destination port */
	tcp_seq	th_seq;			/* sequence number */
	tcp_seq	th_ack;			/* acknowledgement number */

	unsigned char	th_off : 4,		/* data offset */
	th_x2 : 4;		/* (unused) */

	unsigned char	th_flags;

	unsigned short	th_win;			/* window */
	unsigned short	th_sum;			/* checksum */
	unsigned short	th_urp;			/* urgent pointer */
};

struct pkghead16
{
	unsigned short mark;
	unsigned short length;
	unsigned short checksum;
};

struct pkghead32
{
	unsigned short mark;
	unsigned int length;
	unsigned short checksum;
};

struct data_header
{
	unsigned short	mark;
	unsigned short	business;
	unsigned int	length;
};

struct pkghead
{
	unsigned short	_length;
};

struct msghead
{
	unsigned short	_class;
	unsigned short	_message;
	unsigned int	_reserved;
};

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
#define TH_NETDEV        0x00000001
#define TH_TAPI          0x00000002

//
// Size defines
//
#define MAX_IP_SIZE        65535
#define MIN_IP_HDR_SIZE       20

//
// Macros to extract the high and low order 4-bits from a byte
//
#define HI_BYTE(byte)    (((byte) >> 4) & 0x0F)
#define LO_BYTE(byte)    ((byte) & 0x0F)

//
// Used to indicate to parser what fields to filter on
//
#define FILTER_MASK_SOURCE_ADDRESS      0x01
#define FILTER_MASK_SOURCE_PORT         0x02
#define FILTER_MASK_DESTINATION_ADDRESS 0x04
#define FILTER_MASK_DESTINATION_PORT    0x08

#include <poppack.h>
#endif
