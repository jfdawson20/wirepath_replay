/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_header_extract.h
Description: wpr_header_extract.c and wpr_header_extract.h provide an API for parsing packet headers from rte_mbuf structures. The header file includes 
all the relavent struct definitions for parsed headers and function prototypes along with inline helper functions. Header parsing is split into a 
fast-path parser and a slow-path parser. The fast-path parser is optimized for speed and handles the most common cases with minimal processing, and is 
defined as a static inline function in the header file. The slow-path parser handles more complex scenarios including VLANs, IPv6 extension headers,
and VXLAN encapsulation, and is defined in this source file. The slow-path parser is called only when the fast-path parser cannot fully parse the headers.
Both parsers are accessed via a common inlined wrapper function defined in the header file and return a populated wpr_hdrs_t structure with parsed header
information if parsing is successful.

currently the header parser supports explicit parsing of the following protocols:
- Ethernet II
- VLAN (up to 2 tags, QinQ)
- IPv4
- IPv6 (with extension header skipping)
- TCP
- UDP
- SCTP
- ICMPv4
- ICMPv6
- VXLAN (decapsulation only)

For unrecognized protocols, the parser will set the relevant type fields to NONE and continue parsing as far as possible.

*/

#ifndef WPR_HDRS_H
#define WPR_HDRS_H

#include <stdbool.h>
#include <stdint.h>
#include <arpa/inet.h>

#include <rte_memcpy.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_icmp.h>

#include "wpr_log.h"

#ifndef RTE_ETHER_TYPE_QINQ
#define RTE_ETHER_TYPE_QINQ 0x88A8 /* 802.1ad (S-TAG) */
#endif

#ifndef WPR_VXLAN_UDP_PORT
#define WPR_VXLAN_UDP_PORT 4789
#endif

#define WPR_GRE_PROTO_TEB      0x6558  /* Transparent Ethernet Bridging */
#define WPR_GRE_PROTO_ERSPAN2  0x88BE  /* ERSPAN Type II */
#define WPR_GRE_PROTO_ERSPAN3  0x22EB  /* ERSPAN Type III */


#define WPR_IPV4_MAX_HDR_LEN 60


/* Minimal ICMPv6 header (what we actually use) */
typedef struct __attribute__((__packed__)) wpr_icmp6_min{
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
} wpr_icmp6_min_t;

/* Minimal VXLAN header (8 bytes) */
struct wpr_vxlan_hdr {
    uint8_t  flags;       /* I bit (bit 3) must be set for valid VNI */
    uint8_t  rsvd1[3];
    uint8_t  vni[3];      /* 24-bit VNI */
    uint8_t  rsvd2;
} __attribute__((__packed__));

/* Minimal GRE header (we only support no checksum/routing; optional key/seq) */
struct wpr_gre_hdr {
    uint16_t flags_version; /* C,R,K,S,s,recursion,ver */
    uint16_t protocol;      /* payload protocol (e.g. 0x6558, 0x88BE, 0x22EB, 0x0800, 0x86DD) */
} __attribute__((__packed__));

/* ERSPAN Type II base header (first 8 bytes) */
struct wpr_erspan2_hdr {
    uint32_t word1; /* ver(4) | vlan(12) | cos(3) | en(2) | t(1) | session_id(10) */
    uint32_t word2; /* index, timestamp, etc. (we mostly ignore) */
} __attribute__((__packed__));

/* ERSPAN Type III base header (first 12 bytes, ignoring TLVs for now) */
struct wpr_erspan3_hdr {
    uint32_t word1;  /* ver, vlan, cos, en, t, session_id, same as Type II */
    uint32_t word2;  /* O, G, hardware ID, etc. */
    uint32_t word3;  /* sequence, timestamp bits, etc. */
    /* Followed by optional TLVs we will skip over */
} __attribute__((__packed__));


/* Parsed VLAN tag */
typedef struct wpr_vlan{
    bool     present;
    uint16_t tpid;  /* 0x88A8 or 0x8100 */
    uint16_t vid;   /* 0..4095 */
    uint8_t  pcp;   /* 0..7 */
    uint8_t  dei;   /* 0/1 */
} wpr_vlan_t;

/* What we parsed at L3*/
typedef enum wpr_l3 {
    WPR_L3_NONE = 0,
    WPR_L3_IPV4 = 4,
    WPR_L3_IPV6 = 6,
} wpr_l3_t;


/* common L4 protocol enums */
typedef enum {
    WPR_L4_NONE  = 0,
    WPR_L4_TCP   = IPPROTO_TCP,   /* 6  */
    WPR_L4_UDP   = IPPROTO_UDP,   /* 17 */
    WPR_L4_SCTP  = IPPROTO_SCTP,  /* 132 */
    WPR_L4_ICMP  = IPPROTO_ICMP,  /* 1  */
    WPR_L4_ICMP6 = IPPROTO_ICMPV6, /* 58 */
} wpr_l4_t;

/* IPV6 Extension Header structs */
typedef struct __attribute__((__packed__)) ipv6_fragh{
    uint8_t  next_hdr;
    uint8_t  reserved;
    uint16_t frag_offset;
    uint32_t id;
} ipv6_fragh_t;

typedef struct __attribute__((__packed__)) ipv6_exth{
    uint8_t  next_hdr;
    uint8_t  hdr_ext_len; /* in 8-octet units, excluding first 8 bytes */
    uint8_t  rest[6];
} ipv6_exth_t;

typedef struct __attribute__((__packed__)) ipv6_ahh{
    uint8_t next_hdr;
    uint8_t payload_len; 
    uint16_t reserved; 
    uint32_t spi;
    uint32_t seq; 
} ipv6_ahh_t;


/* Parsed header summary */
typedef struct wpr_hdrs{
    /* port */
    uint16_t ingress_port_id;
    uint32_t pkt_hash; 
    uint32_t hash_valid;
    
    /* L2 */
    struct rte_ether_addr src_mac;
    struct rte_ether_addr dst_mac;
    uint16_t ether_type;         /* after VLANs, host-endian */

    /* VLANs (QinQ up to 2) */
    wpr_vlan_t vlan[2];          /* [0] outermost */
    uint8_t    vlan_count;       /* 0..2 */

    /* L3 Outer */
    wpr_l3_t l3_type;

    /* IPv4 */
    uint32_t outer_ipv4_src;     /* host-endian */
    uint32_t outer_ipv4_dst;     /* host-endian */
    uint8_t  outer_ipv4_tos;
    uint8_t  outer_ipv4_ttl;
    uint8_t  outer_ipv4_protocol;
    bool     outer_ipv4_fragmented;
    uint16_t outer_ipv4_frag_off; /* bytes */

    /* IPv6 */
    uint8_t  outer_ipv6_src[16];
    uint8_t  outer_ipv6_dst[16];
    uint8_t  outer_ipv6_protocol;
    uint8_t  outer_ipv6_tc;
    uint8_t  outer_ipv6_hlim;
    uint8_t  outer_ipv6_nh;      /* final L4 after skipping ext hdrs (slow path) */
    //fragment handling 
    bool     outer_ipv6_frag_ext_present;
    uint16_t outer_ipv6_frag_ext_ofs;   /* byte offset of fragment header, if present */

    /* L4 Outer */
    wpr_l4_t l4_type;
    uint16_t outer_l4_src_port;  /* host-endian */
    uint16_t outer_l4_dst_port;  /* host-endian */
    uint8_t  outer_icmp_type;
    uint8_t  outer_icmp_code;

    /* VXLAN */
    bool     vxlan_present;
    uint32_t vxlan_vni;          /* low 24 bits used */

    /* GRE / ERSPAN */
    bool     gre_present;
    uint16_t gre_protocol;       /* host-endian GRE protocol field */
    uint16_t gre_ofs;            /* byte offset of GRE header */
    bool     erspan_present;
    uint8_t  erspan_version;     /* 2 or 3 */
    uint16_t erspan_session_id;  /* low 10 bits from ERSPAN header */
    uint16_t erspan_vlan;        /* mirrored VLAN if present, 0..4095 */
    uint8_t  erspan_dir;         /* 0/1: ingress/egress if you want to use it */

    /* Inner (valid only if vxlan_present) */
    wpr_l3_t inner_l3_type;
    uint32_t inner_ipv4_src;
    uint32_t inner_ipv4_dst;
    uint8_t  inner_ipv4_protocol;
    uint8_t  inner_ipv6_src[16];
    uint8_t  inner_ipv6_dst[16];
    uint8_t  inner_ipv6_protocol;
    wpr_l4_t inner_l4_type;
    uint16_t inner_l4_src_port;
    uint16_t inner_l4_dst_port;
    uint8_t  inner_icmp_type;
    uint8_t  inner_icmp_code;

    /* Offsets for edits (bytes from frame start) */
    uint16_t l2_ofs;             /* 0 */
    uint16_t l2_len;             /* incl. VLANs parsed */
    uint16_t outer_l3_ofs;
    uint16_t outer_l4_ofs;
    uint16_t vxlan_ofs;
    uint16_t inner_l2_ofs;
    uint16_t inner_l3_ofs;
    uint16_t inner_l4_ofs;
} wpr_hdrs_t;

/* Tiny helper for segmented mbufs */
static inline bool wpr_mbuf_read(const struct rte_mbuf *m, uint32_t ofs, uint32_t len, void *dst)
{
    const void *p = rte_pktmbuf_read(m, ofs, len, dst);
    if (p == NULL)
        return false;

    // If data is contiguous, p points into mbuf: copy into dst
    if (p != dst)
        memcpy(dst, p, len); //memcpy vs dpdk 25+ avx memcopy warnings, also not necessary here

    return true;
}

/* -------- Fast-path (inline) --------
 * IPv4 + TCP/UDP, no VLAN, no VXLAN, no IPv4 fragments, no IPv4 options
 * Returns:
 *   0        : parsed in fast path
 *  -EAGAIN   : punt to slow path
 *  -EINVAL   : malformed / too short
 */

/** 
* Fast-path header parser: IPv4 + TCP/UDP, no VLAN, no VXLAN, no fragments, no options
* @param m
*   Pointer to the rte_mbuf structure
* @param h
*   Pointer to the wpr_hdrs_t structure to populate
* @return
*   0 on success (fast path), -EAGAIN to indicate slow path needed, -EINVAL on malformed packet 
**/
static inline int wpr_parse_headers_fast(const struct rte_mbuf *m, wpr_hdrs_t *h)
{
    /* --------------------------------- Basic L2/L3 Header Extract ---------------------------------- */
    //clear header struct
    __builtin_memset(h, 0, sizeof(*h));

    //set ingress port id 
    h->ingress_port_id = m->port;
    h->hash_valid = false;
    if (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
        h->pkt_hash = m->hash.rss;   // 32-bit NIC RSS hash
        h->hash_valid = true; 
    }
    
    //grab the l2 header
    struct rte_ether_hdr eth;
    if (!wpr_mbuf_read(m, 0, sizeof(eth), &eth)) 
        return -EINVAL;

    //if not ipv4, punt to slow path
    const uint16_t et = rte_be_to_cpu_16(eth.ether_type);
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "Fast-path parse: EtherType 0x%04X\n", et);
    if (unlikely(et != RTE_ETHER_TYPE_IPV4))
        return -EAGAIN;

    //grab ipv4 header
    struct rte_ipv4_hdr ip4;
    if (!wpr_mbuf_read(m, sizeof(eth), sizeof(ip4), &ip4))
        return -EINVAL;

    //fastpath doesn't handle options, punt to fastpath 
    const uint8_t ihl = (ip4.version_ihl & 0x0F) * 4;
    if (unlikely(ihl != sizeof(struct rte_ipv4_hdr)))
        return -EAGAIN; /* options -> slow */

    //if fragment headers present, punt to slow path
    const uint16_t frag_off = rte_be_to_cpu_16(ip4.fragment_offset);
    if (unlikely((frag_off & (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) != 0))
        return -EAGAIN;

    //populate common fields L2/l3 sources
    h->l2_ofs        = 0;
    h->l2_len        = sizeof(eth);
    h->outer_l3_ofs  = sizeof(eth);
    h->outer_l4_ofs  = sizeof(eth) + sizeof(ip4);
    h->l3_type       = WPR_L3_IPV4;
    h->ether_type    = et;
    h->dst_mac       = eth.dst_addr;
    h->src_mac       = eth.src_addr;
    h->outer_ipv4_src = rte_be_to_cpu_32(ip4.src_addr);
    h->outer_ipv4_dst = rte_be_to_cpu_32(ip4.dst_addr);
    h->outer_ipv4_protocol = ip4.next_proto_id;
    h->outer_ipv4_tos = ip4.type_of_service;
    h->outer_ipv4_ttl = ip4.time_to_live;

    /* --------------------------------- L4 Parsing ---------------------------------- */
    //process TCP
    if (ip4.next_proto_id == IPPROTO_TCP) {
        struct rte_tcp_hdr th;
        
        //bail if malformed
        if (!wpr_mbuf_read(m, h->outer_l4_ofs, sizeof(th), &th)) 
            return -EINVAL;
        
        //assign L4 TCP fields 
        h->l4_type           = WPR_L4_TCP;
        h->outer_l4_src_port = rte_be_to_cpu_16(th.src_port);
        h->outer_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        
        return 0;
    }

    //process UDP
    if (ip4.next_proto_id == IPPROTO_UDP) {
        struct rte_udp_hdr uh;
        
        //bail if malformed
        if (!wpr_mbuf_read(m, h->outer_l4_ofs, sizeof(uh), &uh)) 
            return -EINVAL;
        
        const uint16_t dport = rte_be_to_cpu_16(uh.dst_port);
        
        //don't handle vxlan in fast path
        if (unlikely(dport == WPR_VXLAN_UDP_PORT))
            return -EAGAIN; /* VXLAN -> slow */
        
        //assign L4 UDP fields
        h->l4_type           = WPR_L4_UDP;
        h->outer_l4_src_port = rte_be_to_cpu_16(uh.src_port);
        h->outer_l4_dst_port = dport;
        return 0;
    }
    return -EAGAIN; /* anything else -> slow */
}

/** 
* Slow-path header parser: full parsing with VLANs, VXLAN, IPv6, fragments, options
* @param m
*   Pointer to the rte_mbuf structure
* @param h
*   Pointer to the wpr_hdrs_t structure to populate
* @return
*   0 on success, -EINVAL on malformed packet
**/
__rte_noinline int wpr_parse_headers_slow(const struct rte_mbuf *m, wpr_hdrs_t *h);

/**
* Header parser with fast-path (inlined) + slow-path (non-inlined) fallback
* @param m
*   Pointer to the rte_mbuf structure
* @param h
*   Pointer to the wpr_hdrs_t structure to populate
* @return
*   0 on success, -EINVAL on malformed packet
**/
static inline int wpr_parse_headers(const struct rte_mbuf *m, wpr_hdrs_t *h)
{
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
        "data_off=%u, l2_len=%u, l3_len=%u, pkt_len=%u\n",
        m->data_off, m->l2_len, m->l3_len, m->pkt_len);
    int rc = wpr_parse_headers_fast(m, h);
    if (likely(rc == 0)) 
        return 0;
    
    if (rc == -EAGAIN) {       
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "Fast-path header parse punted to slow path\n");
        return wpr_parse_headers_slow(m, h);
    }
    return rc; // -EINVAL
}

/* ----------------------------------------- Display / Debug functions ------------------------------------- */

/* helper for MAC string */
static inline void mac_to_str(const struct rte_ether_addr *a, char *buf, size_t sz)
{
    snprintf(buf, sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             a->addr_bytes[0], a->addr_bytes[1], a->addr_bytes[2],
             a->addr_bytes[3], a->addr_bytes[4], a->addr_bytes[5]);
}

/* helper for IPv6 string */
static inline void ipv6_to_str(const uint8_t ip[16], char *buf, size_t sz)
{
    inet_ntop(AF_INET6, ip, buf, sz);
}

/* helper for IPv4 string */
static inline void ipv4_to_str(uint32_t ip, char *buf, size_t sz)
{
    struct in_addr a = { .s_addr = htonl(ip) };
    inet_ntop(AF_INET, &a, buf, sz);
}

/* Helper function to convert L3 protocol enum to string */
static inline const char* wpr_l3_str(wpr_l3_t v)
{
    switch (v) {
    case WPR_L3_NONE: return "NONE";
    case WPR_L3_IPV4: return "IPv4";
    case WPR_L3_IPV6: return "IPv6";
    default:          return "UNKNOWN_L3";
    }
}

/* Helper function to convert L4 protocol enum to string */
static inline const char* wpr_l4_str(wpr_l4_t v)
{
    switch (v) {
    case WPR_L4_NONE: return "NONE";
    case WPR_L4_TCP:  return "TCP";
    case WPR_L4_UDP:  return "UDP";
    case WPR_L4_ICMP: return "ICMP";
    case WPR_L4_ICMP6:return "ICMPv6";
    case WPR_L4_SCTP: return "SCTP";
    default:          return "UNKNOWN_L4";
    }
}

/** 
* Dump parsed header summary to log
* @param h
*   Pointer to the wpr_hdrs_t structure
* @param rx_portid
*   RX port ID where packet was received
**/

static inline void wpr_hdrs_dump(const wpr_hdrs_t *h, uint16_t rx_portid, unsigned int log_level)
{
    //Safety Check 
    if (!h)
        return;

    //don't attempt if log level is below debug
    if(likely(log_level < RTE_LOG_DEBUG)){
        return;
    }


    char smac[32], dmac[32];
    mac_to_str(&h->src_mac, smac, sizeof(smac));
    mac_to_str(&h->dst_mac, dmac, sizeof(dmac));

    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "==== Parsed Header Summary - PortID: %d ====\n", rx_portid);

    /* L2 */
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "L2:\n");
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "  src_mac=%s\n", smac);
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "  dst_mac=%s\n", dmac);
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "  ether_type=0x%04x\n", h->ether_type);

    /* VLANs */
    if (h->vlan_count > 0) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "VLANs (count=%u):\n", h->vlan_count);
        for (uint8_t i = 0; i < h->vlan_count; i++) {
            const wpr_vlan_t *v = &h->vlan[i];

            if (!v->present) {
                WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                        "  [%u] present=0 (skipped)\n", i);
                continue;
            }

            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  [%u] present=1 tpid=0x%04x vid=%u pcp=%u dei=%u\n",
                    i, v->tpid, v->vid, v->pcp, v->dei);
        }
    }

    /* Outer L3 */
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "Outer L3: %s\n", wpr_l3_str(h->l3_type));

    if (h->l3_type == WPR_L3_IPV4) {
        char src[32], dst[32];
        ipv4_to_str(h->outer_ipv4_src, src, sizeof(src));
        ipv4_to_str(h->outer_ipv4_dst, dst, sizeof(dst));

        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  IPv4 src=%s dst=%s tos=%u ttl=%u\n",
                src, dst, h->outer_ipv4_tos, h->outer_ipv4_ttl);

        if (h->outer_ipv4_fragmented) {
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  Fragmented: yes frag_off=%u bytes\n",
                    h->outer_ipv4_frag_off);
        }
    } else if (h->l3_type == WPR_L3_IPV6) {
        char src6[64], dst6[64];
        ipv6_to_str(h->outer_ipv6_src, src6, sizeof(src6));
        ipv6_to_str(h->outer_ipv6_dst, dst6, sizeof(dst6));

        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "  IPv6 src=%s\n", src6);
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "       dst=%s\n", dst6);
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  tc=%u hlim=%u nh=%u\n",
                h->outer_ipv6_tc, h->outer_ipv6_hlim, h->outer_ipv6_nh);
    }

    /* Outer L4 */
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "Outer L4: %s\n", wpr_l4_str(h->l4_type));

    if (h->l4_type == WPR_L4_TCP || h->l4_type == WPR_L4_UDP) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  src_port=%u dst_port=%u\n",
                h->outer_l4_src_port, h->outer_l4_dst_port);
    } else if (h->l4_type == WPR_L4_ICMP) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  icmp_type=%u icmp_code=%u\n",
                h->outer_icmp_type, h->outer_icmp_code);
    }

    /* VXLAN + Inner */
    if (h->vxlan_present) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "VXLAN:\n");
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "  vni=%u\n", h->vxlan_vni);

        /* Inner L3 */
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "Inner L3: %s\n", wpr_l3_str(h->inner_l3_type));

        if (h->inner_l3_type == WPR_L3_IPV4) {
            char src[32], dst[32];
            ipv4_to_str(h->inner_ipv4_src, src, sizeof(src));
            ipv4_to_str(h->inner_ipv4_dst, dst, sizeof(dst));
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  IPv4 src=%s dst=%s\n", src, dst);
        } else if (h->inner_l3_type == WPR_L3_IPV6) {
            char src6[64], dst6[64];
            ipv6_to_str(h->inner_ipv6_src, src6, sizeof(src6));
            ipv6_to_str(h->inner_ipv6_dst, dst6, sizeof(dst6));
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  IPv6 src=%s\n", src6);
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "        dst=%s\n", dst6);
        }

        /* Inner L4 */
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "Inner L4: %s\n", wpr_l4_str(h->inner_l4_type));

        if (h->inner_l4_type == WPR_L4_TCP || h->inner_l4_type == WPR_L4_UDP) {
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  src_port=%u dst_port=%u\n",
                    h->inner_l4_src_port, h->inner_l4_dst_port);
        } else if (h->inner_l4_type == WPR_L4_ICMP) {
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  icmp_type=%u icmp_code=%u\n",
                    h->inner_icmp_type, h->inner_icmp_code);
        }
    }

    /* GRE / ERSPAN + Inner */
    if (h->gre_present) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "GRE:\n");
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  protocol=0x%04x ofs=%u\n",
                h->gre_protocol, h->gre_ofs);
    }

    if (h->erspan_present) {
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "ERSPAN:\n");
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "  version=%u session_id=%u vlan=%u dir=%u\n",
                h->erspan_version,
                h->erspan_session_id,
                h->erspan_vlan,
                h->erspan_dir);
    }

    if (h->gre_present || h->erspan_present) {
        /* Inner is same view as VXLAN case */
        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "Inner L3 (GRE/ERSPAN): %s\n",
                wpr_l3_str(h->inner_l3_type));

        if (h->inner_l3_type == WPR_L3_IPV4) {
            char src[32], dst[32];
            ipv4_to_str(h->inner_ipv4_src, src, sizeof(src));
            ipv4_to_str(h->inner_ipv4_dst, dst, sizeof(dst));
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  IPv4 src=%s dst=%s\n", src, dst);
        } else if (h->inner_l3_type == WPR_L3_IPV6) {
            char src6[64], dst6[64];
            ipv6_to_str(h->inner_ipv6_src, src6, sizeof(src6));
            ipv6_to_str(h->inner_ipv6_dst, dst6, sizeof(dst6));
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  IPv6 src=%s\n", src6);
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "        dst=%s\n", dst6);
        }

        WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                "Inner L4 (GRE/ERSPAN): %s\n", wpr_l4_str(h->inner_l4_type));

        if (h->inner_l4_type == WPR_L4_TCP || h->inner_l4_type == WPR_L4_UDP) {
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  src_port=%u dst_port=%u\n",
                    h->inner_l4_src_port, h->inner_l4_dst_port);
        } else if (h->inner_l4_type == WPR_L4_ICMP || h->inner_l4_type == WPR_L4_ICMP6) {
            WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
                    "  icmp_type=%u icmp_code=%u\n",
                    h->inner_icmp_type, h->inner_icmp_code);
        }
    }

    /* Offsets */
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "\nOffsets:\n");
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
            "  l2_ofs=%u l2_len=%u outer_l3_ofs=%u outer_l4_ofs=%u\n",
            h->l2_ofs, h->l2_len, h->outer_l3_ofs, h->outer_l4_ofs);
    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG,
            "  vxlan_ofs=%u inner_l2_ofs=%u inner_l3_ofs=%u inner_l4_ofs=%u\n",
            h->vxlan_ofs, h->inner_l2_ofs, h->inner_l3_ofs, h->inner_l4_ofs);

    WPR_LOG(WPR_LOG_DP, RTE_LOG_DEBUG, "\n\n==== End Header Summary ====\n");
}

#endif /* WPR_HDRS_H */