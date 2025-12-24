/*
SPDX-License-Identifier: MIT
Copyright (c) 2025 jfdawson20

Filename: wpr_header_extract.c
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
- GRE
- ERSPAN

For unrecognized protocols, the parser will set the relevant type fields to NONE and continue parsing as far as possible.

*/

#define _GNU_SOURCE

#include "wpr_header_extract.h"

/** 
* Skip IPv6 extension headers, updating offset and next header as well as storing the fragment header if present. 
* @param m
*   Pointer to the rte_mbuf structure
* @param ofs_io
*   Pointer to byte offset (input/output)
* @param nh_io
*   Pointer to next header (input/output)
* @return
*   true on success, false on failure (malformed)
**/
static bool ipv6_skip_ext(wpr_hdrs_t *hdrs, const struct rte_mbuf *m, uint16_t *ofs_io, uint8_t *nh_io)
{   
    uint8_t nh = *nh_io;       //next header 
    uint16_t ofs = *ofs_io;    //next header byte offset 


    for (int i = 0; i < 6; i++) {
        //if not a known extension header, break 
        if (!(nh == IPPROTO_HOPOPTS || nh == IPPROTO_ROUTING ||
              nh == IPPROTO_FRAGMENT || nh == IPPROTO_AH ||
              nh == IPPROTO_DSTOPTS || nh == IPPROTO_MH))
            break;
            
        //fragment header is special case, fixed 8 bytes
        if (nh == IPPROTO_FRAGMENT) {
            ipv6_fragh_t fragh;
            if (!wpr_mbuf_read(m, ofs, sizeof(ipv6_fragh_t), &fragh)) 
                return false;
            
            nh  = fragh.next_hdr;
            ofs += sizeof(ipv6_fragh_t);

            //store fragment header info in parsed headers
            hdrs->outer_ipv6_frag_ext_present = true;
            hdrs->outer_ipv6_frag_ext_ofs     = (uint16_t)(ofs - sizeof(ipv6_fragh_t));
    
        //Authentication Header also special case, 
        } else if (nh == IPPROTO_AH) {

            ipv6_ahh_t ah;

            if (!wpr_mbuf_read(m, ofs, sizeof(ah), &ah)) 
                return false;
            
            //ipv6 auth header extension uses 32-bit words for length not counting first two words
            uint16_t hdr_len = (uint16_t)((ah.payload_len + 2) * 4); 
            nh  = ah.next_hdr;
            ofs += hdr_len;

        //all other extension headers are the same length format
        } else {
            
            ipv6_exth_t exth;
            if (!wpr_mbuf_read(m, ofs, sizeof(exth), &exth)) return false;
            uint16_t hdr_len = (uint16_t)((exth.hdr_ext_len + 1) * 8);
            nh  = exth.next_hdr;
            ofs += hdr_len;
        }
    }

    //if we make it here, next header value and offset are now pointing to L4
    *ofs_io = ofs;
    *nh_io  = nh;
    return true;
}

/** 
* Parse VLAN/QinQ headers, updating offset and ethertype, advance pointers past vlan tags
* @param m
*   Pointer to the rte_mbuf structure
* @param ofs_io
*   Pointer to byte offset (input/output)
* @param ethertype_io
*   Pointer to ethertype (input/output)
* @param h
*   Pointer to wpr_hdrs_t structure to populate VLAN info
**/
static void parse_vlans(const struct rte_mbuf *m, uint16_t *ofs_io, uint16_t *ethertype_io,
                        wpr_hdrs_t *h)
{   
    //initialize pointers and vlan count
    h->vlan_count = 0;
    uint16_t ofs = *ofs_io;         //byte offset into frame
    uint16_t et  = *ethertype_io;   //current ethertype

    //support up to 2 VLANs (QinQ)
    for (int i = 0; i < 2; i++) {
        //if not vlan or QinQ break, nothing to parse 
        if (et != RTE_ETHER_TYPE_VLAN && et != RTE_ETHER_TYPE_QINQ)
            break;

        //create vlan header struct and read from mbuf
        struct rte_vlan_hdr vh;
        
        //attempt to read, break if read fails (e.g. segmented mbuf)
        if (!wpr_mbuf_read(m, ofs, sizeof(vh), &vh)) 
            break;

        //decode vlan tag fields and populate in header struct
        uint16_t tci = rte_be_to_cpu_16(vh.vlan_tci);
        h->vlan[i].present = true;
        h->vlan[i].tpid    = et;
        h->vlan[i].vid     = (uint16_t)(tci & 0x0FFF);
        h->vlan[i].pcp     = (uint8_t)((tci >> 13) & 0x7);
        h->vlan[i].dei     = (uint8_t)((tci >> 12) & 0x1);
        h->vlan_count++;

        et = rte_be_to_cpu_16(vh.eth_proto);

        //advance offset past this VLAN header
        ofs += sizeof(struct rte_vlan_hdr);
        
    }

    //final protocol update and offset update
    *ofs_io = ofs;
    *ethertype_io = et;
}

/* Parse inner L2/L3/L4 for a tunneled Ethernet frame (VXLAN / GRE-TEB / ERSPAN).
 * Starting at 'ofs', we expect an inner Ethernet header.
 * On success, fills h->inner_* fields and returns 0.
 * On error, returns negative.
 */
static int
wpr_parse_inner_l2_l3_l4(const struct rte_mbuf *m, wpr_hdrs_t *h, uint16_t ofs)
{
    struct rte_ether_hdr in_eth;
    if (!wpr_mbuf_read(m, ofs, sizeof(in_eth), &in_eth)) {
        return -100; // bad inner Ethernet
    }

    h->inner_l2_ofs = ofs;
    ofs += sizeof(struct rte_ether_hdr);

    uint16_t in_et = rte_be_to_cpu_16(in_eth.ether_type);

    /* Skip up to two inner VLANs (not recorded separately yet) */
    for (int i = 0; i < 2; i++) {
        if (in_et != RTE_ETHER_TYPE_VLAN && in_et != RTE_ETHER_TYPE_QINQ)
            break;

        struct rte_vlan_hdr vh;
        if (!wpr_mbuf_read(m, ofs, sizeof(vh), &vh)) {
            return -101; // bad inner VLAN
        }

        ofs += sizeof(struct rte_vlan_hdr);
        in_et = rte_be_to_cpu_16(vh.eth_proto);
    }

    /* Inner IPv4 */
    if (in_et == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr ip4i;
        uint8_t ip4i_full_buf[WPR_IPV4_MAX_HDR_LEN];

        if (!wpr_mbuf_read(m, ofs, sizeof(ip4i), &ip4i))
            return -102;

        uint8_t ihl_i = (uint8_t)((ip4i.version_ihl & 0x0F) * 4);
        if (ihl_i < sizeof(struct rte_ipv4_hdr) || ihl_i > WPR_IPV4_MAX_HDR_LEN)
            return -103;

        if (!wpr_mbuf_read(m, ofs, ihl_i, ip4i_full_buf))
            return -104;

        const struct rte_ipv4_hdr *ip4i_full =
            (const struct rte_ipv4_hdr *)ip4i_full_buf;

        h->inner_l3_type       = WPR_L3_IPV4;
        h->inner_ipv4_src      = rte_be_to_cpu_32(ip4i_full->src_addr);
        h->inner_ipv4_dst      = rte_be_to_cpu_32(ip4i_full->dst_addr);
        h->inner_ipv4_protocol = ip4i_full->next_proto_id;
        h->inner_l3_ofs        = ofs;

        ofs += ihl_i;
        h->inner_l4_ofs = ofs;

        uint8_t iwproto_i = ip4i_full->next_proto_id;

        if (iwproto_i == IPPROTO_TCP) {
            struct rte_tcp_hdr th;
            if (!wpr_mbuf_read(m, ofs, sizeof(th), &th))
                return -105;
            h->inner_l4_type     = WPR_L4_TCP;
            h->inner_l4_src_port = rte_be_to_cpu_16(th.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        } else if (iwproto_i == IPPROTO_UDP) {
            struct rte_udp_hdr uh_i;
            if (!wpr_mbuf_read(m, ofs, sizeof(uh_i), &uh_i))
                return -106;
            h->inner_l4_type     = WPR_L4_UDP;
            h->inner_l4_src_port = rte_be_to_cpu_16(uh_i.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(uh_i.dst_port);
        } else if (iwproto_i == IPPROTO_SCTP) {
            struct rte_sctp_hdr sh;
            if (!wpr_mbuf_read(m, ofs, sizeof(sh), &sh))
                return -107;
            h->inner_l4_type     = WPR_L4_SCTP;
            h->inner_l4_src_port = rte_be_to_cpu_16(sh.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
        } else if (iwproto_i == IPPROTO_ICMP) {
            struct rte_icmp_hdr ic;
            if (!wpr_mbuf_read(m, ofs, sizeof(ic), &ic))
                return -108;
            h->inner_l4_type   = WPR_L4_ICMP;
            h->inner_icmp_type = ic.icmp_type;
            h->inner_icmp_code = ic.icmp_code;
        } else {
            h->inner_l4_type = WPR_L4_NONE;
        }

        return 0;
    }

    /* Inner IPv6 */
    if (in_et == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr ip6i;
        if (!wpr_mbuf_read(m, ofs, sizeof(ip6i), &ip6i))
            return -109;

        h->inner_l3_type = WPR_L3_IPV6;
        rte_memcpy(h->inner_ipv6_src, &ip6i.src_addr, 16);
        rte_memcpy(h->inner_ipv6_dst, &ip6i.dst_addr, 16);
        h->inner_ipv6_protocol = ip6i.proto;
        h->inner_l3_ofs        = ofs;

        uint16_t ofs_i = (uint16_t)(ofs + sizeof(struct rte_ipv6_hdr));
        uint8_t  nh_i  = ip6i.proto;
        if (!ipv6_skip_ext(h, m, &ofs_i, &nh_i))
            return -110;

        h->inner_l4_ofs = ofs_i;

        if (nh_i == IPPROTO_TCP) {
            struct rte_tcp_hdr th;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(th), &th))
                return -111;
            h->inner_l4_type     = WPR_L4_TCP;
            h->inner_l4_src_port = rte_be_to_cpu_16(th.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        } else if (nh_i == IPPROTO_UDP) {
            struct rte_udp_hdr uh_i;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(uh_i), &uh_i))
                return -112;
            h->inner_l4_type     = WPR_L4_UDP;
            h->inner_l4_src_port = rte_be_to_cpu_16(uh_i.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(uh_i.dst_port);
        } else if (nh_i == IPPROTO_SCTP) {
            struct rte_sctp_hdr sh;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(sh), &sh))
                return -113;
            h->inner_l4_type     = WPR_L4_SCTP;
            h->inner_l4_src_port = rte_be_to_cpu_16(sh.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
        } else if (nh_i == IPPROTO_ICMPV6) {
            wpr_icmp6_min_t ic6;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(ic6), &ic6))
                return -114;
            h->inner_l4_type   = WPR_L4_ICMP6;
            h->inner_icmp_type = ic6.icmp6_type;
            h->inner_icmp_code = ic6.icmp6_code;
        } else {
            h->inner_l4_type = WPR_L4_NONE;
        }

        return 0;
    }

    /* Inner non-IP – we just know it's Ethernet */
    h->inner_l3_type = WPR_L3_NONE;
    h->inner_l4_type = WPR_L4_NONE;
    h->inner_l3_ofs  = ofs;
    return 0;
}

/* Parse GRE (outer L3 already parsed as IPv4/IPv6).
 * Supports:
 *   - GRE carrying Ethernet (TEB / ERSPAN)
 *   - GRE carrying IPv4/IPv6 directly
 *   - ERSPAN Type II / basic Type III (no TLV interpretation, just skipping).
 */
static int
wpr_parse_gre_outer(const struct rte_mbuf *m, wpr_hdrs_t *h, uint16_t ofs)
{
    struct wpr_gre_hdr gh;
    if (!wpr_mbuf_read(m, ofs, sizeof(gh), &gh)) {
        return -115; // truncated GRE header
    }

    uint16_t flags_version = rte_be_to_cpu_16(gh.flags_version);
    uint16_t gre_proto     = rte_be_to_cpu_16(gh.protocol);

    h->gre_present   = true;
    h->gre_protocol  = gre_proto;
    h->gre_ofs       = ofs;

    ofs += sizeof(struct wpr_gre_hdr);

    /* We only support GRE without checksum/routing.
     * C(0x8000), R(0x4000) must be zero.
     */
    if (flags_version & 0xC000) {
        return -116; // unsupported GRE options (checksum/routing)
    }

    /* Optional Key and Sequence fields */
    if (flags_version & 0x2000) { /* K bit -> key present */
        uint32_t key;
        if (!wpr_mbuf_read(m, ofs, sizeof(key), &key))
            return -117;
        ofs += sizeof(uint32_t);
        /* Optional: stash key */
    }

    if (flags_version & 0x1000) { /* S bit -> sequence present */
        uint32_t seq;
        if (!wpr_mbuf_read(m, ofs, sizeof(seq), &seq))
            return -118;
        ofs += sizeof(uint32_t);
        /* Optional: stash seq */
    }

    /* ERSPAN Type II or III */
    if (gre_proto == WPR_GRE_PROTO_ERSPAN2) {
        struct wpr_erspan2_hdr eh;
        if (!wpr_mbuf_read(m, ofs, sizeof(eh), &eh))
            return -119;

        uint32_t w1 = rte_be_to_cpu_32(eh.word1);

        h->erspan_present     = true;
        h->erspan_version     = 2;
        h->erspan_session_id  = (uint16_t)(w1 & 0x3FF);          /* bits 0..9 */
        h->erspan_dir         = (uint8_t)((w1 >> 10) & 0x1);     /* bit 10 T */
        h->erspan_vlan        = (uint16_t)((w1 >> 16) & 0x0FFF); /* bits 16..27 */

        ofs += sizeof(struct wpr_erspan2_hdr);

        /* Now at inner Ethernet frame */
        return wpr_parse_inner_l2_l3_l4(m, h, ofs);
    }

    if (gre_proto == WPR_GRE_PROTO_ERSPAN3) {
        struct wpr_erspan3_hdr eh3;
        if (!wpr_mbuf_read(m, ofs, sizeof(eh3), &eh3))
            return -120;

        uint32_t w1 = rte_be_to_cpu_32(eh3.word1);

        h->erspan_present     = true;
        h->erspan_version     = 3;
        h->erspan_session_id  = (uint16_t)(w1 & 0x3FF);
        h->erspan_dir         = (uint8_t)((w1 >> 10) & 0x1);
        h->erspan_vlan        = (uint16_t)((w1 >> 16) & 0x0FFF);

        ofs += sizeof(struct wpr_erspan3_hdr);

        /* TODO: Type III TLVs – for now we assume none.
         * If you parse TLVs later, advance 'ofs' here.
         */

        return wpr_parse_inner_l2_l3_l4(m, h, ofs);
    }

    /* Generic GRE: IP-in-GRE or Ethernet-in-GRE */

    if (gre_proto == RTE_ETHER_TYPE_IPV4) {
        struct rte_ipv4_hdr ip4;
        uint8_t ip4_full_buf[WPR_IPV4_MAX_HDR_LEN];

        if (!wpr_mbuf_read(m, ofs, sizeof(ip4), &ip4))
            return -121;

        uint8_t ihl = (uint8_t)((ip4.version_ihl & 0x0F) * 4);
        if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > WPR_IPV4_MAX_HDR_LEN)
            return -122;

        if (!wpr_mbuf_read(m, ofs, ihl, ip4_full_buf))
            return -123;

        const struct rte_ipv4_hdr *ip4_full =
            (const struct rte_ipv4_hdr *)ip4_full_buf;

        h->inner_l3_type       = WPR_L3_IPV4;
        h->inner_ipv4_src      = rte_be_to_cpu_32(ip4_full->src_addr);
        h->inner_ipv4_dst      = rte_be_to_cpu_32(ip4_full->dst_addr);
        h->inner_ipv4_protocol = ip4_full->next_proto_id;
        h->inner_l3_ofs        = ofs;

        ofs += ihl;
        h->inner_l4_ofs = ofs;

        uint8_t iwproto_i = ip4_full->next_proto_id;

        if (iwproto_i == IPPROTO_TCP) {
            struct rte_tcp_hdr th;
            if (!wpr_mbuf_read(m, ofs, sizeof(th), &th))
                return -124;
            h->inner_l4_type     = WPR_L4_TCP;
            h->inner_l4_src_port = rte_be_to_cpu_16(th.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        } else if (iwproto_i == IPPROTO_UDP) {
            struct rte_udp_hdr uh_i;
            if (!wpr_mbuf_read(m, ofs, sizeof(uh_i), &uh_i))
                return -125;
            h->inner_l4_type     = WPR_L4_UDP;
            h->inner_l4_src_port = rte_be_to_cpu_16(uh_i.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(uh_i.dst_port);
        } else if (iwproto_i == IPPROTO_SCTP) {
            struct rte_sctp_hdr sh;
            if (!wpr_mbuf_read(m, ofs, sizeof(sh), &sh))
                return -126;
            h->inner_l4_type     = WPR_L4_SCTP;
            h->inner_l4_src_port = rte_be_to_cpu_16(sh.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
        } else if (iwproto_i == IPPROTO_ICMP) {
            struct rte_icmp_hdr ic;
            if (!wpr_mbuf_read(m, ofs, sizeof(ic), &ic))
                return -127;
            h->inner_l4_type   = WPR_L4_ICMP;
            h->inner_icmp_type = ic.icmp_type;
            h->inner_icmp_code = ic.icmp_code;
        } else {
            h->inner_l4_type = WPR_L4_NONE;
        }

        return 0;
    }

    if (gre_proto == RTE_ETHER_TYPE_IPV6) {
        struct rte_ipv6_hdr ip6i;
        if (!wpr_mbuf_read(m, ofs, sizeof(ip6i), &ip6i))
            return -128;

        h->inner_l3_type = WPR_L3_IPV6;
        rte_memcpy(h->inner_ipv6_src, &ip6i.src_addr, 16);
        rte_memcpy(h->inner_ipv6_dst, &ip6i.dst_addr, 16);
        h->inner_ipv6_protocol = ip6i.proto;
        h->inner_l3_ofs        = ofs;

        uint16_t ofs_i = (uint16_t)(ofs + sizeof(struct rte_ipv6_hdr));
        uint8_t  nh_i  = ip6i.proto;
        if (!ipv6_skip_ext(h, m, &ofs_i, &nh_i))
            return -129;

        h->inner_l4_ofs = ofs_i;

        if (nh_i == IPPROTO_TCP) {
            struct rte_tcp_hdr th;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(th), &th))
                return -130;
            h->inner_l4_type     = WPR_L4_TCP;
            h->inner_l4_src_port = rte_be_to_cpu_16(th.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        } else if (nh_i == IPPROTO_UDP) {
            struct rte_udp_hdr uh_i;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(uh_i), &uh_i))
                return -131;
            h->inner_l4_type     = WPR_L4_UDP;
            h->inner_l4_src_port = rte_be_to_cpu_16(uh_i.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(uh_i.dst_port);
        } else if (nh_i == IPPROTO_SCTP) {
            struct rte_sctp_hdr sh;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(sh), &sh))
                return -132;
            h->inner_l4_type     = WPR_L4_SCTP;
            h->inner_l4_src_port = rte_be_to_cpu_16(sh.src_port);
            h->inner_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
        } else if (nh_i == IPPROTO_ICMPV6) {
            wpr_icmp6_min_t ic6;
            if (!wpr_mbuf_read(m, ofs_i, sizeof(ic6), &ic6))
                return -133;
            h->inner_l4_type   = WPR_L4_ICMP6;
            h->inner_icmp_type = ic6.icmp6_type;
            h->inner_icmp_code = ic6.icmp6_code;
        } else {
            h->inner_l4_type = WPR_L4_NONE;
        }

        return 0;
    }

    if (gre_proto == WPR_GRE_PROTO_TEB) {
        /* Transparent Ethernet Bridging – inner is Ethernet frame */
        return wpr_parse_inner_l2_l3_l4(m, h, ofs);
    }

    /* Unknown GRE payload – we still mark GRE present but don't decode inner */
    return 0;
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
__rte_noinline int wpr_parse_headers_slow(const struct rte_mbuf *m, wpr_hdrs_t *h)
{
    //zero out header struct and l2 offset  
    __builtin_memset(h, 0, sizeof(*h));
    h->l2_ofs = 0;

    //store ingress port id 
    h->ingress_port_id = m->port;


    h->ingress_port_id = m->port;
    
    h->hash_valid = false;
    if (m->ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
        h->pkt_hash = m->hash.rss;   // 32-bit NIC RSS hash
        h->hash_valid = true;
    }

    /* ------------------------------- Ethernet Header Parse ------------------------------ */
    //attempt to parse Ethernet header
    struct rte_ether_hdr eth;
    if (!wpr_mbuf_read(m, 0, sizeof(eth), &eth)) {
        return -1;
    }

    //assign header struct src/dst mac addresses
    h->dst_mac = eth.dst_addr;
    h->src_mac = eth.src_addr;

    //extract ethertype and set initial offset
    uint16_t ethertype = rte_be_to_cpu_16(eth.ether_type);
    uint16_t ofs = sizeof(struct rte_ether_hdr);
    h->l2_len = ofs;

    /* ------------------------------- VLAN Parsing -------------------------------------- */
    parse_vlans(m, &ofs, &ethertype, h);
    
    //assign final ethertype and L2 offset after VLAN parsing (inner vlan if present)
    h->ether_type = ethertype;
    h->l2_len     = ofs;

    /* ------------------------------- Outer L3: IPv4 or IPv6 ------------------------------ */
    //handle IPV4 Parsing
    if (ethertype == RTE_ETHER_TYPE_IPV4) {
        
        //define ipv4 header struct and buffer to hold full header
        struct rte_ipv4_hdr ip4;
        uint8_t ip4_full_buf[WPR_IPV4_MAX_HDR_LEN];

        //attempt to read ipv4 header, default length used
        if (!wpr_mbuf_read(m, ofs, sizeof(ip4), &ip4)){
            return -2;
        }

        //determine full header length from IHL field
        uint8_t ihl = (uint8_t)((ip4.version_ihl & 0x0F) * 4);

        // malformed header
        if (ihl < sizeof(struct rte_ipv4_hdr) || ihl > WPR_IPV4_MAX_HDR_LEN){
            return -3;  
        }

        //read full ipv4 header, includes IHL fields 
        if (!wpr_mbuf_read(m, ofs, ihl, ip4_full_buf))
            return -4;

        //now that we have a full header, recast as ipv4 struct pointer for access
        const struct rte_ipv4_hdr *ip4_full = (const struct rte_ipv4_hdr *)ip4_full_buf;

        //populate parsed IPV4 header struct fields
        h->l3_type            = WPR_L3_IPV4;
        h->outer_ipv4_src     = rte_be_to_cpu_32(ip4_full->src_addr);
        h->outer_ipv4_dst     = rte_be_to_cpu_32(ip4_full->dst_addr);
        h->outer_ipv4_protocol= ip4_full->next_proto_id;
        h->outer_ipv4_tos     = ip4_full->type_of_service;
        h->outer_ipv4_ttl     = ip4_full->time_to_live;

        //fragmentation fields
        uint16_t frag_off   = rte_be_to_cpu_16(ip4_full->fragment_offset);
        h->outer_ipv4_fragmented = ((frag_off & (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_DF_FLAG)) & RTE_IPV4_HDR_MF_FLAG) ||
                                   ((frag_off & RTE_IPV4_HDR_OFFSET_MASK) != 0);
        
        h->outer_ipv4_frag_off   = (uint16_t)((frag_off & RTE_IPV4_HDR_OFFSET_MASK) << 3);

        //record protocol and L3 offset before advancing to L4
        uint8_t proto = ip4_full->next_proto_id;
        h->outer_l3_ofs = ofs;
        ofs += ihl;

        /* ------------------------------- Outer L4 (If not fragmented) ------------------------------ */
        //if we are not fragmented, attempt to parse L4 information
        if (!h->outer_ipv4_fragmented) {

            //store outer l4 offset 
            h->outer_l4_ofs = ofs;

            /* IPv4 + GRE (generic + ERSPAN) */
            if (proto == IPPROTO_GRE) {
                int rc_gre = wpr_parse_gre_outer(m, h, ofs);
                if (rc_gre < 0)
                    return rc_gre;
                /* We treat GRE/ERSPAN as fully parsed at this point. */
                return 0;
            }

            //if we are UDP 
            if (proto == IPPROTO_UDP) {
                //create and read a UDP struct
                struct rte_udp_hdr uh;
                if (!wpr_mbuf_read(m, ofs, sizeof(uh), &uh)) {
                    return -5;
                }

                //if successful store outer L4 
                h->l4_type           = WPR_L4_UDP;
                h->outer_l4_src_port = rte_be_to_cpu_16(uh.src_port);
                h->outer_l4_dst_port = rte_be_to_cpu_16(uh.dst_port);
                ofs += sizeof(struct rte_udp_hdr);

                /* ------------------------------- IPV4 Outer + VXLAN / Inner Header Parsing -------------------------- */
                //VXLAN is a sepecial case of UDP for supporting multi-tenant overlay networks, if we detect VXLAN port, parse inner headers
                if (h->outer_l4_dst_port == WPR_VXLAN_UDP_PORT) {
                    
                    //build and read VXLAN Header
                    struct wpr_vxlan_hdr vxh;
                    
                    if (!wpr_mbuf_read(m, ofs, sizeof(vxh), &vxh)) {
                        // truncated header – *maybe* treat as malformed
                        return -5;  // or just "give up" and let caller drop
                    }

                    if (!(vxh.flags & 0x08)) {
                        // I-bit not set: not a valid VXLAN frame → just treat as plain UDP
                        // We already set h->l4_type, ports, etc. above, so just:
                        return 0;
                    }
                        
                    //mark VXLAN present and populate fields
                    h->vxlan_present = true;
                    h->vxlan_ofs     = ofs;
                    h->vxlan_vni     = ((uint32_t)vxh.vni[0] << 16) |
                                       ((uint32_t)vxh.vni[1] << 8)  |
                                       ((uint32_t)vxh.vni[2]);
                    ofs += sizeof(struct wpr_vxlan_hdr);

                    /* ------------------------------- IPV4 Outer + VXLAN + Inner Ethernet Processing -------------------------- */
                    int rc_inner = wpr_parse_inner_l2_l3_l4(m, h, ofs);
                    if (rc_inner < 0)
                        return rc_inner;
                } 
            //back to outer L4 parsing if TCP
            } else if (proto == IPPROTO_TCP) {
                //parse or bail 
                struct rte_tcp_hdr th;
                if (!wpr_mbuf_read(m, ofs, sizeof(th), &th)) {
                    return -21;
                }
                h->l4_type           = WPR_L4_TCP;
                h->outer_l4_src_port = rte_be_to_cpu_16(th.src_port);
                h->outer_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
            
            // if we are SCTP
            } else if (proto == IPPROTO_SCTP) {
                //parse or bail
                struct rte_sctp_hdr sh;
                if (!wpr_mbuf_read(m, ofs, sizeof(sh), &sh)) {
                    return -23;
                }
                h->l4_type           = WPR_L4_SCTP;
                h->outer_l4_src_port = rte_be_to_cpu_16(sh.src_port);
                h->outer_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
            
            //if we are ICMP 
            } else if (proto == IPPROTO_ICMP) {
                //parse or bail
                struct rte_icmp_hdr ic;
                if (!wpr_mbuf_read(m, ofs, sizeof(ic), &ic)) {
                    return -24;
                }
                h->l4_type        = WPR_L4_ICMP;
                h->outer_icmp_type = ic.icmp_type;
                h->outer_icmp_code = ic.icmp_code;
            }
        }

    /* ------------------------------- Outer IPV6/L4 Processing -------------------------- */
    } else if (ethertype == RTE_ETHER_TYPE_IPV6) {
        //define ipv6 header struct and attempt to read, bail if malformed
        struct rte_ipv6_hdr ip6;
        if (!wpr_mbuf_read(m, ofs, sizeof(ip6), &ip6)) {
            return -25;
        }

        //populate parsed IPV6 header struct fields
        h->l3_type = WPR_L3_IPV6;
        rte_memcpy(h->outer_ipv6_src, &ip6.src_addr, 16);
        rte_memcpy(h->outer_ipv6_dst, &ip6.dst_addr, 16);
        h->outer_ipv6_protocol = ip6.proto;

        uint32_t vtc = rte_be_to_cpu_32(ip6.vtc_flow);
        h->outer_ipv6_tc   = (uint8_t)((vtc >> 20) & 0xFF);
        h->outer_ipv6_hlim = ip6.hop_limits;
        uint8_t nh = ip6.proto;

        h->outer_l3_ofs = ofs;
        ofs += sizeof(struct rte_ipv6_hdr);

        //advance offset past ipv6 headers, bail if malformed
        if (!ipv6_skip_ext(h,m, &ofs, &nh)) {
            return -26;
        }
        h->outer_l4_ofs = ofs;
        h->outer_ipv6_nh = nh;

        /* IPv6 + GRE (generic + ERSPAN) */
        if (nh == IPPROTO_GRE) {
            int rc_gre = wpr_parse_gre_outer(m, h, ofs);
            if (rc_gre < 0)
                return rc_gre;
            return 0;
        }

        /* ------------------------------- Outer L4 (If not fragmented) ------------------------------ */
        //if we are UDP
        if (nh == IPPROTO_UDP) {
            //parse or bail
            struct rte_udp_hdr uh;
            if (!wpr_mbuf_read(m, ofs, sizeof(uh), &uh)) {
                return -27;
            }
            h->l4_type           = WPR_L4_UDP;
            h->outer_l4_src_port = rte_be_to_cpu_16(uh.src_port);
            h->outer_l4_dst_port = rte_be_to_cpu_16(uh.dst_port);
            ofs += sizeof(struct rte_udp_hdr);

            /* ------------------------------- IPV6 Outer + VXLAN / Inner Header Parsing -------------------------- */
            if (h->outer_l4_dst_port == WPR_VXLAN_UDP_PORT) {

                //parse or bail
                struct wpr_vxlan_hdr vxh;
                if (!wpr_mbuf_read(m, ofs, sizeof(vxh), &vxh)) {
                    // truncated header – *maybe* treat as malformed
                    return -5;  // or just "give up" and let caller drop
                }

                if (!(vxh.flags & 0x08)) {
                    // I-bit not set: not a valid VXLAN frame → just treat as plain UDP
                    // We already set h->l4_type, ports, etc. above, so just:
                    return 0;
                }
                h->vxlan_present = true;
                h->vxlan_ofs     = ofs;
                h->vxlan_vni     = ((uint32_t)vxh.vni[0] << 16) |
                                   ((uint32_t)vxh.vni[1] << 8)  |
                                   ((uint32_t)vxh.vni[2]);
                ofs += sizeof(struct wpr_vxlan_hdr);

                /* ------------------------------- IPV6 Outer + VXLAN + Inner Ethernet Processing -------------------------- */
                int rc_inner = wpr_parse_inner_l2_l3_l4(m, h, ofs);
                if (rc_inner < 0)
                    return rc_inner;                
            }
        //back to outer L4 parsing if TCP
        } else if (nh == IPPROTO_TCP) {
            //parse or bail
            struct rte_tcp_hdr th;
            if (!wpr_mbuf_read(m, ofs, sizeof(th), &th)) {
                return -44;
            };
            h->l4_type           = WPR_L4_TCP;
            h->outer_l4_src_port = rte_be_to_cpu_16(th.src_port);
            h->outer_l4_dst_port = rte_be_to_cpu_16(th.dst_port);
        
        //if we are SCTP
        } else if (nh == IPPROTO_SCTP) {
            //parse or bail
            struct rte_sctp_hdr sh;
            if (!wpr_mbuf_read(m, ofs, sizeof(sh), &sh)) {
                return -45;
            }
            h->l4_type           = WPR_L4_SCTP;
            h->outer_l4_src_port = rte_be_to_cpu_16(sh.src_port);
            h->outer_l4_dst_port = rte_be_to_cpu_16(sh.dst_port);
        
        //if we are ICMPv6
        } else if (nh == IPPROTO_ICMPV6) {
            //parse or bail
            wpr_icmp6_min_t ic6;
            if (!wpr_mbuf_read(m, ofs, sizeof(ic6), &ic6)) {
                return -46;
            }
            h->l4_type         = WPR_L4_ICMP6;
            h->outer_icmp_type = ic6.icmp6_type;
            h->outer_icmp_code = ic6.icmp6_code;
        }
    } else {
        /* Non-IP payload (ARP/LLDP/etc.) — L2-only is fine */
    }

    return 0;
}