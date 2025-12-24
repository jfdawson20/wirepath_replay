#ifndef WPR_FLOWKEY_H
#define WPR_FLOWKEY_H

#include "wpr_header_extract.h"

/* -------------------------------------------- Flow Key Structs ------------------------------------------------- */

//L2 flow key for L2 (Non IP) Flow Tables
typedef struct wpr_l2_flow_key {
    uint32_t tenant_id;   // same concept as IP table

    uint16_t in_port;     // ingress port id
    uint16_t outer_vlan;  // 0 if absent
    uint16_t inner_vlan;  // 0 if absent (QinQ)
    uint16_t ether_type;  // outer or inner, depending on your design

    struct rte_ether_addr src;
    struct rte_ether_addr dst;

    uint32_t hash;        // precomputed signature if you want it here too
} wpr_l2_flow_key_t __rte_aligned(8);


//ipv4 flow key 
typedef struct wpr_flow_key_v4{
    uint32_t src_ip;   // be32
    uint32_t dst_ip;   // be32
    uint16_t src_port; // be16
    uint16_t dst_port; // be16
    uint8_t  proto;    // IPPROTO_*
    uint8_t  _pad[3];  // keep alignment (explicit)
} wpr_flow_key_v4_t __rte_aligned(8);


//ipv6 flow key
typedef struct wpr_flow_key_v6{
    uint8_t  src_ip[16]; // raw bytes (network order)
    uint8_t  dst_ip[16]; // raw bytes (network order)
    uint16_t src_port;   // be16
    uint16_t dst_port;   // be16 
    uint8_t  proto;      // IPPROTO_*
    uint8_t  _pad[1];    // keep alignment
} wpr_flow_key_v6_t __rte_aligned(8);


// Unify v4/v6: we store family + union
// Family is AF_INET / AF_INET6 
typedef struct wpr_flow_key{
    uint32_t tenant_id;  
    uint8_t  family;     
    uint8_t  _pad0[3];

    union {
        wpr_flow_key_v4_t v4;
        wpr_flow_key_v6_t v6;
    } ip;

    uint32_t hash; 
    uint32_t _pad1;
} wpr_flow_key_t __rte_aligned(8);

//calculate max key size 
#define WPR_FT_MAX_KEY_SIZE \
    (sizeof(wpr_flow_key_t) > sizeof(wpr_l2_flow_key_t) ? \
        sizeof(wpr_flow_key_t) : sizeof(wpr_l2_flow_key_t))



/** 
* Build a flow table key from a packet headers structure
* @param ft
*   Pointer to flow table structure
* @param hdrs
*   Pointer to packet headers structure
* @param keys
*   Pointer to flow key structure to populate
* @return
*   0 on success, negative errno on failure 
**/
static inline int
wpr_flowkey_from_hdr(const wpr_hdrs_t *hdrs,
                     wpr_flow_key_t *key,
                     uint32_t pcap_slot_id)
{
    if (hdrs->l3_type == WPR_L3_NONE)
        return -1;

    // Zero the key – we’ll fill every field we care about.
    // (You can drop this later if you guarantee no padding is hashed.)
    memset(key, 0, sizeof(*key));

    uint32_t tenant_id = pcap_slot_id;

    /* ---------- IPv4 path (no IPv6 memcpy at all) ---------- */
    if (hdrs->l3_type == WPR_L3_IPV4) {
        uint32_t src_ip = hdrs->outer_ipv4_src;
        uint32_t dst_ip = hdrs->outer_ipv4_dst;
        uint16_t src_port = hdrs->outer_l4_src_port;
        uint16_t dst_port = hdrs->outer_l4_dst_port;
        uint8_t  proto    = hdrs->outer_ipv4_protocol;


        key->family             = AF_INET;
        key->tenant_id          = tenant_id;
        key->ip.v4.src_ip       = src_ip;
        key->ip.v4.dst_ip       = dst_ip;
        key->ip.v4.src_port     = src_port;
        key->ip.v4.dst_port     = dst_port;
        key->ip.v4.proto        = proto;

        goto compute_hash;
    }

    /* ---------- IPv6 path ---------- */
    if (hdrs->l3_type == WPR_L3_IPV6) {
        const uint8_t *src_ip = hdrs->outer_ipv6_src;
        const uint8_t *dst_ip = hdrs->outer_ipv6_dst;
        uint16_t src_port     = hdrs->outer_l4_src_port;
        uint16_t dst_port     = hdrs->outer_l4_dst_port;
        uint8_t  proto        = hdrs->outer_ipv6_protocol;

        key->family         = AF_INET6;
        key->tenant_id      = tenant_id;
        memcpy(key->ip.v6.src_ip, src_ip, 16);
        memcpy(key->ip.v6.dst_ip, dst_ip, 16);
        key->ip.v6.src_port = src_port;
        key->ip.v6.dst_port = dst_port;
        key->ip.v6.proto    = proto;

        goto compute_hash;
    }

    // Unsupported l3 type
    return -1;

compute_hash:
    key->hash = 0;

    return 0;
}

/** 
* Build a L2 flow table key from a packet headers structure
* @param ft
*   Pointer to flow table structure
* @param hdrs
*   Pointer to packet headers structure
* @param key
*   Pointer to L2 flow key structure to populate
* @return
*   0 on success, negative errno on failure
**/
static inline int wpr_l2_flowkey_from_hdr(const wpr_hdrs_t *hdrs,
                                          wpr_l2_flow_key_t *key,
                                          uint32_t pcap_slot_id)
{

    memset(key, 0, sizeof(*key));

    uint32_t tenant_id = pcap_slot_id;

    key->tenant_id  = tenant_id;
    key->in_port    = hdrs->ingress_port_id;        // or hdrs->input_port_id
    key->outer_vlan = hdrs->vlan_count > 0 ? hdrs->vlan[0].vid : 0;
    key->inner_vlan = hdrs->vlan_count > 1 ? hdrs->vlan[1].vid : 0;
    key->ether_type = hdrs->ether_type;     // whatever you already parsed

    key->src = hdrs->src_mac;
    key->dst = hdrs->dst_mac;

    //decide were to get the hash signature 
    key->hash = 0;



    return 0;
}

#endif /* WPR_FLOWKEY_H */